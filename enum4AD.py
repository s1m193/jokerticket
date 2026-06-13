#!/usr/bin/env python3
"""
BloodHound Full Data Collector + ACE Diagnostic
================================================
Run once → collects everything → diagnoses ACE gaps → auto-corrects output.
"""
import os, sys, re, json, socket, struct, platform, signal, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, BASE
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init

init(autoreset=True)

def _exit(sig, frame):
    print(Fore.YELLOW + "\n[!] Exiting..." + Style.RESET_ALL); sys.exit(0)
signal.signal(signal.SIGINT, _exit)


# ══════════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════════

SD_CTRL = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]

ACE_TYPES = {
    0x00: "ACCESS_ALLOWED",          0x01: "ACCESS_DENIED",
    0x02: "SYSTEM_AUDIT",            0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",    0x09: "ACCESS_ALLOWED_CALLBACK",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
}

MASK_BITS = {
    0x00000001: "CreateChild",       0x00000002: "DeleteChild",
    0x00000004: "ListContents",      0x00000008: "Self/ValidatedWrite",
    0x00000010: "ReadProperty",      0x00000020: "WriteProperty",
    0x00000040: "DeleteTree",        0x00000080: "ListObject",
    0x00000100: "ExtendedRight",     0x00010000: "Delete",
    0x00020000: "ReadControl",       0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",        0x10000000: "GenericAll",
    0x40000000: "GenericWrite",      0x80000000: "GenericRead",
}

ACE_FLAG_NAMES = {
    0x01: "OI", 0x02: "CI", 0x04: "NP",
    0x08: "INHERIT_ONLY", 0x10: "INHERITED",
    0x40: "SA", 0x80: "FA",
}

EXT_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "msDS-KeyCredentialLink",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll-Certificate",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnrollment",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
}

SCHEMA_ATTRS = {
    "bf967953-0de6-11d0-a285-00aa003049e2": "scriptPath",
    "bf967a7f-0de6-11d0-a285-00aa003049e2": "userAccountControl",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
    "28630eb8-41d5-11d1-a9c1-0000f80367c1": "msDS-KeyCredentialLink",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",   # shadow creds
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "msDS-KeyCredentialLink",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",                   # group member write
    "3e74f60e-3e73-11d1-a9c0-0000f80367c1": "userPassword",
    "bf967a68-0de6-11d0-a285-00aa003049e2": "userParameters",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "mail",
    "bf967950-0de6-11d0-a285-00aa003049e2": "pwdLastSet",
    "bf9679e3-0de6-11d0-a285-00aa003049e2": "unicodePwd",
    "bf96793f-0de6-11d0-a285-00aa003049e2": "lmPwdHistory",
    "bf967994-0de6-11d0-a285-00aa003049e2": "ntPwdHistory",
    "4c164200-20c0-11d0-a768-00aa006e0529": "userAccountControl",       # alt GUID
    "19195a5b-6da0-11d0-afd3-00c04fd930c9": "objectSid",
    "bf967915-0de6-11d0-a285-00aa003049e2": "dBCSPwd",
}

# BloodHound edge name mappings
# ExtendedRight GUID names → BH graph edge names
EXT_RIGHT_TO_BH = {
    "User-Force-Change-Password":                    "ForceChangePassword",
    "DS-Replication-Get-Changes":                    "GetChanges",
    "DS-Replication-Get-Changes-All":                "GetChangesAll",
    "DS-Replication-Get-Changes-In-Filtered-Set":    "GetChangesInFilteredSet",
    "Self-Membership":                               "AddSelf",
    "Validated-SPN":                                 "WriteSPN",
    "DNS-Host-Name-Attributes":                      "WriteAccountRestrictions",
    "User-Account-Restrictions":                     "WriteAccountRestrictions",
    "msDS-KeyCredentialLink":                        "AddKeyCredentialLink",
    "Enroll-Certificate":                            "Enroll",
    "AutoEnrollment":                                "AutoEnroll",
}

# WriteProperty attr names → BH graph edge names
WRITE_PROP_TO_BH = {
    "member":                   "AddMember",
    "msDS-KeyCredentialLink":   "AddKeyCredentialLink",
    "servicePrincipalName":     "WriteSPN",
    "scriptPath":               "WriteProperty-scriptPath",
    "userAccountControl":       "WriteProperty-userAccountControl",
    "userPassword":             "WriteProperty-userPassword",
    "userParameters":           "WriteProperty-userParameters",
    "mail":                     "WriteProperty-mail",
    "unicodePwd":               "WriteProperty-unicodePwd",
    "lmPwdHistory":             "WriteProperty-lmPwdHistory",
    "ntPwdHistory":             "WriteProperty-ntPwdHistory",
    "dBCSPwd":                  "WriteProperty-dBCSPwd",
}

HIGH_VALUE_GROUPS = {
    'domain admins', 'enterprise admins', 'schema admins', 'administrators',
    'backup operators', 'account operators', 'print operators', 'server operators',
    'group policy creator owners', 'dns admins', 'exchange windows permissions',
    'remote management users', 'domain controllers', 'read-only domain controllers',
}


# ══════════════════════════════════════════════════════════════════
#  Banner / Input / Validation
# ══════════════════════════════════════════════════════════════════

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════╗
    ║              BloodHound  Data Collector           ║
    ║  	       Collects AD data -> BloodHound JSON      ║
    ╚═══════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Platform: {platform.system()} {platform.release()}" + Style.RESET_ALL)

def validate_ip(ip):
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip): return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def validate_domain(d):
    if not re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', d): return False
    return all(p and not p.startswith('-') and not p.endswith('-') for p in d.split('.'))

def ask(prompt, validator=None, err=None, allow_empty=False):
    while True:
        try:
            v = input(prompt).strip()
            if not v and not allow_empty:
                print(Fore.RED + "[!] Cannot be empty!" + Style.RESET_ALL); continue
            if validator and v and not validator(v):
                print(Fore.RED + f"[!] {err}" + Style.RESET_ALL); continue
            return v
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Exiting..." + Style.RESET_ALL); sys.exit(0)

def resolve_output_dir(user_input, ts):
    path = os.path.join(os.getcwd(), user_input.lstrip('/\\') if user_input else f"bloodhound-{ts}")
    path = os.path.normpath(path)
    try:
        os.makedirs(path, exist_ok=True); return path
    except:
        fb = os.path.join(os.getcwd(), f"bloodhound-{ts}")
        os.makedirs(fb, exist_ok=True); return fb


# ══════════════════════════════════════════════════════════════════
#  Network / LDAP
# ══════════════════════════════════════════════════════════════════

def check_port(ip, port=445, timeout=3):
    try:
        s = socket.socket(); s.settimeout(timeout)
        r = s.connect_ex((ip, port)); s.close(); return r == 0
    except: return False

def verify_creds(dc_ip, domain, username, password):
    try:
        base = ','.join(f"DC={p}" for p in domain.split('.'))
        srv  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(srv, user=f"{domain}\\{username}", password=password,
                          authentication=NTLM, auto_bind=True)
        conn.search(base, '(objectClass=domain)', search_scope=SUBTREE, attributes=['dc'])
        ok = len(conn.entries) > 0; conn.unbind(); return ok
    except LDAPBindError: return "bad_creds"
    except: return False

def ldap_connect(dc_ip, domain, username, password):
    try:
        srv  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(srv, user=f"{domain}\\{username}", password=password,
                          authentication=NTLM, auto_bind=True)
        return conn
    except Exception as e:
        print(Fore.RED + f"[-] LDAP failed: {e}" + Style.RESET_ALL); return None

def get_base_dn(domain):
    return ','.join(f"DC={p}" for p in domain.split('.'))


# ══════════════════════════════════════════════════════════════════
#  Data helpers
# ══════════════════════════════════════════════════════════════════

def sid_to_str(b):
    try:
        if isinstance(b, str): return b
        if not b or len(b) < 8: return ""
        rev  = b[0]; cnt = b[1]
        auth = int.from_bytes(b[2:8], 'big')
        subs = []
        for i in range(cnt):
            off = 8+4*i
            if off+4 > len(b): break
            subs.append(str(struct.unpack_from('<I', b, off)[0]))
        return f"S-{rev}-{auth}-{'-'.join(subs)}"
    except: return ""

def ft2epoch(ft):
    try:
        if not ft or ft == 0 or ft == -1: return -1
        if isinstance(ft, datetime): return int(ft.timestamp())
        v = int(ft); return -1 if v <= 0 else (v - 116444736000000000) // 10000000
    except: return -1

def ga(a, k, d=None):
    try:
        v = a.get(k)
        if v is None: return d
        if isinstance(v, list): return d if not v else v[0]
        return v
    except: return d

def gal(a, k):
    try:
        v = a.get(k)
        if v is None: return []
        return [str(x) for x in (v if isinstance(v, list) else [v]) if x is not None]
    except: return []

def graw(e, attr):
    try:
        vals = e[attr].raw_values; return vals[0] if vals else None
    except: return None

def guid_from_bytes(b):
    if not b or len(b) < 16: return None
    p1 = struct.unpack_from('<I', b, 0)[0]
    p2 = struct.unpack_from('<H', b, 4)[0]
    p3 = struct.unpack_from('<H', b, 6)[0]
    return f"{p1:08x}-{p2:04x}-{p3:04x}-{b[8:10].hex()}-{b[10:16].hex()}"

def mask_desc(mask):
    return ' | '.join(n for bit, n in MASK_BITS.items() if mask & bit) or f"0x{mask:08X}"

def flags_desc(f):
    return ' '.join(n for bit, n in ACE_FLAG_NAMES.items() if f & bit) or "none"


# ══════════════════════════════════════════════════════════════════
#  ACE Parser  (full + diagnostic mode)
# ══════════════════════════════════════════════════════════════════

def map_rights(mask, obj_guid, verbose=False):
    """
    Map ACCESS_MASK + optional ObjectType GUID → BloodHound right names.

    Priority rules (matching SharpHound):
    - ExtendedRight  (0x100)  → look in EXT_RIGHTS by GUID
    - WriteProperty  (0x020)  → look in SCHEMA_ATTRS by GUID
                                 (NOT EXT_RIGHTS — different bit means different table)
    - Self/Validated (0x008)  → look in EXT_RIGHTS by GUID
    """
    g = obj_guid.lower() if obj_guid else None
    r = []

    # ── GenericAll ────────────────────────────────────────────────
    if (mask & 0x000F01FF) == 0x000F01FF or (mask & 0x10000000):
        return ["GenericAll"]

    # ── DACL / Owner ──────────────────────────────────────────────
    if mask & 0x00040000: r.append("WriteDacl")
    if mask & 0x00080000: r.append("WriteOwner")

    # ── GenericWrite ───────────────────────────────────────────────
    if mask & 0x40000000: r.append("GenericWrite")

    # ── ExtendedRight / ControlAccess (0x100) ─────────────────────
    if mask & 0x00000100:
        if g:
            raw_name = EXT_RIGHTS.get(g)
            if raw_name:
                r.append(EXT_RIGHT_TO_BH.get(raw_name, raw_name))
            else:
                r.append(f"ExtendedRight({obj_guid})" if verbose else "ExtendedRight")
        else:
            r.append("ExtendedRight")

    # ── WriteProperty (0x020) ──────────────────────────────────────
    if mask & 0x00000020:
        if g:
            attr = SCHEMA_ATTRS.get(g)
            if attr:
                r.append(WRITE_PROP_TO_BH.get(attr, f"WriteProperty-{attr}"))
            else:
                r.append(f"WriteProperty({obj_guid})" if verbose else "WriteProperty")
        else:
            if "GenericWrite" not in r:
                r.append("GenericWrite")

    # ── Validated Write / Self (0x008) ────────────────────────────
    if mask & 0x00000008:
        if g:
            raw_name = EXT_RIGHTS.get(g)
            if raw_name:
                r.append(EXT_RIGHT_TO_BH.get(raw_name, raw_name))
            else:
                r.append("Self")
        else:
            r.append("Self")

    # ── CreateChild / DeleteChild ─────────────────────────────────
    if mask & 0x00000001: r.append("CreateChild")
    if mask & 0x00000002: r.append("DeleteChild")

    return r


def parse_aces(sd_bytes, verbose=False, label=""):
    """
    Parse binary Security Descriptor DACL.
    verbose=True → prints every ACE with full detail (diagnostic mode).
    Returns list of BH-format ACE dicts.
    """
    aces = []
    if not sd_bytes or len(sd_bytes) < 20:
        return aces

    try:
        ctrl     = struct.unpack_from('<H', sd_bytes, 2)[0]
        off_dacl = struct.unpack_from('<I', sd_bytes, 16)[0]
        off_own  = struct.unpack_from('<I', sd_bytes, 4)[0]

        if verbose:
            print(f"\n  {'─'*60}")
            print(f"  SD: {label}  ({len(sd_bytes)} bytes)")
            owner = sid_to_str(sd_bytes[off_own:]) if off_own else "N/A"
            print(f"  Owner  : {owner}")
            print(f"  Control: 0x{ctrl:04X}  DACL={'YES' if ctrl&4 else 'NO'}")

        if not (ctrl & 0x0004) or off_dacl == 0 or off_dacl+8 > len(sd_bytes):
            return aces

        ace_count = struct.unpack_from('<H', sd_bytes, off_dacl+4)[0]
        pos = off_dacl + 8

        if verbose:
            print(f"  DACL @ {off_dacl}  |  ACEs: {ace_count}")

        for i in range(ace_count):
            if pos+4 > len(sd_bytes): break
            atype  = sd_bytes[pos]
            aflags = sd_bytes[pos+1]
            asize  = struct.unpack_from('<H', sd_bytes, pos+2)[0]
            if asize < 4 or pos+asize > len(sd_bytes): break
            adata = sd_bytes[pos:pos+asize]; pos += asize

            type_name = ACE_TYPES.get(atype, f"0x{atype:02X}")
            inh_only  = bool(aflags & 0x08)
            inherited = bool(aflags & 0x10)

            if verbose:
                print(f"\n  ── ACE[{i:02d}]  {type_name}  flags={flags_desc(aflags)}", end="")
                if inh_only: print(f"  ⚠ INHERIT_ONLY (skipped)", end="")
                print()

            # Skip INHERIT_ONLY and DENY ACEs
            if inh_only:
                continue
            if atype in (0x01, 0x06):  # ACCESS_DENIED*
                continue
            if atype not in (0x00, 0x05, 0x09, 0x0B):
                continue

            try:
                if atype in (0x00, 0x09):   # Simple ALLOW
                    if len(adata) < 12: continue
                    mask = struct.unpack_from('<I', adata, 4)[0]
                    sid  = sid_to_str(adata[8:])
                    if not sid: continue

                    if verbose:
                        print(f"     Mask : {mask_desc(mask)}")
                        print(f"     SID  : {sid}")

                    rights = map_rights(mask, None, verbose)
                    if verbose:
                        print(f"     BH   : {rights or '(none)'}")
                    for r in rights:
                        aces.append({"PrincipalSID": sid, "PrincipalType": "Base",
                                     "RightName": r, "IsInherited": inherited})

                elif atype in (0x05, 0x0B):  # Object ALLOW
                    if len(adata) < 16: continue
                    mask   = struct.unpack_from('<I', adata, 4)[0]
                    oflags = struct.unpack_from('<I', adata, 8)[0]
                    cur    = 12
                    obj_guid = None
                    if oflags & 0x1: obj_guid = guid_from_bytes(adata[cur:cur+16]); cur += 16
                    if oflags & 0x2: cur += 16
                    sid = sid_to_str(adata[cur:])
                    if not sid: continue

                    if verbose:
                        g    = obj_guid.lower() if obj_guid else None
                        desc = EXT_RIGHTS.get(g, SCHEMA_ATTRS.get(g, "")) if g else ""
                        print(f"     Mask : {mask_desc(mask)}")
                        print(f"     GUID : {obj_guid or 'None'}  {f'({desc})' if desc else ''}")
                        print(f"     SID  : {sid}")

                    rights = map_rights(mask, obj_guid, verbose)
                    if verbose:
                        print(f"     BH   : {rights or '(none)'}")
                    for r in rights:
                        aces.append({"PrincipalSID": sid, "PrincipalType": "Base",
                                     "RightName": r, "IsInherited": inherited})
            except:
                continue

        if verbose:
            print(f"\n  → BH ACEs found: {len(aces)}")

    except:
        pass

    return aces


# ══════════════════════════════════════════════════════════════════
#  Diagnostic: scan all objects for a specific SID
# ══════════════════════════════════════════════════════════════════

def diagnose_user(conn, base_dn, domain, target_sam, all_collected):
    """
    For a specific user:
    1. Show their ACE dump (verbose)
    2. Scan all collected objects and find where their SID appears
    3. Compare with what we collected
    4. Return missing ACEs that need to be added
    """
    print(Fore.CYAN + f"\n{'═'*65}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  DIAGNOSTIC: {target_sam}" + Style.RESET_ALL)
    print(Fore.CYAN + f"{'═'*65}" + Style.RESET_ALL)

    # Find user SID
    target_sid = None
    for obj_list in all_collected.values():
        for obj in obj_list:
            props = obj.get("Properties", {})
            sam   = props.get("samaccountname", "")
            if sam.lower() == target_sam.lower():
                target_sid = obj.get("ObjectIdentifier", "")
                break
        if target_sid:
            break

    if not target_sid:
        # Try to get from LDAP directly
        conn.search(base_dn, f"(sAMAccountName={target_sam})", search_scope=SUBTREE,
                    attributes=["objectSid", "nTSecurityDescriptor", "sAMAccountName",
                                "distinguishedName"], controls=SD_CTRL)
        if conn.entries:
            e = conn.entries[0]
            target_sid = sid_to_str(graw(e, "objectSid"))
            sd_r = graw(e, "nTSecurityDescriptor")
            if sd_r:
                print(Fore.YELLOW + f"\n[*] Verbose ACE dump of {target_sam}'s own SD:" + Style.RESET_ALL)
                parse_aces(sd_r, verbose=True, label=str(e["distinguishedName"]))

    if not target_sid:
        print(Fore.RED + f"[-] Cannot find SID for {target_sam}" + Style.RESET_ALL)
        return {}

    print(Fore.GREEN + f"[+] Target SID: {target_sid}" + Style.RESET_ALL)

    # Scan ALL objects for this SID in their ACEs
    print(Fore.YELLOW + f"\n[*] Scanning all objects for SID {target_sid}..." + Style.RESET_ALL)

    found_in = []    # objects where this SID has rights
    missing  = {}    # obj_id -> list of rights that are missing from collected data

    obj_type_map = {
        "users":      "User",
        "groups":     "Group",
        "computers":  "Computer",
        "ous":        "OU",
        "gpos":       "GPO",
        "containers": "Container",
        "domains":    "Domain",
    }

    for ctype, obj_list in all_collected.items():
        obj_type = obj_type_map.get(ctype, ctype)
        for obj in obj_list:
            obj_id   = obj.get("ObjectIdentifier", "")
            obj_name = obj.get("Properties", {}).get("name", obj_id)
            existing_aces = obj.get("Aces", [])

            # Find this SID in existing ACEs
            existing_rights = set(
                a["RightName"] for a in existing_aces
                if a.get("PrincipalSID") == target_sid
            )

            # Re-parse the SD from LDAP to get ground truth
            # We need to re-fetch this object's SD
            # Use distinguishedname to re-fetch
            dn = obj.get("Properties", {}).get("distinguishedname", "")
            if not dn:
                continue

            conn.search(dn, "(objectClass=*)", search_scope=BASE,
                        attributes=["nTSecurityDescriptor", "sAMAccountName",
                                    "name", "displayName"], controls=SD_CTRL)
            if not conn.entries:
                continue

            sd_r = graw(conn.entries[0], "nTSecurityDescriptor")
            if not sd_r:
                continue

            # Parse fresh
            fresh_aces  = parse_aces(sd_r)
            fresh_rights = set(
                a["RightName"] for a in fresh_aces
                if a.get("PrincipalSID") == target_sid
            )

            if fresh_rights:
                found_in.append({
                    "type":   obj_type,
                    "name":   obj_name,
                    "id":     obj_id,
                    "rights": list(fresh_rights),
                    "existing": list(existing_rights),
                    "missing":  list(fresh_rights - existing_rights),
                })
                if fresh_rights - existing_rights:
                    missing[obj_id] = {
                        "name":    obj_name,
                        "type":    obj_type,
                        "to_add":  [
                            a for a in fresh_aces
                            if a.get("PrincipalSID") == target_sid
                            and a["RightName"] not in existing_rights
                        ],
                    }

    # Print results
    print(Fore.CYAN + f"\n  Objects where {target_sam} has control:" + Style.RESET_ALL)
    total_outbound = 0
    for item in found_in:
        status = Fore.GREEN + "✓" if not item["missing"] else Fore.RED + "✗ MISSING"
        print(f"  {status}{Style.RESET_ALL}  [{item['type']:9s}] {item['name']}")
        print(f"            Rights    : {item['rights']}")
        if item["missing"]:
            print(Fore.RED + f"            MISSING   : {item['missing']}" + Style.RESET_ALL)
        total_outbound += 1

    print(Fore.CYAN + f"\n  Total outbound: {total_outbound}  |  Missing from collected: {len(missing)}" + Style.RESET_ALL)
    return missing


def apply_missing_aces(all_collected, missing_map):
    """Patch collected objects with missing ACEs."""
    patched = 0
    for ctype, obj_list in all_collected.items():
        for obj in obj_list:
            obj_id = obj.get("ObjectIdentifier", "")
            if obj_id in missing_map:
                for ace in missing_map[obj_id]["to_add"]:
                    if ace not in obj["Aces"]:
                        obj["Aces"].append(ace)
                        patched += 1
    return patched


# ══════════════════════════════════════════════════════════════════
#  Live enum (Sessions / Local Admins)
# ══════════════════════════════════════════════════════════════════

def net_session_enum(target, domain, username, password, timeout=5):
    sessions = []
    try:
        from impacket.dcerpc.v5 import transport, srvs
        from impacket.dcerpc.v5.dtypes import NULL
        rpc = transport.DCERPCTransportFactory(f'ncacn_np:{target}[\\pipe\\srvsvc]')
        rpc.set_credentials(username, password, domain)
        rpc.set_connect_timeout(timeout)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        for s in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            user = s['sesi10_username'][:-1]; host = s['sesi10_cname'][:-1]
            if user and not user.startswith('$'):
                sessions.append({"UserName": user, "ComputerName": host.lstrip('\\')})
        dce.disconnect()
    except: pass
    return sessions

def samr_local_admins(target, domain, username, password, timeout=5):
    admins = []
    try:
        from impacket.dcerpc.v5 import transport, samr
        rpc = transport.DCERPCTransportFactory(f'ncacn_np:{target}[\\pipe\\samr]')
        rpc.set_credentials(username, password, domain)
        rpc.set_connect_timeout(timeout)
        dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
        srv_hd = samr.hSamrConnect(dce)['ServerHandle']
        for di in samr.hSamrEnumerateDomainsInSamServer(dce, srv_hd)['Buffer']['Buffer']:
            if 'BUILTIN' not in str(di['Name']).upper(): continue
            dr  = samr.hSamrLookupDomainInSamServer(dce, srv_hd, di['Name'])
            dh  = samr.hSamrOpenDomain(dce, srv_hd, domainId=dr['DomainId'])['DomainHandle']
            gh  = samr.hSamrOpenGroup(dce, dh, groupId=544)['GroupHandle']
            sid_s = dr['DomainId']
            base  = sid_to_str(b'\x01' + bytes([sid_s.subAuthorityCount]) +
                               sid_s.identifierAuthority['Value'] +
                               b''.join(struct.pack('<I',x) for x in sid_s.subAuthority))
            for m in samr.hSamrGetMembersInGroup(dce, gh)['Members']['Members']:
                admins.append({"ObjectIdentifier": f"{base}-{m['Data']}", "ObjectType": "User"})
            samr.hSamrCloseHandle(dce, gh); samr.hSamrCloseHandle(dce, dh)
        samr.hSamrCloseHandle(dce, srv_hd); dce.disconnect()
    except: pass
    return admins


# ══════════════════════════════════════════════════════════════════
#  Collectors
# ══════════════════════════════════════════════════════════════════

def collect_domain(conn, base_dn, domain):
    print(Fore.YELLOW + "[*] Collecting Domain..." + Style.RESET_ALL)
    try:
        conn.search(base_dn, '(objectClass=domain)', search_scope=BASE,
                    attributes=['objectSid','ms-DS-MachineAccountQuota','minPwdLength',
                                'pwdHistoryLength','pwdProperties','lockoutThreshold',
                                'distinguishedName','name','whenCreated','objectGUID',
                                'lockoutDuration','maxPwdAge','minPwdAge',
                                'nTSecurityDescriptor'], controls=SD_CTRL)
        if not conn.entries: return None, ""
        e = conn.entries[0]; a = e.entry_attributes_as_dict
        sid  = sid_to_str(graw(e,'objectSid'))
        aces = parse_aces(graw(e,'nTSecurityDescriptor'))
        obj = {
            "ObjectIdentifier": sid,
            "Properties": {
                "name": domain.upper(), "domain": domain.upper(),
                "distinguishedname":   str(ga(a,'distinguishedName','')),
                "domainsid":           sid, "highvalue": True,
                "functionallevel":     "Unknown",
                "machineaccountquota": int(ga(a,'ms-DS-MachineAccountQuota',10) or 10),
                "minpwdlength":        int(ga(a,'minPwdLength',0) or 0),
                "pwdhistorylength":    int(ga(a,'pwdHistoryLength',0) or 0),
                "pwdproperties":       int(ga(a,'pwdProperties',0) or 0),
                "lockoutthreshold":    int(ga(a,'lockoutThreshold',0) or 0),
            },
            "Trusts":[], "Links":[], "ChildObjects":[], "Aces": aces, "IsDeleted": False,
        }
        print(Fore.GREEN + f"[+] Domain: {domain.upper()}  SID: {sid}  ACEs: {len(aces)}" + Style.RESET_ALL)
        return obj, sid
    except Exception as ex:
        print(Fore.RED + f"[-] Domain: {ex}" + Style.RESET_ALL); return None, ""

def collect_trusts(conn, base_dn, domain):
    print(Fore.YELLOW + "[*] Collecting Trusts..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(objectClass=trustedDomain)',search_scope=SUBTREE,
                    attributes=['name','trustDirection','trustType','trustAttributes','securityIdentifier'])
        DIR  = {1:"Inbound",2:"Outbound",3:"Bidirectional"}
        TYPE = {1:"WINDOWS_NON_ACTIVE_DIRECTORY",2:"WINDOWS",3:"MIT",4:"DCE"}
        trusts = []
        for e in conn.entries:
            try:
                a = e.entry_attributes_as_dict
                trusts.append({
                    "TargetDomainSid":     sid_to_str(graw(e,'securityIdentifier')),
                    "TargetDomainName":    str(ga(a,'name','')).upper(),
                    "IsTransitive":        bool(int(ga(a,'trustAttributes',0) or 0) & 1),
                    "SidFilteringEnabled": not bool(int(ga(a,'trustAttributes',0) or 0) & 4),
                    "TrustDirection":      DIR.get(int(ga(a,'trustDirection',0) or 0),"Unknown"),
                    "TrustType":           TYPE.get(int(ga(a,'trustType',0) or 0),"Unknown"),
                })
            except: continue
        print(Fore.GREEN + f"[+] Trusts: {len(trusts)}" + Style.RESET_ALL)
        return trusts
    except Exception as ex:
        print(Fore.RED + f"[-] Trusts: {ex}" + Style.RESET_ALL); return []

def collect_users(conn, base_dn, domain, domain_sid):
    print(Fore.YELLOW + "[*] Collecting Users..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(samAccountType=805306368)',search_scope=SUBTREE,
                    attributes=['sAMAccountName','distinguishedName','objectSid','objectGUID',
                                'userAccountControl','memberOf','primaryGroupID','adminCount',
                                'servicePrincipalName','mail','displayName','description',
                                'pwdLastSet','lastLogon','lastLogonTimestamp','whenCreated',
                                'userPrincipalName','title','department','company',
                                'msDS-AllowedToDelegateTo','scriptPath','homeDirectory',
                                'sIDHistory','nTSecurityDescriptor'], controls=SD_CTRL)
        users = []; dom_u = domain.upper()
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                sid  = sid_to_str(graw(e,'objectSid'))
                if not sid: continue
                sam  = str(ga(a,'sAMAccountName',''))
                uac  = int(ga(a,'userAccountControl',0) or 0)
                spns = gal(a,'servicePrincipalName')
                delg = gal(a,'msDS-AllowedToDelegateTo')
                mof  = gal(a,'memberOf')
                hist = gal(a,'sIDHistory')
                dsid = sid.rsplit('-',1)[0] if sid.count('-')>=3 else domain_sid
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                users.append({
                    "ObjectIdentifier": sid,
                    "Properties": {
                        "name": f"{sam.upper()}@{dom_u}", "domain": dom_u, "domainsid": dsid,
                        "distinguishedname":      str(ga(a,'distinguishedName','')),
                        "samaccountname":         sam,
                        "displayname":            str(ga(a,'displayName','') or ''),
                        "email":                  str(ga(a,'mail','') or ''),
                        "title":                  str(ga(a,'title','') or ''),
                        "department":             str(ga(a,'department','') or ''),
                        "description":            str(ga(a,'description','') or ''),
                        "enabled":                not bool(uac & 0x0002),
                        "admincount":             bool(ga(a,'adminCount',0)),
                        "pwdneverexpires":         bool(uac & 0x10000),
                        "dontreqpreauth":          bool(uac & 0x400000),
                        "passwordnotreqd":         bool(uac & 0x0020),
                        "sensitive":              bool(uac & 0x100000),
                        "trustedtoauth":           bool(uac & 0x1000000),
                        "unconstraineddelegation": bool(uac & 0x80000),
                        "pwdlastset":      ft2epoch(ga(a,'pwdLastSet')),
                        "lastlogon":       ft2epoch(ga(a,'lastLogon')),
                        "lastlogontimestamp": ft2epoch(ga(a,'lastLogonTimestamp')),
                        "serviceprincipalnames": spns, "hasspn": len(spns)>0,
                        "highvalue": False, "allowedtodelegate": delg, "sidhistory": hist,
                        "scriptpath":    str(ga(a,'scriptPath','') or ''),
                        "homedirectory": str(ga(a,'homeDirectory','') or ''),
                    },
                    "PrimaryGroupSid":   f"{dsid}-{ga(a,'primaryGroupID',513) or 513}",
                    "SPNTargets":        [{"ComputerSID":"","Port":0,"Service":s.split('/')[0]}
                                          for s in spns if '/' in s],
                    "HasSIDHistory":     [{"ObjectIdentifier":s,"ObjectType":"Base"} for s in hist],
                    "AllowedToDelegate": [{"ObjectIdentifier":d,"ObjectType":"Computer"} for d in delg],
                    "Aces": aces, "IsDeleted": False,
                    "MemberOf": [{"ObjectIdentifier":m,"ObjectType":"Group"} for m in mof],
                })
            except: continue
        print(Fore.GREEN + f"[+] Users: {len(users)}  ACEs: {sum(len(u['Aces']) for u in users)}" + Style.RESET_ALL)
        return users
    except Exception as ex:
        print(Fore.RED + f"[-] Users: {ex}" + Style.RESET_ALL); return []

def collect_groups(conn, base_dn, domain, domain_sid):
    print(Fore.YELLOW + "[*] Collecting Groups..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(objectClass=group)',search_scope=SUBTREE,
                    attributes=['sAMAccountName','distinguishedName','objectSid',
                                'member','memberOf','adminCount','description',
                                'groupType','whenCreated','objectGUID',
                                'sIDHistory','nTSecurityDescriptor'], controls=SD_CTRL)
        groups = []; dom_u = domain.upper()
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                sid  = sid_to_str(graw(e,'objectSid'))
                if not sid: continue
                sam  = str(ga(a,'sAMAccountName',''))
                mems = gal(a,'member'); mof = gal(a,'memberOf'); hist = gal(a,'sIDHistory')
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                ml   = []
                for m in mems:
                    cn = m.split(',')[0].replace('CN=','').replace('cn=','')
                    ml.append({"ObjectIdentifier":m,"ObjectType":"Computer" if cn.endswith('$') else "User"})
                groups.append({
                    "ObjectIdentifier": sid,
                    "Properties": {
                        "name": f"{sam.upper()}@{dom_u}", "domain": dom_u,
                        "domainsid": sid.rsplit('-',1)[0] if sid.count('-')>=3 else domain_sid,
                        "distinguishedname": str(ga(a,'distinguishedName','')),
                        "samaccountname": sam, "description": str(ga(a,'description','') or ''),
                        "admincount": bool(ga(a,'adminCount',0)),
                        "highvalue":  sam.lower() in HIGH_VALUE_GROUPS, "sidhistory": hist,
                    },
                    "Members": ml,
                    "MemberOf": [{"ObjectIdentifier":m,"ObjectType":"Group"} for m in mof],
                    "Aces": aces, "IsDeleted": False,
                })
            except: continue
        print(Fore.GREEN + f"[+] Groups: {len(groups)}  ACEs: {sum(len(g['Aces']) for g in groups)}" + Style.RESET_ALL)
        return groups
    except Exception as ex:
        print(Fore.RED + f"[-] Groups: {ex}" + Style.RESET_ALL); return []

def collect_computers(conn, base_dn, domain, domain_sid,
                      dc_ip, username, password,
                      do_sessions=True, do_admins=True, threads=20):
    print(Fore.YELLOW + "[*] Collecting Computers..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(samAccountType=805306369)',search_scope=SUBTREE,
                    attributes=['sAMAccountName','distinguishedName','objectSid','objectGUID',
                                'dNSHostName','operatingSystem','operatingSystemVersion',
                                'userAccountControl','memberOf','primaryGroupID','adminCount',
                                'servicePrincipalName','lastLogon','lastLogonTimestamp',
                                'whenCreated','description',
                                'msDS-AllowedToDelegateTo',
                                'msDS-AllowedToActOnBehalfOfOtherIdentity',
                                'sIDHistory','nTSecurityDescriptor'], controls=SD_CTRL)
        computers = []; seen = set(); dom_u = domain.upper()
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                sid  = sid_to_str(graw(e,'objectSid'))
                if not sid or sid in seen: continue
                seen.add(sid)
                sam  = str(ga(a,'sAMAccountName',''))
                uac  = int(ga(a,'userAccountControl',0) or 0)
                dns  = str(ga(a,'dNSHostName','') or '')
                is_dc= bool(uac & 0x2000)
                delg = gal(a,'msDS-AllowedToDelegateTo')
                mof  = gal(a,'memberOf'); hist = gal(a,'sIDHistory')
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                dsid = sid.rsplit('-',1)[0] if sid.count('-')>=3 else domain_sid
                name = dns.upper() if dns else f"{sam.rstrip('$').upper()}.{dom_u}"
                pgid = "516" if is_dc else str(ga(a,'primaryGroupID',515) or 515)
                computers.append({
                    "ObjectIdentifier": sid, "_target": dns or name,
                    "Properties": {
                        "name": name, "domain": dom_u, "domainsid": dsid,
                        "distinguishedname":      str(ga(a,'distinguishedName','')),
                        "samaccountname":         sam, "dnshostname": dns,
                        "description":            str(ga(a,'description','') or ''),
                        "operatingsystem":        str(ga(a,'operatingSystem','') or ''),
                        "operatingsystemversion": str(ga(a,'operatingSystemVersion','') or ''),
                        "enabled":                not bool(uac & 0x0002),
                        "admincount":             bool(ga(a,'adminCount',0)),
                        "unconstraineddelegation": bool(uac & 0x80000) or is_dc,
                        "trustedtoauth":           bool(uac & 0x1000000),
                        "lastlogon":      ft2epoch(ga(a,'lastLogon')),
                        "lastlogontimestamp": ft2epoch(ga(a,'lastLogonTimestamp')),
                        "highvalue": is_dc, "allowedtodelegate": delg,
                        "sidhistory": hist, "isdc": is_dc,
                    },
                    "PrimaryGroupSid":    f"{dsid}-{pgid}",
                    "AllowedToDelegate":  [{"ObjectIdentifier":d,"ObjectType":"Computer"} for d in delg],
                    "AllowedToAct":       [],
                    "Sessions":           {"Results":[],"Collected":False,"FailureReason":None},
                    "PrivilegedSessions": {"Results":[],"Collected":False,"FailureReason":None},
                    "RegistrySessions":   {"Results":[],"Collected":False,"FailureReason":None},
                    "LocalAdmins":        {"Results":[],"Collected":False,"FailureReason":None},
                    "RemoteDesktopUsers": {"Results":[],"Collected":False,"FailureReason":None},
                    "DcomUsers":          {"Results":[],"Collected":False,"FailureReason":None},
                    "PSRemoteUsers":      {"Results":[],"Collected":False,"FailureReason":None},
                    "MemberOf":  [{"ObjectIdentifier":m,"ObjectType":"Group"} for m in mof],
                    "HasSIDHistory": [{"ObjectIdentifier":s,"ObjectType":"Base"} for s in hist],
                    "Aces": aces, "IsDeleted": False,
                })
            except: continue

        if (do_sessions or do_admins) and computers:
            print(Fore.YELLOW + f"[*] Live enum on {len(computers)} hosts..." + Style.RESET_ALL)
            s_ok = a_ok = 0; lock = threading.Lock()
            def _enum(c):
                nonlocal s_ok, a_ok
                t = c.pop("_target", None)
                if not t: return
                if do_sessions:
                    s = net_session_enum(t, domain, username, password)
                    if s:
                        c["Sessions"]["Results"]=s; c["Sessions"]["Collected"]=True
                        with lock: s_ok += 1
                if do_admins:
                    adm = samr_local_admins(t, domain, username, password)
                    if adm:
                        c["LocalAdmins"]["Results"]=adm; c["LocalAdmins"]["Collected"]=True
                        with lock: a_ok += 1
            with ThreadPoolExecutor(max_workers=threads) as ex:
                list(as_completed([ex.submit(_enum,c) for c in computers]))
            print(Fore.GREEN + f"[+] Sessions: {s_ok} hosts  |  Admins: {a_ok} hosts" + Style.RESET_ALL)
        else:
            for c in computers: c.pop("_target", None)

        dc_c = sum(1 for c in computers if c["Properties"].get("isdc"))
        print(Fore.GREEN + f"[+] Computers: {len(computers)-dc_c} WS + {dc_c} DC  ACEs: {sum(len(c['Aces']) for c in computers)}" + Style.RESET_ALL)
        return computers
    except Exception as ex:
        print(Fore.RED + f"[-] Computers: {ex}" + Style.RESET_ALL); return []

def collect_ous(conn, base_dn, domain, domain_sid):
    print(Fore.YELLOW + "[*] Collecting OUs..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(objectClass=organizationalUnit)',search_scope=SUBTREE,
                    attributes=['distinguishedName','name','objectGUID','description',
                                'gPLink','whenCreated','nTSecurityDescriptor'], controls=SD_CTRL)
        ous = []
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                dn   = str(ga(a,'distinguishedName',''))
                name = str(ga(a,'name',''))
                guid = str(ga(a,'objectGUID',''))
                gpl  = str(ga(a,'gPLink','') or '')
                links= [{"GUID":f"{{{g.upper()}}}","IsEnforced":False} for g in re.findall(r'\{([^}]+)\}',gpl)]
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                ous.append({
                    "ObjectIdentifier": guid.upper() if guid else dn,
                    "Properties": {"name":f"{name.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "highvalue":False},
                    "Links":links,"ChildObjects":[],"Aces":aces,"IsDeleted":False,
                })
            except: continue
        print(Fore.GREEN + f"[+] OUs: {len(ous)}" + Style.RESET_ALL)
        return ous
    except Exception as ex:
        print(Fore.RED + f"[-] OUs: {ex}" + Style.RESET_ALL); return []

def collect_gpos(conn, base_dn, domain, domain_sid):
    print(Fore.YELLOW + "[*] Collecting GPOs..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(objectClass=groupPolicyContainer)',search_scope=SUBTREE,
                    attributes=['distinguishedName','displayName','name','objectGUID',
                                'gPCFileSysPath','whenCreated','description',
                                'nTSecurityDescriptor'], controls=SD_CTRL)
        gpos = []
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                dn   = str(ga(a,'distinguishedName',''))
                dname= str(ga(a,'displayName','') or '')
                name = str(ga(a,'name','') or '')
                guid = name.strip('{}').upper() if name else ""
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                gpos.append({
                    "ObjectIdentifier": f"{{{guid}}}",
                    "Properties": {"name":f"{dname.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "gpcpath":str(ga(a,'gPCFileSysPath','') or ''),"highvalue":False},
                    "Aces":aces,"IsDeleted":False,
                })
            except: continue
        print(Fore.GREEN + f"[+] GPOs: {len(gpos)}" + Style.RESET_ALL)
        return gpos
    except Exception as ex:
        print(Fore.RED + f"[-] GPOs: {ex}" + Style.RESET_ALL); return []

def collect_containers(conn, base_dn, domain, domain_sid):
    print(Fore.YELLOW + "[*] Collecting Containers..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,'(objectClass=container)',search_scope=SUBTREE,
                    attributes=['distinguishedName','name','objectGUID','description',
                                'whenCreated','nTSecurityDescriptor'], controls=SD_CTRL)
        containers = []
        for e in conn.entries:
            try:
                a    = e.entry_attributes_as_dict
                dn   = str(ga(a,'distinguishedName',''))
                name = str(ga(a,'name',''))
                guid = str(ga(a,'objectGUID',''))
                aces = parse_aces(graw(e,'nTSecurityDescriptor'))
                containers.append({
                    "ObjectIdentifier": guid.upper() if guid else dn,
                    "Properties": {"name":f"{name.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "highvalue":False},
                    "ChildObjects":[],"Aces":aces,"IsDeleted":False,
                })
            except: continue
        print(Fore.GREEN + f"[+] Containers: {len(containers)}" + Style.RESET_ALL)
        return containers
    except Exception as ex:
        print(Fore.RED + f"[-] Containers: {ex}" + Style.RESET_ALL); return []


# ══════════════════════════════════════════════════════════════════
#  Save
# ══════════════════════════════════════════════════════════════════

def save_json(objects, meta_type, output_dir, filename):
    try:
        path = os.path.join(output_dir, filename)
        with open(path,'w',encoding='utf-8') as f:
            json.dump({"data":objects,"meta":{"methods":0,"type":meta_type,
                       "count":len(objects),"version":4}},f,indent=2,default=str)
        print(Fore.GREEN + f"[+] Saved: {filename}  ({os.path.getsize(path):,} bytes)" + Style.RESET_ALL)
    except Exception as ex:
        print(Fore.RED + f"[-] Save {filename}: {ex}" + Style.RESET_ALL)


# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    banner()

    # ── Credentials ───────────────────────────────────────────────
    dc_ip    = ask(Fore.CYAN+"[?] DC IP Address   : "+Style.RESET_ALL, validate_ip, "Invalid IP")
    print(Fore.YELLOW+"[*] Checking port 445..."+Style.RESET_ALL)
    if not check_port(dc_ip):
        print(Fore.RED+f"[!] {dc_ip}:445 unreachable!"+Style.RESET_ALL); sys.exit(1)
    print(Fore.GREEN+f"[+] {dc_ip} reachable!"+Style.RESET_ALL)

    domain   = ask(Fore.CYAN+"[?] Domain Name     : "+Style.RESET_ALL, validate_domain, "Invalid domain")
    username = ask(Fore.CYAN+"[?] Username        : "+Style.RESET_ALL)
    password = ask(Fore.CYAN+"[?] Password        : "+Style.RESET_ALL)

    print(Fore.YELLOW+"[*] Verifying credentials..."+Style.RESET_ALL)
    chk = verify_creds(dc_ip, domain, username, password)
    if chk == "bad_creds":
        print(Fore.RED+"[!] Bad credentials!"+Style.RESET_ALL); sys.exit(1)
    elif not chk:
        print(Fore.RED+f"[!] Domain not found!"+Style.RESET_ALL); sys.exit(1)
    print(Fore.GREEN+"[+] Credentials OK!"+Style.RESET_ALL)

    ts       = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    out_name = ask(Fore.CYAN+f"[?] Output folder   : "+Style.RESET_ALL+
                   Fore.YELLOW+f"(default: bloodhound-{ts}) "+Style.RESET_ALL, allow_empty=True)
    output_dir = resolve_output_dir(out_name, ts)
    print(Fore.GREEN+f"[+] Output: {output_dir}"+Style.RESET_ALL)

    do_sess = ask(Fore.CYAN+"[?] Enumerate sessions?    (y/n default y): "+Style.RESET_ALL, allow_empty=True).lower() != 'n'
    do_adm  = ask(Fore.CYAN+"[?] Enumerate local admins?(y/n default y): "+Style.RESET_ALL, allow_empty=True).lower() != 'n'

    # ── Diagnostic user (optional) ────────────────────────────────
    diag_user = ask(
        Fore.CYAN+"[?] Diagnose specific user? "+Style.RESET_ALL+
        Fore.YELLOW+"(sAMAccountName or Enter to skip): "+Style.RESET_ALL,
        allow_empty=True)

    # ── Connect ───────────────────────────────────────────────────
    print(Fore.YELLOW+"\n[*] Connecting to LDAP..."+Style.RESET_ALL)
    conn = ldap_connect(dc_ip, domain, username, password)
    if not conn: sys.exit(1)
    print(Fore.GREEN+"[+] LDAP connected!"+Style.RESET_ALL)

    base_dn = get_base_dn(domain)
    print(Fore.CYAN+"\n[*] Starting collection...\n"+Style.RESET_ALL)

    # ── Collect ───────────────────────────────────────────────────
    domain_obj, domain_sid = collect_domain(conn, base_dn, domain)
    trusts     = collect_trusts(conn, base_dn, domain)
    users      = collect_users(conn, base_dn, domain, domain_sid)
    groups     = collect_groups(conn, base_dn, domain, domain_sid)
    computers  = collect_computers(conn, base_dn, domain, domain_sid,
                                   dc_ip, username, password,
                                   do_sessions=do_sess, do_admins=do_adm, threads=20)
    ous        = collect_ous(conn, base_dn, domain, domain_sid)
    gpos       = collect_gpos(conn, base_dn, domain, domain_sid)
    containers = collect_containers(conn, base_dn, domain, domain_sid)

    if domain_obj and trusts:
        domain_obj["Trusts"] = trusts

    # ── Diagnostic + Auto-fix ─────────────────────────────────────
    all_collected = {
        "domains":    [domain_obj] if domain_obj else [],
        "users":      users,
        "groups":     groups,
        "computers":  computers,
        "ous":        ous,
        "gpos":       gpos,
        "containers": containers,
    }

    if diag_user:
        print(Fore.CYAN+"\n[*] Running diagnostic..."+Style.RESET_ALL)
        missing = diagnose_user(conn, base_dn, domain, diag_user, all_collected)
        if missing:
            print(Fore.YELLOW+f"\n[*] Auto-patching {len(missing)} objects with missing ACEs..."+Style.RESET_ALL)
            patched = apply_missing_aces(all_collected, missing)
            print(Fore.GREEN+f"[+] Patched {patched} ACEs into collected data!"+Style.RESET_ALL)
        else:
            print(Fore.GREEN+"[+] No missing ACEs found — data is complete!"+Style.RESET_ALL)

    # ── Save ──────────────────────────────────────────────────────
    print(Fore.CYAN+"\n[*] Saving JSON files...\n"+Style.RESET_ALL)
    if domain_obj: save_json([domain_obj],"domains",   output_dir,"domains.json")
    save_json(users,      "users",      output_dir, "users.json")
    save_json(groups,     "groups",     output_dir, "groups.json")
    save_json(computers,  "computers",  output_dir, "computers.json")
    save_json(ous,        "ous",        output_dir, "ous.json")
    save_json(gpos,       "gpos",       output_dir, "gpos.json")
    save_json(containers, "containers", output_dir, "containers.json")

    # ── Summary ───────────────────────────────────────────────────
    dc_c  = sum(1 for c in computers if c["Properties"].get("isdc"))
    total_aces = (sum(len(u["Aces"]) for u in users) +
                  sum(len(g["Aces"]) for g in groups) +
                  sum(len(c["Aces"]) for c in computers) +
                  sum(len(o["Aces"]) for o in ous) +
                  sum(len(g["Aces"]) for g in gpos) +
                  sum(len(c["Aces"]) for c in containers) +
                  (len(domain_obj["Aces"]) if domain_obj else 0))

    print(Fore.CYAN +"\n[*] Collection Summary:"+Style.RESET_ALL)
    print(Fore.WHITE+f"    Domain        : 1")
    print(Fore.WHITE+f"    Trusts        : {len(trusts)}")
    print(Fore.WHITE+f"    Users         : {len(users)}")
    print(Fore.WHITE+f"    Groups        : {len(groups)}")
    print(Fore.WHITE+f"    Workstations  : {len(computers)-dc_c}")
    print(Fore.WHITE+f"    DCs           : {dc_c}")
    print(Fore.WHITE+f"    OUs           : {len(ous)}")
    print(Fore.WHITE+f"    GPOs          : {len(gpos)}")
    print(Fore.WHITE+f"    Containers    : {len(containers)}")
    print(Fore.WHITE+f"    Total ACEs    : {total_aces}")
    print(Fore.WHITE+f"    Sessions      : {sum(len(c['Sessions']['Results']) for c in computers)}")
    print(Fore.WHITE+f"    Local Admins  : {sum(len(c['LocalAdmins']['Results']) for c in computers)}")
    print(Fore.GREEN+f"\n[+] Saved to: {output_dir}"+Style.RESET_ALL)
    print(Fore.CYAN +f"[*] Import JSON files into BloodHound!"+Style.RESET_ALL)
