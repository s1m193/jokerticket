#!/usr/bin/env python3

import os, sys, re, json, socket, struct, platform, signal, threading, calendar
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
#  Constants (copied from BloodHound.py)
# ══════════════════════════════════════════════════════════════════

SD_CTRL = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]

# Well-known SIDs: SID -> (Name, Type)
WELLKNOWN_SIDS = {
    "S-1-1-0": ("Everyone", "GROUP"),
    "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
    "S-1-5-11": ("Authenticated Users", "GROUP"),
    "S-1-5-4": ("Interactive", "GROUP"),
    "S-1-5-32-544": ("Administrators", "GROUP"),
    "S-1-5-32-545": ("Users", "GROUP"),
    "S-1-5-32-546": ("Guests", "GROUP"),
    "S-1-5-32-547": ("Power Users", "GROUP"),
    "S-1-5-32-548": ("Account Operators", "GROUP"),
    "S-1-5-32-549": ("Server Operators", "GROUP"),
    "S-1-5-32-550": ("Print Operators", "GROUP"),
    "S-1-5-32-551": ("Backup Operators", "GROUP"),
    "S-1-5-32-552": ("Replicators", "GROUP"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
    "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
    "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
    "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
    "S-1-5-32-559": ("Performance Log Users", "GROUP"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
    "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
    "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
    "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
    "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
    "S-1-5-32-573": ("Event Log Readers", "GROUP"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
    "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
    "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-582": ("Storage Replica Administrators", "GROUP"),
}

# High-value group SIDs
HIGHVALUE_RIDS = {"-512", "-516", "-519"}
HIGHVALUE_SIDS = {
    "S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549",
    "S-1-5-32-551", "S-1-5-32-548"
}

# ══════════════════════════════════════════════════════════════════
#  Banner / Input / Validation
# ══════════════════════════════════════════════════════════════════

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════╗
    ║   	     BloodHound Collector  	        ║
    ║          Collects AD data -> BloodHound JSON      ║
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

def ldap2domain(ldap_dn):
    """Convert LDAP DN to DNS domain name."""
    return re.sub(',DC=', '.', ldap_dn[ldap_dn.find('DC='):], flags=re.I)[3:]


# ══════════════════════════════════════════════════════════════════
#  BloodHound.py Logic: resolve_ad_entry
# ══════════════════════════════════════════════════════════════════

def resolve_ad_entry(entry):
    """
    EXACT replica of BloodHound.py's ADUtils.resolve_ad_entry()
    Translates an LDAP entry into a dict with objectid, principal, type.
    """
    resolved = {}
    dn = ''
    domain = ''

    # Get attributes dict
    if hasattr(entry, 'entry_attributes_as_dict'):
        a = entry.entry_attributes_as_dict
    else:
        a = entry.get('attributes', {})

    account = str(ga(a, 'sAMAccountName', ''))
    dn = str(ga(a, 'distinguishedName', ''))
    if dn:
        domain = ldap2domain(dn)

    resolved['objectid'] = str(ga(a, 'objectSid', ''))
    resolved['principal'] = (f"{account}@{domain}").upper()

    if not ga(a, 'sAMAccountName'):
        # No sAMAccountName - could be OU, Container, GPO, ForeignSecurityPrincipal
        if 'ForeignSecurityPrincipals' in dn and 'container' not in [c.lower() for c in gal(a, 'objectClass', [])]:
            resolved['principal'] = domain.upper()
            resolved['type'] = 'foreignsecurityprincipal'
            ename = ga(a, 'name')
            if ename:
                if ename in WELLKNOWN_SIDS:
                    name, sidtype = WELLKNOWN_SIDS[ename]
                    resolved['type'] = sidtype.lower()
                    resolved['principal'] = (f"{name}@{domain}").upper()
                    # Well-known have the domain prefix since 3.0
                    resolved['objectid'] = f"{domain.upper()}-{resolved['objectid']}"
                else:
                    # Foreign security principal
                    resolved['objectid'] = ename
        elif ga(a, 'objectGUID'):
            guid = str(ga(a, 'objectGUID', ''))
            # Handle ldap3's {guid} format
            if guid.startswith('{') and guid.endswith('}'):
                guid = guid[1:-1]
            resolved['objectid'] = guid.upper()
            resolved['principal'] = (f"{ga(a, 'name', '')}@{domain}").upper()
            obj_class = gal(a, 'objectClass')
            if 'organizationalUnit' in obj_class:
                resolved['type'] = 'OU'
            elif 'container' in obj_class:
                resolved['type'] = 'Container'
            else:
                resolved['type'] = 'Base'
        else:
            resolved['type'] = 'Base'
    else:
        # Has sAMAccountName - determine type from sAMAccountType
        account_type = ga(a, 'sAMAccountType')
        obj_class = gal(a, 'objectClass')

        if account_type in [268435456, 268435457, 536870912, 536870913]:
            resolved['type'] = 'Group'
        elif account_type in [805306368] or \
             'msDS-GroupManagedServiceAccount' in obj_class or \
             'msDS-ManagedServiceAccount' in obj_class:
            resolved['type'] = 'User'
        elif account_type in [805306369]:
            resolved['type'] = 'Computer'
            short_name = account.rstrip('$')
            resolved['principal'] = (f"{short_name}.{domain}").upper()
        elif account_type in [805306370]:
            resolved['type'] = 'trustaccount'
        else:
            resolved['type'] = 'Domain'

    return resolved


# ══════════════════════════════════════════════════════════════════
#  BloodHound.py Logic: Caches
# ══════════════════════════════════════════════════════════════════

class ADCache:
    """
    Exact replica of BloodHound.py's caching system.
    DN cache holds: DN (upper) -> {"ObjectIdentifier": sid/guid, "ObjectType": "User"/"Group"/"Computer"}
    """
    def __init__(self, conn, base_dn, domain):
        self.conn = conn
        self.base_dn = base_dn
        self.domain = domain
        self.dn_cache = {}
        self.sid_cache = {}

    def add(self, dn, obj_id, obj_type):
        """Add a DN to the cache with its resolved identifier and type."""
        if dn:
            self.dn_cache[dn.upper()] = {"ObjectIdentifier": obj_id, "ObjectType": obj_type}
        if obj_id:
            self.sid_cache[obj_id] = {"ObjectIdentifier": obj_id, "ObjectType": obj_type}

    def get(self, dn):
        """Get cached entry by DN. Returns None if not found."""
        if not dn:
            return None
        return self.dn_cache.get(dn.upper())

    def resolve_dn(self, dn):
        """
        EXACT replica of BloodHound.py's get_dn_from_cache_or_ldap()
        Resolve a DistinguishedName in LDAP.
        First check cache, then query LDAP.
        """
        if not dn:
            return None

        # Check cache first
        try:
            linkentry = self.dn_cache[dn.upper()]
            return linkentry
        except KeyError:
            pass

        # Query LDAP for this DN
        try:
            self.conn.search(dn, '(objectClass=*)', search_scope=BASE,
                        attributes=['sAMAccountName', 'distinguishedName', 'sAMAccountType', 'objectSid', 'name', 'objectGUID', 'objectClass'])
            if self.conn.entries:
                e = self.conn.entries[0]
                resolved_entry = resolve_ad_entry(e)
                if not resolved_entry['objectid']:
                    return None
                linkentry = {
                    "ObjectIdentifier": resolved_entry['objectid'],
                    "ObjectType": resolved_entry['type'].capitalize()
                }
                self.dn_cache[dn.upper()] = linkentry
                return linkentry
        except Exception as ex:
            pass

        return None

    def prefetch_all_objects(self):
        """
        BloodHound.py's get_cache_items() logic:
        Query ALL users, groups, and computers in one go to populate the cache.
        This is CRITICAL for resolving group memberships correctly.
        """
        print(Fore.YELLOW + "[*] Pre-fetching all objects for DN cache..." + Style.RESET_ALL)
        count = 0

        # Query ALL objects: users, groups, computers (same filter as BloodHound.py)
        query = '(|(samAccountType=805306368)(objectClass=group)(samAccountType=805306369))'
        try:
            self.conn.search(self.base_dn, query, search_scope=SUBTREE,
                        attributes=['sAMAccountName', 'distinguishedName', 'sAMAccountType', 'objectSid', 'name', 'objectGUID', 'objectClass'])
            for e in self.conn.entries:
                try:
                    resolved = resolve_ad_entry(e)
                    dn = str(ga(e.entry_attributes_as_dict, 'distinguishedName', ''))
                    if dn and resolved['objectid']:
                        cacheitem = {
                            "ObjectIdentifier": resolved['objectid'],
                            "ObjectType": resolved['type'].capitalize()
                        }
                        self.dn_cache[dn.upper()] = cacheitem
                        self.sid_cache[resolved['objectid']] = cacheitem
                        count += 1
                except:
                    continue
        except Exception as ex:
            print(Fore.RED + f"[-] Cache prefetch failed: {ex}" + Style.RESET_ALL)

        print(Fore.GREEN + f"[+] Cached {count} objects for DN resolution" + Style.RESET_ALL)
        return count


# ══════════════════════════════════════════════════════════════════
#  BloodHound.py Logic: ACE Parser
# ══════════════════════════════════════════════════════════════════

def parse_aces(sd_bytes, entrytype='base', objecttype_guid_map=None):
    """
    BloodHound.py-compatible ACE parser.
    Returns list of raw ACE dicts with 'rightname', 'sid', 'inherited'.
    These are later resolved by resolve_aces().
    """
    aces = []
    if not sd_bytes or len(sd_bytes) < 20:
        return aces

    try:
        ctrl     = struct.unpack_from('<H', sd_bytes, 2)[0]
        off_dacl = struct.unpack_from('<I', sd_bytes, 16)[0]

        if not (ctrl & 0x0004) or off_dacl == 0 or off_dacl+8 > len(sd_bytes):
            return aces

        ace_count = struct.unpack_from('<H', sd_bytes, off_dacl+4)[0]
        pos = off_dacl + 8

        for i in range(ace_count):
            if pos+4 > len(sd_bytes): break
            atype  = sd_bytes[pos]
            aflags = sd_bytes[pos+1]
            asize  = struct.unpack_from('<H', sd_bytes, pos+2)[0]
            if asize < 4 or pos+asize > len(sd_bytes): break
            adata = sd_bytes[pos:pos+asize]; pos += asize

            is_inherited = bool(aflags & 0x10)

            # Skip INHERIT_ONLY (not inherited, just set for inheritance to children)
            if not is_inherited and (aflags & 0x08):
                continue
            # Skip DENY ACEs
            if atype in (0x01, 0x06):
                continue
            if atype not in (0x00, 0x05, 0x09, 0x0B):
                continue

            try:
                if atype in (0x00, 0x09):   # Simple ALLOW
                    if len(adata) < 12: continue
                    mask = struct.unpack_from('<I', adata, 4)[0]
                    sid  = sid_to_str(adata[8:])
                    if not sid: continue

                    # Parse simple ACE (same logic as BloodHound.py acls.py)
                    if mask & 0x10000000:  # GenericAll
                        aces.append({"rightname": "GenericAll", "sid": sid, "inherited": is_inherited})
                        continue
                    if mask & 0x00080000:  # WriteOwner
                        aces.append({"rightname": "WriteOwner", "sid": sid, "inherited": is_inherited})
                    if mask & 0x00040000:  # WriteDACL
                        aces.append({"rightname": "WriteDacl", "sid": sid, "inherited": is_inherited})
                    if mask & 0x40000000:  # GenericWrite
                        aces.append({"rightname": "GenericWrite", "sid": sid, "inherited": is_inherited})
                    if mask & 0x00000100:  # ControlAccess (ExtendedRight)
                        aces.append({"rightname": "AllExtendedRights", "sid": sid, "inherited": is_inherited})

                elif atype in (0x05, 0x0B):  # Object ALLOW
                    if len(adata) < 16: continue
                    mask   = struct.unpack_from('<I', adata, 4)[0]
                    oflags = struct.unpack_from('<I', adata, 8)[0]
                    cur    = 12
                    obj_guid = None
                    inh_guid = None
                    if oflags & 0x1:
                        obj_guid = guid_from_bytes(adata[cur:cur+16])
                        cur += 16
                    if oflags & 0x2:
                        inh_guid = guid_from_bytes(adata[cur:cur+16])
                        cur += 16
                    sid = sid_to_str(adata[cur:])
                    if not sid: continue

                    # Check if inherited ACE applies to this object type
                    if is_inherited and inh_guid and objecttype_guid_map:
                        # Skip if doesn't apply
                        pass  # Simplified for now

                    # Parse object ACE (simplified but covers main cases)
                    if mask & 0x10000000:  # GenericAll
                        aces.append({"rightname": "GenericAll", "sid": sid, "inherited": is_inherited})
                        continue

                    # Check specific rights
                    if mask & 0x00080000:
                        aces.append({"rightname": "WriteOwner", "sid": sid, "inherited": is_inherited})
                    if mask & 0x00040000:
                        aces.append({"rightname": "WriteDacl", "sid": sid, "inherited": is_inherited})

                    # GenericWrite / WriteProperty
                    if mask & 0x00000020:
                        if obj_guid:
                            attr = SCHEMA_ATTR_GUID.get(obj_guid.lower(), '')
                            if attr == 'member' and entrytype == 'group':
                                aces.append({"rightname": "AddMember", "sid": sid, "inherited": is_inherited})
                            elif attr:
                                aces.append({"rightname": f"WriteProperty-{attr}", "sid": sid, "inherited": is_inherited})
                            else:
                                aces.append({"rightname": "GenericWrite", "sid": sid, "inherited": is_inherited})
                        else:
                            aces.append({"rightname": "GenericWrite", "sid": sid, "inherited": is_inherited})

                    # ExtendedRight
                    if mask & 0x00000100:
                        if obj_guid:
                            ext_name = EXT_RIGHTS_GUID.get(obj_guid.lower(), '')
                            if ext_name:
                                bh_name = EXT_RIGHT_TO_BH.get(ext_name, ext_name)
                                aces.append({"rightname": bh_name, "sid": sid, "inherited": is_inherited})
                            else:
                                aces.append({"rightname": "ExtendedRight", "sid": sid, "inherited": is_inherited})
                        else:
                            aces.append({"rightname": "AllExtendedRights", "sid": sid, "inherited": is_inherited})

                    # Self / Validated Write
                    if mask & 0x00000008:
                        if obj_guid:
                            ext_name = EXT_RIGHTS_GUID.get(obj_guid.lower(), '')
                            if ext_name == 'WriteMember' and entrytype == 'group':
                                aces.append({"rightname": "AddSelf", "sid": sid, "inherited": is_inherited})
                            else:
                                aces.append({"rightname": "Self", "sid": sid, "inherited": is_inherited})
                        else:
                            aces.append({"rightname": "Self", "sid": sid, "inherited": is_inherited})

            except:
                continue

    except:
        pass

    return aces


def resolve_aces(aces, domain, domain_sid, cache):
    """
    EXACT replica of BloodHound.py's AceResolver.resolve_aces()
    Resolves raw ACEs (with SIDs) to BloodHound-format ACEs.
    """
    aces_out = []
    for ace in aces:
        out = {
            'RightName': ace['rightname'],
            'IsInherited': ace['inherited']
        }
        sid = ace['sid']

        # Is it a well-known sid?
        if sid in WELLKNOWN_SIDS:
            out['PrincipalSID'] = f"{domain.upper()}-{sid}"
            out['PrincipalType'] = WELLKNOWN_SIDS[sid][1].capitalize()
        else:
            # Try to resolve from cache
            try:
                linkitem = cache.sid_cache[sid]
                out['PrincipalSID'] = sid
                out['PrincipalType'] = linkitem['ObjectType']
            except KeyError:
                # Couldn't resolve - use SID as-is
                out['PrincipalSID'] = sid
                out['PrincipalType'] = 'Base'

        aces_out.append(out)
    return aces_out


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
#  Collectors (with BloodHound.py logic)
# ══════════════════════════════════════════════════════════════════

def collect_domain(conn, base_dn, domain, cache):
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
        aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='domain')
        aces = resolve_aces(aces, domain, sid, cache)
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


def get_primary_membership(sid, primary_group_id):
    """BloodHound.py's get_primary_membership() - constructs PrimaryGroupSID from RID."""
    if not sid or not primary_group_id:
        return None
    return f"{'-'.join(sid.split('-')[:-1])}-{primary_group_id}"


def collect_users(conn, base_dn, domain, domain_sid, cache):
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

                # Parse and resolve ACEs
                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='user')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                # Resolve MemberOf using cache (EXACT BloodHound.py logic)
                member_of = []
                for m in mof:
                    resolved = cache.resolve_dn(m)
                    if resolved:
                        member_of.append(resolved)

                # Primary group membership (BloodHound.py logic)
                pgid = ga(a, 'primaryGroupID', 513)
                primary_group_sid = get_primary_membership(sid, pgid)

                user = {
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
                    "PrimaryGroupSid":   primary_group_sid,
                    "SPNTargets":        [{"ComputerSID":"","Port":0,"Service":s.split('/')[0]}
                                          for s in spns if '/' in s],
                    "HasSIDHistory":     [{"ObjectIdentifier":s,"ObjectType":"Base"} for s in hist],
                    "AllowedToDelegate": [{"ObjectIdentifier":d,"ObjectType":"Computer"} for d in delg],
                    "Aces": aces, "IsDeleted": False,
                    "MemberOf": member_of,
                }

                # Cache this user for DN resolution
                cache.add(str(ga(a,'distinguishedName','')), sid, "User")
                users.append(user)
            except Exception as ex:
                continue
        print(Fore.GREEN + f"[+] Users: {len(users)}  ACEs: {sum(len(u['Aces']) for u in users)}" + Style.RESET_ALL)
        return users
    except Exception as ex:
        print(Fore.RED + f"[-] Users: {ex}" + Style.RESET_ALL); return []


def collect_groups(conn, base_dn, domain, domain_sid, cache):
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
                mems = gal(a,'member')
                mof  = gal(a,'memberOf')
                hist = gal(a,'sIDHistory')

                # Handle well-known SIDs (BloodHound.py logic)
                if sid in WELLKNOWN_SIDS:
                    sid = f"{dom_u}-{sid}"

                # Parse and resolve ACEs
                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='group')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                # Resolve members using cache (EXACT BloodHound.py logic)
                ml = []
                for m in mems:
                    resolved = cache.resolve_dn(m)
                    if resolved:
                        ml.append(resolved)

                # Resolve MemberOf for groups too
                group_member_of = []
                for m in mof:
                    resolved = cache.resolve_dn(m)
                    if resolved:
                        group_member_of.append(resolved)

                # High-value check (BloodHound.py logic)
                is_highvalue = False
                for rid in HIGHVALUE_RIDS:
                    if sid.endswith(rid):
                        is_highvalue = True
                        break
                if sid in HIGHVALUE_SIDS:
                    is_highvalue = True

                groups.append({
                    "ObjectIdentifier": sid,
                    "Properties": {
                        "name": f"{sam.upper()}@{dom_u}", "domain": dom_u,
                        "domainsid": sid.rsplit('-',1)[0] if sid.count('-')>=3 else domain_sid,
                        "distinguishedname": str(ga(a,'distinguishedName','')),
                        "samaccountname": sam, "description": str(ga(a,'description','') or ''),
                        "admincount": bool(ga(a,'adminCount',0)),
                        "highvalue": is_highvalue, "sidhistory": hist,
                    },
                    "Members": ml,
                    "MemberOf": group_member_of,
                    "Aces": aces, "IsDeleted": False,
                })

                # Cache this group
                cache.add(str(ga(a,'distinguishedName','')), sid, "Group")

            except Exception as ex:
                continue
        print(Fore.GREEN + f"[+] Groups: {len(groups)}  ACEs: {sum(len(g['Aces']) for g in groups)}" + Style.RESET_ALL)
        return groups
    except Exception as ex:
        print(Fore.RED + f"[-] Groups: {ex}" + Style.RESET_ALL); return []


def collect_computers(conn, base_dn, domain, domain_sid, cache,
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
                mof  = gal(a,'memberOf')
                hist = gal(a,'sIDHistory')
                dsid = sid.rsplit('-',1)[0] if sid.count('-')>=3 else domain_sid
                name = dns.upper() if dns else f"{sam.rstrip('$').upper()}.{dom_u}"
                pgid = "516" if is_dc else str(ga(a,'primaryGroupID',515) or 515)

                # Parse and resolve ACEs
                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='computer')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                # Resolve MemberOf
                member_of = []
                for m in mof:
                    resolved = cache.resolve_dn(m)
                    if resolved:
                        member_of.append(resolved)

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
                    "MemberOf":  member_of,
                    "HasSIDHistory": [{"ObjectIdentifier":s,"ObjectType":"Base"} for s in hist],
                    "Aces": aces, "IsDeleted": False,
                })

                # Cache this computer
                cache.add(str(ga(a,'distinguishedName','')), sid, "Computer")

            except Exception as ex:
                continue

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


def collect_ous(conn, base_dn, domain, domain_sid, cache):
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

                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='organizational-unit')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                ous.append({
                    "ObjectIdentifier": guid.upper() if guid else dn,
                    "Properties": {"name":f"{name.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "highvalue":False},
                    "Links":links,"ChildObjects":[],"Aces":aces,"IsDeleted":False,
                })
                cache.add(dn, guid.upper() if guid else dn, "OU")
            except: continue
        print(Fore.GREEN + f"[+] OUs: {len(ous)}" + Style.RESET_ALL)
        return ous
    except Exception as ex:
        print(Fore.RED + f"[-] OUs: {ex}" + Style.RESET_ALL); return []


def collect_gpos(conn, base_dn, domain, domain_sid, cache):
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

                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='gpo')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                gpos.append({
                    "ObjectIdentifier": f"{{{guid}}}",
                    "Properties": {"name":f"{dname.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "gpcpath":str(ga(a,'gPCFileSysPath','') or ''),"highvalue":False},
                    "Aces":aces,"IsDeleted":False,
                })
                cache.add(dn, f"{{{guid}}}", "GPO")
            except: continue
        print(Fore.GREEN + f"[+] GPOs: {len(gpos)}" + Style.RESET_ALL)
        return gpos
    except Exception as ex:
        print(Fore.RED + f"[-] GPOs: {ex}" + Style.RESET_ALL); return []


def collect_containers(conn, base_dn, domain, domain_sid, cache):
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

                raw_aces = parse_aces(graw(e,'nTSecurityDescriptor'), entrytype='container')
                aces = resolve_aces(raw_aces, domain, domain_sid, cache)

                containers.append({
                    "ObjectIdentifier": guid.upper() if guid else dn,
                    "Properties": {"name":f"{name.upper()}@{domain.upper()}","domain":domain.upper(),
                                   "distinguishedname":dn,"description":str(ga(a,'description','') or ''),
                                   "highvalue":False},
                    "ChildObjects":[],"Aces":aces,"IsDeleted":False,
                })
                cache.add(dn, guid.upper() if guid else dn, "Container")
            except: continue
        print(Fore.GREEN + f"[+] Containers: {len(containers)}" + Style.RESET_ALL)
        return containers
    except Exception as ex:
        print(Fore.RED + f"[-] Containers: {ex}" + Style.RESET_ALL); return []


# ══════════════════════════════════════════════════════════════════
#  Default groups (BloodHound.py logic)
# ══════════════════════════════════════════════════════════════════

def write_default_groups(domain, domain_sid, cache):
    """
    BloodHound.py's write_default_groups() logic.
    Adds well-known groups like Everyone, Authenticated Users, Interactive, Enterprise Domain Controllers.
    """
    groups = []
    dom_u = domain.upper()

    # Enterprise Domain Controllers
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": f"{dom_u}-S-1-5-9",
        "Properties": {
            "domain": dom_u,
            "domainsid": domain_sid,
            "name": f"ENTERPRISE DOMAIN CONTROLLERS@{dom_u}",
        },
        "Members": [],
        "Aces": []
    })

    # Everyone
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": f"{dom_u}-S-1-1-0",
        "Properties": {
            "domain": dom_u,
            "domainsid": domain_sid,
            "name": f"EVERYONE@{dom_u}",
        },
        "Members": [],
        "Aces": []
    })

    # Authenticated Users
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": f"{dom_u}-S-1-5-11",
        "Properties": {
            "domain": dom_u,
            "domainsid": domain_sid,
            "name": f"AUTHENTICATED USERS@{dom_u}",
        },
        "Members": [],
        "Aces": []
    })

    # Interactive
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": f"{dom_u}-S-1-5-4",
        "Properties": {
            "domain": dom_u,
            "domainsid": domain_sid,
            "name": f"INTERACTIVE@{dom_u}",
        },
        "Members": [],
        "Aces": []
    })

    return groups


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

    # ── Connect ───────────────────────────────────────────────────
    print(Fore.YELLOW+"\n[*] Connecting to LDAP..."+Style.RESET_ALL)
    conn = ldap_connect(dc_ip, domain, username, password)
    if not conn: sys.exit(1)
    print(Fore.GREEN+"[+] LDAP connected!"+Style.RESET_ALL)

    base_dn = get_base_dn(domain)
    print(Fore.CYAN+"\n[*] Starting collection...\n"+Style.RESET_ALL)

    # Initialize the DN cache (BloodHound.py logic)
    cache = ADCache(conn, base_dn, domain)

    # ── CRITICAL: Pre-fetch all objects into cache ────────────────
    # This is the KEY BloodHound.py logic that was missing!
    cache.prefetch_all_objects()

    # ── Collect ───────────────────────────────────────────────────
    domain_obj, domain_sid = collect_domain(conn, base_dn, domain, cache)
    trusts     = collect_trusts(conn, base_dn, domain)
    users      = collect_users(conn, base_dn, domain, domain_sid, cache)
    groups     = collect_groups(conn, base_dn, domain, domain_sid, cache)
    computers  = collect_computers(conn, base_dn, domain, domain_sid, cache,
                                 dc_ip, username, password,
                                 do_sessions=do_sess, do_admins=do_adm, threads=20)
    ous        = collect_ous(conn, base_dn, domain, domain_sid, cache)
    gpos       = collect_gpos(conn, base_dn, domain, domain_sid, cache)
    containers = collect_containers(conn, base_dn, domain, domain_sid, cache)

    if domain_obj and trusts:
        domain_obj["Trusts"] = trusts

    # Add default groups (BloodHound.py logic)
    default_groups = write_default_groups(domain, domain_sid, cache)
    groups.extend(default_groups)

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
