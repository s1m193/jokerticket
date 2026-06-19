#!/usr/bin/env python3
import os
import sys
import re
import socket
import random
import platform
import logging
from datetime import datetime, timedelta, timezone
from time import sleep

from impacket.krb5.asn1 import AS_REQ, KRB_ERROR
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from ldap3 import Server, Connection, ALL
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
    ║       Kerberos User Enumeration           ║
    ║   Enumerate Valid AD Users via AS-REQ     ║
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


def check_domain_valid(dc_ip, domain):
    try:
        user = Principal(
            "test_nonexistent_user_xyz123",
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        asreq = AS_REQ()
        asreq['pvno']     = 5
        asreq['msg-type'] = constants.ApplicationTagNumbers.AS_REQ.value
        asreq['req-body']['kdc-options'] = asreq['req-body']['kdc-options'].clone(
            "'00000000000000000000000000000000'B"
        )
        asreq['req-body']['cname'] = user.components_to_asn1(asreq['req-body']['cname'])
        asreq['req-body']['realm'] = domain.upper()
        asreq['req-body']['sname'] = Principal(
            ['krbtgt', domain.upper()],
            type=constants.PrincipalNameType.NT_SRV_INST.value
        ).components_to_asn1(asreq['req-body']['sname'])
        asreq['req-body']['till']  = KerberosTime.to_asn1(
            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
        )
        asreq['req-body']['nonce'] = random.getrandbits(31)
        asreq['req-body']['etype'] = noValue
        asreq['req-body']['etype'].setComponentByPosition(
            0, constants.EncryptionTypes.rc4_hmac.value
        )

        data = encoder.encode(asreq)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(data, (dc_ip, 88))

        try:
            resp, _ = sock.recvfrom(4096)
            sock.close()
        except socket.timeout:
            sock.close()
            return "timeout"

        try:
            krb_error  = decoder.decode(resp, asn1Spec=KRB_ERROR())[0]
            error_code = int(krb_error['error-code'])
            if error_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                return "wrong_domain"
            return "ok"
        except Exception:
            return "ok"

    except Exception:
        return "error"


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
    with open(full_path, 'r', errors='ignore') as f:
        entries = [line.strip() for line in f if line.strip()]
    if not entries:
        print(Fore.RED + f"[!] No entries found in: {full_path}" + Style.RESET_ALL)
        return None
    print(Fore.GREEN + f"[+] Loaded {len(entries)} entries from: {full_path}" + Style.RESET_ALL)
    return entries


def resolve_output_file(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return os.path.join(os.getcwd(), f"kerbenum-{timestamp}.txt")
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


def generate_patterns(full_name):
    parts = full_name.strip().split()
    if len(parts) < 2:
        return [full_name.lower()]

    first = parts[0].lower()
    last  = parts[-1].lower()

    if not first or not last:
        return [full_name.lower()]

    f  = first
    l  = last
    fi = first[0]
    li = last[0]

    patterns = set()
    patterns.add(f"{f}.{l}")
    patterns.add(f"{fi}.{l}")
    patterns.add(f"{f}.{li}")
    patterns.add(f"{fi}.{li}")
    patterns.add(f"{l}.{f}")
    patterns.add(f"{l}.{fi}")
    patterns.add(f"{f}{l}")
    patterns.add(f"{fi}{l}")
    patterns.add(f"{f}{li}")
    patterns.add(f"{f}-{l}")
    patterns.add(f"{f}_{l}")
    patterns.add(f"{l}{f}")
    patterns.add(f"{l}{fi}")

    return list(patterns)


def send_asreq(dc_ip, domain, username):
    try:
        user = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asreq = AS_REQ()
        asreq['pvno']     = 5
        asreq['msg-type'] = constants.ApplicationTagNumbers.AS_REQ.value
        asreq['req-body']['kdc-options'] = asreq['req-body']['kdc-options'].clone(
            "'00000000000000000000000000000000'B"
        )
        asreq['req-body']['cname'] = user.components_to_asn1(asreq['req-body']['cname'])
        asreq['req-body']['realm'] = domain.upper()
        asreq['req-body']['sname'] = Principal(
            ['krbtgt', domain.upper()],
            type=constants.PrincipalNameType.NT_SRV_INST.value
        ).components_to_asn1(asreq['req-body']['sname'])
        asreq['req-body']['till']  = KerberosTime.to_asn1(
            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
        )
        asreq['req-body']['nonce'] = random.getrandbits(31)
        asreq['req-body']['etype'] = noValue
        asreq['req-body']['etype'].setComponentByPosition(
            0, constants.EncryptionTypes.rc4_hmac.value
        )

        data = encoder.encode(asreq)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(data, (dc_ip, 88))

        try:
            resp, _ = sock.recvfrom(4096)
        except socket.timeout:
            sock.close()
            return "timeout"
        finally:
            sock.close()

        if resp and resp[0] == 0x6B:
            return "valid"

        try:
            krb_error  = decoder.decode(resp, asn1Spec=KRB_ERROR())[0]
            error_code = int(krb_error['error-code'])

            if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                return "valid"
            elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return "invalid"
            elif error_code in [14, 23, 24, 25, 36, 39]:
                return "valid"
            else:
                return "unknown"
        except Exception:
            return "valid"

    except Exception:
        return "error"


def run_enumeration(dc_ip, domain, userlist, output_file):
    print(Fore.YELLOW + f"\n[*] Starting Kerberos enumeration..." + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Target DC    : {dc_ip}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Domain       : {domain}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Total users  : {len(userlist)}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Output file  : {output_file}" + Style.RESET_ALL)
    print(Fore.CYAN   + "-" * 50 + Style.RESET_ALL)

    valid_users   = []
    invalid_count = 0
    error_count   = 0

    try:
        fd = open(output_file, 'w')
        fd.write(f"Kerberos Enumeration Results\n")
        fd.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fd.write(f"Target : {dc_ip}\n")
        fd.write(f"Domain : {domain}\n")
        fd.write(f"Total  : {len(userlist)}\n")
        fd.write("-" * 50 + "\n\n")
    except Exception as e:
        print(Fore.RED + f"[!] Cannot create output file: {e}" + Style.RESET_ALL)
        fd = None

    try:
        for i, username in enumerate(userlist, 1):
            progress = f"[{i}/{len(userlist)}]"
            result   = send_asreq(dc_ip, domain, username)

            if result == "valid":
                valid_users.append(username)
                print(Fore.GREEN + f"{progress} [+] FOUND    : {username}" + Style.RESET_ALL)
                if fd:
                    fd.write(f"[VALID] {username}\n")

            elif result == "invalid":
                invalid_count += 1
                print(Fore.WHITE + f"{progress} [-] NOT FOUND: {username}" + Style.RESET_ALL)

            elif result == "timeout":
                error_count += 1
                print(Fore.YELLOW + f"{progress} [!] TIMEOUT  : {username}" + Style.RESET_ALL)

            else:
                error_count += 1
                print(Fore.YELLOW + f"{progress} [!] ERROR    : {username}" + Style.RESET_ALL)

            sleep(0.05)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        if fd:
            fd.close()
        sys.exit(0)

    if fd:
        fd.write("\n" + "-" * 50 + "\n")
        fd.write(f"Valid users : {len(valid_users)}\n")
        fd.write(f"Not found   : {invalid_count}\n")
        fd.write(f"Errors      : {error_count}\n")
        fd.close()

    print(Fore.CYAN + "\n" + "=" * 50 + Style.RESET_ALL)
    print(Fore.CYAN + "[*] ENUMERATION SUMMARY" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)
    print(Fore.GREEN  + f"[+] Valid users  : {len(valid_users)}" + Style.RESET_ALL)
    print(Fore.WHITE  + f"[-] Not found    : {invalid_count}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[!] Errors       : {error_count}" + Style.RESET_ALL)

    if valid_users:
        print(Fore.GREEN + "\n[+] Valid users found:" + Style.RESET_ALL)
        for user in valid_users:
            print(Fore.GREEN + f"    ✔ {user}" + Style.RESET_ALL)

    print(Fore.CYAN + f"\n[*] Results saved to: {output_file}" + Style.RESET_ALL)


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

    domain = get_input(
        Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
        validate_domain, "Invalid domain! Example: domain.com"
    )

    print(Fore.YELLOW + "[*] Verifying domain..." + Style.RESET_ALL)
    domain_check = check_domain_valid(dc_ip, domain)
    if domain_check == "wrong_domain":
        print(Fore.RED + f"[!] Domain '{domain}' not recognized by DC!" + Style.RESET_ALL)
        sys.exit(1)
    elif domain_check == "timeout":
        print(Fore.RED + f"[!] Timeout - no response from DC on port 88!" + Style.RESET_ALL)
        sys.exit(1)
    elif domain_check == "error":
        print(Fore.RED + f"[!] Cannot connect to Kerberos service on {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

    print(Fore.CYAN + "\n[?] Enumeration mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Single username")
    print(Fore.WHITE + "    2. Username list from file")
    print(Fore.WHITE + "    3. Full name list (auto-generate patterns)")
    mode = get_input(
        Fore.CYAN + "[?] Choose mode          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    userlist = []

    if mode == '1':
        single_user = get_input(Fore.CYAN + "[?] Enter username       : " + Style.RESET_ALL)
        userlist    = [single_user]

    elif mode == '2':
        while True:
            list_input = get_input(
                Fore.CYAN   + "[?] Enter userlist path  : " + Style.RESET_ALL +
                Fore.YELLOW + "(e.g. users.txt or /lists/users.txt) " + Style.RESET_ALL
            )
            userlist = validate_userlist_file(list_input)
            if userlist:
                break

    else:
        while True:
            list_input = get_input(
                Fore.CYAN   + "[?] Enter names file     : " + Style.RESET_ALL +
                Fore.YELLOW + "(e.g. names.txt - one full name per line) " + Style.RESET_ALL
            )
            names = validate_userlist_file(list_input)
            if names:
                break

        print(Fore.YELLOW + "[*] Generating username patterns..." + Style.RESET_ALL)
        all_patterns = set()
        for name in names:
            all_patterns.update(generate_patterns(name))
        userlist = sorted(list(all_patterns))
        print(Fore.GREEN + f"[+] Generated {len(userlist)} unique patterns!" + Style.RESET_ALL)

    timestamp    = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    default_name = f"kerbenum-{timestamp}.txt"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_file = resolve_output_file(out_input if out_input else "")

    run_enumeration(dc_ip, domain, userlist, output_file)
