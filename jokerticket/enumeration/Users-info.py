#!/usr/bin/env python3
# AD User Enumeration Script
# Requirements: pip install ldap3 colorama

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from colorama import Fore, Style, init
from datetime import datetime
import sys
import re
import os
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)
init(autoreset=True)

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════╗
    ║        AD User Enumerator             ║
    ╚═══════════════════════════════════════╝
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
    parts = domain.split('.')
    for part in parts:
        if part.startswith('-') or part.endswith('-'):
            return False
        if not part:
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

def check_domain_exists(dc_ip, domain, username, password):
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

def resolve_output_path(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        filename  = f"user-info-{timestamp}.txt"
        return os.path.join(os.getcwd(), filename)

    user_input = user_input.lstrip('/')
    full_path  = os.path.normpath(os.path.join(os.getcwd(), user_input))
    directory  = os.path.dirname(full_path)

    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(Fore.YELLOW + f"[*] Created directory: {directory}" + Style.RESET_ALL)
        except PermissionError:
            print(Fore.RED + f"[!] Permission denied: {directory}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"[*] Saving to current directory instead..." + Style.RESET_ALL)
            full_path = os.path.join(os.getcwd(), os.path.basename(user_input))
        except Exception as e:
            print(Fore.RED + f"[!] Cannot create directory: {e}" + Style.RESET_ALL)
            sys.exit(1)
    else:
        print(Fore.GREEN + f"[*] Directory exists: {directory}" + Style.RESET_ALL)

    return full_path

def enumerate_users(dc_ip, domain, username, password, output_path):
    base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
    server  = Server(dc_ip, get_info=ALL)

    print(Fore.YELLOW + f"\n[*] Fetching users from {dc_ip}..." + Style.RESET_ALL)

    try:
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
    except LDAPBindError:
        print(Fore.RED + "[-] Authentication failed!" + Style.RESET_ALL)
        sys.exit(1)
    except LDAPSocketOpenError:
        print(Fore.RED + f"[-] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Unexpected error: {e}" + Style.RESET_ALL)
        sys.exit(1)

    try:
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=user)',
            search_scope=SUBTREE,
            attributes=[
                'sAMAccountName', 'displayName', 'mail',
                'userAccountControl', 'description',
                'memberOf', 'givenName', 'sn'
            ]
        )
    except Exception as e:
        print(Fore.RED + f"[-] LDAP Search failed: {e}" + Style.RESET_ALL)
        sys.exit(1)

    # ---- Collect all rows first ----
    rows = []
    for entry in conn.entries:
        try:
            uname = str(entry.sAMAccountName.value) if entry.sAMAccountName.value else "N/A"
            fname = str(entry.givenName.value)       if entry.givenName.value      else ""
            lname = str(entry.sn.value)              if entry.sn.value             else ""
            fname = f"{fname} {lname}".strip() or "N/A"
            email = str(entry.mail.value)            if entry.mail.value           else "N/A"
            desc  = str(entry.description.value)     if entry.description.value    else "N/A"

            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
            if uac & 2:
                status_label = "Disabled"
                status_color = Fore.RED
            elif uac & 8388608:
                status_label = "PwdExpired"
                status_color = Fore.YELLOW
            elif uac & 65536:
                status_label = "PwdNeverExpires"
                status_color = Fore.MAGENTA
            else:
                status_label = "Active"
                status_color = Fore.GREEN

            rows.append((uname, fname, email, status_label, status_color, desc))
        except Exception as e:
            print(Fore.RED + f"[!] Error processing entry: {e}" + Style.RESET_ALL)
            continue

    conn.unbind()

    if not rows:
        print(Fore.RED + "[-] No users found!" + Style.RESET_ALL)
        sys.exit(0)

    # ---- Calculate column widths dynamically ----
    col_widths = [
        max(len("Username"),    max(len(r[0]) for r in rows)) + 2,
        max(len("Full Name"),   max(len(r[1]) for r in rows)) + 2,
        max(len("Email"),       max(len(r[2]) for r in rows)) + 2,
        max(len("Status"),      max(len(r[3]) for r in rows)) + 2,
        max(len("Description"), max(len(r[5]) for r in rows)) + 2,
    ]

    separator = "-" * sum(col_widths)

    # ---- Print to terminal ----
    print(Fore.CYAN + f"\n[*] Total users found: {len(rows)}\n")
    print(Fore.CYAN + separator)
    print(
        Fore.CYAN  + f"{'Username':<{col_widths[0]}}" +
        Fore.WHITE + f"{'Full Name':<{col_widths[1]}}" +
        Fore.WHITE + f"{'Email':<{col_widths[2]}}" +
        Fore.WHITE + f"{'Status':<{col_widths[3]}}" +
        Fore.WHITE + f"{'Description':<{col_widths[4]}}"
    )
    print(Fore.CYAN + separator)

    for (uname, fname, email, status_label, status_color, desc) in rows:
        print(
            Fore.CYAN    + f"{uname:<{col_widths[0]}}" +
            Fore.WHITE   + f"{fname:<{col_widths[1]}}" +
            Fore.WHITE   + f"{email:<{col_widths[2]}}" +
            status_color + f"{status_label:<{col_widths[3]}}" +
            Fore.YELLOW  + f"{desc:<{col_widths[4]}}"
        )

    print(Fore.CYAN + separator)

    # ---- Save to file (no colors) ----
    try:
        with open(output_path, 'w') as f:
            header_line = (
                f"{'Username':<{col_widths[0]}}"
                f"{'Full Name':<{col_widths[1]}}"
                f"{'Email':<{col_widths[2]}}"
                f"{'Status':<{col_widths[3]}}"
                f"{'Description':<{col_widths[4]}}\n"
            )
            f.write(separator + "\n")
            f.write(header_line)
            f.write(separator + "\n")
            for (uname, fname, email, status_label, _, desc) in rows:
                f.write(
                    f"{uname:<{col_widths[0]}}"
                    f"{fname:<{col_widths[1]}}"
                    f"{email:<{col_widths[2]}}"
                    f"{status_label:<{col_widths[3]}}"
                    f"{desc:<{col_widths[4]}}\n"
                )
            f.write(separator + "\n")
            f.write(f"\nTotal users: {len(rows)}\n")

        print(Fore.GREEN + f"\n[+] Results saved to: {output_path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save file: {e}" + Style.RESET_ALL)


if __name__ == "__main__":
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

    domain   = get_input(Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
                         validate_domain, "Invalid domain format! Example: domain.com")
    username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
    password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)


    print(Fore.YELLOW + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
    result = check_domain_exists(dc_ip, domain, username, password)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials! Check username and password." + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found on {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] Credentials verified!" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

    # Output file
    timestamp    = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    default_name = f"users-info-{timestamp}.txt"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_path = resolve_output_path(out_input if out_input else "")

    enumerate_users(dc_ip, domain, username, password, output_path)
