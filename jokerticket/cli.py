#!/usr/bin/env python3

import os
import sys
import time
import signal
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def _exit_handler(sig, frame):
    print(Y + "\n\n[!] Exiting... Goodbye!" + E)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)

# Colors
R = "\033[91m"   # Red
G = "\033[92m"   # Green
Y = "\033[93m"   # Yellow
P = "\033[95m"   # Purple
C = "\033[96m"   # Cyan
B = "\033[94m"   # Blue
W = "\033[97m"   # White
E = "\033[0m"    # End

def banner():
    os.system("clear")
    print(f"{P}")
    print("""
    /$$$$$           /$$                        /$$$$$$$$ /$$           /$$                   /$$    
   |__  $$          | $$                       |__  $$__/|__/          | $$                  | $$    
      | $$  /$$$$$$ | $$   /$$  /$$$$$$   /$$$$$$ | $$    /$$  /$$$$$$$| $$   /$$  /$$$$$$  /$$$$$$  
      | $$ /$$__  $$| $$  /$$/ /$$__  $$ /$$__  $$| $$   | $$ /$$_____/| $$  /$$/ /$$__  $$|_  $$_/  
 /$$  | $$| $$  \ $$| $$$$$$/ | $$$$$$$$| $$  \__/| $$   | $$| $$      | $$$$$$/ | $$$$$$$$  | $$    
| $$  | $$| $$  | $$| $$_  $$ | $$_____/| $$      | $$   | $$| $$      | $$_  $$ | $$_____/  | $$ /$$
|  $$$$$$/|  $$$$$$/| $$ \  $$|  $$$$$$$| $$      | $$   | $$|  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/
 \______/  \______/ |__/  \__/ \_______/|__/      |__/   |__/ \_______/|__/  \__/ \_______/   \___/  
 
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣷⡿⠋⢁⣀⣤⣴⣶⣶⣶⣾⣿⣿⣷⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢟⣋⣭⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠞⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠛⠉⠸⣿⡿⣿⣿⠿⢿⡿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⣀⠀
⠀⠀⠀⠀⢰⡏⠀⠀⠉⠛⠛⠛⠛⠉⠁⠈⠛⠛⠉⠁⠀⠀⣀⣴⣶⣿⣿⣿⣿⣿⣷⣦⣝⠻⣿⣿⣿⣶⣶⣶⡶⢒⡿⢋⡀
⠀⠀⠀⠀⠸⣼⣷⣄⡀⠀⢀⣴⣿⣿⣶⣦⣄⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⣠⣖⣩⣶⡟⠁
⠀⠀⠀⠀⠀⠉⠻⣿⣿⣶⣾⣿⣿⣿⣿⣿⣿⣣⢔⡿⠟⠉⠁⠀⠀⠀⢀⣠⣠⣤⣿⣿⣟⣛⣿⣧⣤⣶⣾⣿⣿⣿⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⢻⠿⣿⣿⣿⣿⢟⠕⠋⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⠀⠀⠈⠉⠛⠃⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⡿⠛⠛⢻⡿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠇⠀⠀⠀⠢⡀⠀⠀⢀⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⠏⠀⡠⢮⢿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠈⠢⣀⠊⠀⠀⠀⢀⣀⡠⠤⠶⢶⡾⠋⠀⠀⠈⢻⢀⡮⢶⠀⢸⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⣀⣀⣀⣀⣤⣬⠷⠤⠖⠚⠯⣥⣄⣠⣴⠟⠁⠀⠀⠀⠀⠈⡉⠀⠞⢀⡏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠛⢿⠶⣤⣀⣭⡏⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠒⠒⠂⠀⠹⡤⠴⢯⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠈⠙⢳⠁⠀⠀⠀⠀⣀⠄⠚⠉⠉⢉⡝⠉⣲⣄⠀⠀⠀⢧⠀⠀⠙⢦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⣰⣎⡉⢸⠀⠀⡠⣲⠏⠁⠀⢀⡠⡖⠁⢧⠀⣿⠈⠆⠀⠀⢸⠀⠀⠀⠀⠈⡒⢤⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⣇⠈⢻⣾⠀⣠⣊⣤⠤⣶⠚⠉⠀⡇⠀⢸⡄⡿⠀⠀⠀⠀⣼⠀⠀⠀⡜⠀⡇⠀⠈⠑
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣎⠀⠀⢙⣾⡅⢸⠀⠀⠸⡄⠀⠀⡇⠀⣸⣷⡇⠀⠀⠀⣴⠏⠀⠀⣸⠁⢠⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠈⠸⢷⣈⣇⣀⣀⣳⡄⠠⠓⡎⠁⣾⠀⠀⠀⣼⠟⠀⠀⢠⠃⠀⢸⠀⠀⠀⠀
⠀⠀⣀⡤⣠⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⡄⠐⡏⠁⠈⡆⠀⠀⢳⠀⠀⢳⣰⠃⠀⠀⣼⡟⠀⠀⢀⠎⠀⠀⡇⠀⠀⠀⠀
⠀⢸⡷⣟⣿⠗⢋⡄⢀⣀⡀⠀⠀⠀⠀⠀⠘⣄⢸⡀⠀⡇⠀⠀⠈⡆⣀⣼⠏⠀⢠⣾⠟⠀⠀⠀⡞⠀⠀⢸⠀⠀⠀⠀⠀
⢀⣰⢅⣠⢤⢞⣿⠁⠛⠋⠀⠀⠀⠀⠀⠀⠀⠈⢎⠛⠿⠿⠷⠶⠶⠭⠗⠋⠀⣰⡿⠧⠤⠤⣀⡼⠁⠀⢀⡇⠀⠀⠀⠀⠀
⣸⣁⣟⠜⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠙⢆⠀⠀⡜⠁⠀⠀⣸⠀⠀⠀⠀⠀⠀
⠟⠁⠀⠀⠀⠀⣤⠀⠀⠀⠀⢠⡆⠀⠀⠀⠀⠀⠀⢀⣱⡀⠀⠀⠀⢀⡴⠛⠦⡀⠀⠀⢣⠞⠀⠀⣀⡠⠧⠒⠲⡆⠀⠀⠀
⠀⠀⠀⠀⣠⢤⣇⣀⣤⣄⡶⣻⠀⠀⠀⠀⠀⢀⠔⠋⠀⠹⡄⠀⡠⠮⠤⠤⢄⣈⣓⣖⣫⡤⠖⠉⠁⠀⠀⠀⢀⠇⠀⠀⠀
⠀⠀⠂⠚⠛⠺⠟⠋⠛⠋⠉⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠙⠚⢣⠀⠀⠀⠀⠀⢹⡀⠘⡆⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀
⠀⠀⣀⣴⢺⠟⠀⣀⡠⠖⠀⠀⠀⠀⣀⡄⢸⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⢙⠶⣷⡀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀
⠀⠐⠁⣼⣁⡐⢫⢻⣁⡠⠤⠒⠊⠉⠀⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⣼⢧⠀⠀⠀⡰⡏⢸⠇⣿⠲⣄⠀⠀⠀⡎⠀⠀⠀⠀
⠀⠀⠀⣿⡴⠻⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⢸⠈⣆⢀⡜⢡⠃⡞⠇⣿⠀⢸⠳⢄⣠⠇⠀⠀⠀⠀
⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⢸⠀⠘⠊⠀⡞⠀⣿⡀⣿⠀⡎⠀⠀⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠘⡆⠀⠀⠀⠉⠙⢻⡇⢹⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠷⠋⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠧⠀⠀⠀⠀⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀                                      


    """)
    print(f"{R}       ╔═══════════════════════════════════════════╗{E}")
    print(f"{R}       ║ {Y} JokerTicket v1.0 - Active Directory Chaos{R}║{E}")
    print(f"{R}       ║ {G}  \"All it takes is one bad day...\" 🤡{R}     ║{E}")
    print(f"{R}       ╚═══════════════════════════════════════════╝{E}")
    print(f"{P}                HA HA HA HA HA HA HA HA HA HA HA{E}")
    print(f"{G}          Put on a happy face... or I'll do it for you.\n{E}")

def menu():
    categories = {
        "1": ("Enumeration", {
            "1": ("Kerberos Users Enumeration", "enumeration/kerberos_user_enum.py"),
            "2": ("Users Information", "enumeration/Users-info.py"),
            "3": ("Domain Enumeration → BloodHound JSON", "enumeration/enum4AD.py"),
            "4": ("Exploit Database Search", "enumeration/exploits-dbs.py"),
        }),
        "2": ("Kerberos Attacks", {
            "1": ("AS-REP Roasting → Passwords without preauth", "kerberos/AS-REPRoasting.py"),
            "2": ("Kerberoasting → SPN Hash Party!", "kerberos/Kerberoasting.py"),
            "3": ("Golden Ticket Attack", "kerberos/Golden-Ticket.py"),
            "4": ("SPN Abuse", "kerberos/SPN.py"),
            "5": ("Shadow Credentials Attack", "kerberos/Shadow-credentials.py"),
            "6": ("Intercept Kerberos Tickets", "kerberos/intercept_kerberos_tickets.py"),
            "7": ("Force Change Password", "kerberos/ForceChangePassword.py"),
            "8": ("Password Spray", "kerberos/PassworSpray.py"),
        }),
        "3": ("Credential Access", {
            "1": ("DCSync Laugh Attack → Secrets Dump", "credential_access/Secrets_Dump.py"),
            "2": ("Credential Access Module", "credential_access/credential_access.py"),
        }),
        "4": ("Lateral Movement", {
            "1": ("Pass the Hash", "lateral_movement/PtH.py"),
            "2": ("Pass the Ticket", "lateral_movement/PtT.py"),
            "3": ("Token Impersonation Shell", "lateral_movement/Token_shell6.py"),
            "4": ("Get Tokens (PowerShell)", "lateral_movement/get_tokens.ps1"),
            "5": ("Lateral Movement Module", "lateral_movement/leteral_movement.py"),
            "6": ("Overpass the Hash", "lateral_movement/opth.py"),
            "7": ("Pass the Key", "lateral_movement/pass_the_key.py"),
        }),
        "5": ("Delegation Abuse", {
            "1": ("S4U Abuse (Constrained Delegation)", "delegation/s4u.py"),
        }),
        "6": ("ADCS Attacks", {
            "1": ("CA Admin Abuse", "adcs/ca_admin.py"),
            "2": ("Golden Certificate Attack", "adcs/golden_cert.py"),
        }),
        "7": ("NTLM Attacks", {
            "1": ("NTLM Relay", "ntlm/ntlm-ralay.py"),
        }),
        "8": ("Password Attacks", {
            "1": ("Kerberos Ticket Brute-Force", "password_attacks/bruteforce-kerbros-tickets.py"),
            "2": ("Change Default Password", "password_attacks/change-default-password.py"),
        }),
        "9": ("Privilege Escalation", {
            "1": ("ACL Takeover", "privilege_escalation/acl_takeover.py"),
            "2": ("Group Abuse", "privilege_escalation/group_abuse.py"),
        }),
        "10": ("Trusts Abuse", {}),
        "0": ("Exit", "exit")
    }

    while True:
        banner()
        print(f"{C}[+] Choose your poison, sweetheart:\n{E}")
        for k, v in categories.items():
            if k == "0":
                print(f"{R}{k}){E}  {v[0]}")
            else:
                print(f"{Y}{k}){E}  {v[0]}")
        print()
        choice = input(f"{P}[🤡] Number → {E}")

        if choice == "0":
            print(f"{R}Bye bye, Batsy... We live in a society!{E}")
            sys.exit(0)

        if choice not in categories:
            print(f"{R}[!] Why so serious? Wrong number!{E}")
            time.sleep(2)
            continue

        submenu(categories[choice])


def submenu(category):
    title, attacks = category

    if not attacks:
        print(f"{R}[!] No attacks available yet in '{title}'... still writing the joke!{E}")
        input(f"\n{G}Press Enter to go back...{E}")
        return

    while True:
        banner()
        print(f"{C}[+] {title} → Pick your weapon:\n{E}")
        for k, v in attacks.items():
            print(f"{Y}{k}){E}  {v[0]}")
        print(f"{R}0){E}  Back to main menu")
        print()
        choice = input(f"{P}[🤡] Number → {E}")

        if choice == "0":
            return

        if choice in attacks:
            script_path = str(BASE_DIR / attacks[choice][1])
            if os.path.exists(script_path):
                if script_path.endswith(".ps1"):
                    os.system(f"pwsh {script_path}")
                else:
                    os.system(f"python3 {script_path}")
            else:
                print(f"{R}[!] Script not found yet... still writing the joke!{E}")
            input(f"\n{G}Press Enter to continue the chaos...{E}")
        else:
            print(f"{R}[!] Why so serious? Wrong number!{E}")
            time.sleep(2)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{R}Catch you later, Batman! 🤡{E}")
