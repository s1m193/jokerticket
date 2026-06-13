#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JokerTicket.py - Active Directory Chaos Framework 🤡
# Run with: python3 JokerTicket.py

import os
import sys
import time
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
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
    attacks = {
   	"1": ("Users Enumeration → kerbros users enumeration",        "kerberos_user_enum.py"),
   	"2": ("Users' information → Information about users",        "Users-info.py"),
        "3": ("Domain Enumeration → BloodHound JSON",        "enum4AD.py"),
        "4": ("AS-REP Roasting → Passwords without preauth",        "AS-REPRoasting.py"),
        "5": ("Kerberoasting → SPN Hash Party!",      "Kerberoasting.py"),
        "6": ("DCSync Laugh Attack",       "Secrets_Dump.py"),
        "7": ("WinRM Shell → I'm in your system, Batsy!",                   "Remote_Access.py"),
        "8": ("DCSync Laugh Attack",        "attacks/dcsync.py"),
        "9": ("ZeroLogon & PrintNightmare", "attacks/zerologon_printnightmare.py"),
        "10": ("LDAP Chaos Queries",         "attacks/ldap_chaos.py"),
        "11": ("SharpHound Ingest",          "attacks/sharphound.py"),
        "12":("Unconstrained Delegation",   "attacks/unconstrained.py"),
        "13":("Exit",                       "exit")
    }

    while True:
        banner()
        print(f"{C}[+] Choose your poison, sweetheart:\n{E}")
        for k, v in attacks.items():
            if k != "11":
                print(f"{Y}{k}){E}  {v[0]}")
            else:
                print(f"{R}{k}){E}  {v[0]}{E}")
        print()
        choice = input(f"{P}[🤡] Number → {E}")

        if choice in attacks:
            if attacks[choice][1] == "exit":
                print(f"{R}Bye bye, Batsy... We live in a society!{E}")
                sys.exit(0)
            elif os.path.exists(attacks[choice][1]):
                os.system(f"python3 {attacks[choice][1]}")
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
