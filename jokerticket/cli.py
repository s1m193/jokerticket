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
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
P = "\033[95m"
C = "\033[96m"
B = "\033[94m"
W = "\033[97m"
E = "\033[0m"

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


categories = {
    "1": ("Enumeration", {
        "1": ("Kerberos Users Enumeration", "enumeration/kerberos_user_enum.py",
              ["kerberos_user_enum", "user enum", "enumerate users"]),
        "2": ("Users Information", "enumeration/Users-info.py",
              ["Users-info", "user info", "user details"]),
        "3": ("Domain Enumeration → BloodHound JSON", "enumeration/enum4AD.py",
              ["enum4AD", "BloodHound", "bloodhound json", "edges", "domain enumeration",
               "ad recon", "ldap enum", "ADCSESC1", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
               "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b", "ADCSESC9a", "ADCSESC9b",
               "AddAllowedToAct", "AddKeyCredentialLink", "AddMember", "AddSelf", "AdminTo",
               "AllExtendedRights", "AllowedToAct", "AllowedToDelegate", "CanPSRemote", "CanRDP",
               "ClaimSpecialIdentity", "CoerceAndRelayNTLMToADCS", "CoerceAndRelayNTLMToLDAP",
               "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToSMB", "CrossForestTrust",
               "DCSync", "DelegatedEnrollmentAgent", "DumpSMSAPassword", "Enroll",
               "EnrollOnBehalfOf", "ExecuteDCOM", "ForceChangePassword", "GPLink", "GenericAll",
               "GenericWrite", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
               "GoldenCert", "HasSIDHistory", "HasSession", "HasTrustKeys", "ManageCA",
               "ManageCertificates", "Owns", "OwnsLimitedRights", "OwnsRaw", "ReadGMSAPassword",
               "ReadLAPSPassword", "RemoteInteractiveLogonRight", "SQLAdmin", "SameForestTrust",
               "SpoofSIDHistory", "SyncLAPSPassword", "WriteAccountRestrictions", "WriteDacl",
               "WriteOwner", "WriteOwnerLimitedRights", "WriteOwnerRaw", "WritePKIEnrollmentFlag",
               "WritePKINameFlag", "WriteSPN"]),
        "4": ("Exploit Database Search", "enumeration/exploits-dbs.py",
              ["exploits-dbs", "exploit search", "searchsploit", "cve"]),
    }),
    "2": ("Kerberos Attacks", {
        "1": ("AS-REP Roasting → Passwords without preauth", "kerberos/AS-REPRoasting.py",
              ["AS-REPRoasting", "asreproast", "preauth", "no preauth"]),
        "2": ("Kerberoasting → SPN Hash Party!", "kerberos/Kerberoasting.py",
              ["Kerberoasting", "kerberoast", "SPN hash"]),
        "3": ("Golden Ticket Attack", "kerberos/Golden-Ticket.py",
              ["Golden-Ticket", "golden ticket", "krbtgt", "forge TGT", "SpoofSIDHistory"]),
        "4": ("SPN Scan / Targeted Kerberoasting", "kerberos/SPN.py",
              ["SPN", "spn scan", "servicePrincipalName", "targeted kerberoasting",
               "GenericWrite", "WriteSPN"]),
        "5": ("Shadow Credentials Attack", "kerberos/Shadow-credentials.py",
              ["Shadow-credentials", "shadow credentials", "PKINIT", "msDS-KeyCredentialLink",
               "AddKeyCredentialLink", "GenericAll", "GenericWrite"]),
        "6": ("Silver Ticket Attack", "kerberos/Silver-Ticket.py",
              ["Silver-Ticket", "silver ticket", "service ticket forge"]),
        "7": ("Intercept Kerberos Tickets", "kerberos/intercept_kerberos_tickets.py",
              ["intercept_kerberos_tickets", "ticket interception", "sniff tickets"]),
        "8": ("PAC Manipulation", "kerberos/pac_manipulate.py",
              ["pac_manipulate", "PAC manipulation", "MS14-068", "pac forge"]),
        "9": ("Pass the Key", "kerberos/pass_the_key.py",
              ["pass_the_key", "pass the key", "PtK", "AS-REQ key"]),
    }),
    "3": ("Credential Access", {
        "1": ("DCSync Laugh Attack → Secrets Dump", "credential_access/Secrets_Dump.py",
              ["Secrets_Dump", "secretsdump", "ntds dump", "AllExtendedRights", "DCSync",
               "GenericAll", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]),
        "2": ("Credential Access Module (LAPS/GMSA/SMSA)", "credential_access/credential_access.py",
              ["credential_access", "laps", "gmsa", "smsa", "service password",
               "AllExtendedRights", "DumpSMSAPassword", "GenericAll", "GenericWrite",
               "ReadGMSAPassword", "ReadLAPSPassword", "SyncLAPSPassword"]),
        "3": ("DPAPI Secrets Decryption", "credential_access/dpapi_decrypt.py",
              ["dpapi_decrypt", "dpapi", "credential vault", "masterkey decrypt"]),
    }),
    "4": ("Delegation Abuse", {
        "1": ("Kerberos Constrained Delegation (KCD)", "delegation/KCD.py",
              ["KCD", "constrained delegation", "S4U2Self", "S4U2Proxy", "AllowedToDelegate"]),
        "2": ("Kerberos Delegation Enumerator", "delegation/Kerberos_Delegation_Enumerator.py",
              ["Kerberos_Delegation_Enumerator", "delegation enum", "find delegation",
               "unconstrained delegation", "CanPSRemote"]),
        "3": ("Resource-Based Constrained Delegation (RBCD)", "delegation/rbcd.py",
              ["rbcd", "RBCD", "resource based constrained delegation", "AddAllowedToAct",
               "AllowedToAct", "GenericAll", "GenericWrite", "WriteAccountRestrictions"]),
        "4": ("S4U Abuse", "delegation/s4u.py", ["s4u", "s4u abuse", "AllowedToDelegate"]),
    }),
    "5": ("ADCS Attacks", {
        "1": ("CA Admin Abuse", "adcs/ca_admin.py",
              ["ca_admin", "CA admin", "certificate authority takeover", "ManageCA",
               "ManageCertificates"]),
        "2": ("Certificate Enrollment Abuse (ESC1/ESC3)", "adcs/cert_enroll_abuse.py",
              ["cert_enroll_abuse", "enroll on behalf", "ADCSESC1", "ADCSESC3",
               "CoerceAndRelayNTLMToADCS", "DelegatedEnrollmentAgent", "Enroll",
               "EnrollOnBehalfOf"]),
        "3": ("Certificate Template Abuse (ESC4/6/9/10/13)", "adcs/cert_template_abuse.py",
              ["cert_template_abuse", "template misconfiguration", "san", "SAN injection",
               "weak certificate security", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
               "ADCSESC4", "ADCSESC6a", "ADCSESC6b", "ADCSESC9a", "ADCSESC9b", "Enroll",
               "WritePKIEnrollmentFlag", "WritePKINameFlag"]),
        "4": ("Golden Certificate Attack", "adcs/golden_cert.py",
              ["golden_cert", "forge certificate", "ca private key", "GoldenCert"]),
    }),
    "6": ("NTLM Attacks", {
        "1": ("NTLM Relay", "ntlm/ntlm-ralay.py",
              ["ntlm-ralay", "NTLM Relay", "ntlmrelayx", "CoerceAndRelayNTLMToADCS",
               "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS",
               "CoerceAndRelayNTLMToSMB"]),
        "2": ("Authentication Coercion", "ntlm/coerce_auth.py",
              ["coerce_auth", "PetitPotam", "PrinterBug", "coercion", "force authentication",
               "CoerceAndRelayNTLMToADCS", "CoerceAndRelayNTLMToLDAP",
               "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToSMB"]),
    }),
    "7": ("Password Attacks", {
        "1": ("Force Change Password", "password_attacks/ForceChangePassword.py",
              ["ForceChangePassword", "change user password", "reset password",
               "AllExtendedRights", "GenericAll"]),
        "2": ("Password Spray", "password_attacks/PassworSpray.py",
              ["PassworSpray", "password spray", "spray attack"]),
        "3": ("Kerberos Ticket Brute-Force", "password_attacks/bruteforce-kerbros-tickets.py",
              ["bruteforce-kerbros-tickets", "brute force kerberos", "ticket bruteforce"]),
        "4": ("Change Default Password", "password_attacks/change-default-password.py",
              ["change-default-password", "default password", "default creds"]),
    }),
    "8": ("Privilege Escalation", {
        "1": ("ACL Takeover", "privilege_escalation/acl_takeover.py",
              ["acl_takeover", "acl abuse", "object takeover", "GenericAll", "Owns",
               "OwnsLimitedRights", "OwnsRaw", "WriteDacl", "WriteOwner",
               "WriteOwnerLimitedRights", "WriteOwnerRaw"]),
        "2": ("Group Abuse", "privilege_escalation/group_abuse.py",
              ["group_abuse", "group membership abuse", "AddMember", "AddSelf", "GenericAll",
               "WriteDacl"]),
    }),
    "9": ("Lateral Movement", {
        "1": ("Pass the Hash", "lateral_movement/PtH.py",
              ["PtH", "Pass the Hash", "NTLM hash auth", "AdminTo"]),
        "2": ("Pass the Ticket", "lateral_movement/PtT.py",
              ["PtT", "Pass the Ticket", "kerberos ticket reuse"]),
        "3": ("Token Impersonation Shell", "lateral_movement/Token_shell6.py",
              ["Token_shell6", "token impersonation", "ClaimSpecialIdentity", "HasSession"]),
        "4": ("Get Tokens (PowerShell)", "lateral_movement/get_tokens.ps1",
              ["get_tokens", "powershell tokens"]),
        "5": ("Lateral Movement Abuse", "lateral_movement/leteral_movement_abuse.py",
              ["leteral_movement_abuse", "remote execution", "session abuse", "AdminTo",
               "CanPSRemote", "CanRDP", "ClaimSpecialIdentity", "ExecuteDCOM", "HasSession",
               "RemoteInteractiveLogonRight", "SQLAdmin"]),
        "6": ("Overpass the Hash", "lateral_movement/opth.py",
              ["opth", "Overpass the Hash", "OPtH", "ntlm to kerberos", "AdminTo"]),
    }),
    "10": ("Trusts Abuse", {
        "1": ("GPO Abuse", "trusts/gpo_abuse.py",
              ["gpo_abuse", "Group Policy Object", "GPO", "GPLink"]),
        "2": ("Trust Abuse", "trusts/trust_abuse.py",
              ["trust_abuse", "cross domain", "cross forest", "trust attack",
               "CrossForestTrust", "HasTrustKeys", "SameForestTrust"]),
    }),
    "0": ("Exit", "exit"),
}


# ============================================================
#  KNOWLEDGE GRAPH: Edge → Modules mapping
# ============================================================

EDGE_TO_MODULES = {
    "GenericAll": [
        "enumeration/enum4AD.py",
        "kerberos/Shadow-credentials.py",
        "credential_access/Secrets_Dump.py",
        "credential_access/credential_access.py",
        "delegation/rbcd.py",
        "password_attacks/ForceChangePassword.py",
        "privilege_escalation/acl_takeover.py",
        "privilege_escalation/group_abuse.py",
        "kerberos/Golden-Ticket.py",
        "kerberos/Kerberoasting.py",
        "kerberos/Silver-Ticket.py",
        "adcs/ca_admin.py",
        "adcs/cert_enroll_abuse.py",
        "adcs/cert_template_abuse.py",
        "adcs/golden_cert.py",
        "lateral_movement/PtH.py",
        "lateral_movement/PtT.py",
        "lateral_movement/leteral_movement_abuse.py",
        "lateral_movement/opth.py",
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
        "delegation/KCD.py",
        "delegation/s4u.py",
        "trusts/gpo_abuse.py",
    ],
    "GenericWrite": [
        "kerberos/Shadow-credentials.py",
        "credential_access/credential_access.py",
        "delegation/rbcd.py",
        "kerberos/SPN.py",
        "kerberos/Kerberoasting.py",
        "adcs/cert_template_abuse.py",
        "password_attacks/ForceChangePassword.py",
        "privilege_escalation/acl_takeover.py",
        "trusts/gpo_abuse.py",
    ],
    "WriteDacl": [
        "privilege_escalation/acl_takeover.py",
        "privilege_escalation/group_abuse.py",
        "kerberos/Golden-Ticket.py",
        "credential_access/Secrets_Dump.py",
        "adcs/ca_admin.py",
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "WriteOwner": [
        "privilege_escalation/acl_takeover.py",
        "kerberos/Golden-Ticket.py",
        "credential_access/Secrets_Dump.py",
        "adcs/ca_admin.py",
        "adcs/golden_cert.py",
    ],
    "AdminTo": [
        "lateral_movement/PtH.py",
        "lateral_movement/PtT.py",
        "lateral_movement/leteral_movement_abuse.py",
        "lateral_movement/opth.py",
        "lateral_movement/Token_shell6.py",
        "kerberos/Golden-Ticket.py",
        "credential_access/Secrets_Dump.py",
    ],
    "DCSync": [
        "credential_access/Secrets_Dump.py",
        "kerberos/Golden-Ticket.py",
        "kerberos/Silver-Ticket.py",
        "kerberos/pac_manipulate.py",
        "lateral_movement/PtT.py",
        "lateral_movement/opth.py",
    ],
    "GetChanges": [
        "credential_access/Secrets_Dump.py",
        "kerberos/Golden-Ticket.py",
    ],
    "GetChangesAll": [
        "credential_access/Secrets_Dump.py",
        "kerberos/Golden-Ticket.py",
    ],
    "GetChangesInFilteredSet": [
        "credential_access/Secrets_Dump.py",
    ],
    "AllExtendedRights": [
        "credential_access/Secrets_Dump.py",
        "password_attacks/ForceChangePassword.py",
        "kerberos/Shadow-credentials.py",
        "kerberos/Golden-Ticket.py",
        "adcs/cert_enroll_abuse.py",
        "adcs/ca_admin.py",
    ],
    "AddMember": [
        "privilege_escalation/group_abuse.py",
        "kerberos/Golden-Ticket.py",
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "AddSelf": [
        "privilege_escalation/group_abuse.py",
        "kerberos/Golden-Ticket.py",
    ],
    "AllowedToDelegate": [
        "delegation/KCD.py",
        "delegation/s4u.py",
        "kerberos/Kerberoasting.py",
    ],
    "AllowedToAct": [
        "delegation/rbcd.py",
        "delegation/KCD.py",
        "delegation/s4u.py",
        "ntlm/ntlm-ralay.py",
    ],
    "AddAllowedToAct": [
        "delegation/rbcd.py",
    ],
    "WriteAccountRestrictions": [
        "delegation/rbcd.py",
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "ReadLAPSPassword": [
        "credential_access/credential_access.py",
        "lateral_movement/PtH.py",
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "ReadGMSAPassword": [
        "credential_access/credential_access.py",
        "lateral_movement/PtH.py",
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "SyncLAPSPassword": [
        "credential_access/credential_access.py",
    ],
    "DumpSMSAPassword": [
        "credential_access/credential_access.py",
    ],
    "HasSession": [
        "lateral_movement/Token_shell6.py",
        "lateral_movement/leteral_movement_abuse.py",
        "kerberos/intercept_kerberos_tickets.py",
    ],
    "CanPSRemote": [
        "lateral_movement/leteral_movement_abuse.py",
        "delegation/Kerberos_Delegation_Enumerator.py",
    ],
    "CanRDP": [
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "ExecuteDCOM": [
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "SQLAdmin": [
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "RemoteInteractiveLogonRight": [
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "ClaimSpecialIdentity": [
        "lateral_movement/Token_shell6.py",
        "lateral_movement/leteral_movement_abuse.py",
    ],
    "GPLink": [
        "trusts/gpo_abuse.py",
        "privilege_escalation/acl_takeover.py",
    ],
    "Owns": [
        "privilege_escalation/acl_takeover.py",
        "adcs/ca_admin.py",
        "adcs/golden_cert.py",
    ],
    "OwnsLimitedRights": [
        "privilege_escalation/acl_takeover.py",
    ],
    "OwnsRaw": [
        "privilege_escalation/acl_takeover.py",
    ],
    "WriteOwnerLimitedRights": [
        "privilege_escalation/acl_takeover.py",
    ],
    "WriteOwnerRaw": [
        "privilege_escalation/acl_takeover.py",
    ],
    "Enroll": [
        "adcs/cert_enroll_abuse.py",
        "adcs/cert_template_abuse.py",
    ],
    "EnrollOnBehalfOf": [
        "adcs/cert_enroll_abuse.py",
    ],
    "DelegatedEnrollmentAgent": [
        "adcs/cert_enroll_abuse.py",
    ],
    "ManageCA": [
        "adcs/ca_admin.py",
        "adcs/golden_cert.py",
    ],
    "ManageCertificates": [
        "adcs/ca_admin.py",
    ],
    "GoldenCert": [
        "adcs/golden_cert.py",
    ],
    "ADCSESC1": [
        "adcs/cert_enroll_abuse.py",
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC3": [
        "adcs/cert_enroll_abuse.py",
    ],
    "ADCSESC4": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC6a": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC6b": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC9a": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC9b": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC10a": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC10b": [
        "adcs/cert_template_abuse.py",
    ],
    "ADCSESC13": [
        "adcs/cert_template_abuse.py",
    ],
    "WritePKIEnrollmentFlag": [
        "adcs/cert_template_abuse.py",
    ],
    "WritePKINameFlag": [
        "adcs/cert_template_abuse.py",
    ],
    "AddKeyCredentialLink": [
        "kerberos/Shadow-credentials.py",
    ],
    "SpoofSIDHistory": [
        "kerberos/Golden-Ticket.py",
        "trusts/trust_abuse.py",
    ],
    "HasTrustKeys": [
        "trusts/trust_abuse.py",
    ],
    "CrossForestTrust": [
        "trusts/trust_abuse.py",
    ],
    "SameForestTrust": [
        "trusts/trust_abuse.py",
    ],
    "CoerceAndRelayNTLMToADCS": [
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "CoerceAndRelayNTLMToLDAP": [
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "CoerceAndRelayNTLMToLDAPS": [
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "CoerceAndRelayNTLMToSMB": [
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "ForceChangePassword": [
        "password_attacks/ForceChangePassword.py",
    ],
    "AS-REPRoasting": [
        "kerberos/AS-REPRoasting.py",
    ],
    "Kerberoasting": [
        "kerberos/Kerberoasting.py",
        "kerberos/SPN.py",
    ],
    "Golden-Ticket": [
        "kerberos/Golden-Ticket.py",
    ],
    "Silver-Ticket": [
        "kerberos/Silver-Ticket.py",
    ],
    "Shadow-credentials": [
        "kerberos/Shadow-credentials.py",
    ],
    "Pass-the-Hash": [
        "lateral_movement/PtH.py",
    ],
    "Pass-the-Ticket": [
        "lateral_movement/PtT.py",
    ],
    "Overpass-the-Hash": [
        "lateral_movement/opth.py",
    ],
    "Token-Impersonation": [
        "lateral_movement/Token_shell6.py",
    ],
    "RBCD": [
        "delegation/rbcd.py",
    ],
    "KCD": [
        "delegation/KCD.py",
    ],
    "S4U": [
        "delegation/s4u.py",
    ],
    "Unconstrained-Delegation": [
        "delegation/Kerberos_Delegation_Enumerator.py",
    ],
    "NTLM-Relay": [
        "ntlm/ntlm-ralay.py",
    ],
    "Auth-Coercion": [
        "ntlm/coerce_auth.py",
    ],
    "Password-Spray": [
        "password_attacks/PassworSpray.py",
    ],
    "Bruteforce-Kerberos": [
        "password_attacks/bruteforce-kerbros-tickets.py",
    ],
    "Default-Password": [
        "password_attacks/change-default-password.py",
    ],
    "DPAPI": [
        "credential_access/dpapi_decrypt.py",
    ],
    "Secrets-Dump": [
        "credential_access/Secrets_Dump.py",
    ],
    "LAPS": [
        "credential_access/credential_access.py",
    ],
    "GMSA": [
        "credential_access/credential_access.py",
    ],
    "SMSA": [
        "credential_access/credential_access.py",
    ],
    "GPO-Abuse": [
        "trusts/gpo_abuse.py",
    ],
    "Trust-Abuse": [
        "trusts/trust_abuse.py",
    ],
    "BloodHound": [
        "enumeration/enum4AD.py",
    ],
    "enum4AD": [
        "enumeration/enum4AD.py",
    ],
    "User-Enum": [
        "enumeration/kerberos_user_enum.py",
        "enumeration/Users-info.py",
    ],
    "Exploit-DB": [
        "enumeration/exploits-dbs.py",
    ],
    "PAC-Manipulation": [
        "kerberos/pac_manipulate.py",
    ],
    "Pass-the-Key": [
        "kerberos/pass_the_key.py",
    ],
    "Intercept-Tickets": [
        "kerberos/intercept_kerberos_tickets.py",
    ],
    "CA-Admin": [
        "adcs/ca_admin.py",
    ],
    "Cert-Enroll": [
        "adcs/cert_enroll_abuse.py",
    ],
    "Cert-Template": [
        "adcs/cert_template_abuse.py",
    ],
    "ACL-Takeover": [
        "privilege_escalation/acl_takeover.py",
    ],
    "Group-Abuse": [
        "privilege_escalation/group_abuse.py",
    ],
    "Lateral-Movement": [
        "lateral_movement/leteral_movement_abuse.py",
        "lateral_movement/PtH.py",
        "lateral_movement/PtT.py",
        "lateral_movement/opth.py",
        "lateral_movement/Token_shell6.py",
    ],
    "WriteSPN": [
        "kerberos/SPN.py",
        "kerberos/Kerberoasting.py",
    ],
    "HasSIDHistory": [
        "trusts/trust_abuse.py",
        "kerberos/Golden-Ticket.py",
    ],
    "Credential-Access": [
        "credential_access/Secrets_Dump.py",
        "credential_access/credential_access.py",
        "credential_access/dpapi_decrypt.py",
    ],
    "Delegation-Abuse": [
        "delegation/KCD.py",
        "delegation/Kerberos_Delegation_Enumerator.py",
        "delegation/rbcd.py",
        "delegation/s4u.py",
    ],
    "ADCS-Attacks": [
        "adcs/ca_admin.py",
        "adcs/cert_enroll_abuse.py",
        "adcs/cert_template_abuse.py",
        "adcs/golden_cert.py",
    ],
    "Privilege-Escalation": [
        "privilege_escalation/acl_takeover.py",
        "privilege_escalation/group_abuse.py",
    ],
    "Password-Attacks": [
        "password_attacks/ForceChangePassword.py",
        "password_attacks/PassworSpray.py",
        "password_attacks/bruteforce-kerbros-tickets.py",
        "password_attacks/change-default-password.py",
    ],
    "Enumeration-All": [
        "enumeration/kerberos_user_enum.py",
        "enumeration/Users-info.py",
        "enumeration/enum4AD.py",
        "enumeration/exploits-dbs.py",
    ],
    "Kerberos-Attacks-All": [
        "kerberos/AS-REPRoasting.py",
        "kerberos/Kerberoasting.py",
        "kerberos/Golden-Ticket.py",
        "kerberos/SPN.py",
        "kerberos/Shadow-credentials.py",
        "kerberos/Silver-Ticket.py",
        "kerberos/intercept_kerberos_tickets.py",
        "kerberos/pac_manipulate.py",
        "kerberos/pass_the_key.py",
    ],
    "NTLM-Attacks-All": [
        "ntlm/ntlm-ralay.py",
        "ntlm/coerce_auth.py",
    ],
    "Trusts-Abuse-All": [
        "trusts/gpo_abuse.py",
        "trusts/trust_abuse.py",
    ],
}


# ============================================================
#  ALIASES: Common aliases/misspellings → Edge
# ============================================================
ALIASES = {
    "genericall": "GenericAll",
    "generic all": "GenericAll",
    "genericwrite": "GenericWrite",
    "generic write": "GenericWrite",
    "writedacl": "WriteDacl",
    "write dacl": "WriteDacl",
    "writeowner": "WriteOwner",
    "write owner": "WriteOwner",
    "adminto": "AdminTo",
    "admin to": "AdminTo",
    "dcsync": "DCSync",
    "dc sync": "DCSync",
    "getchanges": "GetChanges",
    "get changes": "GetChanges",
    "getchangesall": "GetChangesAll",
    "get changes all": "GetChangesAll",
    "getchangesinfilteredset": "GetChangesInFilteredSet",
    "get changes in filtered set": "GetChangesInFilteredSet",
    "allextendedrights": "AllExtendedRights",
    "all extended rights": "AllExtendedRights",
    "addmember": "AddMember",
    "add member": "AddMember",
    "addself": "AddSelf",
    "add self": "AddSelf",
    "allowedtodelegate": "AllowedToDelegate",
    "allowed to delegate": "AllowedToDelegate",
    "allowedtoact": "AllowedToAct",
    "allowed to act": "AllowedToAct",
    "addallowedtoact": "AddAllowedToAct",
    "add allowed to act": "AddAllowedToAct",
    "writeaccountrestrictions": "WriteAccountRestrictions",
    "write account restrictions": "WriteAccountRestrictions",
    "readlapspassword": "ReadLAPSPassword",
    "read laps password": "ReadLAPSPassword",
    "readgmsapassword": "ReadGMSAPassword",
    "read gmsa password": "ReadGMSAPassword",
    "synclapspassword": "SyncLAPSPassword",
    "sync laps password": "SyncLAPSPassword",
    "dumpsmsapassword": "DumpSMSAPassword",
    "dump smsa password": "DumpSMSAPassword",
    "hassession": "HasSession",
    "has session": "HasSession",
    "canpsremote": "CanPSRemote",
    "can ps remote": "CanPSRemote",
    "canrdp": "CanRDP",
    "can rdp": "CanRDP",
    "executedcom": "ExecuteDCOM",
    "execute dcom": "ExecuteDCOM",
    "sqladmin": "SQLAdmin",
    "sql admin": "SQLAdmin",
    "remoteinteractivelogonright": "RemoteInteractiveLogonRight",
    "remote interactive logon right": "RemoteInteractiveLogonRight",
    "claimspecialidentity": "ClaimSpecialIdentity",
    "claim special identity": "ClaimSpecialIdentity",
    "gplink": "GPLink",
    "gp link": "GPLink",
    "owns": "Owns",
    "ownslimitedrights": "OwnsLimitedRights",
    "owns limited rights": "OwnsLimitedRights",
    "ownsraw": "OwnsRaw",
    "owns raw": "OwnsRaw",
    "writeownerlimitedrights": "WriteOwnerLimitedRights",
    "write owner limited rights": "WriteOwnerLimitedRights",
    "writeownerraw": "WriteOwnerRaw",
    "write owner raw": "WriteOwnerRaw",
    "enroll": "Enroll",
    "enrollonbehalfof": "EnrollOnBehalfOf",
    "enroll on behalf of": "EnrollOnBehalfOf",
    "delegatedenrollmentagent": "DelegatedEnrollmentAgent",
    "delegated enrollment agent": "DelegatedEnrollmentAgent",
    "manageca": "ManageCA",
    "manage ca": "ManageCA",
    "managecertificates": "ManageCertificates",
    "manage certificates": "ManageCertificates",
    "goldencert": "GoldenCert",
    "golden cert": "GoldenCert",
    "adcscesc1": "ADCSESC1",
    "esc1": "ADCSESC1",
    "adcscesc3": "ADCSESC3",
    "esc3": "ADCSESC3",
    "adcscesc4": "ADCSESC4",
    "esc4": "ADCSESC4",
    "adcscesc6a": "ADCSESC6a",
    "esc6": "ADCSESC6a",
    "adcscesc6b": "ADCSESC6b",
    "adcscesc9a": "ADCSESC9a",
    "esc9": "ADCSESC9a",
    "adcscesc9b": "ADCSESC9b",
    "adcscesc10a": "ADCSESC10a",
    "esc10": "ADCSESC10a",
    "adcscesc10b": "ADCSESC10b",
    "adcscesc13": "ADCSESC13",
    "esc13": "ADCSESC13",
    "writepkienrollmentflag": "WritePKIEnrollmentFlag",
    "write pki enrollment flag": "WritePKIEnrollmentFlag",
    "writepkinameflag": "WritePKINameFlag",
    "write pki name flag": "WritePKINameFlag",
    "addkeycredentiallink": "AddKeyCredentialLink",
    "add key credential link": "AddKeyCredentialLink",
    "spoofsidhistory": "SpoofSIDHistory",
    "spoof sid history": "SpoofSIDHistory",
    "hassidhistory": "HasSIDHistory",
    "has sid history": "HasSIDHistory",
    "sid history": "HasSIDHistory",
    "hastrustkeys": "HasTrustKeys",
    "has trust keys": "HasTrustKeys",
    "crossforesttrust": "CrossForestTrust",
    "cross forest trust": "CrossForestTrust",
    "sameforesttrust": "SameForestTrust",
    "same forest trust": "SameForestTrust",
    "coerceandrelayntlmtoadcs": "CoerceAndRelayNTLMToADCS",
    "coerce and relay ntlm to adcs": "CoerceAndRelayNTLMToADCS",
    "coerceandrelayntlmtoldap": "CoerceAndRelayNTLMToLDAP",
    "coerce and relay ntlm to ldap": "CoerceAndRelayNTLMToLDAP",
    "coerceandrelayntlmtoLdaps": "CoerceAndRelayNTLMToLDAPS",
    "coerce and relay ntlm to ldaps": "CoerceAndRelayNTLMToLDAPS",
    "coerceandrelayntlmtosmb": "CoerceAndRelayNTLMToSMB",
    "coerce and relay ntlm to smb": "CoerceAndRelayNTLMToSMB",
    "forcechangepassword": "ForceChangePassword",
    "force change password": "ForceChangePassword",
    "change password": "ForceChangePassword",
    "asreproasting": "AS-REPRoasting",
    "as-rep roasting": "AS-REPRoasting",
    "asrep": "AS-REPRoasting",
    "as-rep": "AS-REPRoasting",
    "kerberoasting": "Kerberoasting",
    "kerberoast": "Kerberoasting",
    "goldenticket": "Golden-Ticket",
    "golden ticket": "Golden-Ticket",
    "gt": "Golden-Ticket",
    "silverticket": "Silver-Ticket",
    "silver ticket": "Silver-Ticket",
    "st": "Silver-Ticket",
    "shadowcredentials": "Shadow-credentials",
    "shadow credentials": "Shadow-credentials",
    "shadow cred": "Shadow-credentials",
    "pth": "Pass-the-Hash",
    "pass the hash": "Pass-the-Hash",
    "passthehash": "Pass-the-Hash",
    "ptt": "Pass-the-Ticket",
    "pass the ticket": "Pass-the-Ticket",
    "passtheticket": "Pass-the-Ticket",
    "opth": "Overpass-the-Hash",
    "overpass": "Overpass-the-Hash",
    "overpass the hash": "Overpass-the-Hash",
    "overpassthehash": "Overpass-the-Hash",
    "tokenimpersonation": "Token-Impersonation",
    "token impersonation": "Token-Impersonation",
    "rbcd": "RBCD",
    "resource based constrained delegation": "RBCD",
    "resource-based constrained delegation": "RBCD",
    "kcd": "KCD",
    "constrained delegation": "KCD",
    "s4u": "S4U",
    "s4u2self": "S4U",
    "s4u2proxy": "S4U",
    "unconstrained delegation": "Unconstrained-Delegation",
    "unconstraineddelegation": "Unconstrained-Delegation",
    "ntlmrelay": "NTLM-Relay",
    "ntlm relay": "NTLM-Relay",
    "ntlm-ralay": "NTLM-Relay",
    "authcoercion": "Auth-Coercion",
    "auth coercion": "Auth-Coercion",
    "authentication coercion": "Auth-Coercion",
    "petitpotam": "Auth-Coercion",
    "printerbug": "Auth-Coercion",
    "printer bug": "Auth-Coercion",
    "passwordspray": "Password-Spray",
    "password spray": "Password-Spray",
    "spray": "Password-Spray",
    "bruteforce": "Bruteforce-Kerberos",
    "brute force": "Bruteforce-Kerberos",
    "brute force kerberos": "Bruteforce-Kerberos",
    "defaultpassword": "Default-Password",
    "default password": "Default-Password",
    "default creds": "Default-Password",
    "dpapi": "DPAPI",
    "secretsdump": "Secrets-Dump",
    "secrets dump": "Secrets-Dump",
    "laps": "LAPS",
    "gmsa": "GMSA",
    "smsa": "SMSA",
    "gpo": "GPO-Abuse",
    "gpo abuse": "GPO-Abuse",
    "trust": "Trust-Abuse",
    "trust abuse": "Trust-Abuse",
    "cross domain": "Trust-Abuse",
    "cross forest": "Trust-Abuse",
    "bloodhound": "BloodHound",
    "enum4ad": "enum4AD",
    "user enum": "User-Enum",
    "userenum": "User-Enum",
    "users info": "User-Enum",
    "users-info": "User-Enum",
    "exploitdb": "Exploit-DB",
    "exploit db": "Exploit-DB",
    "exploits-dbs": "Exploit-DB",
    "pac": "PAC-Manipulation",
    "pac manipulation": "PAC-Manipulation",
    "ms14-068": "PAC-Manipulation",
    "ms14_068": "PAC-Manipulation",
    "ptk": "Pass-the-Key",
    "pass the key": "Pass-the-Key",
    "passthekey": "Pass-the-Key",
    "intercept": "Intercept-Tickets",
    "intercept tickets": "Intercept-Tickets",
    "ticket interception": "Intercept-Tickets",
    "caadmin": "CA-Admin",
    "ca admin": "CA-Admin",
    "certenroll": "Cert-Enroll",
    "cert enroll": "Cert-Enroll",
    "certtemplate": "Cert-Template",
    "cert template": "Cert-Template",
    "acltakeover": "ACL-Takeover",
    "acl takeover": "ACL-Takeover",
    "acl abuse": "ACL-Takeover",
    "groupabuse": "Group-Abuse",
    "group abuse": "Group-Abuse",
    "group membership abuse": "Group-Abuse",
    "lateralmovement": "Lateral-Movement",
    "lateral movement": "Lateral-Movement",
    "remote execution": "Lateral-Movement",
    "session abuse": "Lateral-Movement",
    "writespen": "WriteSPN",
    "write spn": "WriteSPN",
    "krbtgt": "Golden-Ticket",
    "tgt": "Golden-Ticket",
    "service ticket": "Silver-Ticket",
    "forged ticket": "Golden-Ticket",
    "dcsync laugh": "Secrets-Dump",
    "secrets dump laugh": "Secrets-Dump",
    "credential access": "Credential-Access",
    "credentialaccess": "Credential-Access",
    "delegation": "Delegation-Abuse",
    "delegation abuse": "Delegation-Abuse",
    "adcs": "ADCS-Attacks",
    "adcs attacks": "ADCS-Attacks",
    "certificate": "ADCS-Attacks",
    "certificate abuse": "ADCS-Attacks",
    "privesc": "Privilege-Escalation",
    "privilege escalation": "Privilege-Escalation",
    "privilegeescalation": "Privilege-Escalation",
    "laps gmsa smsa": "Credential-Access",
    "laps gmsa": "Credential-Access",
    "preauth": "AS-REPRoasting",
    "no preauth": "AS-REPRoasting",
    "spn": "Kerberoasting",
    "spn scan": "Kerberoasting",
    "service principal name": "Kerberoasting",
    "targeted kerberoasting": "Kerberoasting",
    "pkinit": "Shadow-credentials",
    "key credential link": "Shadow-credentials",
    "msds-keycredentiallink": "Shadow-credentials",
    "relay": "NTLM-Relay",
    "coerce": "Auth-Coercion",
    "coercion": "Auth-Coercion",
    "force authentication": "Auth-Coercion",
    "reset password": "ForceChangePassword",
    "change user password": "ForceChangePassword",
    "object takeover": "ACL-Takeover",
    "takeover": "ACL-Takeover",
    "domain admins": "Golden-Ticket",
    "enterprise admins": "Golden-Ticket",
    "domain controller": "Golden-Ticket",
    "ntds": "Secrets-Dump",
    "ntds.dit": "Secrets-Dump",
    "sam": "Secrets-Dump",
    "lsa": "Secrets-Dump",
    "masterkey": "DPAPI",
    "credential vault": "DPAPI",
    "vault": "DPAPI",
    "forge certificate": "GoldenCert",
    "ca private key": "GoldenCert",
    "san": "Cert-Template",
    "san injection": "Cert-Template",
    "template misconfiguration": "Cert-Template",
    "weak certificate": "Cert-Template",
    "enroll on behalf": "Cert-Enroll",
    "ca takeover": "CA-Admin",
    "certificate authority": "CA-Admin",
    "cross domain trust": "Trust-Abuse",
    "intra forest": "Trust-Abuse",
    "inter forest": "Trust-Abuse",
    "group policy": "GPO-Abuse",
    "gpo abuse": "GPO-Abuse",
    "gplink abuse": "GPO-Abuse",
    "enum": "Enumeration-All",
    "recon": "Enumeration-All",
    "reconnaissance": "Enumeration-All",
    "ad recon": "Enumeration-All",
    "ldap enum": "Enumeration-All",
    "user enumeration": "User-Enum",
    "enumerate users": "User-Enum",
    "exploit search": "Exploit-DB",
    "searchsploit": "Exploit-DB",
    "cve": "Exploit-DB",
    "ticket interception": "Intercept-Tickets",
    "sniff tickets": "Intercept-Tickets",
    "as-req key": "Pass-the-Key",
    "s4u abuse": "S4U",
    "find delegation": "Unconstrained-Delegation",
    "delegation enum": "Unconstrained-Delegation",
    "ntlm to kerberos": "Overpass-the-Hash",
    "ntlm hash auth": "Pass-the-Hash",
    "kerberos ticket reuse": "Pass-the-Ticket",
    "powershell tokens": "Token-Impersonation",
    "get tokens": "Token-Impersonation",
    "winrm": "CanPSRemote",
    "remote management": "CanPSRemote",
    "remote desktop protocol": "CanRDP",
    "dcom remote": "ExecuteDCOM",
    "mssql": "SQLAdmin",
    "sql server": "SQLAdmin",
    "interactive remote": "RemoteInteractiveLogonRight",
    "special id": "ClaimSpecialIdentity",
    "gpo object": "GPO-Abuse",
    "policy abuse": "GPO-Abuse",
    "trust keys abuse": "HasTrustKeys",
    "forest abuse": "Trust-Abuse",
    "cross abuse": "Trust-Abuse",
    "cert authority": "CA-Admin",
    "pki abuse": "ADCS-Attacks",
    "pki attack": "ADCS-Attacks",
    "template pki": "Cert-Template",
    "enroll pki": "Cert-Enroll",
    "cert golden attack": "GoldenCert",
    "privilege acl abuse": "ACL-Takeover",
    "privilege group abuse": "Group-Abuse",
    "move hash": "Pass-the-Hash",
    "move ticket": "Pass-the-Ticket",
    "move token": "Token-Impersonation",
    "move overpass": "Overpass-the-Hash",
    "reset user password": "ForceChangePassword",
    "change password force": "ForceChangePassword",
    "force user password": "ForceChangePassword",
    "spray active directory": "Password-Spray",
    "ad spray": "Password-Spray",
    "brute force ad": "Bruteforce-Kerberos",
    "ad brute": "Bruteforce-Kerberos",
    "default ad password": "Default-Password",
    "ad default creds": "Default-Password",
    "bloodhound ad": "BloodHound",
    "ad bloodhound": "BloodHound",
    "enum ad domain": "BloodHound",
    "ad domain enum": "BloodHound",
    "user ad enum": "User-Enum",
    "ad user enum": "User-Enum",
    "exploit ad": "Exploit-DB",
    "ad exploit": "Exploit-DB",
    "pac ad": "PAC-Manipulation",
    "ad pac": "PAC-Manipulation",
    "key ad pass": "Pass-the-Key",
    "ad key pass": "Pass-the-Key",
    "ticket ad intercept": "Intercept-Tickets",
    "ad ticket intercept": "Intercept-Tickets",
    "s4u ad": "S4U",
    "ad s4u": "S4U",
    "delegation ad": "Delegation-Abuse",
    "ad delegation": "Delegation-Abuse",
    "find ad delegation": "Unconstrained-Delegation",
    "ad unconstrained": "Unconstrained-Delegation",
    "overpass ad": "Overpass-the-Hash",
    "ad overpass": "Overpass-the-Hash",
    "pth ad": "Pass-the-Hash",
    "ad pth": "Pass-the-Hash",
    "ptt ad": "Pass-the-Ticket",
    "ad ptt": "Pass-the-Ticket",
    "token ad": "Token-Impersonation",
    "ad token": "Token-Impersonation",
    "psremote ad": "CanPSRemote",
    "ad psremote": "CanPSRemote",
    "rdp ad": "CanRDP",
    "ad rdp": "CanRDP",
    "dcom ad": "ExecuteDCOM",
    "ad dcom": "ExecuteDCOM",
    "sql ad": "SQLAdmin",
    "ad sql": "SQLAdmin",
    "interactive ad": "RemoteInteractiveLogonRight",
    "ad interactive": "RemoteInteractiveLogonRight",
    "claim ad": "ClaimSpecialIdentity",
    "ad claim": "ClaimSpecialIdentity",
    "gpo ad": "GPO-Abuse",
    "ad gpo": "GPO-Abuse",
    "trust ad": "Trust-Abuse",
    "ad trust": "Trust-Abuse",
    "ca ad": "CA-Admin",
    "ad ca": "CA-Admin",
    "cert ad": "ADCS-Attacks",
    "ad cert": "ADCS-Attacks",
    "template ad": "Cert-Template",
    "ad template": "Cert-Template",
    "enroll ad": "Cert-Enroll",
    "ad enroll": "Cert-Enroll",
    "golden ad": "GoldenCert",
    "ad golden": "GoldenCert",
    "acl ad": "ACL-Takeover",
    "ad acl": "ACL-Takeover",
    "group ad": "Group-Abuse",
    "ad group": "Group-Abuse",
    "lateral ad": "Lateral-Movement",
    "ad lateral": "Lateral-Movement",
    "password ad": "Password-Attacks",
    "ad password": "Password-Attacks",
    "cred ad": "Credential-Access",
    "ad cred": "Credential-Access",
    "secrets ad": "Secrets-Dump",
    "ad secrets": "Secrets-Dump",
    "dpapi ad": "DPAPI",
    "ad dpapi": "DPAPI",
    "laps ad": "LAPS",
    "ad laps": "LAPS",
    "gmsa ad": "GMSA",
    "ad gmsa": "GMSA",
    "smsa ad": "SMSA",
    "ad smsa": "SMSA",
    "enum ad users": "User-Enum",
    "ad users enum": "User-Enum",
    "ad user info": "User-Enum",
    "user info ad": "User-Enum",
    "exploit db ad": "Exploit-DB",
    "ad exploit db": "Exploit-DB",
    "pac manipulation ad": "PAC-Manipulation",
    "ad pac manipulation": "PAC-Manipulation",
    "key pass ad": "Pass-the-Key",
    "ad key pass": "Pass-the-Key",
    "intercept ad tickets": "Intercept-Tickets",
    "ad intercept tickets": "Intercept-Tickets",
    "s4u ad abuse": "S4U",
    "ad s4u abuse": "S4U",
    "delegation ad abuse": "Delegation-Abuse",
    "ad delegation abuse": "Delegation-Abuse",
    "find ad unconstrained": "Unconstrained-Delegation",
    "ad find unconstrained": "Unconstrained-Delegation",
    "overpass ad hash": "Overpass-the-Hash",
    "ad overpass hash": "Overpass-the-Hash",
    "pth ad attack": "Pass-the-Hash",
    "ad pth attack": "Pass-the-Hash",
    "ptt ad attack": "Pass-the-Ticket",
    "ad ptt attack": "Pass-the-Ticket",
    "token ad attack": "Token-Impersonation",
    "ad token attack": "Token-Impersonation",
    "psremote ad attack": "CanPSRemote",
    "ad psremote attack": "CanPSRemote",
    "rdp ad attack": "CanRDP",
    "ad rdp attack": "CanRDP",
    "dcom ad attack": "ExecuteDCOM",
    "ad dcom attack": "ExecuteDCOM",
    "sql ad attack": "SQLAdmin",
    "ad sql attack": "SQLAdmin",
    "interactive ad attack": "RemoteInteractiveLogonRight",
    "ad interactive attack": "RemoteInteractiveLogonRight",
    "claim ad attack": "ClaimSpecialIdentity",
    "ad claim attack": "ClaimSpecialIdentity",
    "gpo ad attack": "GPO-Abuse",
    "ad gpo attack": "GPO-Abuse",
    "trust ad attack": "Trust-Abuse",
    "ad trust attack": "Trust-Abuse",
    "ca ad attack": "CA-Admin",
    "ad ca attack": "CA-Admin",
    "cert ad attack": "ADCS-Attacks",
    "ad cert attack": "ADCS-Attacks",
    "template ad attack": "Cert-Template",
    "ad template attack": "Cert-Template",
    "enroll ad attack": "Cert-Enroll",
    "ad enroll attack": "Cert-Enroll",
    "golden ad attack": "GoldenCert",
    "ad golden attack": "GoldenCert",
    "acl ad attack": "ACL-Takeover",
    "ad acl attack": "ACL-Takeover",
    "group ad attack": "Group-Abuse",
    "ad group attack": "Group-Abuse",
    "lateral ad attack": "Lateral-Movement",
    "ad lateral attack": "Lateral-Movement",
    "password ad attack": "Password-Attacks",
    "ad password attack": "Password-Attacks",
    "cred ad attack": "Credential-Access",
    "ad cred attack": "Credential-Access",
    "secrets ad attack": "Secrets-Dump",
    "ad secrets attack": "Secrets-Dump",
    "dpapi ad attack": "DPAPI",
    "ad dpapi attack": "DPAPI",
    "laps ad attack": "LAPS",
    "ad laps attack": "LAPS",
    "gmsa ad attack": "GMSA",
    "ad gmsa attack": "GMSA",
    "smsa ad attack": "SMSA",
    "ad smsa attack": "SMSA",
    "enumeration all": "Enumeration-All",
    "enum all": "Enumeration-All",
    "recon all": "Enumeration-All",
    "kerberos all": "Kerberos-Attacks-All",
    "kerb all": "Kerberos-Attacks-All",
    "ntlm all": "NTLM-Attacks-All",
    "trusts all": "Trusts-Abuse-All",
    "trust all": "Trusts-Abuse-All",
    "all enumeration": "Enumeration-All",
    "all enum": "Enumeration-All",
    "all recon": "Enumeration-All",
    "all kerberos": "Kerberos-Attacks-All",
    "all kerb": "Kerberos-Attacks-All",
    "all ntlm": "NTLM-Attacks-All",
    "all trusts": "Trusts-Abuse-All",
    "all trust": "Trusts-Abuse-All",
    "all lateral": "Lateral-Movement",
    "all privilege": "Privilege-Escalation",
    "all password": "Password-Attacks",
    "all credential": "Credential-Access",
    "all delegation": "Delegation-Abuse",
    "all adcs": "ADCS-Attacks",
    "all acl": "ACL-Takeover",
    "all group": "Group-Abuse",
    "all cert": "ADCS-Attacks",
    "all ca": "CA-Admin",
    "all template": "Cert-Template",
    "all enroll": "Cert-Enroll",
    "all golden": "GoldenCert",
    "all gpo": "GPO-Abuse",
    "all exploit": "Exploit-DB",
    "all user": "User-Enum",
    "all bloodhound": "BloodHound",
    "all pac": "PAC-Manipulation",
    "all key": "Pass-the-Key",
    "all intercept": "Intercept-Tickets",
    "all s4u": "S4U",
    "all rbcd": "RBCD",
    "all kcd": "KCD",
    "all unconstrained": "Unconstrained-Delegation",
    "all overpass": "Overpass-the-Hash",
    "all pth": "Pass-the-Hash",
    "all ptt": "Pass-the-Ticket",
    "all token": "Token-Impersonation",
    "all psremote": "CanPSRemote",
    "all rdp": "CanRDP",
    "all dcom": "ExecuteDCOM",
    "all sql": "SQLAdmin",
    "all interactive": "RemoteInteractiveLogonRight",
    "all claim": "ClaimSpecialIdentity",
    "all gplink": "GPLink",
    "all owns": "Owns",
    "all enroll": "Enroll",
    "all enrollonbehalfof": "EnrollOnBehalfOf",
    "all delegated": "DelegatedEnrollmentAgent",
    "all manageca": "ManageCA",
    "all managecert": "ManageCertificates",
    "all esc1": "ADCSESC1",
    "all esc3": "ADCSESC3",
    "all esc4": "ADCSESC4",
    "all esc6": "ADCSESC6a",
    "all esc9": "ADCSESC9a",
    "all esc10": "ADCSESC10a",
    "all esc13": "ADCSESC13",
    "all writepki": "WritePKIEnrollmentFlag",
    "all writepkiname": "WritePKINameFlag",
    "all addkey": "AddKeyCredentialLink",
    "all spoof": "SpoofSIDHistory",
    "all hastrust": "HasTrustKeys",
    "all crossforest": "CrossForestTrust",
    "all sameforest": "SameForestTrust",
    "all coerceadcs": "CoerceAndRelayNTLMToADCS",
    "all coerceldap": "CoerceAndRelayNTLMToLDAP",
    "all coerceldaps": "CoerceAndRelayNTLMToLDAPS",
    "all coercesmb": "CoerceAndRelayNTLMToSMB",
    "all forcechange": "ForceChangePassword",
    "all asrep": "AS-REPRoasting",
    "all kerberoast": "Kerberoasting",
    "all goldenticket": "Golden-Ticket",
    "all silverticket": "Silver-Ticket",
    "all shadow": "Shadow-credentials",
    "all passthehash": "Pass-the-Hash",
    "all passtheticket": "Pass-the-Ticket",
    "all overpassthehash": "Overpass-the-Hash",
    "all tokenimpersonation": "Token-Impersonation",
    "all rbcd": "RBCD",
    "all kcd": "KCD",
    "all s4u": "S4U",
    "all unconstrained": "Unconstrained-Delegation",
    "all ntlmrelay": "NTLM-Relay",
    "all authcoercion": "Auth-Coercion",
    "all password spray": "Password-Spray",
    "all bruteforce": "Bruteforce-Kerberos",
    "all defaultpassword": "Default-Password",
    "all dpapi": "DPAPI",
    "all secretsdump": "Secrets-Dump",
    "all laps": "LAPS",
    "all gmsa": "GMSA",
    "all smsa": "SMSA",
    "all gpo": "GPO-Abuse",
    "all trust": "Trust-Abuse",
    "all bloodhound": "BloodHound",
    "all enum4ad": "enum4AD",
    "all userenum": "User-Enum",
    "all exploitdb": "Exploit-DB",
    "all pac": "PAC-Manipulation",
    "all passthekey": "Pass-the-Key",
    "all intercept": "Intercept-Tickets",
    "all caadmin": "CA-Admin",
    "all certenroll": "Cert-Enroll",
    "all certtemplate": "Cert-Template",
    "all acltakeover": "ACL-Takeover",
    "all groupabuse": "Group-Abuse",
    "all lateralmovement": "Lateral-Movement",
    "all writespen": "WriteSPN",
    "all hassidhistory": "HasSIDHistory",
    "all credentialaccess": "Credential-Access",
    "all delegationabuse": "Delegation-Abuse",
    "all adcsattacks": "ADCS-Attacks",
    "all privilegeescalation": "Privilege-Escalation",
    "all passwordattacks": "Password-Attacks",
}


# ============================================================
#  REVERSE LOOKUP: Build path → module info from categories
# ============================================================

def build_module_index():
    index = {}
    for cat_id, (cat_title, modules) in categories.items():
        if cat_id == "0":
            continue
        for mod_id, mod_data in modules.items():
            mod_title, mod_path, keywords = mod_data
            index[mod_path] = (cat_id, cat_title, mod_id, mod_title, keywords)
    return index


MODULE_INDEX = build_module_index()


# ============================================================
#  NEW SEARCH ENGINE (Graph-Based + Fuzzy + Aliases)
# ============================================================

def search_modules(query):
    query = query.strip().lower()
    results = []
    if not query:
        return results

    matched_edges = set()

    # --- Stage 1: Exact Edge Match (Graph Lookup) ---
    for edge, paths in EDGE_TO_MODULES.items():
        if query == edge.lower():
            matched_edges.add(edge)
            for path in paths:
                if path in MODULE_INDEX:
                    cat_id, cat_title, mod_id, mod_title, _ = MODULE_INDEX[path]
                    if not any(r[4] == path for r in results):
                        results.append((cat_id, cat_title, mod_id, mod_title, path))

    # --- Stage 2: Partial Edge Match ---
    for edge, paths in EDGE_TO_MODULES.items():
        if query in edge.lower() and edge.lower() not in matched_edges:
            matched_edges.add(edge)
            for path in paths:
                if path in MODULE_INDEX:
                    cat_id, cat_title, mod_id, mod_title, _ = MODULE_INDEX[path]
                    if not any(r[4] == path for r in results):
                        results.append((cat_id, cat_title, mod_id, mod_title, path))

    # --- Stage 3: Alias Resolution ---
    for alias, edge in ALIASES.items():
        if query == alias or query.startswith(alias):
            if edge in EDGE_TO_MODULES:
                matched_edges.add(edge)
                for path in EDGE_TO_MODULES[edge]:
                    if path in MODULE_INDEX:
                        cat_id, cat_title, mod_id, mod_title, _ = MODULE_INDEX[path]
                        if not any(r[4] == path for r in results):
                            results.append((cat_id, cat_title, mod_id, mod_title, path))

    # --- Stage 4: Substring Match in titles, paths, and keywords ---
    for cat_id, (cat_title, modules) in categories.items():
        if cat_id == "0":
            continue
        for mod_id, mod_data in modules.items():
            mod_title, mod_path, keywords = mod_data
            haystack = (mod_title + " " + mod_path + " " + " ".join(keywords)).lower()
            if query in haystack:
                if not any(r[4] == mod_path for r in results):
                    results.append((cat_id, cat_title, mod_id, mod_title, mod_path))

    # --- Stage 5: Category-wide search ---
    category_aliases = {
        "enumeration": "1", "enum": "1", "recon": "1",
        "kerberos": "2", "kerb": "2",
        "credential": "3", "cred": "3", "secrets": "3", "dpapi": "3", "laps": "3", "gmsa": "3", "smsa": "3",
        "delegation": "4", "delegate": "4",
        "adcs": "5", "certificate": "5", "cert": "5", "pki": "5", "ca": "5",
        "ntlm": "6", "relay": "6", "coerce": "6",
        "password": "7", "pass": "7", "spray": "7", "brute": "7",
        "privilege": "8", "privesc": "8", "escalation": "8", "acl": "8", "group": "8",
        "lateral": "9", "movement": "9", "pth": "9", "ptt": "9", "opth": "9", "token": "9",
        "trust": "10", "gpo": "10", "forest": "10", "cross": "10",
    }
    for alias, cat_id in category_aliases.items():
        if query == alias or query.startswith(alias):
            if cat_id in categories and cat_id != "0":
                cat_title, modules = categories[cat_id]
                for mod_id, mod_data in modules.items():
                    mod_title, mod_path, keywords = mod_data
                    if not any(r[4] == mod_path for r in results):
                        results.append((cat_id, cat_title, mod_id, mod_title, mod_path))

    return results


# ============================================================
#  SEARCH MENU
# ============================================================
def search_menu():
    while True:
        banner()
        print(f"{C}[+] Search Mode → Type a keyword (e.g. 'GenericAll', 'DCSync', 'ESC1'){E}")
        print(f"{R}    Type 0 to go back to main menu{E}\n")
        query = input(f"{P}[🔍] Search → {E}")

        if query.strip() == "0":
            return

        if not query.strip():
            continue

        results = search_modules(query)

        banner()
        if not results:
            print(f"{R}[!] No modules matched '{query}'... try another keyword!{E}")
            input(f"\n{G}Press Enter to search again...{E}")
            continue

        print(f"{C}[+] Found {len(results)} module(s) matching '{query}':\n{E}")
        for idx, (cat_id, cat_title, mod_id, mod_title, mod_path) in enumerate(results, start=1):
            print(f"{Y}{idx}){E}  [{C}{cat_title}{E}]  {mod_title}")
        print(f"{R}0){E}  Back to search")
        print()

        choice = input(f"{P}[🤡] Number → {E}")

        if choice == "0":
            continue

        try:
            sel_idx = int(choice) - 1
            if sel_idx < 0 or sel_idx >= len(results):
                raise ValueError
        except ValueError:
            print(f"{R}[!] Why so serious? Wrong number!{E}")
            time.sleep(2)
            continue

        _, _, _, _, mod_path = results[sel_idx]
        run_script(mod_path)
        input(f"\n{G}Press Enter to continue the chaos...{E}")


def run_script(rel_path):
    script_path = str(BASE_DIR / rel_path)
    if os.path.exists(script_path):
        if script_path.endswith(".ps1"):
            os.system(f'pwsh "{script_path}"')
        else:
            os.system(f'python3 "{script_path}"')
    else:
        print(f"{R}[!] Script not found yet... still writing the joke!{E}")


# ============================================================
#  MAIN MENU
# ============================================================
def menu():
    while True:
        banner()
        print(f"{C}[+] Choose your poison, sweetheart:\n{E}")
        for k, v in categories.items():
            if k == "0":
                continue
            print(f"{Y}{k}){E}  {v[0]}")
        print(f"{B}S){E}  🔍 Search by keyword (e.g. GenericAll, DCSync, ESC1...)")
        print(f"{R}0){E}  Exit")
        print()
        choice = input(f"{P}[🤡] Number → {E}")

        if choice == "0":
            print(f"{R}Bye bye, Batsy... We live in a society!{E}")
            sys.exit(0)

        if choice.lower() == "s":
            search_menu()
            continue

        if choice not in categories or choice == "0":
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
            run_script(attacks[choice][1])
            input(f"\n{G}Press Enter to continue the chaos...{E}")
        else:
            print(f"{R}[!] Why so serious? Wrong number!{E}")
            time.sleep(2)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{R}Catch you later, Batman! 🤡{E}")
