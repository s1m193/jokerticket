import sys
import re
import socket
import signal
import ssl
import logging
from colorama import Fore, Style, init
from ldap3 import Server, Connection, ALL, SIMPLE, MODIFY_DELETE, MODIFY_ADD, Tls
from ldap3.core.exceptions import LDAPConstraintViolationResult, LDAPInvalidCredentialsResult

init(autoreset=True)

def signal_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Process interrupted. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class JokerResetter:
    def __init__(self, debug=False):
        self.target_ip = ""
        self.domain = ""
        self.username = ""
        self.old_password = ""
        self.new_password = ""
        self.debug = debug
        self.setup_logging()
        
        self.banner = Fore.RED + r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║        🃏  JOKER PASSWORD RESETTER (JPR)    🃏            ║
    ║      Target: AD Users with 'Must Change Password'         ║ 
    ╚═══════════════════════════════════════════════════════════╝
    """

    def setup_logging(self):
        if self.debug:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        else:
            logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

    def validate_ip(self, ip):
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(ip):
            return False, "Invalid IP format."
        try:
            socket.create_connection((ip, 389), timeout=1)
            return True, ""
        except:
            return False, "DC unreachable on port 389"

    def encode_ldap_password(self, password):
        return f'"{password}"'.encode("utf-16-le")

    def get_input(self, prompt_text, validation_func=None, is_password=False):
        while True:
            try:
                if is_password:
                    import getpass
                    user_input = getpass.getpass(Fore.BLUE + f"[?] {prompt_text}: " + Style.RESET_ALL)
                else:
                    user_input = input(Fore.BLUE + f"[?] {prompt_text}: " + Style.RESET_ALL).strip()
                
                if not user_input and not is_password:
                    continue
                if validation_func:
                    is_valid, error_msg = validation_func(user_input)
                    if not is_valid:
                        print(Fore.RED + f"[-] {error_msg}")
                        continue
                return user_input
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)

    def find_target_dn(self, conn, target_username, target_domain):
        domain_dn = ",".join([f"dc={p}" for p in target_domain.split('.')])
        
        logging.debug(f"Searching for sAMAccountName={target_username} in {domain_dn}")
        
        try:
            conn.search(
                search_base=domain_dn,
                search_filter=f'(sAMAccountName={target_username})',
                attributes=['distinguishedName']
            )
            
            for entry in conn.entries:
                if hasattr(entry, 'entry_dn'):
                    logging.debug(f"Found DN: {entry.entry_dn}")
                    return entry.entry_dn
        except Exception as e:
            logging.debug(f"Search failed: {e}")
        
        logging.debug(f"Constructing DN: cn={target_username},cn=users,{domain_dn}")
        return f"cn={target_username},cn=users,{domain_dn}"

    def change_password_kpasswd(self):
        logging.info("Attempting password change via Kerberos Kpasswd (port 464)")
        
        try:
            from impacket.krb5 import kerberosv5, kpasswd
            
            logging.debug(f"Calling kpasswd.changePassword for {self.username}@{self.domain}")
            
            kpasswd.changePassword(
                self.username,
                self.domain,
                self.new_password,
                self.old_password,
                "",
                "",
                kdcHost=self.target_ip
            )
            
            logging.info("Password changed successfully via Kerberos Kpasswd")
            return True
            
        except ImportError as e:
            logging.error(f"Impacket module not available: {e}")
            return False
        except kerberosv5.KerberosError as e:
            if "Password must change" in str(e):
                logging.warning("Kerberos requires password change - trying alternative method")
            else:
                logging.error(f"Kerberos error: {e}")
            return False
        except Exception as e:
            logging.error(f"Kpasswd failed: {e}")
            return False

    def change_password_samr_anonymous(self):
        logging.info("Attempting password change via SAMR with anonymous bind (NULL session)")
        
        try:
            from impacket.dcerpc.v5 import transport, samr
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            
            logging.debug("Creating anonymous SMB connection to IPC$")
            
            string_binding = f"ncacn_np:{self.target_ip}[\\pipe\\samr]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(self.target_ip)
            rpctransport.set_credentials("", "", "", "", "")
            rpctransport.set_kerberos(False, None)
            
            logging.debug("Attempting anonymous DCE/RPC bind")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            logging.debug("Calling SamrUnicodeChangePasswordUser2 with NULL session")
            
            resp = samr.hSamrUnicodeChangePasswordUser2(
                dce,
                self.target_ip + "\x00",
                self.username,
                self.old_password,
                self.new_password,
                "",
                ""
            )
            
            if resp['ErrorCode'] == 0:
                logging.info("Password changed successfully via SAMR anonymous")
                return True
            else:
                error_code = resp['ErrorCode']
                logging.error(f"SAMR change failed with error code: 0x{error_code:08x}")
                
                if error_code == 0xc0000224:
                    logging.error("STATUS_PASSWORD_MUST_CHANGE - Account requires password change")
                elif error_code == 0xc000006a:
                    logging.error("STATUS_WRONG_PASSWORD - Old password is incorrect")
                elif error_code == 0xc000006c:
                    logging.error("STATUS_PASSWORD_RESTRICTION - Password policy violation")
                
                return False
                
        except ImportError as e:
            logging.error(f"Impacket module not available: {e}")
            print(Fore.YELLOW + "[!] Install impacket: pip install impacket")
            return False
        except Exception as e:
            error_str = str(e)
            if "STATUS_ACCESS_DENIED" in error_str:
                logging.error("Anonymous access denied - SMB signing may be required")
            elif "STATUS_PASSWORD_RESTRICTION" in error_str:
                logging.error("Password does not meet domain policy requirements")
            else:
                logging.error(f"SAMR anonymous failed: {e}")
            return False

    def change_password_ldap_anonymous(self, target_dn):
        logging.info("Attempting password change via LDAP with anonymous bind")
        
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        
        try:
            logging.debug("Attempting anonymous LDAPS connection")
            server = Server(self.target_ip, port=636, use_ssl=True, tls=tls, get_info=ALL)
            conn = Connection(server, user="", password="", authentication=SIMPLE)
            
            if not conn.bind():
                logging.debug("Anonymous LDAPS bind failed, trying LDAP with StartTLS")
                server = Server(self.target_ip, port=389, use_ssl=False, tls=tls)
                conn = Connection(server, user="", password="", authentication=SIMPLE)
                conn.open()
                conn.start_tls()
                if not conn.bind():
                    logging.error("Cannot establish anonymous LDAP connection")
                    return False
            
            logging.debug("Anonymous bind successful")
            
            old_encoded = self.encode_ldap_password(self.old_password)
            new_encoded = self.encode_ldap_password(self.new_password)
            
            changes = {
                'unicodePwd': [
                    (MODIFY_DELETE, [old_encoded]),
                    (MODIFY_ADD, [new_encoded])
                ]
            }
            
            logging.debug("Sending atomic modify request (DELETE + ADD)")
            success = conn.modify(target_dn, changes)
            
            if success:
                logging.info("Password changed successfully via LDAP anonymous")
                return True
            else:
                result_code = conn.result.get('result', 0)
                if result_code == 19:
                    logging.error("Password constraint violation - check domain policy")
                elif result_code == 50:
                    logging.error("Insufficient access rights - anonymous may be restricted")
                else:
                    logging.error(f"LDAP modify failed: {conn.result.get('description')}")
                return False
                
        except Exception as e:
            logging.error(f"LDAP anonymous failed: {e}")
            return False

    def execute_reset(self):
        try:
            print(Fore.CYAN + "\n[*] Initializing Password Change Protocol")
            print(Fore.CYAN + "[*] " + "="*50)
            
            target_dn = f"cn={self.username},cn=users," + ",".join([f"dc={p}" for p in self.domain.split('.')])
            print(Fore.GREEN + f"[+] Target DN: {target_dn}")
            
            print(Fore.YELLOW + "\n[*] Strategy 1: Kerberos Kpasswd (port 464)")
            if self.change_password_kpasswd():
                print(Fore.GREEN + "\n" + "="*60)
                print(Fore.GREEN + f" [SUCCESS] Password changed for: {self.domain}\\{self.username}")
                print(Fore.GREEN + " [PROTOCOL] Kerberos Kpasswd - RFC 3244")
                print(Fore.GREEN + "="*60)
                return
            
            print(Fore.YELLOW + "\n[*] Strategy 2: SAMR Anonymous (NULL session)")
            if self.change_password_samr_anonymous():
                print(Fore.GREEN + "\n" + "="*60)
                print(Fore.GREEN + f" [SUCCESS] Password changed for: {self.domain}\\{self.username}")
                print(Fore.GREEN + " [PROTOCOL] MS-SAMR with NULL session")
                print(Fore.GREEN + "="*60)
                return
            
            print(Fore.YELLOW + "\n[*] Strategy 3: LDAP Anonymous (Atomic Modify)")
            if self.change_password_ldap_anonymous(target_dn):
                print(Fore.GREEN + "\n" + "="*60)
                print(Fore.GREEN + f" [SUCCESS] Password changed for: {self.domain}\\{self.username}")
                print(Fore.GREEN + " [PROTOCOL] LDAP with anonymous bind")
                print(Fore.GREEN + "="*60)
                return
            
            print(Fore.RED + "\n" + "="*60)
            print(Fore.RED + " [FAILED] Password change was unsuccessful")
            print(Fore.RED + " [REASONS] - Account may have 'Must Change Password' flag")
            print(Fore.RED + "          - Password does not meet domain policy")
            print(Fore.RED + "          - Old password is incorrect")
            print(Fore.RED + "          - SMB signing may be enforced")
            print(Fore.RED + "="*60)
            
        except Exception as e:
            logging.error(f"Unexpected error: {str(e).splitlines()[0]}")
            if self.debug:
                import traceback
                traceback.print_exc()

    def run(self):
        print(self.banner)
        
        print(Fore.CYAN + "\n[*] Target Information")
        print(Fore.CYAN + "[*] " + "="*50)
        
        self.target_ip = self.get_input("Target DC IP", self.validate_ip)
        self.domain = self.get_input("Domain (e.g., cs.org)")
        self.username = self.get_input("Username")
        self.old_password = self.get_input("Current Password", is_password=True)
        
        print(Fore.YELLOW + "\n[*] Password Policy Requirements")
        print(Fore.YELLOW + "[*] - Minimum length, complexity, and history enforced")
        
        self.new_password = self.get_input(
            "New Password", 
            lambda p: (True, "") if len(p) >= 7 else (False, "Password must be at least 7 characters"),
            is_password=True
        )
        
        confirm_password = self.get_input("Confirm New Password", is_password=True)
        
        if self.new_password != confirm_password:
            print(Fore.RED + "[-] Passwords do not match. Exiting...")
            sys.exit(1)
        
        self.execute_reset()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--debug":
        app = JokerResetter(debug=True)
    else:
        app = JokerResetter(debug=False)
    app.run()
