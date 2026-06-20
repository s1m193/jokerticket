#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AD Kerberos Delegation Enumerator
Kerberos Constrained Delegation (KCD) Enumeration & Abuse Detection
Fully manual LDAP via raw sockets + impacket library for SMB auth
"""

import sys
import re
import ssl
import socket
import signal
import struct
import logging
import os
import time
from datetime import datetime

logging.getLogger().setLevel(logging.ERROR)


# ------------------------------------------------------------------
# ANSI Colors (built-in)
# ------------------------------------------------------------------
class _C:
    RESET   = '\033[0m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    MAGENTA = '\033[95m'
    DIM     = '\033[90m'


# ------------------------------------------------------------------
# Signal Handler
# ------------------------------------------------------------------
def _exit_handler(sig, frame):
    print(_C.YELLOW + "\n\n[!] Exiting... Goodbye!" + _C.RESET)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


# ------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------
def banner():
    print(_C.CYAN + """
    ╔═══════════════════════════════════════════╗
    ║   Kerberos Delegation Enumerator          ║
    ║  Unconstrained | Constrained | RBCD       ║
    ╚═══════════════════════════════════════════╝
    """ + _C.RESET)


# ------------------------------------------------------------------
# Validators
# ------------------------------------------------------------------
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


def validate_positive_int(val):
    try:
        return int(val) > 0
    except ValueError:
        return False


def validate_file_path(path):
    return os.path.isfile(path)


# ------------------------------------------------------------------
# Input Helper
# ------------------------------------------------------------------
def get_input(prompt, validator=None, error_msg=None, allow_empty=False):
    while True:
        try:
            value = input(prompt).strip()
            if not value and not allow_empty:
                print(_C.RED + "[!] This field cannot be empty!" + _C.RESET)
                continue
            if validator and value and not validator(value):
                print(_C.RED + f"[!] {error_msg}" + _C.RESET)
                continue
            return value
        except KeyboardInterrupt:
            print(_C.YELLOW + "\n\n[!] Exiting... Goodbye!" + _C.RESET)
            sys.exit(0)


# ------------------------------------------------------------------
# Domain Helpers
# ------------------------------------------------------------------
def get_base_dn(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])


# ------------------------------------------------------------------
# Reachability Check
# ------------------------------------------------------------------
def check_ip_reachable(ip):
    for port in (636, 389, 445):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
    return False


# ------------------------------------------------------------------
# BER Codec (manual implementation)
# ------------------------------------------------------------------
class BER:
    @staticmethod
    def _encode_length(length):
        if length < 128:
            return bytes([length])
        octets = []
        temp = length
        while temp:
            octets.insert(0, temp & 0xff)
            temp >>= 8
        return bytes([0x80 | len(octets)] + octets)

    @staticmethod
    def encode_integer(value):
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        octets = []
        temp = value
        while temp:
            octets.insert(0, temp & 0xff)
            temp >>= 8
        if octets[0] & 0x80:
            octets.insert(0, 0x00)
        return bytes([0x02, len(octets)] + octets)

    @staticmethod
    def encode_octet_string(data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return bytes([0x04]) + BER._encode_length(len(data)) + data

    @staticmethod
    def encode_boolean(value):
        return bytes([0x01, 0x01, 0xff if value else 0x00])

    @staticmethod
    def encode_enum(value):
        return bytes([0x0a, 0x01, value & 0xff])

    @staticmethod
    def encode_sequence(contents):
        return bytes([0x30]) + BER._encode_length(len(contents)) + contents

    @staticmethod
    def encode_application(tag_num, contents):
        tag = 0x60 | (tag_num & 0x1f)
        return bytes([tag]) + BER._encode_length(len(contents)) + contents

    @staticmethod
    def encode_context_primitive(tag_num, data):
        tag = 0x80 | (tag_num & 0x1f)
        if isinstance(data, str):
            data = data.encode('utf-8')
        return bytes([tag]) + BER._encode_length(len(data)) + data

    @staticmethod
    def encode_context_constructed(tag_num, contents):
        tag = 0xa0 | (tag_num & 0x1f)
        return bytes([tag]) + BER._encode_length(len(contents)) + contents


# ------------------------------------------------------------------
# BER Parser
# ------------------------------------------------------------------
class BERParser:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def _read_tag(self):
        if self.offset >= len(self.data):
            return None
        tag = self.data[self.offset]
        self.offset += 1
        return tag

    def _read_length(self):
        if self.offset >= len(self.data):
            return 0
        b = self.data[self.offset]
        self.offset += 1
        if b & 0x80:
            num_bytes = b & 0x7f
            length = int.from_bytes(self.data[self.offset:self.offset + num_bytes], 'big')
            self.offset += num_bytes
            return length
        return b

    def read_element(self):
        tag = self._read_tag()
        if tag is None:
            return None
        length = self._read_length()
        content = self.data[self.offset:self.offset + length]
        self.offset += length
        return tag, content

    def parse(self):
        elements = []
        while self.offset < len(self.data):
            el = self.read_element()
            if el is None:
                break
            tag, content = el
            if tag in (0x30, 0x31) or (tag & 0xe0) == 0x20:
                sub = BERParser(content)
                elements.append((tag, sub.parse()))
            else:
                elements.append((tag, content))
        return elements


# ------------------------------------------------------------------
# LDAP Protocol Builders
# ------------------------------------------------------------------
def build_bind_request(msg_id, username, password):
    version = BER.encode_integer(3)
    name = BER.encode_octet_string(username)
    auth = BER.encode_context_primitive(0, password)
    bind_req = BER.encode_application(0, version + name + auth)
    return BER.encode_sequence(BER.encode_integer(msg_id) + bind_req)


def build_search_request(msg_id, base_dn, filter_bytes, attributes=None):
    if attributes is None:
        attributes = []
    base = BER.encode_octet_string(base_dn)
    scope = BER.encode_enum(2)
    deref = BER.encode_enum(0)
    size_limit = BER.encode_integer(0)
    time_limit = BER.encode_integer(0)
    types_only = BER.encode_boolean(False)
    attr_seq = BER.encode_sequence(b''.join(BER.encode_octet_string(a) for a in attributes))
    search_req = BER.encode_application(3, base + scope + deref + size_limit + time_limit + types_only + filter_bytes + attr_seq)
    return BER.encode_sequence(BER.encode_integer(msg_id) + search_req)


def build_unbind_request(msg_id):
    unbind_req = BER.encode_application(2, b'')
    return BER.encode_sequence(BER.encode_integer(msg_id) + unbind_req)


# ------------------------------------------------------------------
# Filter Builders
# ------------------------------------------------------------------
def encode_filter_equality(attr, value):
    return BER.encode_context_constructed(3, BER.encode_octet_string(attr) + BER.encode_octet_string(value))


def encode_filter_and(filters):
    return BER.encode_context_constructed(0, b''.join(filters))


def encode_filter_or(filters):
    return BER.encode_context_constructed(1, b''.join(filters))


def encode_filter_present(attr):
    return BER.encode_context_primitive(7, attr)


def encode_filter_bitwise_match(attr, oid, value):
    attr_desc = BER.encode_octet_string(attr)
    match_value = BER.encode_octet_string(str(value))
    matching_rule = BER.encode_octet_string(oid)
    dn_attrs = BER.encode_boolean(False)
    return BER.encode_context_constructed(9, attr_desc + matching_rule + match_value + dn_attrs)


# ------------------------------------------------------------------
# LDAP Socket I/O
# ------------------------------------------------------------------
def create_ldap_socket(dc_ip, use_ssl=False, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    port = 636 if use_ssl else 389
    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=dc_ip)
    sock.connect((dc_ip, port))
    return sock


def read_ldap_message(sock):
    tag_b = b''
    while len(tag_b) < 1:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed reading tag")
        tag_b += chunk
    tag = tag_b[0]

    len_b = b''
    while len(len_b) < 1:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed reading length")
        len_b += chunk
    length_byte = len_b[0]

    if length_byte & 0x80:
        num_bytes = length_byte & 0x7f
        len_bytes = b''
        while len(len_bytes) < num_bytes:
            chunk = sock.recv(num_bytes - len(len_bytes))
            if not chunk:
                raise ConnectionError("Connection closed reading length bytes")
            len_bytes += chunk
        msg_len = int.from_bytes(len_bytes, 'big')
    else:
        msg_len = length_byte
        len_bytes = b''

    body = b''
    while len(body) < msg_len:
        chunk = sock.recv(msg_len - len(body))
        if not chunk:
            raise ConnectionError("Connection closed reading body")
        body += chunk

    return bytes([tag, length_byte]) + len_bytes + body


# ------------------------------------------------------------------
# LDAP Response Parsers
# ------------------------------------------------------------------
def parse_bind_response(data):
    parser = BERParser(data)
    tree = parser.parse()
    if not tree or tree[0][0] != 0x30:
        return -1
    msg = tree[0][1]
    if len(msg) < 2 or msg[1][0] != 0x61:
        return -1
    bind_resp = msg[1][1]
    if not bind_resp or bind_resp[0][0] != 0x0a:
        return -1
    return bind_resp[0][1][0]


def parse_search_responses(data):
    parser = BERParser(data)
    tree = parser.parse()
    entries = []
    done = False
    result_code = 0

    for msg in tree:
        if msg[0] != 0x30:
            continue
        msg_parts = msg[1]
        if len(msg_parts) < 2:
            continue
        op = msg_parts[1]
        tag = op[0]

        if tag == 0x64:
            entry_data = op[1]
            if len(entry_data) < 2:
                continue
            dn = entry_data[0][1].decode('utf-8', errors='replace')
            attrs = {}
            if len(entry_data) > 1 and entry_data[1][0] == 0x30:
                for attr_seq in entry_data[1][1]:
                    if attr_seq[0] != 0x30 or len(attr_seq[1]) < 2:
                        continue
                    attr_name = attr_seq[1][0][1].decode('utf-8', errors='replace')
                    values = []
                    if attr_seq[1][1][0] == 0x31:
                        for v in attr_seq[1][1][1]:
                            if v[0] == 0x04:
                                values.append(v[1].decode('utf-8', errors='replace'))
                    attrs[attr_name] = values
            entries.append({'dn': dn, 'attributes': attrs})

        elif tag == 0x65:
            done = True
            done_data = op[1]
            if done_data and done_data[0][0] == 0x0a:
                result_code = done_data[0][1][0]

    return entries, done, result_code


# ------------------------------------------------------------------
# Core LDAP Operations
# ------------------------------------------------------------------
def ldap_bind(sock, msg_id, username, password):
    req = build_bind_request(msg_id, username, password)
    sock.sendall(req)
    resp = read_ldap_message(sock)
    return parse_bind_response(resp)


def try_auto_base_dn(dc_ip, use_ssl=False):
    try:
        sock = create_ldap_socket(dc_ip, use_ssl, timeout=5)
        filt = encode_filter_present('objectClass')
        req = build_search_request(1, '', filt, ['defaultNamingContext'])
        sock.sendall(req)
        resp = read_ldap_message(sock)
        entries, done, code = parse_search_responses(resp)
        sock.close()
        for e in entries:
            if 'defaultNamingContext' in e['attributes']:
                return e['attributes']['defaultNamingContext'][0]
    except Exception:
        pass
    return None


def check_credentials_and_domain(dc_ip, domain, username, password, use_ssl=False):
    try:
        upn = f"{username}@{domain}"
        sock = create_ldap_socket(dc_ip, use_ssl)
        result = ldap_bind(sock, 1, upn, password)
        if result == 49:
            sock.close()
            return "invalid_credentials"
        if result != 0:
            sock.close()
            return False

        base_dn = get_base_dn(domain)
        f1 = encode_filter_equality('objectClass', 'domain')
        filt = encode_filter_and([f1])
        req = build_search_request(2, base_dn, filt, ['dc'])
        sock.sendall(req)
        resp = read_ldap_message(sock)
        entries, done, code = parse_search_responses(resp)
        sock.close()
        return len(entries) > 0
    except Exception:
        return False


def ldap_search(dc_ip, base_dn, bind_dn, password, filter_bytes, attributes, use_ssl=False):
    results = []
    try:
        sock = create_ldap_socket(dc_ip, use_ssl)
        msg_id = 1

        result = ldap_bind(sock, msg_id, bind_dn, password)
        msg_id += 1
        if result != 0:
            print(_C.RED + f"[-] Bind failed (code {result})" + _C.RESET)
            sock.close()
            return []

        req = build_search_request(msg_id, base_dn, filter_bytes, attributes)
        sock.sendall(req)

        while True:
            resp = read_ldap_message(sock)
            entries, done, code = parse_search_responses(resp)
            results.extend(entries)
            if done:
                if code != 0:
                    print(_C.YELLOW + f"[!] Search completed with code: {code}" + _C.RESET)
                break

        sock.sendall(build_unbind_request(msg_id + 1))
        sock.close()

    except Exception as e:
        print(_C.RED + f"[-] Search error: {e}" + _C.RESET)

    return results


# ------------------------------------------------------------------
# SMB Credential Validation (impacket library import)
# ------------------------------------------------------------------
def validate_credentials_smb(dc_ip, domain, username, password, port=445):
    try:
        from impacket.smbconnection import SMBConnection
        smb = SMBConnection(dc_ip, dc_ip, sess_port=int(port))
        smb.login(username, password, domain)
        smb.logoff()
        return True, "Credentials validated successfully"
    except Exception as e:
        error_str = str(e).lower()
        if "logon_failure" in error_str or "status_logon_failure" in error_str:
            return False, "Invalid credentials"
        if "access_denied" in error_str or "status_access_denied" in error_str:
            return False, "Access denied - credentials may be correct but insufficient privileges"
        if "connection refused" in error_str:
            return False, "Connection refused"
        if "timeout" in error_str or "timed out" in error_str:
            return False, "Connection timeout"
        return False, f"Validation error: {str(e)}"


# ------------------------------------------------------------------
# KCD Enumeration Logic
# ------------------------------------------------------------------
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x0100000
OID_BITWISE_AND = '1.2.840.113556.1.4.803'


def enumerate_unconstrained(dc_ip, base_dn, bind_dn, password, use_ssl):
    print(_C.YELLOW + "[*] Searching for Unconstrained Delegation..." + _C.RESET)
    filt = encode_filter_bitwise_match('userAccountControl', OID_BITWISE_AND, UAC_TRUSTED_FOR_DELEGATION)
    attrs = ['sAMAccountName', 'distinguishedName', 'userAccountControl', 'servicePrincipalName', 'objectClass']
    return ldap_search(dc_ip, base_dn, bind_dn, password, filt, attrs, use_ssl)


def enumerate_constrained(dc_ip, base_dn, bind_dn, password, use_ssl):
    print(_C.YELLOW + "[*] Searching for Constrained Delegation..." + _C.RESET)
    f1 = encode_filter_present('msDS-AllowedToDelegateTo')
    f2 = encode_filter_bitwise_match('userAccountControl', OID_BITWISE_AND, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
    filt = encode_filter_or([f1, f2])
    attrs = ['sAMAccountName', 'distinguishedName', 'msDS-AllowedToDelegateTo', 'userAccountControl', 'servicePrincipalName']
    return ldap_search(dc_ip, base_dn, bind_dn, password, filt, attrs, use_ssl)


def enumerate_rbcd(dc_ip, base_dn, bind_dn, password, use_ssl):
    print(_C.YELLOW + "[*] Searching for Resource-Based Constrained Delegation..." + _C.RESET)
    filt = encode_filter_present('msDS-AllowedToActOnBehalfOfOtherIdentity')
    attrs = ['sAMAccountName', 'distinguishedName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
    return ldap_search(dc_ip, base_dn, bind_dn, password, filt, attrs, use_ssl)


def parse_uac_flags(uac_val):
    flags = []
    val = int(uac_val) if isinstance(uac_val, str) else uac_val
    if val & 0x00000002: flags.append('ACCOUNTDISABLE')
    if val & 0x00020000: flags.append('SMARTCARD_REQUIRED')
    if val & 0x00080000: flags.append('TRUSTED_FOR_DELEGATION')
    if val & 0x0100000: flags.append('TRUSTED_TO_AUTH_FOR_DELEGATION')
    if val & 0x0400000: flags.append('PARTIAL_SECRETS_ACCOUNT')
    if val & 0x1000000: flags.append('USE_AES_KEYS')
    return flags


def print_delegation_results(title, entries, color=_C.GREEN):
    if not entries:
        print(_C.YELLOW + f"[!] No {title} objects found." + _C.RESET)
        return

    print(color + f"[+] Found {len(entries)} {title} object(s):" + _C.RESET)
    for i, e in enumerate(entries, 1):
        sam = e['attributes'].get('sAMAccountName', ['?'])[0]
        dn = e['attributes'].get('distinguishedName', ['?'])[0]
        print(_C.WHITE + f"    {i:3}. {sam}" + _C.RESET)
        print(_C.DIM + f"        DN: {dn}" + _C.RESET)

        uac = e['attributes'].get('userAccountControl', [None])[0]
        if uac:
            flags = parse_uac_flags(uac)
            print(_C.DIM + f"        UAC: {uac} ({', '.join(flags)})" + _C.RESET)

        spn = e['attributes'].get('servicePrincipalName', [])
        if spn:
            print(_C.DIM + f"        SPN: {', '.join(spn[:3])}" + _C.RESET)

        del_to = e['attributes'].get('msDS-AllowedToDelegateTo', [])
        if del_to:
            print(_C.CYAN + f"        AllowedToDelegateTo:" + _C.RESET)
            for d in del_to:
                print(_C.CYAN + f"          -> {d}" + _C.RESET)

        rbcd = e['attributes'].get('msDS-AllowedToActOnBehalfOfOtherIdentity', [])
        if rbcd:
            print(_C.MAGENTA + f"        RBCD configured (raw length: {len(rbcd[0])} bytes)" + _C.RESET)


def analyze_abuse_vectors(unconstrained, constrained, rbcd):
    vectors = []

    for e in unconstrained:
        sam = e['attributes'].get('sAMAccountName', ['?'])[0]
        vectors.append({
            'type': 'Unconstrained',
            'target': sam,
            'risk': 'CRITICAL',
            'detail': f"{sam} has TRUSTED_FOR_DELEGATION — can impersonate any user to any service"
        })

    for e in constrained:
        sam = e['attributes'].get('sAMAccountName', ['?'])[0]
        del_to = e['attributes'].get('msDS-AllowedToDelegateTo', [])
        uac = e['attributes'].get('userAccountControl', [0])[0]
        has_protocol_transition = False
        try:
            if int(uac) & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
                has_protocol_transition = True
        except (ValueError, TypeError):
            pass

        for svc in del_to:
            risk = 'HIGH' if has_protocol_transition else 'MEDIUM'
            detail = f"{sam} constrained to {svc}"
            if has_protocol_transition:
                detail += " with Protocol Transition (S4U2Self enabled)"
            vectors.append({
                'type': 'Constrained',
                'target': sam,
                'risk': risk,
                'detail': detail
            })

    for e in rbcd:
        sam = e['attributes'].get('sAMAccountName', ['?'])[0]
        vectors.append({
            'type': 'RBCD',
            'target': sam,
            'risk': 'HIGH',
            'detail': f"{sam} has msDS-AllowedToActOnBehalfOfOtherIdentity"
        })

    return vectors


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
if __name__ == '__main__':
    banner()

    dc_ip = get_input(
        _C.CYAN + "[?] Enter DC IP Address  : " + _C.RESET,
        validate_ip, "Invalid IP! Example: 192.168.1.1"
    )

    print(_C.YELLOW + "[*] Checking DC reachability..." + _C.RESET)
    if not check_ip_reachable(dc_ip):
        print(_C.RED + f"[!] Cannot reach {dc_ip}!" + _C.RESET)
        sys.exit(1)
    print(_C.GREEN + f"[+] DC {dc_ip} is reachable!" + _C.RESET)

    domain = get_input(
        _C.CYAN + "[?] Enter Domain Name    : " + _C.RESET,
        validate_domain, "Invalid domain! Example: corp.local"
    )

    print(_C.CYAN + "\n[?] Choose authentication type:" + _C.RESET)
    print(_C.WHITE + "    1. Password (LDAP + SMB validation)")
    print(_C.WHITE + "    2. Anonymous bind (limited enumeration)")

    auth_choice = get_input(
        _C.CYAN + "[?] Your choice          : " + _C.RESET,
        lambda x: x in ['1', '2'],
        "Invalid choice! Enter 1 or 2"
    )

    username = ''
    password = ''
    bind_dn = ''

    if auth_choice == '1':
        username = get_input(_C.CYAN + "[?] Enter Username       : " + _C.RESET)
        password = get_input(_C.CYAN + "[?] Enter Password       : " + _C.RESET)
        bind_dn = f"{username}@{domain}"

        print(_C.YELLOW + "[*] Verifying credentials via LDAP..." + _C.RESET)
        result = check_credentials_and_domain(dc_ip, domain, username, password)
        if result == "invalid_credentials":
            print(_C.RED + "[!] Invalid credentials!" + _C.RESET)
            sys.exit(1)
        elif not result:
            print(_C.RED + f"[!] Domain '{domain}' not found or unreachable!" + _C.RESET)
            sys.exit(1)
        print(_C.GREEN + "[+] LDAP credentials verified!" + _C.RESET)
        print(_C.GREEN + f"[+] Domain '{domain}' verified!" + _C.RESET)

        # Optional SMB validation
        print(_C.YELLOW + "[*] Validating via SMB (impacket library)..." + _C.RESET)
        smb_ok, smb_msg = validate_credentials_smb(dc_ip, domain, username, password)
        if smb_ok:
            print(_C.GREEN + f"[+] SMB validation: {smb_msg}" + _C.RESET)
        else:
            print(_C.YELLOW + f"[!] SMB validation: {smb_msg} - continuing with LDAP only" + _C.RESET)

    else:
        bind_dn = ''
        password = ''
        print(_C.YELLOW + "[!] Anonymous mode — some queries may be restricted" + _C.RESET)

    # Auto-detect or build base DN
    print(_C.YELLOW + "[*] Resolving Base DN..." + _C.RESET)
    base_dn = try_auto_base_dn(dc_ip)
    if not base_dn:
        base_dn = get_base_dn(domain)
        print(_C.YELLOW + f"[!] Auto-discovery failed, using derived: {base_dn}" + _C.RESET)
    else:
        print(_C.GREEN + f"[+] Base DN resolved: {base_dn}" + _C.RESET)

    # Determine SSL preference
    use_ssl = False
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        if test_sock.connect_ex((dc_ip, 636)) == 0:
            use_ssl = True
            print(_C.GREEN + "[+] LDAPS (636) available — using encrypted channel" + _C.RESET)
        test_sock.close()
    except Exception:
        pass
    if not use_ssl:
        print(_C.YELLOW + "[!] Using LDAP (389) — consider LDAPS for credential safety" + _C.RESET)

    # Store all results
    all_results = {'unconstrained': [], 'constrained': [], 'rbcd': []}

    while True:
        print(_C.CYAN + "\n[?] Choose action:" + _C.RESET)
        print(_C.WHITE + "    1. Enumerate Unconstrained Delegation")
        print(_C.WHITE + "    2. Enumerate Constrained Delegation")
        print(_C.WHITE + "    3. Enumerate Resource-Based Constrained Delegation (RBCD)")
        print(_C.WHITE + "    4. Run full delegation audit (all types)")
        print(_C.WHITE + "    5. Export results to file")
        print(_C.WHITE + "    6. Exit")

        choice = get_input(
            _C.CYAN + "[?] Your choice          : " + _C.RESET,
            lambda x: x in ['1', '2', '3', '4', '5', '6'],
            "Invalid choice! Enter 1-6"
        )

        if choice == '1':
            all_results['unconstrained'] = enumerate_unconstrained(dc_ip, base_dn, bind_dn, password, use_ssl)
            print_delegation_results("Unconstrained Delegation", all_results['unconstrained'], _C.RED)

        elif choice == '2':
            all_results['constrained'] = enumerate_constrained(dc_ip, base_dn, bind_dn, password, use_ssl)
            print_delegation_results("Constrained Delegation", all_results['constrained'], _C.YELLOW)

        elif choice == '3':
            all_results['rbcd'] = enumerate_rbcd(dc_ip, base_dn, bind_dn, password, use_ssl)
            print_delegation_results("RBCD", all_results['rbcd'], _C.MAGENTA)

        elif choice == '4':
            print(_C.CYAN + "\n[*] Running full delegation audit..." + _C.RESET)
            all_results['unconstrained'] = enumerate_unconstrained(dc_ip, base_dn, bind_dn, password, use_ssl)
            all_results['constrained'] = enumerate_constrained(dc_ip, base_dn, bind_dn, password, use_ssl)
            all_results['rbcd'] = enumerate_rbcd(dc_ip, base_dn, bind_dn, password, use_ssl)

            print()
            print_delegation_results("Unconstrained Delegation", all_results['unconstrained'], _C.RED)
            print()
            print_delegation_results("Constrained Delegation", all_results['constrained'], _C.YELLOW)
            print()
            print_delegation_results("RBCD", all_results['rbcd'], _C.MAGENTA)

            vectors = analyze_abuse_vectors(
                all_results['unconstrained'],
                all_results['constrained'],
                all_results['rbcd']
            )

            if vectors:
                print(_C.CYAN + "\n[*] Abuse Vector Analysis:" + _C.RESET)
                for v in vectors:
                    color = _C.RED if v['risk'] == 'CRITICAL' else (_C.YELLOW if v['risk'] == 'HIGH' else _C.GREEN)
                    print(color + f"    [{v['risk']}] ({v['type']}) {v['detail']}" + _C.RESET)
            else:
                print(_C.GREEN + "\n[+] No delegation abuse vectors detected." + _C.RESET)

        elif choice == '5':
            fname = get_input(_C.CYAN + "[?] Output filename      : " + _C.RESET)
            if not fname:
                fname = f"kcd_audit_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

            try:
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write(f"Kerberos Delegation Audit Report\n")
                    f.write(f"Domain: {domain}\n")
                    f.write(f"DC: {dc_ip}\n")
                    f.write(f"Time: {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n\n")

                    for cat, entries in all_results.items():
                        f.write(f"[{cat.upper()}]\n")
                        f.write(f"Count: {len(entries)}\n")
                        for e in entries:
                            sam = e['attributes'].get('sAMAccountName', ['?'])[0]
                            dn = e['attributes'].get('distinguishedName', ['?'])[0]
                            f.write(f"  {sam}\n")
                            f.write(f"    DN: {dn}\n")
                            for attr, vals in e['attributes'].items():
                                if attr not in ('sAMAccountName', 'distinguishedName') and vals:
                                    f.write(f"    {attr}: {vals}\n")
                            f.write("\n")
                        f.write("-" * 40 + "\n\n")

                    vectors = analyze_abuse_vectors(
                        all_results['unconstrained'],
                        all_results['constrained'],
                        all_results['rbcd']
                    )
                    if vectors:
                        f.write("[ABUSE VECTORS]\n")
                        for v in vectors:
                            f.write(f"  [{v['risk']}] ({v['type']}) {v['detail']}\n")

                print(_C.GREEN + f"[+] Report saved to: {fname}" + _C.RESET)
            except Exception as e:
                print(_C.RED + f"[-] Failed to save report: {e}" + _C.RESET)

        elif choice == '6':
            print(_C.YELLOW + "\n[!] Exiting... Goodbye!" + _C.RESET)
            break
