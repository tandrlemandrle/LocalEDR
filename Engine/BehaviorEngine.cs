using System.Text.RegularExpressions;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class BehaviorEngine
{
    // ── LOLBins ───────────────────────────────────────────────
    private static readonly Dictionary<string, (string Risk, string[] SuspiciousArgs)> LOLBins = new(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell.exe"] = ("Script execution engine", ["-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass", "iex", "invoke-expression", "downloadstring", "downloadfile", "frombase64string", "invoke-webrequest", "bitstransfer"]),
        ["cmd.exe"] = ("Command interpreter", ["/c powershell", "/c mshta", "/c certutil", "/c bitsadmin", "/c wscript", "/c cscript"]),
        ["mshta.exe"] = ("HTML Application host", ["javascript:", "vbscript:", "http://", "https://"]),
        ["rundll32.exe"] = ("DLL execution proxy", ["javascript:", "shell32.dll", "url.dll", "advpack.dll"]),
        ["regsvr32.exe"] = ("COM registration / script execution", ["/s", "/u", "/i:http", "scrobj.dll"]),
        ["certutil.exe"] = ("Certificate utility (download proxy)", ["-urlcache", "-decode", "-encode", "-decodehex", "http://", "https://", "-split"]),
        ["wmic.exe"] = ("WMI command-line", ["process call create", "os get", "/node:", "shadowcopy delete", "/format:"]),
        ["msiexec.exe"] = ("MSI installer (remote payload)", ["/q", "http://", "https://"]),
        ["cscript.exe"] = ("Script host", ["//e:", "//b", ".vbs", ".js"]),
        ["wscript.exe"] = ("Script host", ["//e:", "//b", ".vbs", ".js"]),
        ["bitsadmin.exe"] = ("BITS transfer (download proxy)", ["/transfer", "/create", "/addfile", "http://", "https://"]),
        ["schtasks.exe"] = ("Scheduled task manipulation", ["/create", "/change", "/run", "/tn", "/sc"]),
        ["sc.exe"] = ("Service control", ["create", "config", "start", "binpath="]),
        ["reg.exe"] = ("Registry manipulation", ["add", "delete", "export", "CurrentVersion\\Run"]),
        ["net.exe"] = ("Network/user enumeration", ["user /add", "localgroup administrators", "share", "use \\\\", "view"]),
        ["nltest.exe"] = ("Domain trust enumeration", ["/dclist", "/domain_trusts", "/dsgetdc"]),
        ["esentutl.exe"] = ("Database utility (file copy proxy)", ["/y", "/vss", "/d"]),
    };

    // ── Suspicious parent-child combos ────────────────────────
    private static readonly (string Parent, string Child, int Score, string Desc)[] SuspiciousParentChild =
    [
        ("winword.exe", "powershell.exe", 80, "Office spawning PowerShell"),
        ("winword.exe", "cmd.exe", 70, "Office spawning cmd"),
        ("excel.exe", "powershell.exe", 80, "Excel spawning PowerShell"),
        ("excel.exe", "cmd.exe", 70, "Excel spawning cmd"),
        ("outlook.exe", "powershell.exe", 80, "Outlook spawning PowerShell"),
        ("svchost.exe", "cmd.exe", 50, "svchost spawning cmd"),
        ("explorer.exe", "mshta.exe", 60, "Explorer spawning mshta"),
        ("wmiprvse.exe", "powershell.exe", 70, "WMI spawning PowerShell"),
        ("services.exe", "cmd.exe", 60, "Services spawning cmd"),
        ("w3wp.exe", "cmd.exe", 80, "IIS worker spawning cmd (webshell?)"),
        ("w3wp.exe", "powershell.exe", 90, "IIS worker spawning PowerShell (webshell?)"),
        ("sqlservr.exe", "cmd.exe", 80, "SQL Server spawning cmd"),
        ("mshta.exe", "powershell.exe", 80, "mshta spawning PowerShell"),
    ];

    // ── Command-line heuristics ───────────────────────────────
    private static readonly (string Pattern, int Score, string Flag)[] CommandHeuristics =
    [
        (@"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", 50, "Long encoded PowerShell command"),
        (@"\|\s*iex$|\|\s*invoke-expression", 40, "Pipeline to Invoke-Expression"),
        (@"downloadstring\s*\(\s*['""]https?://", 45, "Download and execute pattern"),
        (@"new-object\s+net\.webclient", 30, "WebClient instantiation"),
        (@"invoke-webrequest.*\|\s*iex", 50, "Web request piped to IEX"),
        (@"start-process.*-windowstyle\s+hidden", 35, "Hidden process launch"),
        (@"-nop\s+-w\s+hidden\s+-enc", 60, "Classic PowerShell cradle flags"),
        (@"bypass.*-nop.*-w\s+hidden", 55, "Evasion flag combination"),
        (@"\[convert\]::frombase64string", 35, "Base64 decoding in command"),
        (@"\[io\.memorystream\]", 30, "In-memory stream (fileless)"),
        (@"\[reflection\.assembly\]::load", 45, "Reflective assembly loading"),
        (@"add-type.*-typedefinition.*dllimport", 50, "P/Invoke via Add-Type"),
        (@"whoami|systeminfo|ipconfig|net\s+user", 15, "Reconnaissance command"),
        (@"tasklist|qprocess|query\s+user", 15, "Process/user enumeration"),
        (@"vssadmin.*delete\s+shadows", 70, "Shadow copy deletion (ransomware)"),
        (@"bcdedit.*recoveryenabled.*no", 70, "Recovery disabled (ransomware)"),
        (@"wbadmin\s+delete\s+catalog", 70, "Backup catalog deletion (ransomware)"),
    ];

    // ── Injection patterns ────────────────────────────────────
    private static readonly (string Pattern, int Score, string Flag)[] InjectionPatterns =
    [
        ("createremotethread", 60, "CreateRemoteThread call"),
        ("writeprocessmemory", 60, "WriteProcessMemory call"),
        ("virtualallocex", 50, "VirtualAllocEx call"),
        ("ntmapviewofsection", 50, "Section mapping (process hollowing)"),
        ("queueuserapc", 50, "APC injection"),
        ("setthreadcontext", 50, "Thread context manipulation"),
        ("ntunmapviewofsection", 60, "Section unmapping (hollowing)"),
    ];

    // ── Persistence patterns ──────────────────────────────────
    private static readonly (string Pattern, int Score, string Flag)[] PersistencePatterns =
    [
        (@"currentversion\\run", 40, "Registry Run key"),
        (@"schtasks\s+/create", 35, "Scheduled task creation"),
        (@"sc\s+(create|config)", 35, "Service creation/modification"),
        ("startup", 20, "Startup folder reference"),
        ("new-service", 35, "PowerShell service creation"),
        (@"wmi.*__eventconsumer", 45, "WMI event subscription persistence"),
        ("register-wmievent", 40, "WMI event registration"),
        (@"new-itemproperty.*\\run", 40, "Registry Run key via PowerShell"),
    ];

    // ── Evasion patterns ──────────────────────────────────────
    private static readonly (string Pattern, int Score, string Flag)[] EvasionPatterns =
    [
        ("amsiutils", 60, "AMSI bypass attempt"),
        ("amsiinitfailed", 70, "AMSI initialization bypass"),
        (@"set-mppreference.*-disablerealtimemonitoring", 80, "Defender real-time disabled"),
        (@"add-mppreference.*-exclusionpath", 60, "Defender exclusion added"),
        (@"stop-service.*windefend", 80, "Defender service stopped"),
        (@"unloadall.*clm", 50, "Constrained Language Mode bypass"),
        (@"etw.*patch|etweventwrite", 60, "ETW patching (log evasion)"),
        (@"del\s+.*\\prefetch\\", 40, "Prefetch deletion (anti-forensics)"),
        (@"clear-eventlog|wevtutil\s+cl", 50, "Event log clearing"),
        (@"remove-item.*-recurse.*\\logs", 30, "Log file deletion"),
    ];

    public BehaviorResult Analyze(int processId, string? commandLine, string? filePath)
    {
        var result = new BehaviorResult
        {
            ProcessId = processId,
            CommandLine = commandLine
        };

        try
        {
            // Get process info via WMI
            if (processId > 0)
            {
                GetProcessInfo(result, processId, ref commandLine);
            }
            else if (!string.IsNullOrEmpty(commandLine))
            {
                var match = Regex.Match(commandLine, @"([^\\/]+\.exe)", RegexOptions.IgnoreCase);
                if (match.Success) result.ProcessName = match.Groups[1].Value.ToLower();
            }

            string cmdLower = (commandLine ?? "").ToLower();
            string procNameLower = result.ProcessName.ToLower();

            // LOLBin detection
            CheckLOLBins(result, procNameLower, cmdLower);

            // Parent-child anomaly
            CheckParentChild(result);

            // Command-line heuristics
            RunPatternChecks(result, cmdLower, CommandHeuristics, result.CommandFlags, "CommandFlag");

            // Injection indicators
            RunSimplePatternChecks(result, cmdLower, InjectionPatterns, result.InjectionIndicators, "Injection");

            // Persistence indicators
            RunSimplePatternChecks(result, cmdLower, PersistencePatterns, result.PersistenceIndicators, "Persistence");

            // Evasion indicators
            RunSimplePatternChecks(result, cmdLower, EvasionPatterns, result.EvasionIndicators, "Evasion");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Behavior analysis error for PID {processId}: {ex.Message}");
        }

        return result;
    }

    private static void GetProcessInfo(BehaviorResult result, int pid, ref string? commandLine)
    {
        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(pid);
            result.ProcessName = proc.ProcessName;

            // Get command line and parent via WMI
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                commandLine ??= obj["CommandLine"]?.ToString();
                result.CommandLine = commandLine;
                result.ParentPID = Convert.ToInt32(obj["ParentProcessId"]);
            }

            // Get parent name
            if (result.ParentPID > 0)
            {
                try
                {
                    var parent = System.Diagnostics.Process.GetProcessById(result.ParentPID);
                    result.ParentName = parent.ProcessName;
                }
                catch { /* parent may have exited */ }
            }
        }
        catch { /* process may have exited */ }
    }

    private static void CheckLOLBins(BehaviorResult result, string procName, string cmdLine)
    {
        foreach (var (binary, (risk, suspiciousArgs)) in LOLBins)
        {
            string binaryLower = binary.ToLower();
            string binaryNoExt = Path.GetFileNameWithoutExtension(binary).ToLower();

            if (procName != binaryLower && procName != binaryNoExt) continue;

            result.IsLOLBin = true;
            var matchedArgs = suspiciousArgs
                .Where(arg => cmdLine.Contains(arg, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedArgs.Count > 0)
            {
                result.LOLBinDetails = new LOLBinDetail
                {
                    Binary = binary,
                    Risk = risk,
                    MatchedArgs = matchedArgs
                };
                result.Score += 20 + matchedArgs.Count * 10;
                result.Indicators.Add($"LOLBin abuse: {binary} with args: {string.Join(", ", matchedArgs)}");
            }
            break;
        }
    }

    private static void CheckParentChild(BehaviorResult result)
    {
        string parentLower = result.ParentName.ToLower();
        string childLower = result.ProcessName.ToLower();

        foreach (var (parent, child, score, desc) in SuspiciousParentChild)
        {
            if (parentLower.Contains(parent, StringComparison.OrdinalIgnoreCase) &&
                childLower.Contains(child, StringComparison.OrdinalIgnoreCase))
            {
                result.ParentChildFlag = new ParentChildFlag
                {
                    Parent = parent, Child = child, Description = desc, Score = score
                };
                result.Score += score;
                result.Indicators.Add($"Suspicious parent-child: {desc}");
                break;
            }
        }
    }

    private static void RunPatternChecks(BehaviorResult result, string cmdLine,
        (string Pattern, int Score, string Flag)[] patterns,
        List<HeuristicFlag> flagList, string category)
    {
        foreach (var (pattern, score, flag) in patterns)
        {
            if (Regex.IsMatch(cmdLine, pattern, RegexOptions.IgnoreCase))
            {
                flagList.Add(new HeuristicFlag { Flag = flag, Score = score });
                result.Score += score;
                result.Indicators.Add($"{category}: {flag}");
            }
        }
    }

    private static void RunSimplePatternChecks(BehaviorResult result, string cmdLine,
        (string Pattern, int Score, string Flag)[] patterns,
        List<string> indicatorList, string category)
    {
        foreach (var (pattern, score, flag) in patterns)
        {
            if (Regex.IsMatch(cmdLine, pattern, RegexOptions.IgnoreCase))
            {
                indicatorList.Add(flag);
                result.Score += score;
                result.Indicators.Add($"{category}: {flag}");
            }
        }
    }
}
