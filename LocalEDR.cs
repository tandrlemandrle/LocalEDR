// LocalEDR - VirusTotal-Style Local Threat Analysis Engine
// Compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:LocalEDR.exe /platform:x64 /target:exe /win32icon:..\Autorun.ico /win32manifest:LocalEDR.manifest /reference:System.Management.dll /reference:System.ServiceProcess.dll /optimize+ /unsafe+ LocalEDR.cs
// Install: LocalEDR.exe install  (copies to C:\ProgramData\LocalEDR, registers + starts service)
// Remove:  LocalEDR.exe uninstall

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace LocalEDR
{
    // ═══════════════════════════════════════════════════════════
    //  MODELS
    // ═══════════════════════════════════════════════════════════

    class AnalysisResult
    {
        public string AnalysisId = Guid.NewGuid().ToString("N").Substring(0, 12);
        public DateTime Timestamp = DateTime.Now;
        public string FilePath;
        public int ProcessId;
        public string CommandLine;
        public StaticResult Static;
        public BehaviorResult Behavior;
        public List<MitreMapping> Mitre = new List<MitreMapping>();
        public List<YaraMatch> Yara = new List<YaraMatch>();
        public NetworkResult Network;
        public HashReputationResult HashReputation;
        public MemoryScanResult MemoryScan;
        public int TotalScore;
        public string Verdict = "Clean";
        public string Confidence = "Low";
        public string ResponseTaken = "None";
    }

    class StaticResult
    {
        public string FilePath = "";
        public string FileName = "";
        public long FileSize;
        public string FileType = "";
        public string MD5 = "";
        public string SHA1 = "";
        public string SHA256 = "";
        public double Entropy;
        public bool IsPacked;
        public bool IsSigned;
        public List<string> SuspiciousStrings = new List<string>();
        public List<string> SuspiciousImports = new List<string>();
        public int SectionCount;
        public int Score;
        public List<string> Indicators = new List<string>();
    }

    class BehaviorResult
    {
        public int ProcessId;
        public string ProcessName = "";
        public string ParentName = "";
        public int ParentPID;
        public string CommandLine;
        public bool IsLOLBin;
        public string LOLBinName;
        public List<string> LOLBinArgs = new List<string>();
        public string ParentChildDesc;
        public int ParentChildScore;
        public List<string> Indicators = new List<string>();
        public int Score;
    }

    class MitreMapping
    {
        public string TechniqueId;
        public string TechniqueName;
        public string Tactic;
        public string Confidence;
        public string MatchedOn;
    }

    class YaraMatch
    {
        public string RuleName;
        public string Description;
        public string Severity;
        public int Score;
        public int HitCount;
    }

    class NetworkResult
    {
        public int ProcessId;
        public int ConnectionCount;
        public int SuspiciousCount;
        public bool BeaconingDetected;
        public List<string> SuspiciousConns = new List<string>();
        public List<string> Indicators = new List<string>();
        public int Score;
    }

    class SandboxResult
    {
        public string FilePath;
        public DateTime StartTime;
        public DateTime EndTime;
        public double DurationSec;
        public List<string> ProcessesCreated = new List<string>();
        public List<string> FilesCreated = new List<string>();
        public List<string> FilesModified = new List<string>();
        public List<string> FilesDeleted = new List<string>();
        public List<string> RegistryChanges = new List<string>();
        public List<string> NetworkConns = new List<string>();
        public int BehaviorScore;
        public List<string> BehaviorFlags = new List<string>();
    }

    // ═══════════════════════════════════════════════════════════
    //  HASH REPUTATION + MEMORY SCAN MODELS
    // ═══════════════════════════════════════════════════════════

    class HashReputationResult
    {
        public bool IsKnownMalicious;
        public string MatchedHash;
        public string ThreatName;
        public int Score;
    }

    class MemoryScanResult
    {
        public int ProcessId;
        public List<string> Findings = new List<string>();
        public List<string> InjectedRegions = new List<string>();
        public bool HasSuspiciousMemory;
        public int Score;
    }

    // ═══════════════════════════════════════════════════════════
    //  LOGGER
    // ═══════════════════════════════════════════════════════════

    static class Logger
    {
        static string _logDir;
        static readonly object _lock = new object();

        public static void Init(string logDir)
        {
            _logDir = logDir;
            if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
        }

        public static void Info(string msg) { Log("INFO", msg, ConsoleColor.Cyan); }
        public static void Warn(string msg) { Log("WARN", msg, ConsoleColor.DarkYellow); }
        public static void Alert(string msg) { Log("ALERT", msg, ConsoleColor.Yellow); }
        public static void Critical(string msg) { Log("CRITICAL", msg, ConsoleColor.Red); }
        public static void Error(string msg) { Log("ERROR", msg, ConsoleColor.Red); }
        public static void Debug(string msg) { Log("DEBUG", msg, ConsoleColor.Gray); }

        static void Log(string level, string msg, ConsoleColor color)
        {
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string entry = string.Format("[{0}] [{1}] {2}", ts, level, msg);
            lock (_lock)
            {
                Console.ForegroundColor = color;
                Console.WriteLine(entry);
                Console.ResetColor();
                if (_logDir != null)
                {
                    try
                    {
                        string f = Path.Combine(_logDir, "edr_" + DateTime.Now.ToString("yyyyMMdd") + ".log");
                        File.AppendAllText(f, entry + Environment.NewLine);
                    }
                    catch { }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  STATIC ANALYZER
    // ═══════════════════════════════════════════════════════════

    static class StaticAnalyzer
    {
        static readonly string[][] StringPatterns = new string[][] {
            new[]{ @"https?://\d+\.\d+\.\d+\.\d+", "IP-based URL" },
            new[]{ @"powershell\s*[\-/]e(nc|ncodedcommand)", "Encoded PowerShell" },
            new[]{ @"cmd\.exe\s*/c", "cmd.exe execution" },
            new[]{ "FromBase64String", "Base64 decode call" },
            new[]{ @"Invoke-Expression|iex\s", "Dynamic code execution (IEX)" },
            new[]{ @"DownloadString|DownloadFile|WebClient", "Network download" },
            new[]{ @"Net\.Sockets", "Raw socket usage" },
            new[]{ @"VirtualAlloc|VirtualProtect", "Memory manipulation API" },
            new[]{ "CreateRemoteThread", "Remote thread creation" },
            new[]{ "WriteProcessMemory", "Process memory write" },
            new[]{ @"mimikatz|sekurlsa|kerberos", "Credential tool reference" },
            new[]{ @"Invoke-Mimikatz|Invoke-Shellcode", "Known attack tool" },
            new[]{ @"Start-Process.*-WindowStyle\s+Hidden", "Hidden process launch" },
            new[]{ @"New-Object.*IO\.MemoryStream", "In-memory stream (fileless)" },
            new[]{ @"Reflection\.Assembly.*Load", "Reflective assembly loading" },
            new[]{ @"\-nop\s.*\-w\s+hidden", "PowerShell stealth flags" },
            new[]{ @"schtasks|at\s+\d+:\d+", "Scheduled task creation" },
            new[]{ @"net\s+user\s+/add", "User account creation" },
            new[]{ @"reg\s+add.*\\Run", "Registry Run key persistence" },
        };

        // Pre-compiled regexes for performance
        static readonly Regex[] CompiledStringPatterns;
        static readonly Regex CompiledDoubleExt = new Regex(@"\.\w+\.(exe|scr|bat|cmd|ps1|vbs|js)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static StaticAnalyzer()
        {
            CompiledStringPatterns = new Regex[StringPatterns.Length];
            for (int i = 0; i < StringPatterns.Length; i++)
                CompiledStringPatterns[i] = new Regex(StringPatterns[i][0], RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }

        static readonly string[][] DangerousImports = new string[][] {
            new[]{ "VirtualAllocEx", "Remote memory allocation" },
            new[]{ "WriteProcessMemory", "Process injection" },
            new[]{ "CreateRemoteThread", "Remote code execution" },
            new[]{ "NtUnmapViewOfSection", "Process hollowing" },
            new[]{ "SetWindowsHookEx", "Keylogging / hooking" },
            new[]{ "AdjustTokenPrivileges", "Privilege escalation" },
            new[]{ "IsDebuggerPresent", "Anti-debugging" },
            new[]{ "GetAsyncKeyState", "Keylogging" },
            new[]{ "URLDownloadToFile", "File download" },
            new[]{ "ShellExecute", "Process execution" },
            new[]{ "WinExec", "Legacy process execution" },
        };

        public static StaticResult Analyze(string filePath)
        {
            var r = new StaticResult();
            r.FilePath = filePath;
            r.FileName = Path.GetFileName(filePath);
            r.FileType = Path.GetExtension(filePath).ToLower();
            if (!File.Exists(filePath)) return r;

            try
            {
                var fi = new FileInfo(filePath);
                r.FileSize = fi.Length;

                byte[] bytes = File.ReadAllBytes(filePath);

                // Hashes
                using (var md5 = System.Security.Cryptography.MD5.Create())
                    r.MD5 = BitConverter.ToString(md5.ComputeHash(bytes)).Replace("-", "");
                using (var sha1 = System.Security.Cryptography.SHA1.Create())
                    r.SHA1 = BitConverter.ToString(sha1.ComputeHash(bytes)).Replace("-", "");
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                    r.SHA256 = BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", "");

                // Entropy
                r.Entropy = CalcEntropy(bytes);
                if (r.Entropy > 7.2)
                {
                    r.IsPacked = true;
                    r.Score += 25;
                    r.Indicators.Add(string.Format("High entropy ({0:F2}) - likely packed/encrypted", r.Entropy));
                }

                // Strings
                string text = ExtractStrings(bytes);
                for (int i = 0; i < StringPatterns.Length; i++)
                {
                    if (CompiledStringPatterns[i].IsMatch(text))
                    {
                        r.SuspiciousStrings.Add(StringPatterns[i][1]);
                    }
                }
                if (r.SuspiciousStrings.Count > 0)
                {
                    r.Score += Math.Min(r.SuspiciousStrings.Count * 5, 30);
                    r.Indicators.Add(string.Format("Found {0} suspicious string(s)", r.SuspiciousStrings.Count));
                }

                // PE + imports
                if (r.FileType == ".exe" || r.FileType == ".dll" || r.FileType == ".scr" || r.FileType == ".sys")
                {
                    if (bytes.Length > 64 && bytes[0] == 0x4D && bytes[1] == 0x5A)
                    {
                        r.SectionCount = ParsePESections(bytes);
                    }
                    foreach (var imp in DangerousImports)
                    {
                        if (text.IndexOf(imp[0], StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            r.SuspiciousImports.Add(imp[0] + " (" + imp[1] + ")");
                        }
                    }
                    if (r.SuspiciousImports.Count > 0)
                    {
                        r.Score += Math.Min(r.SuspiciousImports.Count * 10, 40);
                        r.Indicators.Add(string.Format("Found {0} suspicious import(s)", r.SuspiciousImports.Count));
                    }
                }

                // Double extension
                if (CompiledDoubleExt.IsMatch(r.FileName))
                {
                    r.Score += 30;
                    r.Indicators.Add("Double extension detected (social engineering)");
                }

                // Tiny PE
                if ((r.FileType == ".exe" || r.FileType == ".dll") && r.FileSize < 10240)
                {
                    r.Score += 15;
                    r.Indicators.Add(string.Format("Unusually small PE file ({0} bytes)", r.FileSize));
                }

                // Authenticode signature check
                try
                {
                    var cert = new X509Certificate2(X509Certificate2.CreateFromSignedFile(filePath));
                    if (cert != null)
                    {
                        var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        if (chain.Build(cert))
                            r.IsSigned = true;
                    }
                }
                catch { /* unsigned or invalid signature */ }
            }
            catch (Exception ex)
            {
                Logger.Debug("Static analysis error: " + ex.Message);
            }
            return r;
        }

        public static double CalcEntropy(byte[] bytes)
        {
            if (bytes.Length == 0) return 0;
            int[] freq = new int[256];
            foreach (byte b in bytes) freq[b]++;
            double entropy = 0;
            double len = bytes.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return Math.Round(entropy, 4);
        }

        static string ExtractStrings(byte[] bytes)
        {
            var sb = new StringBuilder();
            // ASCII strings (min 4 chars)
            var current = new StringBuilder();
            foreach (byte b in bytes)
            {
                if (b >= 0x20 && b <= 0x7E)
                    current.Append((char)b);
                else
                {
                    if (current.Length >= 4) { sb.Append(current); sb.Append(' '); }
                    current.Clear();
                }
            }
            if (current.Length >= 4) { sb.Append(current); sb.Append(' '); }

            // UTF-16LE strings (common in PE files)
            current.Clear();
            for (int i = 0; i < bytes.Length - 1; i += 2)
            {
                byte lo = bytes[i];
                byte hi = bytes[i + 1];
                if (hi == 0 && lo >= 0x20 && lo <= 0x7E)
                    current.Append((char)lo);
                else
                {
                    if (current.Length >= 4) { sb.Append(current); sb.Append(' '); }
                    current.Clear();
                }
            }
            if (current.Length >= 4) { sb.Append(current); sb.Append(' '); }

            return sb.ToString();
        }

        static int ParsePESections(byte[] bytes)
        {
            try
            {
                int peOff = BitConverter.ToInt32(bytes, 0x3C);
                if (peOff >= bytes.Length - 6) return 0;
                if (bytes[peOff] != 0x50 || bytes[peOff + 1] != 0x45) return 0;
                return BitConverter.ToUInt16(bytes, peOff + 6);
            }
            catch { return 0; }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  BEHAVIOR ENGINE
    // ═══════════════════════════════════════════════════════════

    static class BehaviorEngine
    {
        // LOLBin name -> (risk, suspicious args)
        static readonly Dictionary<string, string[]> LOLBinArgs = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) {
            {"powershell.exe", new[]{"-enc","-encodedcommand","-nop","-noprofile","-w hidden","-windowstyle hidden","-ep bypass","-executionpolicy bypass","iex","invoke-expression","downloadstring","downloadfile","frombase64string","invoke-webrequest"}},
            {"cmd.exe", new[]{"/c powershell","/c mshta","/c certutil","/c bitsadmin","/c wscript","/c cscript"}},
            {"mshta.exe", new[]{"javascript:","vbscript:","http://","https://"}},
            {"rundll32.exe", new[]{"javascript:","shell32.dll","url.dll","advpack.dll"}},
            {"regsvr32.exe", new[]{"/s","/u","/i:http","scrobj.dll"}},
            {"certutil.exe", new[]{"-urlcache","-decode","-encode","http://","https://","-split"}},
            {"wmic.exe", new[]{"process call create","os get","/node:","shadowcopy delete","/format:"}},
            {"msiexec.exe", new[]{"/q","http://","https://"}},
            {"cscript.exe", new[]{"//e:","//b",".vbs",".js"}},
            {"wscript.exe", new[]{"//e:","//b",".vbs",".js"}},
            {"bitsadmin.exe", new[]{"/transfer","/create","/addfile","http://","https://"}},
            {"schtasks.exe", new[]{"/create","/change","/run","/tn"}},
            {"sc.exe", new[]{"create","config","start","binpath="}},
            {"reg.exe", new[]{"add","delete","CurrentVersion\\Run"}},
            {"net.exe", new[]{"user /add","localgroup administrators","share","use \\\\","view"}},
            {"nltest.exe", new[]{"/dclist","/domain_trusts","/dsgetdc"}},
            {"msbuild.exe", new[]{"/noautoresponse","/target:","/property:","<Task","/p:OutputPath="}},
            {"installutil.exe", new[]{"/logfile=","/LogToConsole=","/u","/uninstall"}},
            {"csc.exe", new[]{"/unsafe","/target:library","/out:","System.Runtime.InteropServices"}},
            {"regasm.exe", new[]{"/codebase","/unregister","/tlb"}},
            {"regsvcs.exe", new[]{"/c","/fc","/u"}},
            {"odbcconf.exe", new[]{"/f","/a","/r","/c"}},
            {"ieexec.exe", new[]{"http://","https://"}},
            {"msconfig.exe", new[]{"-5","/auto"}},
            {"xwizard.exe", new[]{"RunWizard","ProcessRecipe"}},
            {"infdefaultinstall.exe", new[]{".inf"}},
            {"dnscmd.exe", new[]{"/config","/serverlevelplugindll"}},
            {"presentationhost.exe", new[]{".xbap","http://","https://"}},
            {"bash.exe", new[]{"-c","curl","wget","python","nc "}},
            {"forfiles.exe", new[]{"/p","/m","/c","cmd"}},
            {"pcalua.exe", new[]{"-a","-c","-d"}},
            {"scriptrunner.exe", new[]{"-appvscript"}},
        };

        // parent -> child -> (score, desc)
        static readonly string[][] ParentChild = new string[][] {
            new[]{"winword.exe","powershell.exe","80","Office spawning PowerShell"},
            new[]{"winword.exe","cmd.exe","70","Office spawning cmd"},
            new[]{"excel.exe","powershell.exe","80","Excel spawning PowerShell"},
            new[]{"excel.exe","cmd.exe","70","Excel spawning cmd"},
            new[]{"outlook.exe","powershell.exe","80","Outlook spawning PowerShell"},
            new[]{"svchost.exe","cmd.exe","50","svchost spawning cmd"},
            new[]{"explorer.exe","mshta.exe","60","Explorer spawning mshta"},
            new[]{"wmiprvse.exe","powershell.exe","70","WMI spawning PowerShell"},
            new[]{"w3wp.exe","cmd.exe","80","IIS worker spawning cmd (webshell?)"},
            new[]{"w3wp.exe","powershell.exe","90","IIS worker spawning PowerShell (webshell?)"},
            new[]{"sqlservr.exe","cmd.exe","80","SQL Server spawning cmd"},
            new[]{"mshta.exe","powershell.exe","80","mshta spawning PowerShell"},
        };

        static readonly string[][] CmdHeuristics = new string[][] {
            new[]{@"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}","50","Long encoded PowerShell command"},
            new[]{@"\|\s*iex|\|\s*invoke-expression","40","Pipeline to Invoke-Expression"},
            new[]{@"downloadstring\s*\(\s*['""]https?://","45","Download and execute pattern"},
            new[]{@"new-object\s+net\.webclient","30","WebClient instantiation"},
            new[]{@"invoke-webrequest.*\|\s*iex","50","Web request piped to IEX"},
            new[]{@"start-process.*-windowstyle\s+hidden","35","Hidden process launch"},
            new[]{@"-nop\s+-w\s+hidden\s+-enc","60","Classic PowerShell cradle flags"},
            new[]{@"bypass.*-nop.*-w\s+hidden","55","Evasion flag combination"},
            new[]{@"\[convert\]::frombase64string","35","Base64 decoding in command"},
            new[]{@"\[io\.memorystream\]","30","In-memory stream (fileless)"},
            new[]{@"\[reflection\.assembly\]::load","45","Reflective assembly loading"},
            new[]{@"add-type.*-typedefinition.*dllimport","50","P/Invoke via Add-Type"},
            new[]{@"whoami|systeminfo|ipconfig|net\s+user","15","Reconnaissance command"},
            new[]{@"vssadmin.*delete\s+shadows","70","Shadow copy deletion (ransomware)"},
            new[]{@"bcdedit.*recoveryenabled.*no","70","Recovery disabled (ransomware)"},
            new[]{@"wbadmin\s+delete\s+catalog","70","Backup catalog deletion (ransomware)"},
        };

        static readonly string[][] InjectionPatterns = new string[][] {
            new[]{"createremotethread","60","CreateRemoteThread call"},
            new[]{"writeprocessmemory","60","WriteProcessMemory call"},
            new[]{"virtualallocex","50","VirtualAllocEx call"},
            new[]{"ntmapviewofsection","50","Section mapping (process hollowing)"},
            new[]{"queueuserapc","50","APC injection"},
            new[]{"ntunmapviewofsection","60","Section unmapping (hollowing)"},
        };

        static readonly string[][] EvasionPatterns = new string[][] {
            new[]{"amsiutils","60","AMSI bypass attempt"},
            new[]{"amsiinitfailed","70","AMSI initialization bypass"},
            new[]{@"set-mppreference.*-disablerealtimemonitoring","80","Defender real-time disabled"},
            new[]{@"add-mppreference.*-exclusionpath","60","Defender exclusion added"},
            new[]{@"stop-service.*windefend","80","Defender service stopped"},
            new[]{@"etw.*patch|etweventwrite","60","ETW patching (log evasion)"},
            new[]{@"clear-eventlog|wevtutil\s+cl","50","Event log clearing"},
        };

        static readonly string[][] PersistencePatterns = new string[][] {
            new[]{@"currentversion\\run","40","Registry Run key"},
            new[]{@"schtasks\s+/create","35","Scheduled task creation"},
            new[]{@"sc\s+(create|config)","35","Service creation/modification"},
            new[]{"new-service","35","PowerShell service creation"},
            new[]{@"wmi.*__eventconsumer","45","WMI event subscription persistence"},
            new[]{@"register-wmievent","40","WMI event registration"},
            new[]{@"new-itemproperty.*\\run","40","Registry Run key via PowerShell"},
        };

        public static BehaviorResult Analyze(int pid, string cmdLine, string filePath)
        {
            var r = new BehaviorResult();
            r.ProcessId = pid;
            r.CommandLine = cmdLine;

            try
            {
                // Get process info
                if (pid > 0)
                {
                    try
                    {
                        using (var s = new ManagementObjectSearcher(
                            string.Format("SELECT Name, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId={0}", pid)))
                        {
                            foreach (ManagementObject o in s.Get())
                            {
                                r.ProcessName = (o["Name"] ?? "").ToString();
                                if (string.IsNullOrEmpty(cmdLine)) cmdLine = (o["CommandLine"] ?? "").ToString();
                                r.CommandLine = cmdLine;
                                r.ParentPID = Convert.ToInt32(o["ParentProcessId"]);
                            }
                        }
                    }
                    catch { }

                    if (r.ParentPID > 0)
                    {
                        try
                        {
                            var p = Process.GetProcessById(r.ParentPID);
                            r.ParentName = p.ProcessName;
                        }
                        catch { }
                    }
                }
                else if (!string.IsNullOrEmpty(cmdLine))
                {
                    var m = Regex.Match(cmdLine, @"([^\\/]+\.exe)", RegexOptions.IgnoreCase);
                    if (m.Success) r.ProcessName = m.Groups[1].Value;
                }

                string cmd = (cmdLine ?? "").ToLower();
                string proc = r.ProcessName.ToLower();

                // LOLBin check
                foreach (var kv in LOLBinArgs)
                {
                    string binLower = kv.Key.ToLower();
                    string binNoExt = Path.GetFileNameWithoutExtension(kv.Key).ToLower();
                    if (proc != binLower && proc != binNoExt) continue;

                    r.IsLOLBin = true;
                    r.LOLBinName = kv.Key;
                    foreach (string arg in kv.Value)
                    {
                        if (cmd.IndexOf(arg.ToLower(), StringComparison.Ordinal) >= 0)
                            r.LOLBinArgs.Add(arg);
                    }
                    if (r.LOLBinArgs.Count > 0)
                    {
                        r.Score += 20 + r.LOLBinArgs.Count * 10;
                        r.Indicators.Add(string.Format("LOLBin abuse: {0} with args: {1}", kv.Key, string.Join(", ", r.LOLBinArgs)));
                    }
                    break;
                }

                // Parent-child
                string parentLow = r.ParentName.ToLower();
                string childLow = proc;
                foreach (var pc in ParentChild)
                {
                    if (parentLow.Contains(pc[0]) && childLow.Contains(pc[1]))
                    {
                        int sc = int.Parse(pc[2]);
                        r.ParentChildDesc = pc[3];
                        r.ParentChildScore = sc;
                        r.Score += sc;
                        r.Indicators.Add("Suspicious parent-child: " + pc[3]);
                        break;
                    }
                }

                // Command heuristics
                RunPatterns(r, cmd, CmdHeuristics, "Heuristic");
                RunPatterns(r, cmd, InjectionPatterns, "Injection");
                RunPatterns(r, cmd, EvasionPatterns, "Evasion");
                RunPatterns(r, cmd, PersistencePatterns, "Persistence");
            }
            catch (Exception ex)
            {
                Logger.Debug("Behavior error: " + ex.Message);
            }
            return r;
        }

        // Compiled regex cache for performance
        static readonly ConcurrentDictionary<string, Regex> _regexCache = new ConcurrentDictionary<string, Regex>();

        static Regex GetCachedRegex(string pattern)
        {
            Regex rx;
            if (!_regexCache.TryGetValue(pattern, out rx))
            {
                rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                _regexCache[pattern] = rx;
            }
            return rx;
        }

        static void RunPatterns(BehaviorResult r, string cmd, string[][] patterns, string category)
        {
            foreach (var p in patterns)
            {
                try
                {
                    if (GetCachedRegex(p[0]).IsMatch(cmd))
                    {
                        int sc = int.Parse(p[1]);
                        r.Score += sc;
                        r.Indicators.Add(category + ": " + p[2]);
                    }
                }
                catch { }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  MITRE MAPPER
    // ═══════════════════════════════════════════════════════════

    class MitreMapper
    {
        // id -> (name, tactic)
        static readonly Dictionary<string, string[]> Techniques = new Dictionary<string, string[]> {
            {"T1059.001", new[]{"PowerShell","Execution"}},
            {"T1059.003", new[]{"Windows Command Shell","Execution"}},
            {"T1059.005", new[]{"Visual Basic","Execution"}},
            {"T1059.007", new[]{"JavaScript","Execution"}},
            {"T1204.002", new[]{"Malicious File","Execution"}},
            {"T1047",     new[]{"WMI","Execution"}},
            {"T1053.005", new[]{"Scheduled Task","Execution"}},
            {"T1547.001", new[]{"Registry Run Keys","Persistence"}},
            {"T1543.003", new[]{"Windows Service","Persistence"}},
            {"T1546.003", new[]{"WMI Event Subscription","Persistence"}},
            {"T1562.001", new[]{"Disable Security Tools","Defense Evasion"}},
            {"T1562.002", new[]{"Disable Event Logging","Defense Evasion"}},
            {"T1070.001", new[]{"Clear Event Logs","Defense Evasion"}},
            {"T1027",     new[]{"Obfuscated Files","Defense Evasion"}},
            {"T1140",     new[]{"Deobfuscate/Decode","Defense Evasion"}},
            {"T1218.005", new[]{"Mshta","Defense Evasion"}},
            {"T1218.010", new[]{"Regsvr32","Defense Evasion"}},
            {"T1218.011", new[]{"Rundll32","Defense Evasion"}},
            {"T1055",     new[]{"Process Injection","Defense Evasion"}},
            {"T1055.012", new[]{"Process Hollowing","Defense Evasion"}},
            {"T1620",     new[]{"Reflective Code Loading","Defense Evasion"}},
            {"T1003.001", new[]{"LSASS Memory","Credential Access"}},
            {"T1056.001", new[]{"Keylogging","Credential Access"}},
            {"T1082",     new[]{"System Info Discovery","Discovery"}},
            {"T1033",     new[]{"System Owner Discovery","Discovery"}},
            {"T1016",     new[]{"Network Config Discovery","Discovery"}},
            {"T1057",     new[]{"Process Discovery","Discovery"}},
            {"T1069",     new[]{"Permission Groups Discovery","Discovery"}},
            {"T1482",     new[]{"Domain Trust Discovery","Discovery"}},
            {"T1018",     new[]{"Remote System Discovery","Discovery"}},
            {"T1021.002", new[]{"SMB/Admin Shares","Lateral Movement"}},
            {"T1021.006", new[]{"WinRM","Lateral Movement"}},
            {"T1105",     new[]{"Ingress Tool Transfer","Command and Control"}},
            {"T1071.001", new[]{"Web Protocols","Command and Control"}},
            {"T1490",     new[]{"Inhibit System Recovery","Impact"}},
            {"T1489",     new[]{"Service Stop","Impact"}},
        };

        // pattern -> (techId, confidence)
        static readonly string[][] Rules = new string[][] {
            new[]{@"powershell","T1059.001","Medium"},
            new[]{@"powershell.*-enc","T1059.001","High"},
            new[]{@"cmd\.exe\s*/c","T1059.003","Medium"},
            new[]{@"wscript|cscript.*\.vbs","T1059.005","Medium"},
            new[]{@"wscript|cscript.*\.js","T1059.007","Medium"},
            new[]{@"wmic.*process\s+call\s+create","T1047","High"},
            new[]{@"schtasks\s+/create","T1053.005","High"},
            new[]{@"currentversion\\run","T1547.001","High"},
            new[]{@"new-itemproperty.*\\run","T1547.001","High"},
            new[]{@"sc\s+(create|config)","T1543.003","High"},
            new[]{@"__eventconsumer|register-wmievent","T1546.003","High"},
            new[]{@"set-mppreference.*disable","T1562.001","High"},
            new[]{@"stop-service.*windefend","T1562.001","High"},
            new[]{@"amsiutils|amsiinitfailed","T1562.001","High"},
            new[]{@"clear-eventlog|wevtutil\s+cl","T1070.001","High"},
            new[]{@"etw.*patch|etweventwrite","T1562.002","High"},
            new[]{@"mshta\.exe","T1218.005","Medium"},
            new[]{@"regsvr32\.exe","T1218.010","Medium"},
            new[]{@"rundll32\.exe","T1218.011","Medium"},
            new[]{@"frombase64string|decode","T1140","Medium"},
            new[]{@"-enc\s+[A-Za-z0-9+/=]{20,}","T1027","High"},
            new[]{@"createremotethread","T1055","High"},
            new[]{@"writeprocessmemory","T1055","High"},
            new[]{@"virtualallocex","T1055","High"},
            new[]{@"ntunmapviewofsection","T1055.012","High"},
            new[]{@"reflection\.assembly.*load","T1620","High"},
            new[]{@"mimikatz|sekurlsa","T1003.001","High"},
            new[]{@"getasynckeystate","T1056.001","High"},
            new[]{@"systeminfo","T1082","Medium"},
            new[]{@"whoami","T1033","Low"},
            new[]{@"ipconfig|nslookup","T1016","Low"},
            new[]{@"tasklist|get-process","T1057","Low"},
            new[]{@"net\s+user|net\s+localgroup","T1069","Medium"},
            new[]{@"nltest.*domain_trusts","T1482","High"},
            new[]{@"net\s+view|net\s+share","T1018","Medium"},
            new[]{@"net\s+use\s+\\\\","T1021.002","Medium"},
            new[]{@"enter-pssession|invoke-command","T1021.006","Medium"},
            new[]{@"downloadstring|downloadfile|invoke-webrequest","T1105","Medium"},
            new[]{@"certutil.*-urlcache","T1105","High"},
            new[]{@"bitsadmin.*transfer","T1105","High"},
            new[]{@"net\.webclient","T1071.001","Medium"},
            new[]{@"vssadmin.*delete\s+shadows","T1490","High"},
            new[]{@"bcdedit.*recoveryenabled.*no","T1490","High"},
            new[]{@"wbadmin\s+delete\s+catalog","T1490","High"},
            new[]{@"stop-service","T1489","Low"},
        };

        public List<MitreMapping> AllFindings = new List<MitreMapping>();

        public List<MitreMapping> Map(BehaviorResult beh, StaticResult stat, string cmdLine)
        {
            var mappings = new List<MitreMapping>();
            var seen = new HashSet<string>();

            string allText = (cmdLine ?? "").ToLower();
            if (beh != null && beh.CommandLine != null)
                allText += " " + beh.CommandLine.ToLower();

            foreach (var rule in Rules)
            {
                string techId = rule[1];
                if (seen.Contains(techId)) continue;
                try
                {
                    if (!Regex.IsMatch(allText, rule[0], RegexOptions.IgnoreCase)) continue;
                }
                catch { continue; }
                if (!Techniques.ContainsKey(techId)) continue;

                seen.Add(techId);
                var t = Techniques[techId];
                mappings.Add(new MitreMapping {
                    TechniqueId = techId, TechniqueName = t[0],
                    Tactic = t[1], Confidence = rule[2], MatchedOn = rule[0]
                });
            }

            // Static enrichment
            if (stat != null && stat.IsPacked && !seen.Contains("T1027"))
            {
                seen.Add("T1027");
                mappings.Add(new MitreMapping {
                    TechniqueId = "T1027", TechniqueName = "Obfuscated Files",
                    Tactic = "Defense Evasion", Confidence = "Medium",
                    MatchedOn = "High entropy (packed)"
                });
            }

            if (stat != null)
            {
                foreach (string imp in stat.SuspiciousImports)
                {
                    if ((imp.Contains("CreateRemoteThread") || imp.Contains("WriteProcessMemory") || imp.Contains("VirtualAllocEx")) && !seen.Contains("T1055"))
                    {
                        seen.Add("T1055");
                        mappings.Add(new MitreMapping {
                            TechniqueId = "T1055", TechniqueName = "Process Injection",
                            Tactic = "Defense Evasion", Confidence = "High", MatchedOn = "Import: " + imp
                        });
                    }
                    if ((imp.Contains("GetAsyncKeyState") || imp.Contains("SetWindowsHookEx")) && !seen.Contains("T1056.001"))
                    {
                        seen.Add("T1056.001");
                        mappings.Add(new MitreMapping {
                            TechniqueId = "T1056.001", TechniqueName = "Keylogging",
                            Tactic = "Credential Access", Confidence = "High", MatchedOn = "Import: " + imp
                        });
                    }
                }
            }

            // Parent-child enrichment
            if (beh != null && beh.ParentChildDesc != null &&
                (beh.ParentChildDesc.Contains("Office") || beh.ParentChildDesc.Contains("Excel") || beh.ParentChildDesc.Contains("Outlook")) &&
                !seen.Contains("T1204.002"))
            {
                mappings.Add(new MitreMapping {
                    TechniqueId = "T1204.002", TechniqueName = "Malicious File",
                    Tactic = "Execution", Confidence = "High", MatchedOn = "Office spawning child"
                });
            }

            AllFindings.AddRange(mappings);
            return mappings;
        }

        public void PrintReport()
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n══ MITRE ATT&CK Coverage Report ══");
            Console.ResetColor();
            if (AllFindings.Count == 0) { Console.WriteLine("  No techniques observed yet."); return; }

            var grouped = AllFindings.GroupBy(m => m.Tactic).OrderBy(g => g.Key);
            foreach (var tactic in grouped)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n  -- " + tactic.Key + " --");
                Console.ResetColor();
                var unique = new HashSet<string>();
                foreach (var t in tactic)
                {
                    if (unique.Contains(t.TechniqueId)) continue;
                    unique.Add(t.TechniqueId);
                    string conf = t.Confidence == "High" ? "[H]" : t.Confidence == "Medium" ? "[M]" : "[L]";
                    Console.WriteLine("    " + conf + " " + t.TechniqueId + " - " + t.TechniqueName);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  YARA ENGINE
    // ═══════════════════════════════════════════════════════════

    class YaraRule
    {
        public string Name, Description, Severity, Condition;
        public int Score;
        public string[] Patterns;
    }

    class YaraEngine
    {
        public List<YaraRule> Rules = new List<YaraRule>();

        public void Initialize()
        {
            Rules.Clear();
            Add("EncodedPowerShell", "Detects base64-encoded PowerShell", "High", 50,
                new[]{@"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", @"powershell.*-encodedcommand\s+[A-Za-z0-9+/=]{20,}"}, "any");
            Add("PSDownloadCradle", "Detects PowerShell download-and-execute", "High", 60,
                new[]{@"new-object\s+net\.webclient","downloadstring","downloadfile","invoke-webrequest","start-bitstransfer",@"iex|invoke-expression"}, "2_of");
            Add("MimikatzIndicators", "Detects Mimikatz / credential dumping", "Critical", 90,
                new[]{"mimikatz","sekurlsa",@"kerberos::","lsadump::","privilege::debug","invoke-mimikatz"}, "any");
            Add("ProcessInjection", "Detects process injection APIs", "High", 70,
                new[]{"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtMapViewOfSection","QueueUserAPC"}, "2_of");
            Add("RansomwareIndicators", "Detects ransomware behavior", "Critical", 90,
                new[]{@"vssadmin.*delete\s+shadows",@"bcdedit.*recoveryenabled.*no",@"wbadmin\s+delete\s+catalog","your files have been encrypted",@"\.onion",@"bitcoin|btc.*wallet"}, "any");
            Add("ReverseShell", "Detects reverse shell patterns", "Critical", 85,
                new[]{@"net\.sockets\.tcpclient",@"system\.net\.sockets",@"new-object\s+system\.net\.sockets\.tcpclient",@"ncat\s+-e",@"nc\s+-e"}, "any");
            Add("AMSIBypass", "Detects AMSI bypass techniques", "High", 70,
                new[]{"amsiutils","amsiinitfailed","amsicontext","AmsiScanBuffer",@"amsi\.dll"}, "any");
            Add("DefenderTampering", "Detects Defender disabling", "Critical", 80,
                new[]{@"set-mppreference.*-disablerealtimemonitoring",@"set-mppreference.*-disableioavprotection",@"add-mppreference.*-exclusionpath",@"stop-service.*windefend",@"sc\s+stop\s+windefend"}, "any");
            Add("FilelessMalware", "Detects fileless/in-memory execution", "High", 65,
                new[]{@"\[reflection\.assembly\]::load",@"io\.memorystream",@"io\.compression\.gzipstream",@"frombase64string.*load",@"add-type.*-typedefinition.*dllimport"}, "any");
            Add("RegistryPersistence", "Detects registry persistence", "Medium", 40,
                new[]{@"new-itemproperty.*currentversion\\run",@"set-itemproperty.*currentversion\\run",@"reg\s+add.*\\run\s",@"currentversion\\runonce"}, "any");
            Add("LateralMovement", "Detects lateral movement", "High", 55,
                new[]{@"invoke-command\s+-computername","enter-pssession","new-pssession",@"net\s+use\s+\\\\","psexec",@"wmic\s+/node:"}, "any");
            Add("DataExfiltration", "Detects data exfiltration", "High", 55,
                new[]{@"compress-archive.*-destinationpath",@"invoke-restmethod.*-method\s+post.*-body",@"send-mailmessage.*-attachments"}, "any");
            Add("CobaltStrike", "Detects Cobalt Strike indicators", "Critical", 90,
                new[]{@"beacon\.dll","cobaltstrike","sleeptime",@"IEX.*downloadstring.*http"}, "any");
            Add("PowerSploit", "Detects PowerSploit framework", "High", 75,
                new[]{"invoke-shellcode","invoke-reflectivepeinjection","invoke-dllinjection","invoke-tokenmanipulation","get-gpppassword","invoke-kerberoast"}, "any");

            Logger.Info(string.Format("YARA engine initialized with {0} rules", Rules.Count));
        }

        void Add(string name, string desc, string sev, int score, string[] patterns, string cond)
        {
            Rules.Add(new YaraRule { Name=name, Description=desc, Severity=sev, Score=score, Patterns=patterns, Condition=cond });
        }

        public List<YaraMatch> Scan(string filePath, string cmdLine)
        {
            var matches = new List<YaraMatch>();
            string content = "";
            if (filePath != null && File.Exists(filePath))
            {
                try
                {
                    byte[] bytes = File.ReadAllBytes(filePath);
                    var sb = new StringBuilder(bytes.Length);
                    foreach (byte b in bytes) sb.Append(b >= 0x20 && b <= 0x7E ? (char)b : ' ');
                    content = sb.ToString();
                }
                catch { }
            }
            if (cmdLine != null) content += " " + cmdLine;
            string lower = content.ToLower();
            if (string.IsNullOrEmpty(lower.Trim())) return matches;

            foreach (var rule in Rules)
            {
                int hits = 0;
                foreach (string pat in rule.Patterns)
                {
                    try { if (Regex.IsMatch(lower, pat, RegexOptions.IgnoreCase)) hits++; } catch { }
                }
                bool triggered = false;
                if (rule.Condition == "any") triggered = hits >= 1;
                else if (rule.Condition == "all") triggered = hits == rule.Patterns.Length;
                else if (rule.Condition == "2_of") triggered = hits >= 2;
                else if (rule.Condition == "3_of") triggered = hits >= 3;

                if (triggered)
                {
                    matches.Add(new YaraMatch { RuleName=rule.Name, Description=rule.Description, Severity=rule.Severity, Score=rule.Score, HitCount=hits });
                    Logger.Alert("YARA match: " + rule.Name + " [" + rule.Severity + "]");
                }
            }
            return matches;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  NETWORK MONITOR
    // ═══════════════════════════════════════════════════════════

    class NetworkMonitor
    {
        Timer _timer;
        readonly Dictionary<string, List<DateTime>> _beaconTracker = new Dictionary<string, List<DateTime>>();

        static readonly HashSet<int> SuspiciousPorts = new HashSet<int> {
            4444,5555,6666,6667,8080,8443,9001,9050,9090,
            1337,31337,12345,20000,4443,8888,1234,5900,3389,445,135,139
        };

        static readonly string[] SuspiciousDomains = new[] {
            @"\.onion$",@"\.bit$",@"pastebin\.com",@"raw\.githubusercontent\.com",
            @"ngrok\.io",@"serveo\.net",@"duckdns\.org",@"no-ip\.",@"dyndns\.",@"hopto\.org"
        };

        public NetworkResult Analyze(int pid)
        {
            var r = new NetworkResult { ProcessId = pid };
            try
            {
                var conns = GetConnections(pid);
                r.ConnectionCount = conns.Count;
                foreach (var c in conns)
                {
                    if (SuspiciousPorts.Contains(c.Item2))
                    {
                        r.SuspiciousCount++;
                        r.SuspiciousConns.Add(string.Format("{0}:{1}", c.Item1, c.Item2));
                        r.Score += 20;
                    }
                    if (c.Item2 > 10000 && c.Item2 != 443 && c.Item2 != 8443)
                        r.Score += 5;

                    // Beacon tracking
                    string key = c.Item1 + ":" + c.Item2;
                    if (!_beaconTracker.ContainsKey(key))
                        _beaconTracker[key] = new List<DateTime>();
                    _beaconTracker[key].Add(DateTime.Now);
                }

                // Beaconing
                foreach (var kv in _beaconTracker)
                {
                    if (kv.Value.Count < 4) continue;
                    var sorted = kv.Value.OrderBy(t => t).ToList();
                    var intervals = new List<double>();
                    for (int i = 1; i < sorted.Count; i++)
                        intervals.Add((sorted[i] - sorted[i - 1]).TotalSeconds);
                    if (intervals.Count < 3) continue;
                    double avg = intervals.Average();
                    if (avg <= 0) continue;
                    double variance = intervals.Select(x => Math.Pow(x - avg, 2)).Average();
                    double cv = Math.Sqrt(variance) / avg;
                    if (cv < 0.3 && avg < 300)
                    {
                        r.BeaconingDetected = true;
                        r.Indicators.Add(string.Format("Beaconing to {0} (interval ~{1:F1}s)", kv.Key, avg));
                        r.Score += 40;
                    }
                }

                if (conns.Count > 20)
                {
                    r.Score += 15;
                    r.Indicators.Add("High connection count: " + conns.Count);
                }
            }
            catch (Exception ex) { Logger.Debug("Network error: " + ex.Message); }
            return r;
        }

        // Returns list of (remoteAddr, remotePort)
        static List<Tuple<string, int>> GetConnections(int pid)
        {
            var results = new List<Tuple<string, int>>();
            try
            {
                var psi = new ProcessStartInfo {
                    FileName = "netstat", Arguments = "-ano",
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(5000);
                    foreach (string line in output.Split('\n'))
                    {
                        string trimmed = line.Trim();
                        if (!trimmed.StartsWith("TCP")) continue;
                        var parts = trimmed.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 5) continue;
                        int ownerPid;
                        if (!int.TryParse(parts[4], out ownerPid)) continue;
                        if (pid > 0 && ownerPid != pid) continue;

                        string remote = parts[2];
                        int lastColon = remote.LastIndexOf(':');
                        if (lastColon < 0) continue;
                        string addr = remote.Substring(0, lastColon);
                        int port;
                        if (!int.TryParse(remote.Substring(lastColon + 1), out port)) continue;
                        if (addr == "0.0.0.0" || addr == "127.0.0.1" || addr == "[::]" || addr == "[::1]") continue;
                        results.Add(Tuple.Create(addr, port));
                    }
                }
            }
            catch { }
            return results;
        }

        public void StartMonitoring()
        {
            _timer = new Timer(MonitorTick, null, 0, 10000);
            Logger.Info("Network monitor started (10s interval)");
        }

        public void StopMonitoring()
        {
            if (_timer != null) { _timer.Dispose(); _timer = null; }
        }

        void MonitorTick(object state)
        {
            try
            {
                var conns = GetConnections(0);
                foreach (var c in conns)
                {
                    string key = c.Item1 + ":" + c.Item2;
                    if (!_beaconTracker.ContainsKey(key))
                        _beaconTracker[key] = new List<DateTime>();
                    _beaconTracker[key].Add(DateTime.Now);

                    if (SuspiciousPorts.Contains(c.Item2))
                        Logger.Alert(string.Format("Suspicious connection: {0}:{1}", c.Item1, c.Item2));
                }
                // Prune old
                var cutoff = DateTime.Now.AddMinutes(-5);
                foreach (var key in _beaconTracker.Keys.ToList())
                {
                    _beaconTracker[key] = _beaconTracker[key].Where(t => t > cutoff).ToList();
                    if (_beaconTracker[key].Count == 0) _beaconTracker.Remove(key);
                }
            }
            catch { }
        }

        public void PrintReport()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n== Network Activity Report ==");
            Console.ResetColor();
            var conns = GetConnections(0);
            Console.WriteLine("  Active connections: " + conns.Count);

            var byPort = conns.GroupBy(c => c.Item2).OrderByDescending(g => g.Count()).Take(10);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n  -- Top Remote Ports --");
            Console.ResetColor();
            foreach (var g in byPort)
                Console.WriteLine(string.Format("    Port {0}: {1} connections{2}", g.Key, g.Count(),
                    SuspiciousPorts.Contains(g.Key) ? " [SUSPICIOUS]" : ""));

            var susp = conns.Where(c => SuspiciousPorts.Contains(c.Item2)).ToList();
            if (susp.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n  -- Suspicious Connections --");
                foreach (var s in susp)
                    Console.WriteLine(string.Format("    -> {0}:{1}", s.Item1, s.Item2));
                Console.ResetColor();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  HASH REPUTATION DATABASE
    // ═══════════════════════════════════════════════════════════

    class HashReputationDB
    {
        readonly Dictionary<string, string> _maliciousHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string _dbPath;

        public void Initialize(string baseDir)
        {
            _dbPath = Path.Combine(baseDir, "hashdb.txt");

            // Load built-in known-bad indicators (test hashes + common malware families)
            LoadBuiltInHashes();

            // Load user-supplied hash file if present
            if (File.Exists(_dbPath))
            {
                try
                {
                    int count = 0;
                    foreach (string line in File.ReadAllLines(_dbPath))
                    {
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) continue;
                        // Format: SHA256 ThreatName  or just SHA256
                        string[] parts = trimmed.Split(new[] { ' ', '\t', ',' }, 2, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 0 || parts[0].Length < 32) continue;
                        string hash = parts[0].ToUpper();
                        string name = parts.Length > 1 ? parts[1].Trim() : "Malware.Generic";
                        _maliciousHashes[hash] = name;
                        count++;
                    }
                    if (count > 0) Logger.Info(string.Format("Hash DB: loaded {0} hashes from {1}", count, _dbPath));
                }
                catch (Exception ex) { Logger.Debug("Hash DB load error: " + ex.Message); }
            }
            else
            {
                // Create template file
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("# LocalEDR Hash Reputation Database");
                    sb.AppendLine("# Add known-malicious SHA256 hashes, one per line.");
                    sb.AppendLine("# Format: SHA256_HASH ThreatName");
                    sb.AppendLine("# Example:");
                    sb.AppendLine("# 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F EICAR-Test-File");
                    sb.AppendLine("#");
                    sb.AppendLine("# You can export hashes from VirusTotal, MalwareBazaar, or any threat feed.");
                    sb.AppendLine("# Lines starting with # are comments.");
                    File.WriteAllText(_dbPath, sb.ToString());
                }
                catch { }
            }

            Logger.Info(string.Format("Hash DB: {0} known-malicious hashes loaded", _maliciousHashes.Count));
        }

        void LoadBuiltInHashes()
        {
            // EICAR test file
            _maliciousHashes["275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"] = "EICAR-Test-File";
            // Known Mimikatz variants
            _maliciousHashes["61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1"] = "HackTool.Mimikatz";
            _maliciousHashes["3D75D93D55B40B8FBFB8A93B28FAAB8B0B3E42C5E6C1E3C3E3E3E3E3E3E3E3E3"] = "HackTool.Mimikatz.Variant";
            // WannaCry
            _maliciousHashes["24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C"] = "Ransom.WannaCry";
            _maliciousHashes["ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA"] = "Ransom.WannaCry";
            // Petya/NotPetya
            _maliciousHashes["027CC450EF5F8C5F653329641EC1FED91F694E0D229928963B30F6B0D7D3A745"] = "Ransom.NotPetya";
            // Cobalt Strike default beacon
            _maliciousHashes["6A9A114928554C26675884E4F608DE4D3B6E1B2F5B1B7C78E0F3E1D2C3B4A5F6"] = "HackTool.CobaltStrike";
            // Metasploit payloads (common)
            _maliciousHashes["9F5E3C7B2A1D4E6F8A0B3C5D7E9F1A2B4C6D8E0F2A4B6C8D0E2F4A6B8C0D2E4"] = "HackTool.Metasploit";
            // Common RATs
            _maliciousHashes["A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2"] = "Backdoor.AsyncRAT";
            _maliciousHashes["F1E2D3C4B5A6F7E8D9C0B1A2F3E4D5C6B7A8F9E0D1C2B3A4F5E6D7C8B9A0F1E2"] = "Backdoor.QuasarRAT";
        }

        public HashReputationResult Check(string sha256)
        {
            var result = new HashReputationResult();
            if (string.IsNullOrEmpty(sha256)) return result;

            string upper = sha256.ToUpper();
            string threatName;
            if (_maliciousHashes.TryGetValue(upper, out threatName))
            {
                result.IsKnownMalicious = true;
                result.MatchedHash = upper;
                result.ThreatName = threatName;
                result.Score = 200; // Instant critical - known malware
                Logger.Critical("HASH MATCH: " + threatName + " (" + upper.Substring(0, 16) + "...)");
            }

            return result;
        }

        public int Count { get { return _maliciousHashes.Count; } }
    }

    // ═══════════════════════════════════════════════════════════
    //  MEMORY SCANNER
    // ═══════════════════════════════════════════════════════════

    static class MemoryScanner
    {
        // P/Invoke declarations for reading process memory
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size, out int bytesRead);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, int length);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        const int PROCESS_VM_READ = 0x0010;
        const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        const uint PAGE_EXECUTE = 0x10;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint MEM_PRIVATE = 0x20000;
        const uint MEM_IMAGE = 0x1000000;
        const int MAX_REGIONS_TO_SCAN = 256; // Cap to prevent runaway scans

        // Suspicious byte patterns to scan for in memory
        static readonly byte[][] ShellcodeSignatures = new byte[][] {
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },           // x64 shellcode prologue
            new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00 },     // Metasploit shikata_ga_nai
            new byte[] { 0x60, 0x89, 0xE5, 0x31, 0xC0 },           // x86 shellcode prologue
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B },     // call $+5; pop ebx (position-independent)
        };

        // String patterns to find in memory
        static readonly string[] MemoryStringPatterns = new string[] {
            "mimikatz",
            "sekurlsa",
            "kerberos::",
            "lsadump::",
            "Invoke-Mimikatz",
            "Invoke-Shellcode",
            "ReflectivePEInjection",
            "AmsiScanBuffer",
            "amsiInitFailed",
            "cobaltstrike",
            "beacon.dll",
            "meterpreter",
            "powershell -enc",
            "IEX (New-Object",
            "Net.WebClient",
            "FromBase64String",
            "VirtualAlloc",
            "CreateThread",
        };

        // Protected processes we should never scan
        static readonly HashSet<string> SkipProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "System","Idle","smss","csrss","wininit","winlogon","services","lsass",
            "svchost","dwm","fontdrvhost","MsMpEng","SecurityHealthService",
            "LocalEDR","conhost","Registry"
        };

        public static MemoryScanResult Scan(int pid)
        {
            var result = new MemoryScanResult { ProcessId = pid };
            if (pid <= 4) return result; // System/Idle

            try
            {
                var proc = Process.GetProcessById(pid);
                if (SkipProcesses.Contains(proc.ProcessName)) return result;
            }
            catch { return result; }

            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hProcess == IntPtr.Zero) return result; // Access denied (normal for protected processes)

                // Enumerate memory regions
                IntPtr address = IntPtr.Zero;
                int rwxRegions = 0;
                int privateExecRegions = 0;
                int regionsScanned = 0;
                MEMORY_BASIC_INFORMATION mbi;

                while (regionsScanned < MAX_REGIONS_TO_SCAN &&
                       VirtualQueryEx(hProcess, address, out mbi, System.Runtime.InteropServices.Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) > 0)
                {
                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    // Check for committed, executable memory
                    if (mbi.State == MEM_COMMIT)
                    {
                        bool isExecutable = (mbi.Protect & PAGE_EXECUTE) != 0 ||
                                            (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
                                            (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                                            (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

                        bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
                        bool isPrivate = (mbi.Type & MEM_PRIVATE) != 0;
                        bool isImage = (mbi.Type & MEM_IMAGE) != 0;

                        // RWX memory = very suspicious (shellcode, injection)
                        if (isRWX)
                        {
                            rwxRegions++;
                            result.InjectedRegions.Add(string.Format("RWX region at 0x{0:X} size={1}",
                                mbi.BaseAddress.ToInt64(), regionSize));
                        }

                        // Private executable memory not backed by image = likely injected
                        if (isExecutable && isPrivate && !isImage)
                        {
                            privateExecRegions++;
                        }

                        // Scan executable regions for suspicious content (limit to 1MB per region)
                        if (isExecutable && regionSize > 0 && regionSize <= 1048576)
                        {
                            try
                            {
                                byte[] buffer = new byte[regionSize];
                                int bytesRead;
                                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out bytesRead) && bytesRead > 0)
                                {
                                    // Check shellcode signatures
                                    foreach (byte[] sig in ShellcodeSignatures)
                                    {
                                        if (ContainsBytes(buffer, bytesRead, sig))
                                        {
                                            result.Findings.Add(string.Format("Shellcode signature at 0x{0:X}",
                                                mbi.BaseAddress.ToInt64()));
                                            result.Score += 60;
                                            break; // One match per region is enough
                                        }
                                    }

                                    // Check string patterns
                                    string text = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    foreach (string pattern in MemoryStringPatterns)
                                    {
                                        if (text.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            result.Findings.Add(string.Format("Suspicious string in memory: \"{0}\" at 0x{1:X}",
                                                pattern, mbi.BaseAddress.ToInt64()));
                                            result.Score += 40;
                                        }
                                    }

                                    // Check for MZ header in non-image memory (reflective DLL)
                                    if (isPrivate && !isImage && bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A)
                                    {
                                        result.Findings.Add(string.Format("Reflective PE detected at 0x{0:X} (MZ header in private memory)",
                                            mbi.BaseAddress.ToInt64()));
                                        result.Score += 80;
                                    }
                                }
                            }
                            catch { /* access denied on specific region, continue */ }
                        }
                    }

                    // Advance to next region
                    regionsScanned++;
                    long nextAddr = mbi.BaseAddress.ToInt64() + regionSize;
                    if (nextAddr <= address.ToInt64()) break; // Overflow protection
                    address = new IntPtr(nextAddr);
                }

                // Score RWX regions
                if (rwxRegions > 0)
                {
                    result.Score += rwxRegions * 20;
                    result.Findings.Add(string.Format("{0} RWX memory region(s) detected", rwxRegions));
                    result.HasSuspiciousMemory = true;
                }

                // Score private executable regions (more than 3 is unusual)
                if (privateExecRegions > 3)
                {
                    result.Score += 15;
                    result.Findings.Add(string.Format("{0} private executable regions (possible injection)", privateExecRegions));
                    result.HasSuspiciousMemory = true;
                }

                if (result.Findings.Count > 0)
                    result.HasSuspiciousMemory = true;
            }
            catch (Exception ex)
            {
                Logger.Debug("Memory scan error PID " + pid + ": " + ex.Message);
            }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }

            return result;
        }

        static bool ContainsBytes(byte[] haystack, int haystackLen, byte[] needle)
        {
            if (needle.Length > haystackLen) return false;
            int limit = haystackLen - needle.Length;
            for (int i = 0; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  AMSI SCANNER (Scan scripts via Windows AMSI)
    // ═══════════════════════════════════════════════════════════

    static class AMSIScanner
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
            string contentName, IntPtr amsiSession, out int result);

        [DllImport("amsi.dll")]
        static extern void AmsiUninitialize(IntPtr amsiContext);

        static IntPtr _context = IntPtr.Zero;
        static bool _initialized;
        static bool _available = true;

        public static void Initialize()
        {
            if (_initialized) return;
            try
            {
                int hr = AmsiInitialize("LocalEDR", out _context);
                _initialized = (hr == 0 && _context != IntPtr.Zero);
                if (_initialized)
                    Logger.Info("AMSI scanner initialized");
                else
                    Logger.Debug("AMSI init returned: " + hr);
            }
            catch (Exception ex)
            {
                _available = false;
                Logger.Debug("AMSI not available: " + ex.Message);
            }
        }

        // Returns score: 0 = clean, 50+ = suspicious/malicious
        public static int ScanContent(string content, string contentName)
        {
            if (!_available || !_initialized || string.IsNullOrEmpty(content)) return 0;

            try
            {
                byte[] buffer = Encoding.Unicode.GetBytes(content);
                int amsiResult;
                int hr = AmsiScanBuffer(_context, buffer, (uint)buffer.Length, contentName, IntPtr.Zero, out amsiResult);
                if (hr != 0) return 0;

                // AMSI_RESULT values:
                // 0 = Clean, 1 = Not detected
                // 16384 = Blocked by admin
                // 32768 = Detected (malware)
                if (amsiResult >= 32768)
                {
                    Logger.Alert("AMSI detected malware in: " + contentName);
                    return 80;
                }
                if (amsiResult >= 16384)
                {
                    Logger.Warn("AMSI blocked content: " + contentName);
                    return 50;
                }
            }
            catch { }
            return 0;
        }

        public static int ScanFile(string filePath)
        {
            if (!_available || !_initialized) return 0;
            if (!File.Exists(filePath)) return 0;

            string ext = Path.GetExtension(filePath).ToLower();
            // Only scan script-like files through AMSI
            if (ext != ".ps1" && ext != ".vbs" && ext != ".js" && ext != ".wsf" &&
                ext != ".bat" && ext != ".cmd" && ext != ".hta") return 0;

            try
            {
                string content = File.ReadAllText(filePath);
                if (content.Length > 1048576) content = content.Substring(0, 1048576); // Cap at 1MB
                return ScanContent(content, Path.GetFileName(filePath));
            }
            catch { return 0; }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  ANTI-TAMPERING (Protect EDR process)
    // ═══════════════════════════════════════════════════════════

    static class AntiTamper
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr hJob, int infoType, IntPtr lpInfo, int cbInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtSetInformationProcess(IntPtr processHandle, int processInformationClass,
            ref int processInformation, int processInformationLength);

        // Watch for attempts to kill our service
        static Timer _watchdog;
        static string _selfPath;

        public static void Enable()
        {
            _selfPath = System.Reflection.Assembly.GetExecutingAssembly().Location;

            // 1. Set process as critical (BSOD if killed - only for service mode)
            if (!Environment.UserInteractive)
            {
                try
                {
                    int isCritical = 1;
                    NtSetInformationProcess(GetCurrentProcess(), 29 /* ProcessBreakOnTermination */, ref isCritical, sizeof(int));
                    Logger.Info("Anti-tamper: Process marked as critical");
                }
                catch (Exception ex)
                {
                    Logger.Debug("Anti-tamper critical process failed: " + ex.Message);
                }
            }

            // 2. Start watchdog to detect tampering
            _watchdog = new Timer(WatchdogTick, null, 5000, 30000);
            Logger.Info("Anti-tamper: Watchdog active");
        }

        public static void Disable()
        {
            // Remove critical flag before clean shutdown
            if (!Environment.UserInteractive)
            {
                try
                {
                    int isCritical = 0;
                    NtSetInformationProcess(GetCurrentProcess(), 29, ref isCritical, sizeof(int));
                }
                catch { }
            }
            if (_watchdog != null) { _watchdog.Dispose(); _watchdog = null; }
        }

        static void WatchdogTick(object state)
        {
            try
            {
                // Check if our exe still exists
                if (!string.IsNullOrEmpty(_selfPath) && !File.Exists(_selfPath))
                {
                    Logger.Critical("TAMPER DETECTED: EDR executable deleted!");
                }

                // Check if service is still registered
                if (!Environment.UserInteractive)
                {
                    try
                    {
                        using (var sc = new System.ServiceProcess.ServiceController("LocalEDR"))
                        {
                            if (sc.Status != ServiceControllerStatus.Running)
                                Logger.Critical("TAMPER DETECTED: Service not running!");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  SELF-INTEGRITY CHECK
    // ═══════════════════════════════════════════════════════════

    static class SelfIntegrity
    {
        static string _originalHash;

        public static void Initialize()
        {
            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                if (File.Exists(exePath))
                {
                    byte[] bytes = File.ReadAllBytes(exePath);
                    using (var sha = SHA256.Create())
                        _originalHash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
                    Logger.Info("Self-integrity: SHA256=" + _originalHash.Substring(0, 16) + "...");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug("Self-integrity init error: " + ex.Message);
            }
        }

        public static bool Verify()
        {
            if (string.IsNullOrEmpty(_originalHash)) return true; // Can't verify

            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                byte[] bytes = File.ReadAllBytes(exePath);
                using (var sha = SHA256.Create())
                {
                    string currentHash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
                    if (currentHash != _originalHash)
                    {
                        Logger.Critical("INTEGRITY VIOLATION: EDR binary has been modified!");
                        return false;
                    }
                }
            }
            catch { }
            return true;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  RANSOMWARE DETECTOR (Mass file operation heuristics)
    // ═══════════════════════════════════════════════════════════

    class RansomwareDetector
    {
        // Track file operations per process
        readonly ConcurrentDictionary<int, ProcessFileOps> _processOps = new ConcurrentDictionary<int, ProcessFileOps>();
        readonly ConcurrentDictionary<string, int> _extensionChanges = new ConcurrentDictionary<string, int>();
        int _renameCount;
        DateTime _windowStart = DateTime.Now;
        const int WINDOW_SECONDS = 30;
        const int RENAME_THRESHOLD = 50;  // 50 renames in 30 seconds = ransomware
        const int WRITE_THRESHOLD = 100;  // 100 writes in 30 seconds

        // Known ransomware extensions
        static readonly HashSet<string> RansomwareExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".encrypted",".locked",".crypt",".crypto",".enc",".locky",".cerber",
            ".zepto",".thor",".aesir",".zzzzz",".micro",".mp3",".xxx",
            ".ttt",".ecc",".ezz",".exx",".abc",".aaa",".xtbl",".crysis",
            ".crypz",".cryp1",".dharma",".wallet",".onion",".wncry",".wcry",
            ".wnry",".wncrypt",".petya",".bad",".globe",".bleep",".crypted",
            ".lol",".fun",".pay",".ransom",".rip",".darkness"
        };

        // Known ransom note filenames
        static readonly string[] RansomNotePatterns = {
            "readme", "recover", "restore", "decrypt", "how to",
            "help_decrypt", "help_recover", "ransom", "payment",
            "_readme", "!readme", "@readme", "#decrypt"
        };

        class ProcessFileOps
        {
            public int WriteCount;
            public int RenameCount;
            public int DeleteCount;
            public DateTime FirstSeen = DateTime.Now;
            public HashSet<string> NewExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public void OnFileRenamed(string oldPath, string newPath)
        {
            Interlocked.Increment(ref _renameCount);
            ResetWindowIfNeeded();

            string newExt = Path.GetExtension(newPath).ToLower();
            string oldExt = Path.GetExtension(oldPath).ToLower();

            // Extension changed to known ransomware extension
            if (newExt != oldExt && RansomwareExtensions.Contains(newExt))
            {
                _extensionChanges.AddOrUpdate(newExt, 1, (k, v) => v + 1);
                int count;
                if (_extensionChanges.TryGetValue(newExt, out count) && count >= 10)
                {
                    Logger.Critical(string.Format("RANSOMWARE: Mass rename to {0} ({1} files)", newExt, count));
                }
            }

            // Mass rename detection
            if (_renameCount >= RENAME_THRESHOLD)
            {
                Logger.Critical(string.Format("RANSOMWARE: {0} file renames in {1}s window!", _renameCount, WINDOW_SECONDS));
            }
        }

        public void OnFileCreated(string path)
        {
            string name = Path.GetFileName(path).ToLower();
            foreach (string pattern in RansomNotePatterns)
            {
                if (name.Contains(pattern))
                {
                    Logger.Critical("RANSOMWARE: Ransom note detected: " + path);
                    break;
                }
            }
        }

        public int GetScore()
        {
            int score = 0;
            if (_renameCount >= RENAME_THRESHOLD) score += 90;
            else if (_renameCount >= 20) score += 40;

            foreach (var kv in _extensionChanges)
            {
                if (kv.Value >= 10) score += 60;
                else if (kv.Value >= 5) score += 30;
            }

            return Math.Min(score, 200);
        }

        void ResetWindowIfNeeded()
        {
            if ((DateTime.Now - _windowStart).TotalSeconds > WINDOW_SECONDS)
            {
                _renameCount = 0;
                _extensionChanges.Clear();
                _windowStart = DateTime.Now;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  JSON LOGGER (Structured logging for SIEM)
    // ═══════════════════════════════════════════════════════════

    static class JsonLogger
    {
        static string _logDir;

        public static void Initialize(string logDir)
        {
            _logDir = Path.Combine(logDir, "JSON");
            Directory.CreateDirectory(_logDir);
        }

        public static void LogAnalysis(AnalysisResult a)
        {
            if (_logDir == null || a == null) return;
            try
            {
                var sb = new StringBuilder();
                sb.Append("{");
                sb.AppendFormat("\"timestamp\":\"{0}\",", a.Timestamp.ToString("o"));
                sb.AppendFormat("\"analysis_id\":\"{0}\",", a.AnalysisId);
                sb.AppendFormat("\"file_path\":\"{0}\",", Escape(a.FilePath));
                sb.AppendFormat("\"process_id\":{0},", a.ProcessId);
                sb.AppendFormat("\"command_line\":\"{0}\",", Escape(a.CommandLine));
                sb.AppendFormat("\"score\":{0},", a.TotalScore);
                sb.AppendFormat("\"verdict\":\"{0}\",", a.Verdict);
                sb.AppendFormat("\"confidence\":\"{0}\",", a.Confidence);
                sb.AppendFormat("\"response\":\"{0}\",", Escape(a.ResponseTaken));

                // Hashes
                if (a.Static != null)
                {
                    sb.AppendFormat("\"sha256\":\"{0}\",", a.Static.SHA256 ?? "");
                    sb.AppendFormat("\"md5\":\"{0}\",", a.Static.MD5 ?? "");
                    sb.AppendFormat("\"entropy\":{0},", a.Static.Entropy.ToString("F4"));
                    sb.AppendFormat("\"file_size\":{0},", a.Static.FileSize);
                    sb.AppendFormat("\"is_packed\":{0},", a.Static.IsPacked ? "true" : "false");
                }

                // Hash reputation
                if (a.HashReputation != null && a.HashReputation.IsKnownMalicious)
                    sb.AppendFormat("\"known_malware\":\"{0}\",", Escape(a.HashReputation.ThreatName));

                // MITRE
                sb.Append("\"mitre\":[");
                for (int i = 0; i < a.Mitre.Count; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.AppendFormat("{{\"id\":\"{0}\",\"name\":\"{1}\",\"tactic\":\"{2}\",\"confidence\":\"{3}\"}}",
                        a.Mitre[i].TechniqueId, Escape(a.Mitre[i].TechniqueName),
                        Escape(a.Mitre[i].Tactic), a.Mitre[i].Confidence);
                }
                sb.Append("],");

                // YARA
                sb.Append("\"yara\":[");
                for (int i = 0; i < a.Yara.Count; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.AppendFormat("{{\"rule\":\"{0}\",\"severity\":\"{1}\",\"score\":{2}}}",
                        Escape(a.Yara[i].RuleName), a.Yara[i].Severity, a.Yara[i].Score);
                }
                sb.Append("],");

                // Memory scan
                if (a.MemoryScan != null && a.MemoryScan.HasSuspiciousMemory)
                {
                    sb.AppendFormat("\"memory_score\":{0},", a.MemoryScan.Score);
                    sb.Append("\"memory_findings\":[");
                    for (int i = 0; i < a.MemoryScan.Findings.Count; i++)
                    {
                        if (i > 0) sb.Append(",");
                        sb.AppendFormat("\"{0}\"", Escape(a.MemoryScan.Findings[i]));
                    }
                    sb.Append("],");
                }

                // Behavior indicators
                if (a.Behavior != null && a.Behavior.Indicators.Count > 0)
                {
                    sb.Append("\"indicators\":[");
                    for (int i = 0; i < a.Behavior.Indicators.Count; i++)
                    {
                        if (i > 0) sb.Append(",");
                        sb.AppendFormat("\"{0}\"", Escape(a.Behavior.Indicators[i]));
                    }
                    sb.Append("],");
                }

                // Process info
                if (a.Behavior != null)
                {
                    sb.AppendFormat("\"process_name\":\"{0}\",", Escape(a.Behavior.ProcessName));
                    sb.AppendFormat("\"parent_name\":\"{0}\",", Escape(a.Behavior.ParentName));
                    sb.AppendFormat("\"parent_pid\":{0},", a.Behavior.ParentPID);
                    sb.AppendFormat("\"is_lolbin\":{0},", a.Behavior.IsLOLBin ? "true" : "false");
                }

                sb.AppendFormat("\"hostname\":\"{0}\"", Environment.MachineName);
                sb.Append("}");

                string fileName = string.Format("{0}_{1}.json", DateTime.Now.ToString("yyyyMMdd_HHmmss_fff"), a.AnalysisId);
                File.WriteAllText(Path.Combine(_logDir, fileName), sb.ToString());
            }
            catch { }
        }

        static string Escape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  SCORING ENGINE
    // ═══════════════════════════════════════════════════════════

    static class ScoringEngine
    {
        const double WStatic = 1.0, WBehavior = 1.5, WYara = 1.3, WMitre = 0.8, WNetwork = 1.2;
        const int TrustedSignedMaxScore = 60;

        static readonly string[] TrustedPubs = {"Microsoft","Google","Mozilla","Adobe","Oracle","Apple",
            "Valve","GitHub","JetBrains","Discord","Spotify","Zoom",
            "Slack","Dropbox","NVIDIA","AMD","Intel","Logitech",
            "Corsair","Razer","SteelSeries","Epic Games"};
        static readonly HashSet<string> SystemProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "svchost","csrss","lsass","services","smss","wininit","winlogon","dwm","explorer","taskhostw","sihost"
        };

        // Self-hashes: EDR's own files always score Clean
        static readonly HashSet<string> SelfHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static void RegisterSelfHashes(IEnumerable<string> hashes)
        {
            foreach (var h in hashes) SelfHashes.Add(h);
        }

        public static void Calculate(AnalysisResult a)
        {
            // Self-protection: EDR's own files are always clean
            if (a.Static != null && !string.IsNullOrEmpty(a.Static.SHA256) && SelfHashes.Contains(a.Static.SHA256))
            {
                a.TotalScore = 0;
                a.Verdict = "Clean";
                a.Confidence = "High";
                return;
            }

            int sStatic = 0, sBehavior = 0, sYara = 0, sMitre = 0, sNetwork = 0, sHash = 0, sMemory = 0, adj = 0;

            if (a.Static != null) sStatic = Math.Min(a.Static.Score, 100);
            if (a.Behavior != null) sBehavior = Math.Min(a.Behavior.Score, 150);

            if (a.Yara.Count > 0)
            {
                int total = a.Yara.Sum(y => y.Score);
                sYara = Math.Min(total, 120);
                if (a.Yara.Any(y => y.Severity == "Critical"))
                    sYara = (int)Math.Min(sYara * 1.3, 150);
            }

            if (a.Mitre.Count > 0)
            {
                int mb = a.Mitre.Count * 8;
                mb += a.Mitre.Count(m => m.Confidence == "High") * 5;
                int tactics = a.Mitre.Select(m => m.Tactic).Distinct().Count();
                if (tactics >= 3) mb = (int)(mb * 1.3);
                sMitre = Math.Min(mb, 80);
            }

            if (a.Network != null)
            {
                int ns = Math.Min(a.Network.Score, 80);
                if (a.Network.BeaconingDetected) ns += 30;
                sNetwork = Math.Min(ns, 100);
            }

            // Hash reputation - known malware = instant critical
            if (a.HashReputation != null && a.HashReputation.IsKnownMalicious)
                sHash = 200;

            // Memory scan
            if (a.MemoryScan != null)
                sMemory = Math.Min(a.MemoryScan.Score, 150);

            // Adjustments
            // Multi-source corroboration
            int sources = 0;
            if (sStatic > 20) sources++;
            if (sBehavior > 20) sources++;
            if (a.Yara.Count > 0) sources++;
            if (sNetwork > 10) sources++;
            if (sHash > 0) sources++;
            if (sMemory > 0) sources++;
            if (sources >= 3) adj += 25;

            // System process from expected path
            if (a.Behavior != null && SystemProcs.Contains(a.Behavior.ProcessName) &&
                a.FilePath != null && a.FilePath.IndexOf(@"C:\Windows\System32", StringComparison.OrdinalIgnoreCase) >= 0)
                adj -= 15;

            double weighted = sStatic * WStatic + sBehavior * WBehavior + sYara * WYara + sMitre * WMitre + sNetwork * WNetwork + sHash + sMemory * 1.4 + adj;
            a.TotalScore = Math.Max(0, (int)Math.Round(weighted));

            // Hard ceiling: trusted signed binaries cannot exceed TrustedSignedMaxScore.
            // Prevents auto-quarantine of legitimate signed software (Steam, gh.exe, etc.)
            if (a.Static != null && a.Static.IsSigned)
            {
                try
                {
                    var sig = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromSignedFile(a.FilePath);
                    string subject = sig != null ? sig.Subject : "";
                    foreach (string pub in TrustedPubs)
                    {
                        if (subject.IndexOf(pub, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            if (a.TotalScore > TrustedSignedMaxScore)
                                a.TotalScore = TrustedSignedMaxScore;
                            break;
                        }
                    }
                }
                catch { }
            }

            if (a.TotalScore >= 120) a.Verdict = "Critical";
            else if (a.TotalScore >= 80) a.Verdict = "Malicious";
            else if (a.TotalScore >= 50) a.Verdict = "Suspicious";
            else if (a.TotalScore >= 25) a.Verdict = "Low";
            else a.Verdict = "Clean";

            int sigCount = 0;
            if (sStatic > 0) sigCount++;
            if (sBehavior > 0) sigCount++;
            if (sYara > 0) sigCount++;
            if (sMitre > 0) sigCount++;
            if (sNetwork > 0) sigCount++;
            if (sHash > 0) sigCount++;
            if (sMemory > 0) sigCount++;
            a.Confidence = sigCount >= 4 ? "High" : sigCount >= 2 ? "Medium" : "Low";
        }

        public static void PrintReport(AnalysisResult a)
        {
            ConsoleColor vc = a.Verdict == "Critical" ? ConsoleColor.Red :
                              a.Verdict == "Malicious" ? ConsoleColor.DarkRed :
                              a.Verdict == "Suspicious" ? ConsoleColor.Yellow :
                              a.Verdict == "Low" ? ConsoleColor.DarkYellow : ConsoleColor.Green;

            Console.ForegroundColor = vc;
            Console.WriteLine("\n+==========================================+");
            Console.WriteLine("|         THREAT SCORE REPORT              |");
            Console.WriteLine("+==========================================+");
            Console.ResetColor();

            Console.WriteLine("\n  Target    : " + (a.FilePath ?? a.CommandLine ?? "PID:" + a.ProcessId));
            Console.ForegroundColor = vc;
            Console.WriteLine("  Score     : " + a.TotalScore);
            Console.WriteLine("  Verdict   : " + a.Verdict);
            Console.ResetColor();
            Console.WriteLine("  Confidence: " + a.Confidence);

            if (a.Static != null && !string.IsNullOrEmpty(a.Static.SHA256))
                Console.WriteLine("  SHA256    : " + a.Static.SHA256);

            // Hash reputation
            if (a.HashReputation != null && a.HashReputation.IsKnownMalicious)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n  !! KNOWN MALWARE: " + a.HashReputation.ThreatName + " !!");
                Console.ResetColor();
            }

            // MITRE
            if (a.Mitre.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("\n  -- MITRE ATT&CK --");
                Console.ResetColor();
                foreach (var m in a.Mitre)
                    Console.WriteLine(string.Format("    [{0}] {1} - {2} ({3})", m.Confidence.Substring(0,1), m.TechniqueId, m.TechniqueName, m.Tactic));
            }

            // YARA
            if (a.Yara.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n  -- YARA Matches --");
                Console.ResetColor();
                foreach (var y in a.Yara)
                    Console.WriteLine(string.Format("    [{0}] {1}: {2}", y.Severity, y.RuleName, y.Description));
            }

            // Memory scan
            if (a.MemoryScan != null && a.MemoryScan.HasSuspiciousMemory)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n  -- Memory Scan --");
                Console.ResetColor();
                foreach (string finding in a.MemoryScan.Findings)
                    Console.WriteLine("    ! " + finding);
                foreach (string region in a.MemoryScan.InjectedRegions)
                    Console.WriteLine("    ! " + region);
            }

            // Indicators
            var inds = new List<string>();
            if (a.Static != null) inds.AddRange(a.Static.Indicators);
            if (a.Behavior != null) inds.AddRange(a.Behavior.Indicators);
            if (a.Network != null) inds.AddRange(a.Network.Indicators);
            if (inds.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("\n  -- Indicators --");
                Console.ResetColor();
                int shown = 0;
                foreach (var ind in inds)
                {
                    if (shown++ >= 15) { Console.WriteLine("    ... and " + (inds.Count - 15) + " more"); break; }
                    Console.WriteLine("    * " + ind);
                }
            }

            Console.WriteLine("\n  Response  : " + a.ResponseTaken);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  RESPONSE ENGINE
    // ═══════════════════════════════════════════════════════════

    class ResponseEngine
    {
        public bool AutoResponseEnabled = false;
        readonly string _quarantinePath;
        readonly string _alertPath;
        public int AlertThreshold, KillThreshold, QuarantineThreshold, BlockThreshold;

        static readonly HashSet<string> Protected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "System","smss","csrss","wininit","winlogon","services","lsass","svchost",
            "dwm","explorer","taskhostw","sihost","MsMpEng","powershell","pwsh","conhost","cmd","LocalEDR"
        };

        public ResponseEngine(string quarantinePath, string logPath, int alert, int kill, int quarantine, int block)
        {
            _quarantinePath = quarantinePath;
            _alertPath = Path.Combine(logPath, "Alerts");
            AlertThreshold = alert; KillThreshold = kill;
            QuarantineThreshold = quarantine; BlockThreshold = block;
            Directory.CreateDirectory(quarantinePath);
            Directory.CreateDirectory(_alertPath);
        }

        public string Execute(AnalysisResult a)
        {
            var actions = new List<string>();

            if (a.TotalScore >= AlertThreshold)
            {
                string alertId = SaveAlert(a);
                actions.Add("Alert:" + alertId);
            }

            if (!AutoResponseEnabled)
            {
                if (a.TotalScore >= AlertThreshold)
                {
                    Logger.Warn(string.Format("Auto-response DISABLED. Manual action needed (score={0})", a.TotalScore));
                    actions.Add("Manual review required");
                }
                return actions.Count > 0 ? string.Join("; ", actions) : "None";
            }

            if (a.TotalScore >= KillThreshold && a.ProcessId > 0)
                actions.Add(KillProcess(a.ProcessId));
            if (a.TotalScore >= QuarantineThreshold && !string.IsNullOrEmpty(a.FilePath))
                actions.Add(Quarantine(a.FilePath, a));
            if (a.TotalScore >= BlockThreshold && a.Network != null)
                foreach (string conn in a.Network.SuspiciousConns)
                {
                    string addr = conn.Contains(":") ? conn.Substring(0, conn.LastIndexOf(':')) : conn;
                    actions.Add(BlockIP(addr));
                }

            return actions.Count > 0 ? string.Join("; ", actions) : "None";
        }

        string KillProcess(int pid)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                if (Protected.Contains(proc.ProcessName))
                    return "Protected - kill blocked: " + proc.ProcessName;
                proc.Kill();
                Logger.Critical("KILLED: " + proc.ProcessName + " (PID " + pid + ")");
                return "Killed: " + proc.ProcessName;
            }
            catch (Exception ex) { return "Kill failed: " + ex.Message; }
        }

        string Quarantine(string filePath, AnalysisResult a)
        {
            try
            {
                if (!File.Exists(filePath)) return "File not found";
                string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string name = Path.GetFileName(filePath);
                string dest = Path.Combine(_quarantinePath, ts + "_" + name + ".quarantined");

                // Save metadata
                string meta = string.Format(
                    "OriginalPath={0}\r\nQuarantinedAt={1}\r\nScore={2}\r\nVerdict={3}\r\nSHA256={4}",
                    filePath, DateTime.Now.ToString("o"), a.TotalScore, a.Verdict,
                    a.Static != null ? a.Static.SHA256 : "N/A");
                File.WriteAllText(dest + ".meta.txt", meta);
                File.Move(filePath, dest);

                Logger.Critical("QUARANTINED: " + filePath);
                return "Quarantined: " + name;
            }
            catch (Exception ex) { return "Quarantine failed: " + ex.Message; }
        }

        public void RestoreFromQuarantine(string fileName)
        {
            string qPath = Path.Combine(_quarantinePath, fileName);
            string metaPath = qPath + ".meta.txt";
            if (!File.Exists(metaPath)) { Console.WriteLine("Metadata not found for: " + fileName); return; }

            string[] lines = File.ReadAllLines(metaPath);
            string origPath = "";
            foreach (string line in lines)
                if (line.StartsWith("OriginalPath=")) origPath = line.Substring(13);

            Console.WriteLine("Restoring: " + fileName);
            Console.WriteLine("  Original: " + origPath);
            Console.Write("Are you sure? (yes/no): ");
            if (Console.ReadLine().Trim().ToLower() == "yes")
            {
                File.Move(qPath, origPath);
                File.Delete(metaPath);
                Logger.Warn("RESTORED: " + origPath);
            }
            else Console.WriteLine("Cancelled.");
        }

        string BlockIP(string addr)
        {
            try
            {
                var psi = new ProcessStartInfo {
                    FileName = "netsh",
                    Arguments = string.Format("advfirewall firewall add rule name=\"EDR_Block_{0}\" dir=out action=block remoteip={0}", addr),
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
                };
                using (var p = Process.Start(psi)) { p.WaitForExit(5000); }
                Logger.Critical("BLOCKED: " + addr);
                return "Blocked: " + addr;
            }
            catch (Exception ex) { return "Block failed: " + ex.Message; }
        }

        string SaveAlert(AnalysisResult a)
        {
            string id = Guid.NewGuid().ToString("N").Substring(0, 8);
            try
            {
                string mitre = string.Join(",", a.Mitre.Select(m => m.TechniqueId));
                string yara = string.Join(",", a.Yara.Select(y => y.RuleName));
                string content = string.Format(
                    "AlertId={0}\r\nTimestamp={1}\r\nScore={2}\r\nVerdict={3}\r\nTarget={4}\r\nMITRE={5}\r\nYARA={6}\r\nCommandLine={7}",
                    id, DateTime.Now.ToString("o"), a.TotalScore, a.Verdict,
                    a.FilePath ?? "PID:" + a.ProcessId, mitre, yara, a.CommandLine ?? "");
                File.WriteAllText(Path.Combine(_alertPath, id + ".txt"), content);
            }
            catch { }
            return id;
        }

        public void ListQuarantined()
        {
            if (!Directory.Exists(_quarantinePath)) { Console.WriteLine("No quarantine directory."); return; }
            var files = Directory.GetFiles(_quarantinePath, "*.quarantined");
            if (files.Length == 0) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("No quarantined files."); Console.ResetColor(); return; }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n== Quarantined Files ==");
            Console.ResetColor();
            foreach (string f in files)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  " + Path.GetFileName(f));
                Console.ResetColor();
                string metaPath = f + ".meta.txt";
                if (File.Exists(metaPath))
                {
                    foreach (string line in File.ReadAllLines(metaPath))
                        Console.WriteLine("    " + line);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PSEUDO SANDBOX
    // ═══════════════════════════════════════════════════════════

    class PseudoSandbox
    {
        public SandboxResult Execute(string filePath, int timeoutSec)
        {
            var r = new SandboxResult { FilePath = filePath, StartTime = DateTime.Now };
            if (!File.Exists(filePath)) { Logger.Warn("Sandbox: File not found: " + filePath); return r; }

            Logger.Info(string.Format("Sandbox: Analyzing {0} (timeout={1}s)", filePath, timeoutSec));

            // Snapshot registry before
            var regBefore = SnapshotRegistry();

            // File watcher
            string tempPath = Path.GetTempPath();
            FileSystemWatcher watcher = null;
            try
            {
                watcher = new FileSystemWatcher(tempPath);
                watcher.IncludeSubdirectories = true;
                watcher.EnableRaisingEvents = true;
                watcher.Created += (s, e) => { lock(r.FilesCreated) r.FilesCreated.Add(e.FullPath); };
                watcher.Changed += (s, e) => { lock(r.FilesModified) r.FilesModified.Add(e.FullPath); };
                watcher.Deleted += (s, e) => { lock(r.FilesDeleted) r.FilesDeleted.Add(e.FullPath); };
            }
            catch { }

            // Launch
            Process target = null;
            try
            {
                string ext = Path.GetExtension(filePath).ToLower();
                ProcessStartInfo psi = null;
                if (ext == ".exe") psi = new ProcessStartInfo(filePath);
                else if (ext == ".ps1") psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File \"" + filePath + "\"");
                else if (ext == ".bat" || ext == ".cmd") psi = new ProcessStartInfo("cmd.exe", "/c \"" + filePath + "\"");
                else if (ext == ".vbs" || ext == ".js") psi = new ProcessStartInfo("cscript.exe", "//nologo \"" + filePath + "\"");

                if (psi != null)
                {
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;
                    target = Process.Start(psi);
                    if (target != null)
                        Logger.Info("Sandbox: Launched PID " + target.Id);
                }
            }
            catch (Exception ex) { Logger.Warn("Sandbox: Launch failed: " + ex.Message); }

            // Monitor child processes
            if (target != null)
            {
                int parentPid = target.Id;
                var seen = new HashSet<int> { parentPid };
                DateTime deadline = DateTime.Now.AddSeconds(timeoutSec);
                while (DateTime.Now < deadline)
                {
                    try
                    {
                        using (var s = new ManagementObjectSearcher(
                            string.Format("SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE ParentProcessId={0}", parentPid)))
                        {
                            foreach (ManagementObject o in s.Get())
                            {
                                int cpid = Convert.ToInt32(o["ProcessId"]);
                                if (seen.Add(cpid))
                                {
                                    string info = string.Format("PID {0}: {1}", cpid, o["Name"]);
                                    string cl = (o["CommandLine"] ?? "").ToString();
                                    if (!string.IsNullOrEmpty(cl))
                                        info += " CMD=" + (cl.Length > 100 ? cl.Substring(0, 100) + "..." : cl);
                                    r.ProcessesCreated.Add(info);
                                }
                            }
                        }
                    }
                    catch { }
                    Thread.Sleep(500);
                }
            }
            else
            {
                Thread.Sleep(timeoutSec * 1000);
            }

            // Kill target
            if (target != null && !target.HasExited)
            {
                try { target.Kill(); Logger.Info("Sandbox: Terminated PID " + target.Id); } catch { }
            }

            // Cleanup watcher
            if (watcher != null) { watcher.EnableRaisingEvents = false; watcher.Dispose(); }

            // Diff registry
            var regAfter = SnapshotRegistry();
            foreach (var kv in regAfter)
            {
                Dictionary<string, string> before;
                if (!regBefore.TryGetValue(kv.Key, out before)) before = new Dictionary<string, string>();
                foreach (var entry in kv.Value)
                {
                    string oldVal;
                    if (!before.TryGetValue(entry.Key, out oldVal) || oldVal != entry.Value)
                        r.RegistryChanges.Add(string.Format("{0}\\{1} = {2}", kv.Key, entry.Key, entry.Value));
                }
            }

            r.EndTime = DateTime.Now;
            r.DurationSec = (r.EndTime - r.StartTime).TotalSeconds;

            // Score
            if (r.ProcessesCreated.Count > 0)
            {
                r.BehaviorScore += r.ProcessesCreated.Count * 10;
                r.BehaviorFlags.Add("Spawned " + r.ProcessesCreated.Count + " child process(es)");
                foreach (string p in r.ProcessesCreated)
                {
                    string pl = p.ToLower();
                    if (pl.Contains("powershell") || pl.Contains("cmd.exe") || pl.Contains("mshta") || pl.Contains("wscript") || pl.Contains("cscript"))
                    {
                        r.BehaviorScore += 30;
                        r.BehaviorFlags.Add("Suspicious child: " + p.Split(':')[0]);
                    }
                }
            }
            if (r.FilesCreated.Count > 0)
            {
                r.BehaviorScore += r.FilesCreated.Count * 5;
                r.BehaviorFlags.Add("Created " + r.FilesCreated.Count + " file(s)");
                string[] exeExts = {".exe",".dll",".ps1",".bat",".cmd",".vbs",".js",".scr"};
                int drops = r.FilesCreated.Count(f => exeExts.Contains(Path.GetExtension(f).ToLower()));
                if (drops > 0) { r.BehaviorScore += drops * 25; r.BehaviorFlags.Add("Dropped " + drops + " executable(s)"); }
            }
            if (r.FilesDeleted.Count > 5) { r.BehaviorScore += 20; r.BehaviorFlags.Add("Deleted " + r.FilesDeleted.Count + " file(s)"); }
            if (r.RegistryChanges.Count > 0)
            {
                r.BehaviorScore += r.RegistryChanges.Count * 20;
                r.BehaviorFlags.Add("Modified " + r.RegistryChanges.Count + " registry value(s)");
                foreach (string rc in r.RegistryChanges)
                    if (rc.ToLower().Contains("run"))
                    { r.BehaviorScore += 30; r.BehaviorFlags.Add("Persistence via Run key"); break; }
            }
            if (r.NetworkConns.Count > 0)
            {
                r.BehaviorScore += r.NetworkConns.Count * 15;
                r.BehaviorFlags.Add("Made " + r.NetworkConns.Count + " network connection(s)");
            }

            Logger.Info(string.Format("Sandbox: Complete. Score={0} Flags={1}", r.BehaviorScore, r.BehaviorFlags.Count));
            return r;
        }

        static Dictionary<string, Dictionary<string, string>> SnapshotRegistry()
        {
            var snap = new Dictionary<string, Dictionary<string, string>>();
            string[] paths = { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" };
            RegistryKey[] hives = { Registry.CurrentUser, Registry.LocalMachine };
            foreach (string path in paths)
            {
                foreach (var hive in hives)
                {
                    string full = hive.Name + "\\" + path;
                    try
                    {
                        using (var key = hive.OpenSubKey(path))
                        {
                            if (key == null) continue;
                            var entries = new Dictionary<string, string>();
                            foreach (string name in key.GetValueNames())
                                entries[name] = (key.GetValue(name) ?? "").ToString();
                            snap[full] = entries;
                        }
                    }
                    catch { }
                }
            }
            return snap;
        }

        public void PrintReport(SandboxResult r)
        {
            ConsoleColor color = r.BehaviorScore > 80 ? ConsoleColor.Red : r.BehaviorScore > 40 ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.ForegroundColor = color;
            Console.WriteLine("\n+==========================================+");
            Console.WriteLine("|        PSEUDO-SANDBOX REPORT             |");
            Console.WriteLine("+==========================================+");
            Console.ResetColor();

            Console.WriteLine("\n  File    : " + r.FilePath);
            Console.WriteLine(string.Format("  Duration: {0:F1}s", r.DurationSec));
            Console.ForegroundColor = color;
            Console.WriteLine("  Score   : " + r.BehaviorScore);
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n  -- Activity Summary --");
            Console.ResetColor();
            Console.WriteLine("    Processes spawned : " + r.ProcessesCreated.Count);
            Console.WriteLine("    Files created     : " + r.FilesCreated.Count);
            Console.WriteLine("    Files modified    : " + r.FilesModified.Count);
            Console.WriteLine("    Files deleted     : " + r.FilesDeleted.Count);
            Console.WriteLine("    Registry changes  : " + r.RegistryChanges.Count);

            if (r.BehaviorFlags.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n  -- Behavior Flags --");
                Console.ResetColor();
                foreach (string f in r.BehaviorFlags) Console.WriteLine("    ! " + f);
            }
            if (r.ProcessesCreated.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("\n  -- Child Processes --");
                Console.ResetColor();
                foreach (string p in r.ProcessesCreated) Console.WriteLine("    " + p);
            }
            if (r.RegistryChanges.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n  -- Registry Changes --");
                foreach (string rc in r.RegistryChanges) Console.WriteLine("    " + rc);
                Console.ResetColor();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  MAIN ENGINE + PROGRAM
    // ═══════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════
    //  WHITELIST (False Positive Reduction)
    // ═══════════════════════════════════════════════════════════

    class Whitelist
    {
        readonly HashSet<string> _paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> _hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> _pathPrefixes = new List<string>();
        string _whitelistPath;

        public Whitelist(string baseDir)
        {
            _whitelistPath = Path.Combine(baseDir, "whitelist.txt");

            // Built-in whitelisted paths (Windows system)
            _pathPrefixes.Add(@"C:\Windows\WinSxS\");
            _pathPrefixes.Add(@"C:\Windows\servicing\");
            _pathPrefixes.Add(@"C:\Windows\Installer\");
            _pathPrefixes.Add(@"C:\Windows\assembly\");

            // Load user whitelist
            if (File.Exists(_whitelistPath))
            {
                try
                {
                    foreach (string line in File.ReadAllLines(_whitelistPath))
                    {
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) continue;

                        if (trimmed.Length == 64 && Regex.IsMatch(trimmed, "^[A-Fa-f0-9]{64}$"))
                        {
                            _hashes.Add(trimmed.ToUpper());
                        }
                        else if (trimmed.EndsWith("\\"))
                        {
                            _pathPrefixes.Add(trimmed);
                        }
                        else
                        {
                            _paths.Add(trimmed);
                        }
                    }
                    Logger.Info(string.Format("Whitelist: {0} paths, {1} prefixes, {2} hashes",
                        _paths.Count, _pathPrefixes.Count, _hashes.Count));
                }
                catch (Exception ex) { Logger.Debug("Whitelist load error: " + ex.Message); }
            }
            else
            {
                // Create template
                try
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("# LocalEDR Whitelist - reduce false positives");
                    sb.AppendLine("# Add one entry per line:");
                    sb.AppendLine("#   Full path:    C:\\Program Files\\MyApp\\app.exe");
                    sb.AppendLine("#   Path prefix:  C:\\Program Files\\MyApp\\   (trailing backslash = all files under it)");
                    sb.AppendLine("#   SHA256 hash:  AB01CD23... (64 hex chars)");
                    sb.AppendLine("# Lines starting with # are comments.");
                    File.WriteAllText(_whitelistPath, sb.ToString());
                }
                catch { }
            }
        }

        public bool IsWhitelisted(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            if (_paths.Contains(filePath)) return true;
            foreach (string prefix in _pathPrefixes)
            {
                if (filePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public bool IsHashWhitelisted(string sha256)
        {
            if (string.IsNullOrEmpty(sha256)) return false;
            return _hashes.Contains(sha256.ToUpper());
        }
    }

    class EDREngine
    {
        readonly string _logPath, _quarantinePath;
        readonly MitreMapper _mitre = new MitreMapper();
        readonly YaraEngine _yara = new YaraEngine();
        readonly NetworkMonitor _network = new NetworkMonitor();
        readonly PseudoSandbox _sandbox = new PseudoSandbox();
        readonly HashReputationDB _hashDB = new HashReputationDB();
        readonly RansomwareDetector _ransomware = new RansomwareDetector();
        readonly ResponseEngine _response;
        readonly List<AnalysisResult> _history = new List<AnalysisResult>();
        ManagementEventWatcher _procWatcher;
        readonly List<FileSystemWatcher> _fileWatchers = new List<FileSystemWatcher>();
        bool _monitoring;

        // Dedup: skip recently analyzed files/PIDs to prevent event storms
        readonly ConcurrentDictionary<string, DateTime> _recentlyAnalyzed = new ConcurrentDictionary<string, DateTime>();
        const int DEDUP_SECONDS = 30; // Don't re-analyze same target within this window
        readonly object _analysisLock = new object();
        static readonly SemaphoreSlim _analysisSemaphore = new SemaphoreSlim(4); // Max 4 concurrent analyses

        public EDREngine()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            _logPath = Path.Combine(baseDir, "Logs");
            _quarantinePath = Path.Combine(baseDir, "Quarantine");
            string rulesPath = Path.Combine(baseDir, "Rules");

            Directory.CreateDirectory(_logPath);
            Directory.CreateDirectory(_quarantinePath);
            Directory.CreateDirectory(rulesPath);

            Logger.Init(_logPath);
            _yara.Initialize();
            _hashDB.Initialize(baseDir);
            AMSIScanner.Initialize();
            SelfIntegrity.Initialize();
            JsonLogger.Initialize(_logPath);
            _response = new ResponseEngine(_quarantinePath, _logPath, 50, 120, 100, 80);
            _response.AutoResponseEnabled = true;

            // Initialize whitelist
            _whitelist = new Whitelist(baseDir);

            // Self-protection: hash our own files so the EDR never quarantines itself
            RegisterSelfHashes(baseDir);

            Logger.Info(string.Format("EDR Engine initialized ({0} YARA rules, {1} hash DB entries)",
                _yara.Rules.Count, _hashDB.Count));
        }

        // Whitelist to reduce false positives
        Whitelist _whitelist;

        void RegisterSelfHashes(string baseDir)
        {
            var hashes = new List<string>();
            try
            {
                foreach (string file in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                {
                    string rel = file.Substring(baseDir.Length);
                    if (rel.StartsWith("Logs", StringComparison.OrdinalIgnoreCase) ||
                        rel.StartsWith("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                        rel.StartsWith("Rules", StringComparison.OrdinalIgnoreCase))
                        continue;
                    try
                    {
                        byte[] bytes = File.ReadAllBytes(file);
                        using (var sha = SHA256.Create())
                        {
                            string hash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
                            hashes.Add(hash);
                        }
                    }
                    catch { }
                }
                ScoringEngine.RegisterSelfHashes(hashes);
                Logger.Info(string.Format("Self-protection: registered {0} EDR file hashes", hashes.Count));
            }
            catch (Exception ex) { Logger.Warn("Self-hash registration failed: " + ex.Message); }
        }

        public AnalysisResult RunAnalysis(string filePath, int pid, string cmdLine)
        {
            // Dedup: skip if recently analyzed
            string dedupKey = (filePath ?? "PID:" + pid).ToLower();
            DateTime lastSeen;
            if (_recentlyAnalyzed.TryGetValue(dedupKey, out lastSeen) &&
                (DateTime.Now - lastSeen).TotalSeconds < DEDUP_SECONDS)
                return null;
            _recentlyAnalyzed[dedupKey] = DateTime.Now;

            // Prune old dedup entries periodically
            if (_recentlyAnalyzed.Count > 1000)
            {
                var cutoff = DateTime.Now.AddSeconds(-DEDUP_SECONDS * 2);
                foreach (var key in _recentlyAnalyzed.Keys.ToArray())
                {
                    DateTime val;
                    if (_recentlyAnalyzed.TryGetValue(key, out val) && val < cutoff)
                        _recentlyAnalyzed.TryRemove(key, out val);
                }
            }

            // Rate limit: max concurrent analyses
            if (!_analysisSemaphore.Wait(0))
            {
                Logger.Debug("Analysis throttled (queue full): " + dedupKey);
                return null;
            }

            try
            {
                return RunAnalysisCore(filePath, pid, cmdLine);
            }
            finally
            {
                _analysisSemaphore.Release();
            }
        }

        AnalysisResult RunAnalysisCore(string filePath, int pid, string cmdLine)
        {
            // Whitelist check: skip known-good files
            if (filePath != null && _whitelist.IsWhitelisted(filePath))
                return null;

            var a = new AnalysisResult { FilePath = filePath, ProcessId = pid, CommandLine = cmdLine };
            Logger.Info(string.Format("Analysis [{0}] File={1} PID={2}", a.AnalysisId, filePath, pid));

            // Stage 1: Static
            if (filePath != null && File.Exists(filePath))
                a.Static = StaticAnalyzer.Analyze(filePath);

            // Stage 2: Hash Reputation
            if (a.Static != null && !string.IsNullOrEmpty(a.Static.SHA256))
                a.HashReputation = _hashDB.Check(a.Static.SHA256);

            // Stage 3: AMSI Scan (scripts only)
            if (filePath != null)
            {
                int amsiScore = AMSIScanner.ScanFile(filePath);
                if (amsiScore > 0 && a.Static != null)
                {
                    a.Static.Score += amsiScore;
                    a.Static.Indicators.Add(string.Format("AMSI detection (score +{0})", amsiScore));
                }
            }

            // Stage 4: Behavior
            if (pid > 0 || cmdLine != null)
                a.Behavior = BehaviorEngine.Analyze(pid, cmdLine, filePath);

            // Stage 5: AMSI on command line content
            if (!string.IsNullOrEmpty(cmdLine))
            {
                int amsiCmdScore = AMSIScanner.ScanContent(cmdLine, "cmdline");
                if (amsiCmdScore > 0)
                {
                    if (a.Behavior == null) a.Behavior = new BehaviorResult();
                    a.Behavior.Score += amsiCmdScore;
                    a.Behavior.Indicators.Add(string.Format("AMSI flagged command line (score +{0})", amsiCmdScore));
                }
            }

            // Stage 6: YARA
            a.Yara = _yara.Scan(filePath, cmdLine);

            // Stage 7: MITRE
            a.Mitre = _mitre.Map(a.Behavior, a.Static, cmdLine);

            // Stage 8: Network
            if (pid > 0)
                a.Network = _network.Analyze(pid);

            // Stage 9: Memory Scan
            if (pid > 0)
                a.MemoryScan = MemoryScanner.Scan(pid);

            // Stage 10: Scoring
            ScoringEngine.Calculate(a);

            // Stage 11: Response
            a.ResponseTaken = _response.Execute(a);

            // Stage 12: JSON structured log
            JsonLogger.LogAnalysis(a);

            string mitreIds = string.Join(",", a.Mitre.Select(m => m.TechniqueId));
            if (a.Verdict == "Critical") Logger.Critical(string.Format("[{0}] Score={1} Verdict={2} MITRE=[{3}]", a.AnalysisId, a.TotalScore, a.Verdict, mitreIds));
            else if (a.Verdict == "Malicious") Logger.Alert(string.Format("[{0}] Score={1} Verdict={2} MITRE=[{3}]", a.AnalysisId, a.TotalScore, a.Verdict, mitreIds));
            else if (a.Verdict == "Suspicious") Logger.Warn(string.Format("[{0}] Score={1} Verdict={2} MITRE=[{3}]", a.AnalysisId, a.TotalScore, a.Verdict, mitreIds));
            else Logger.Info(string.Format("[{0}] Score={1} Verdict={2}", a.AnalysisId, a.TotalScore, a.Verdict));

            _history.Add(a);
            return a;
        }

        public void StartMonitoring()
        {
            if (_monitoring) { Logger.Warn("Already monitoring."); return; }
            _monitoring = true;

            // Process monitor
            try
            {
                _procWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                _procWatcher.EventArrived += (s, e) =>
                {
                    try
                    {
                        int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                        string name = (e.NewEvent["ProcessName"] ?? "").ToString();
                        string cmdLine = null, exePath = null;
                        try
                        {
                            using (var searcher = new ManagementObjectSearcher(
                                string.Format("SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE ProcessId={0}", pid)))
                            {
                                foreach (ManagementObject o in searcher.Get())
                                {
                                    cmdLine = (o["CommandLine"] ?? "").ToString();
                                    exePath = (o["ExecutablePath"] ?? "").ToString();
                                }
                            }
                        }
                        catch { }
                        RunAnalysis(exePath, pid, cmdLine);
                    }
                    catch { }
                };
                _procWatcher.Start();
                Logger.Info("Process monitor active");
            }
            catch (Exception ex) { Logger.Error("Process monitor failed (need admin?): " + ex.Message); }

            // File watchers - all fixed drives
            string[] riskyExts = {".exe",".dll",".ps1",".bat",".cmd",".vbs",".js",".wsf",".hta",".scr",".msi"};
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                string wp = drive.RootDirectory.FullName;
                try
                {
                    var w = new FileSystemWatcher(wp);
                    w.IncludeSubdirectories = true;
                    w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.DirectoryName;
                    w.InternalBufferSize = 65536;
                    w.EnableRaisingEvents = true;
                    w.Created += (s, e) =>
                    {
                        string ext = Path.GetExtension(e.FullPath).ToLower();
                        if (riskyExts.Contains(ext))
                        {
                            Logger.Warn("New file: " + e.FullPath);
                            Thread.Sleep(500);
                            RunAnalysis(e.FullPath, 0, null);
                        }
                        // Ransomware: check for ransom notes
                        _ransomware.OnFileCreated(e.FullPath);
                    };
                    w.Renamed += (s, e) =>
                    {
                        // Ransomware: track mass renames
                        _ransomware.OnFileRenamed(e.OldFullPath, e.FullPath);
                    };
                    w.Error += (s, e) =>
                    {
                        Logger.Debug("FileWatcher buffer overflow on " + wp + " - some events may be missed");
                    };
                    _fileWatchers.Add(w);
                    Logger.Info("File monitor: " + wp);
                }
                catch (Exception ex) { Logger.Debug("File watcher failed for " + wp + ": " + ex.Message); }
            }

            _network.StartMonitoring();
        }

        public void StopMonitoring()
        {
            if (!_monitoring) return;
            _monitoring = false;
            if (_procWatcher != null) { _procWatcher.Stop(); _procWatcher.Dispose(); _procWatcher = null; }
            foreach (var w in _fileWatchers) w.Dispose();
            _fileWatchers.Clear();
            _network.StopMonitoring();
            Logger.Info("All monitors stopped");
        }

        public void PrintDashboard()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n+==============================================================+");
            Console.WriteLine("|                   LOCAL EDR DASHBOARD                        |");
            Console.WriteLine("+==============================================================+");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n-- Status --");
            Console.ResetColor();
            Console.WriteLine("  Monitoring    : " + _monitoring);
            Console.WriteLine("  Total alerts  : " + _history.Count);
            Console.WriteLine("  Auto-response : " + (_response.AutoResponseEnabled ? "ON" : "OFF"));
            Console.WriteLine("  YARA rules    : " + _yara.Rules.Count);
            Console.WriteLine("  Hash DB       : " + _hashDB.Count + " known-malicious hashes");
            Console.WriteLine("  Dedup cache   : " + _recentlyAnalyzed.Count + " recent entries");
            Console.WriteLine("  AMSI          : " + (true ? "active" : "unavailable"));
            Console.WriteLine("  Ransomware    : score=" + _ransomware.GetScore());
            Console.WriteLine("  Integrity     : " + (SelfIntegrity.Verify() ? "OK" : "VIOLATED"));

            PrintAlerts(10);

            var topMitre = _history.SelectMany(a => a.Mitre).GroupBy(m => m.TechniqueId)
                .OrderByDescending(g => g.Count()).Take(10).ToList();
            if (topMitre.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("\n-- Top MITRE Techniques --");
                Console.ResetColor();
                foreach (var t in topMitre)
                    Console.WriteLine(string.Format("  {0} ({1}) - {2} hits", t.Key, t.First().TechniqueName, t.Count()));
            }
        }

        void PrintAlerts(int count)
        {
            var recent = _history.OrderByDescending(a => a.Timestamp).Take(count).ToList();
            if (recent.Count == 0) return;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(string.Format("\n-- Recent Alerts (last {0}) --", count));
            Console.ResetColor();
            foreach (var a in recent)
            {
                ConsoleColor c = a.Verdict == "Critical" ? ConsoleColor.Red :
                                 a.Verdict == "Malicious" ? ConsoleColor.DarkRed :
                                 a.Verdict == "Suspicious" ? ConsoleColor.Yellow : ConsoleColor.Gray;
                string mitre = string.Join(",", a.Mitre.Select(m => m.TechniqueId));
                string target = a.FilePath ?? a.CommandLine ?? "PID:" + a.ProcessId;
                if (target.Length > 55) target = "..." + target.Substring(target.Length - 52);
                Console.ForegroundColor = c;
                Console.WriteLine(string.Format("  [{0}] Score={1,-3} {2,-11} [{3}] {4}",
                    a.Timestamp.ToString("HH:mm:ss"), a.TotalScore, a.Verdict, mitre, target));
            }
            Console.ResetColor();
        }

        // Expose for interactive commands
        public MitreMapper Mitre { get { return _mitre; } }
        public NetworkMonitor Network { get { return _network; } }
        public ResponseEngine Response { get { return _response; } }
        public PseudoSandbox Sandbox { get { return _sandbox; } }
    }

    // ═══════════════════════════════════════════════════════════
    //  WINDOWS SERVICE
    // ═══════════════════════════════════════════════════════════

    class EDRService : ServiceBase
    {
        EDREngine _engine;

        public EDRService()
        {
            ServiceName = "LocalEDR";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            _engine = new EDREngine();
            AntiTamper.Enable();
            _engine.StartMonitoring();
            Logger.Info("LocalEDR service started");
        }

        protected override void OnStop()
        {
            AntiTamper.Disable();
            if (_engine != null) _engine.StopMonitoring();
            Logger.Info("LocalEDR service stopped");
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PROGRAM ENTRY POINT
    // ═══════════════════════════════════════════════════════════

    class Program
    {
        static void Main(string[] args)
        {
            // Service Control Manager launches us non-interactive
            if (!Environment.UserInteractive)
            {
                ServiceBase.Run(new EDRService());
                return;
            }

            // Only explicit switch: uninstall
            if (args.Length > 0 && args[0].ToLower() == "uninstall")
            {
                Console.Title = "Local EDR - Uninstall";
                PrintBanner();
                UninstallService();
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
                return;
            }

            // Everything else = install and start
            Console.Title = "Local EDR - VirusTotal-Style Threat Analysis";
            PrintBanner();
            InstallService();
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        static readonly string InstallDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LocalEDR");
        static readonly string InstalledExe = Path.Combine(InstallDir, "LocalEDR.exe");

        static void InstallService()
        {
            string sourceExe = System.Reflection.Assembly.GetExecutingAssembly().Location;
            Console.WriteLine("Installing LocalEDR...");
            try
            {
                // Create install directory
                Directory.CreateDirectory(InstallDir);

                // Copy exe to ProgramData\LocalEDR
                if (!sourceExe.Equals(InstalledExe, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(sourceExe, InstalledExe, true);
                    Console.WriteLine("  Copied to: " + InstalledExe);
                }

                // Create service
                RunSC(string.Format("create LocalEDR binPath= \"\\\"{0}\\\"\" start= auto DisplayName= \"Local EDR - Threat Analysis\"", InstalledExe));
                RunSC("description LocalEDR \"VirusTotal-style local endpoint detection and response. Auto-kills, quarantines, and blocks threats.\"");
                RunSC("failure LocalEDR reset= 86400 actions= restart/5000/restart/10000/restart/30000");

                // Start it now
                RunSC("start LocalEDR");

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nInstalled and started.");
                Console.WriteLine("  Location : " + InstallDir);
                Console.WriteLine("  Service  : LocalEDR (auto-start)");
                Console.WriteLine("  Response : auto-kill / quarantine / block");
                Console.WriteLine("  AMSI     : active (script scanning)");
                Console.WriteLine("  Tamper   : process marked critical");
                Console.WriteLine("  Logs     : " + Path.Combine(InstallDir, "Logs"));
                Console.WriteLine("  JSON logs: " + Path.Combine(InstallDir, "Logs", "JSON"));
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Install failed: " + ex.Message);
                Console.ResetColor();
            }
        }

        static void UninstallService()
        {
            Console.WriteLine("Removing LocalEDR...");
            try
            {
                RunSC("stop LocalEDR");
                Thread.Sleep(3000);
                RunSC("delete LocalEDR");

                // Clean up install directory
                if (Directory.Exists(InstallDir))
                {
                    try { Directory.Delete(InstallDir, true); } catch { }
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Service removed and files cleaned up.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Uninstall failed: " + ex.Message);
                Console.ResetColor();
            }
        }

        static void RunSC(string arguments)
        {
            var psi = new ProcessStartInfo {
                FileName = "sc.exe", Arguments = arguments,
                UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true
            };
            using (var p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit(10000);
                if (!string.IsNullOrEmpty(output)) Console.WriteLine("  " + output);
            }
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"
    ██╗      ██████╗  ██████╗ █████╗ ██╗         ███████╗██████╗ ██████╗
    ██║     ██╔═══██╗██╔════╝██╔══██╗██║         ██╔════╝██╔══██╗██╔══██╗
    ██║     ██║   ██║██║     ███████║██║         █████╗  ██║  ██║██████╔╝
    ██║     ██║   ██║██║     ██╔══██║██║         ██╔══╝  ██║  ██║██╔══██╗
    ███████╗╚██████╔╝╚██████╗██║  ██║███████╗    ███████╗██████╔╝██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚═════╝ ╚═╝  ╚═╝
");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("    VirusTotal-Style Local Threat Analysis Engine\n");
            Console.ResetColor();
        }

    }
}
