using System.Text.RegularExpressions;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class MitreMapper
{
    private readonly List<MitreMapping> _allFindings = [];

    // ── Technique database ────────────────────────────────────
    private static readonly Dictionary<string, (string Name, string Tactic)> Techniques = new()
    {
        // Execution
        ["T1059.001"] = ("PowerShell", "Execution"),
        ["T1059.003"] = ("Windows Command Shell", "Execution"),
        ["T1059.005"] = ("Visual Basic", "Execution"),
        ["T1059.007"] = ("JavaScript", "Execution"),
        ["T1204.002"] = ("Malicious File", "Execution"),
        ["T1047"] = ("WMI", "Execution"),
        ["T1053.005"] = ("Scheduled Task", "Execution"),
        ["T1569.002"] = ("Service Execution", "Execution"),
        // Persistence
        ["T1547.001"] = ("Registry Run Keys", "Persistence"),
        ["T1543.003"] = ("Windows Service", "Persistence"),
        ["T1546.003"] = ("WMI Event Subscription", "Persistence"),
        // Privilege Escalation
        ["T1134"] = ("Access Token Manipulation", "Privilege Escalation"),
        ["T1548.002"] = ("UAC Bypass", "Privilege Escalation"),
        // Defense Evasion
        ["T1562.001"] = ("Disable Security Tools", "Defense Evasion"),
        ["T1562.002"] = ("Disable Event Logging", "Defense Evasion"),
        ["T1070.001"] = ("Clear Windows Event Logs", "Defense Evasion"),
        ["T1027"] = ("Obfuscated Files", "Defense Evasion"),
        ["T1140"] = ("Deobfuscate/Decode Files", "Defense Evasion"),
        ["T1218.005"] = ("Mshta", "Defense Evasion"),
        ["T1218.010"] = ("Regsvr32", "Defense Evasion"),
        ["T1218.011"] = ("Rundll32", "Defense Evasion"),
        ["T1055"] = ("Process Injection", "Defense Evasion"),
        ["T1055.012"] = ("Process Hollowing", "Defense Evasion"),
        ["T1620"] = ("Reflective Code Loading", "Defense Evasion"),
        // Credential Access
        ["T1003.001"] = ("LSASS Memory", "Credential Access"),
        ["T1003.003"] = ("NTDS", "Credential Access"),
        ["T1056.001"] = ("Keylogging", "Credential Access"),
        // Discovery
        ["T1082"] = ("System Information Discovery", "Discovery"),
        ["T1057"] = ("Process Discovery", "Discovery"),
        ["T1016"] = ("System Network Config", "Discovery"),
        ["T1033"] = ("System Owner/User Discovery", "Discovery"),
        ["T1069"] = ("Permission Groups Discovery", "Discovery"),
        ["T1018"] = ("Remote System Discovery", "Discovery"),
        ["T1482"] = ("Domain Trust Discovery", "Discovery"),
        // Lateral Movement
        ["T1021.002"] = ("SMB/Windows Admin Shares", "Lateral Movement"),
        ["T1021.006"] = ("Windows Remote Management", "Lateral Movement"),
        // C2
        ["T1071.001"] = ("Web Protocols", "Command and Control"),
        ["T1105"] = ("Ingress Tool Transfer", "Command and Control"),
        ["T1132"] = ("Data Encoding", "Command and Control"),
        // Impact
        ["T1486"] = ("Data Encrypted for Impact", "Impact"),
        ["T1490"] = ("Inhibit System Recovery", "Impact"),
        ["T1489"] = ("Service Stop", "Impact"),
    };

    // ── Detection rules ───────────────────────────────────────
    private static readonly (string Pattern, string TechniqueId, string Confidence)[] DetectionRules =
    [
        (@"powershell", "T1059.001", "Medium"),
        (@"powershell.*-enc", "T1059.001", "High"),
        (@"cmd\.exe\s*/c", "T1059.003", "Medium"),
        (@"wscript|cscript.*\.vbs", "T1059.005", "Medium"),
        (@"wscript|cscript.*\.js", "T1059.007", "Medium"),
        (@"wmic.*process\s+call\s+create", "T1047", "High"),
        (@"schtasks\s+/create", "T1053.005", "High"),
        (@"currentversion\\run", "T1547.001", "High"),
        (@"new-itemproperty.*\\run", "T1547.001", "High"),
        (@"sc\s+(create|config)", "T1543.003", "High"),
        (@"__eventconsumer|register-wmievent", "T1546.003", "High"),
        (@"set-mppreference.*disable", "T1562.001", "High"),
        (@"stop-service.*windefend", "T1562.001", "High"),
        (@"amsiutils|amsiinitfailed", "T1562.001", "High"),
        (@"clear-eventlog|wevtutil\s+cl", "T1070.001", "High"),
        (@"etw.*patch|etweventwrite", "T1562.002", "High"),
        (@"mshta\.exe", "T1218.005", "Medium"),
        (@"regsvr32\.exe", "T1218.010", "Medium"),
        (@"rundll32\.exe", "T1218.011", "Medium"),
        (@"frombase64string|decode", "T1140", "Medium"),
        (@"-enc\s+[A-Za-z0-9+/=]{20,}", "T1027", "High"),
        (@"createremotethread", "T1055", "High"),
        (@"writeprocessmemory", "T1055", "High"),
        (@"virtualallocex", "T1055", "High"),
        (@"ntunmapviewofsection", "T1055.012", "High"),
        (@"reflection\.assembly.*load", "T1620", "High"),
        (@"mimikatz|sekurlsa", "T1003.001", "High"),
        (@"getasynckeystate", "T1056.001", "High"),
        (@"ntds\.dit", "T1003.003", "High"),
        (@"systeminfo", "T1082", "Medium"),
        (@"whoami", "T1033", "Low"),
        (@"ipconfig|nslookup", "T1016", "Low"),
        (@"tasklist|get-process", "T1057", "Low"),
        (@"net\s+user|net\s+localgroup", "T1069", "Medium"),
        (@"nltest.*domain_trusts", "T1482", "High"),
        (@"net\s+view|net\s+share", "T1018", "Medium"),
        (@"net\s+use\s+\\\\", "T1021.002", "Medium"),
        (@"enter-pssession|invoke-command", "T1021.006", "Medium"),
        (@"downloadstring|downloadfile|invoke-webrequest", "T1105", "Medium"),
        (@"certutil.*-urlcache", "T1105", "High"),
        (@"bitsadmin.*transfer", "T1105", "High"),
        (@"net\.webclient", "T1071.001", "Medium"),
        (@"vssadmin.*delete\s+shadows", "T1490", "High"),
        (@"bcdedit.*recoveryenabled.*no", "T1490", "High"),
        (@"wbadmin\s+delete\s+catalog", "T1490", "High"),
        (@"stop-service", "T1489", "Low"),
    ];

    public List<MitreMapping> Map(BehaviorResult? behavior, StaticAnalysisResult? staticResult, string? commandLine)
    {
        var mappings = new List<MitreMapping>();
        var seen = new HashSet<string>();

        string allText = (commandLine ?? "").ToLower();
        if (behavior?.CommandLine != null)
            allText += " " + behavior.CommandLine.ToLower();

        // Match detection rules
        foreach (var (pattern, techId, confidence) in DetectionRules)
        {
            if (seen.Contains(techId)) continue;
            if (!Regex.IsMatch(allText, pattern, RegexOptions.IgnoreCase)) continue;
            if (!Techniques.TryGetValue(techId, out var techInfo)) continue;

            seen.Add(techId);
            mappings.Add(new MitreMapping
            {
                TechniqueId = techId,
                TechniqueName = techInfo.Name,
                Tactic = techInfo.Tactic,
                Confidence = confidence,
                MatchedOn = pattern
            });
        }

        // Static analysis enrichment
        if (staticResult != null)
        {
            if (staticResult.IsPacked && !seen.Contains("T1027"))
            {
                seen.Add("T1027");
                mappings.Add(new MitreMapping
                {
                    TechniqueId = "T1027", TechniqueName = "Obfuscated Files",
                    Tactic = "Defense Evasion", Confidence = "Medium",
                    MatchedOn = "High entropy (packed/encrypted)"
                });
            }

            foreach (var imp in staticResult.SuspiciousImports)
            {
                if (imp.Import is "CreateRemoteThread" or "WriteProcessMemory" or "VirtualAllocEx" && !seen.Contains("T1055"))
                {
                    seen.Add("T1055");
                    mappings.Add(new MitreMapping
                    {
                        TechniqueId = "T1055", TechniqueName = "Process Injection",
                        Tactic = "Defense Evasion", Confidence = "High",
                        MatchedOn = $"Import: {imp.Import}"
                    });
                }
                if (imp.Import is "GetAsyncKeyState" or "SetWindowsHookEx" && !seen.Contains("T1056.001"))
                {
                    seen.Add("T1056.001");
                    mappings.Add(new MitreMapping
                    {
                        TechniqueId = "T1056.001", TechniqueName = "Keylogging",
                        Tactic = "Credential Access", Confidence = "High",
                        MatchedOn = $"Import: {imp.Import}"
                    });
                }
            }
        }

        // Parent-child enrichment
        if (behavior?.ParentChildFlag != null)
        {
            if (behavior.ParentChildFlag.Parent.Contains("word") ||
                behavior.ParentChildFlag.Parent.Contains("excel") ||
                behavior.ParentChildFlag.Parent.Contains("outlook"))
            {
                if (!seen.Contains("T1204.002"))
                {
                    mappings.Add(new MitreMapping
                    {
                        TechniqueId = "T1204.002", TechniqueName = "Malicious File",
                        Tactic = "Execution", Confidence = "High",
                        MatchedOn = "Office app spawning child process"
                    });
                }
            }
        }

        // Store globally
        _allFindings.AddRange(mappings);
        return mappings;
    }

    public void PrintReport()
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n══ MITRE ATT&CK Coverage Report ══");
        Console.ResetColor();

        if (_allFindings.Count == 0)
        {
            Console.WriteLine("  No techniques observed yet.");
            return;
        }

        var grouped = _allFindings
            .GroupBy(m => m.Tactic)
            .OrderBy(g => g.Key);

        foreach (var tactic in grouped)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n  ── {tactic.Key} ──");
            Console.ResetColor();

            var unique = tactic.DistinctBy(t => t.TechniqueId);
            foreach (var t in unique)
            {
                string conf = t.Confidence switch
                {
                    "High" => "[H]",
                    "Medium" => "[M]",
                    _ => "[L]"
                };
                Console.WriteLine($"    {conf} {t.TechniqueId} - {t.TechniqueName}");
            }
        }
    }

    public IReadOnlyList<MitreMapping> AllFindings => _allFindings;
}
