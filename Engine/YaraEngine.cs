using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class YaraEngine
{
    private readonly List<YaraRule> _rules = [];

    public void Initialize()
    {
        _rules.Clear();
        LoadBuiltInRules();
        Logger.Info($"YARA engine initialized with {_rules.Count} rules");
    }

    public void LoadRulesFromJson(string path)
    {
        if (!File.Exists(path)) { Logger.Warn($"Rule file not found: {path}"); return; }
        try
        {
            string json = File.ReadAllText(path);
            var rules = JsonSerializer.Deserialize<YaraRule[]>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (rules != null)
            {
                _rules.AddRange(rules);
                Logger.Info($"Loaded {rules.Length} custom rules from {path}");
            }
        }
        catch (Exception ex) { Logger.Warn($"Error loading rules: {ex.Message}"); }
    }

    public List<YaraMatch> Scan(string? filePath, string? commandLine)
    {
        var matches = new List<YaraMatch>();

        string content = "";
        if (filePath != null && File.Exists(filePath))
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(filePath);
                var sb = new StringBuilder(bytes.Length);
                foreach (byte b in bytes)
                    sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : ' ');
                content = sb.ToString();
            }
            catch { /* best effort */ }
        }
        if (commandLine != null) content += " " + commandLine;

        string contentLower = content.ToLower();
        if (string.IsNullOrWhiteSpace(contentLower)) return matches;

        foreach (var rule in _rules)
        {
            if (!rule.Enabled) continue;

            int hitCount = 0;
            var hitPatterns = new List<string>();

            foreach (string pattern in rule.StringPatterns)
            {
                try
                {
                    if (Regex.IsMatch(contentLower, pattern, RegexOptions.IgnoreCase))
                    {
                        hitCount++;
                        hitPatterns.Add(pattern);
                    }
                }
                catch { /* skip bad regex */ }
            }

            bool triggered = rule.Condition switch
            {
                "all" => hitCount == rule.StringPatterns.Length,
                "2_of" => hitCount >= 2,
                "3_of" => hitCount >= 3,
                _ => hitCount >= 1 // "any"
            };

            if (triggered)
            {
                matches.Add(new YaraMatch
                {
                    RuleName = rule.Name,
                    Description = rule.Description,
                    Category = rule.Category,
                    Severity = rule.Severity,
                    Score = rule.Score,
                    HitCount = hitCount,
                    HitPatterns = hitPatterns
                });
                Logger.Alert($"YARA match: {rule.Name} [{rule.Severity}]");
            }
        }

        return matches;
    }

    private void LoadBuiltInRules()
    {
        _rules.AddRange([
            new YaraRule
            {
                Name = "EncodedPowerShell", Description = "Detects base64-encoded PowerShell execution",
                Category = "Execution", Severity = "High", Score = 50,
                StringPatterns = [@"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", @"powershell.*-encodedcommand\s+[A-Za-z0-9+/=]{20,}"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "PSDownloadCradle", Description = "Detects PowerShell download-and-execute patterns",
                Category = "C2", Severity = "High", Score = 60,
                StringPatterns = [@"new-object\s+net\.webclient", "downloadstring", "downloadfile", "invoke-webrequest", "start-bitstransfer", @"iex|invoke-expression"],
                Condition = "2_of"
            },
            new YaraRule
            {
                Name = "MimikatzIndicators", Description = "Detects Mimikatz or credential dumping tools",
                Category = "CredentialAccess", Severity = "Critical", Score = 90,
                StringPatterns = ["mimikatz", "sekurlsa", @"kerberos::", @"lsadump::", @"privilege::debug", "invoke-mimikatz"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "ProcessInjection", Description = "Detects process injection API patterns",
                Category = "Injection", Severity = "High", Score = 70,
                StringPatterns = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection", "QueueUserAPC"],
                Condition = "2_of"
            },
            new YaraRule
            {
                Name = "RansomwareIndicators", Description = "Detects ransomware-like behavior patterns",
                Category = "Impact", Severity = "Critical", Score = 90,
                StringPatterns = [@"vssadmin.*delete\s+shadows", @"bcdedit.*recoveryenabled.*no", @"wbadmin\s+delete\s+catalog", @"cipher\s+/w:", "your files have been encrypted", @"\.onion", @"bitcoin|btc.*wallet"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "ReverseShell", Description = "Detects reverse shell patterns",
                Category = "C2", Severity = "Critical", Score = 85,
                StringPatterns = [@"net\.sockets\.tcpclient", @"system\.net\.sockets", @"new-object\s+system\.net\.sockets\.tcpclient", @"ncat\s+-e", @"nc\s+-e"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "AMSIBypass", Description = "Detects AMSI bypass techniques",
                Category = "Evasion", Severity = "High", Score = 70,
                StringPatterns = ["amsiutils", "amsiinitfailed", "amsicontext", "AmsiScanBuffer", @"amsi\.dll"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "DefenderTampering", Description = "Detects attempts to disable Windows Defender",
                Category = "Evasion", Severity = "Critical", Score = 80,
                StringPatterns = [@"set-mppreference.*-disablerealtimemonitoring\s+\$true", @"set-mppreference.*-disableioavprotection", @"set-mppreference.*-disablebehaviormonitoring", @"add-mppreference.*-exclusionpath", @"stop-service.*windefend", @"sc\s+stop\s+windefend"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "FilelessMalware", Description = "Detects fileless/in-memory execution patterns",
                Category = "Evasion", Severity = "High", Score = 65,
                StringPatterns = [@"\[reflection\.assembly\]::load", @"\[system\.reflection\.assembly\]::load", @"io\.memorystream", @"io\.compression\.gzipstream", @"frombase64string.*load", @"add-type.*-typedefinition.*dllimport"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "RegistryPersistence", Description = "Detects registry-based persistence mechanisms",
                Category = "Persistence", Severity = "Medium", Score = 40,
                StringPatterns = [@"new-itemproperty.*currentversion\\run", @"set-itemproperty.*currentversion\\run", @"reg\s+add.*\\run\s", @"currentversion\\runonce"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "LateralMovement", Description = "Detects lateral movement techniques",
                Category = "LateralMovement", Severity = "High", Score = 55,
                StringPatterns = [@"invoke-command\s+-computername", "enter-pssession", "new-pssession", @"net\s+use\s+\\\\", "psexec", @"wmic\s+/node:"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "DataExfiltration", Description = "Detects data exfiltration patterns",
                Category = "Exfiltration", Severity = "High", Score = 55,
                StringPatterns = [@"compress-archive.*-destinationpath", @"invoke-restmethod.*-method\s+post.*-body", @"convertto-json.*invoke-webrequest", @"send-mailmessage.*-attachments"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "CobaltStrikeIndicators", Description = "Detects Cobalt Strike beacon indicators",
                Category = "C2", Severity = "Critical", Score = 90,
                StringPatterns = [@"beacon\.dll", "cobaltstrike", "sleeptime", @"IEX.*downloadstring.*http"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "PowerSploit", Description = "Detects PowerSploit framework usage",
                Category = "Execution", Severity = "High", Score = 75,
                StringPatterns = ["invoke-shellcode", "invoke-reflectivepeinjection", "invoke-dllinjection", "invoke-tokenmanipulation", "invoke-credentialinjection", "get-gpppassword", "invoke-kerberoast"],
                Condition = "any"
            },
            new YaraRule
            {
                Name = "SuspiciousScript", Description = "Detects suspicious script patterns",
                Category = "Execution", Severity = "Medium", Score = 35,
                StringPatterns = [@"hidden.*-nop.*-w", @"bypass.*executionpolicy", "invoke-shellcode", "invoke-dllinjection", "invoke-reflectivepeinjection"],
                Condition = "any"
            },
        ]);
    }

    public IReadOnlyList<YaraRule> Rules => _rules;
}
