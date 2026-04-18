using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class StaticAnalyzer
{
    private static readonly (string Pattern, string Label)[] SuspiciousStringPatterns =
    [
        (@"https?://\d+\.\d+\.\d+\.\d+", "IP-based URL"),
        (@"powershell\s*[\-/]e(nc|ncodedcommand)", "Encoded PowerShell"),
        (@"cmd\.exe\s*/c", "cmd.exe execution"),
        (@"FromBase64String", "Base64 decode call"),
        (@"Invoke-Expression|iex\s", "Dynamic code execution (IEX)"),
        (@"DownloadString|DownloadFile|WebClient", "Network download"),
        (@"Net\.Sockets", "Raw socket usage"),
        (@"HKLM:\\|HKCU:\\|Registry", "Registry access"),
        (@"VirtualAlloc|VirtualProtect", "Memory manipulation API"),
        (@"CreateRemoteThread", "Remote thread creation"),
        (@"WriteProcessMemory", "Process memory write"),
        (@"OpenProcess", "Process handle opening"),
        (@"mimikatz|sekurlsa|kerberos", "Credential tool reference"),
        (@"Invoke-Mimikatz|Invoke-Shellcode", "Known attack tool"),
        (@"bypass|unrestricted|hidden", "Evasion keyword"),
        (@"Start-Process.*-WindowStyle\s+Hidden", "Hidden process launch"),
        (@"New-Object.*IO\.MemoryStream", "In-memory stream (fileless)"),
        (@"Reflection\.Assembly.*Load", "Reflective assembly loading"),
        (@"\-nop\s.*\-w\s+hidden", "PowerShell stealth flags"),
        (@"schtasks|at\s+\d+:\d+", "Scheduled task creation"),
        (@"net\s+user\s+/add", "User account creation"),
        (@"reg\s+add.*\\Run", "Registry Run key persistence"),
    ];

    private static readonly (string Name, string Risk)[] DangerousImports =
    [
        ("VirtualAllocEx", "Remote memory allocation"),
        ("WriteProcessMemory", "Process injection"),
        ("CreateRemoteThread", "Remote code execution"),
        ("NtUnmapViewOfSection", "Process hollowing"),
        ("SetWindowsHookEx", "Keylogging / hooking"),
        ("AdjustTokenPrivileges", "Privilege escalation"),
        ("IsDebuggerPresent", "Anti-debugging"),
        ("GetAsyncKeyState", "Keylogging"),
        ("InternetOpenUrl", "Network download"),
        ("URLDownloadToFile", "File download"),
        ("ShellExecute", "Process execution"),
        ("WinExec", "Legacy process execution"),
    ];

    public StaticAnalysisResult Analyze(string filePath)
    {
        var result = new StaticAnalysisResult
        {
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            FileType = Path.GetExtension(filePath).ToLower()
        };

        if (!File.Exists(filePath)) return result;

        try
        {
            var fileInfo = new FileInfo(filePath);
            result.FileSize = fileInfo.Length;

            byte[] bytes = File.ReadAllBytes(filePath);

            // Hashes
            result.Hashes = ComputeHashes(bytes);

            // Entropy
            result.Entropy = CalculateEntropy(bytes);
            if (result.Entropy > 7.2)
            {
                result.IsPacked = true;
                result.Score += 25;
                result.Indicators.Add($"High entropy ({result.Entropy:F2}) - likely packed/encrypted");
            }

            // Suspicious strings
            string text = ExtractPrintableStrings(bytes);
            result.SuspiciousStrings = FindSuspiciousStrings(text);
            if (result.SuspiciousStrings.Count > 0)
            {
                result.Score += Math.Min(result.SuspiciousStrings.Count * 5, 30);
                result.Indicators.Add($"Found {result.SuspiciousStrings.Count} suspicious string(s)");
            }

            // PE analysis
            if (result.FileType is ".exe" or ".dll" or ".scr" or ".sys")
            {
                result.PEInfo = ParsePE(bytes);
                result.SuspiciousImports = FindSuspiciousImports(text);
                if (result.SuspiciousImports.Count > 0)
                {
                    result.Score += Math.Min(result.SuspiciousImports.Count * 10, 40);
                    result.Indicators.Add($"Found {result.SuspiciousImports.Count} suspicious import(s)");
                }
            }

            // Authenticode signature check
            CheckSignature(result);

            // Double extension
            if (Regex.IsMatch(result.FileName, @"\.\w+\.(exe|scr|bat|cmd|ps1|vbs|js)$", RegexOptions.IgnoreCase))
            {
                result.Score += 30;
                result.Indicators.Add("Double extension detected (social engineering)");
            }

            // Tiny PE
            if (result.FileType is ".exe" or ".dll" && result.FileSize < 10240)
            {
                result.Score += 15;
                result.Indicators.Add($"Unusually small PE file ({result.FileSize} bytes)");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Static analysis error for {filePath}: {ex.Message}");
        }

        return result;
    }

    public static Dictionary<string, string> ComputeHashes(byte[] bytes)
    {
        return new Dictionary<string, string>
        {
            ["MD5"] = Convert.ToHexString(MD5.HashData(bytes)),
            ["SHA1"] = Convert.ToHexString(SHA1.HashData(bytes)),
            ["SHA256"] = Convert.ToHexString(SHA256.HashData(bytes))
        };
    }

    public static double CalculateEntropy(byte[] bytes)
    {
        if (bytes.Length == 0) return 0;

        int[] freq = new int[256];
        foreach (byte b in bytes) freq[b]++;

        double entropy = 0;
        double len = bytes.Length;
        foreach (int f in freq)
        {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * Math.Log2(p);
        }

        return Math.Round(entropy, 4);
    }

    private static string ExtractPrintableStrings(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
        {
            sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : ' ');
        }
        return sb.ToString();
    }

    private static List<StringFinding> FindSuspiciousStrings(string text)
    {
        var findings = new List<StringFinding>();
        foreach (var (pattern, label) in SuspiciousStringPatterns)
        {
            var match = Regex.Match(text, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                string val = match.Value.Length > 80 ? match.Value[..80] + "..." : match.Value;
                findings.Add(new StringFinding { Label = label, Match = val });
            }
        }
        return findings;
    }

    private static List<ImportFinding> FindSuspiciousImports(string text)
    {
        var findings = new List<ImportFinding>();
        foreach (var (name, risk) in DangerousImports)
        {
            if (text.Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ImportFinding { Import = name, Risk = risk });
            }
        }
        return findings;
    }

    private static PEInfo ParsePE(byte[] bytes)
    {
        var info = new PEInfo();
        try
        {
            if (bytes.Length < 64 || bytes[0] != 0x4D || bytes[1] != 0x5A) return info;
            info.IsPE = true;

            int peOffset = BitConverter.ToInt32(bytes, 0x3C);
            if (peOffset >= bytes.Length - 4) return info;
            if (bytes[peOffset] != 0x50 || bytes[peOffset + 1] != 0x45) return info;

            ushort machine = BitConverter.ToUInt16(bytes, peOffset + 4);
            info.Is64Bit = machine == 0x8664;

            uint timestamp = BitConverter.ToUInt32(bytes, peOffset + 8);
            info.TimeDateStamp = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;

            ushort numSections = BitConverter.ToUInt16(bytes, peOffset + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(bytes, peOffset + 20);
            int sectionStart = peOffset + 24 + optHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                int offset = sectionStart + i * 40;
                if (offset + 40 > bytes.Length) break;

                string name = Encoding.ASCII.GetString(bytes, offset, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(bytes, offset + 8);
                uint rawSize = BitConverter.ToUInt32(bytes, offset + 16);
                uint rawOffset = BitConverter.ToUInt32(bytes, offset + 20);

                double sectionEntropy = 0;
                if (rawSize > 0 && rawOffset + rawSize <= bytes.Length)
                {
                    byte[] sectionBytes = new byte[rawSize];
                    Array.Copy(bytes, rawOffset, sectionBytes, 0, rawSize);
                    sectionEntropy = CalculateEntropy(sectionBytes);
                }

                info.Sections.Add(new PESection
                {
                    Name = name,
                    VirtualSize = virtualSize,
                    RawSize = rawSize,
                    Entropy = sectionEntropy
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"PE parsing error: {ex.Message}");
        }

        return info;
    }

    private static void CheckSignature(StaticAnalysisResult result)
    {
        // Use WinVerifyTrust via process call for simplicity
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -Command \"(Get-AuthenticodeSignature '{result.FilePath}').Status\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            string output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(5000);

            if (output.Equals("Valid", StringComparison.OrdinalIgnoreCase))
            {
                result.IsSigned = true;
            }
        }
        catch { /* signature check is best-effort */ }
    }
}
