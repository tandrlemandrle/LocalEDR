using System.Text.Json;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class ResponseEngine
{
    private readonly EDRConfig _config;
    public bool AutoResponseEnabled { get; set; } = false; // Safe default

    private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss", "csrss", "wininit", "winlogon", "services",
        "lsass", "svchost", "dwm", "explorer", "taskhostw", "sihost",
        "fontdrvhost", "RuntimeBroker", "SearchIndexer",
        "SecurityHealthService", "MsMpEng", "powershell", "pwsh",
        "conhost", "cmd", "LocalEDR"
    };

    public ResponseEngine(EDRConfig config)
    {
        _config = config;
        Directory.CreateDirectory(config.QuarantinePath);
    }

    public string Execute(AnalysisResult analysis, int score, string verdict)
    {
        var actions = new List<string>();

        // Always generate alert above threshold
        if (score >= _config.AlertThreshold)
        {
            var alert = GenerateAlert(analysis, score, verdict);
            actions.Add($"Alert: {alert}");
        }

        if (!AutoResponseEnabled)
        {
            if (score >= _config.AlertThreshold)
            {
                Logger.Warn($"Auto-response DISABLED. Manual action required (score={score}, verdict={verdict})");
                actions.Add("Manual review required");
            }
            return actions.Count > 0 ? string.Join("; ", actions) : "None";
        }

        // Auto-kill
        if (score >= _config.AutoKillThreshold && analysis.ProcessId > 0)
        {
            actions.Add(KillProcess(analysis.ProcessId));
        }

        // Auto-quarantine
        if (score >= _config.AutoQuarantineThreshold && !string.IsNullOrEmpty(analysis.FilePath))
        {
            actions.Add(QuarantineFile(analysis.FilePath, analysis));
        }

        // Auto-block network
        if (score >= _config.AutoBlockThreshold && analysis.NetworkResults?.SuspiciousConnections.Count > 0)
        {
            foreach (var conn in analysis.NetworkResults.SuspiciousConnections)
                actions.Add(BlockConnection(conn.RemoteAddress));
        }

        return actions.Count > 0 ? string.Join("; ", actions) : "None";
    }

    public string KillProcess(int pid)
    {
        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(pid);
            if (ProtectedProcesses.Contains(proc.ProcessName))
            {
                Logger.Warn($"BLOCKED: Cannot kill protected process {proc.ProcessName} (PID {pid})");
                return $"Protected process - kill blocked: {proc.ProcessName}";
            }

            proc.Kill(true);
            Logger.Critical($"KILLED: Process {proc.ProcessName} (PID {pid})");
            return $"Process killed: {proc.ProcessName} (PID {pid})";
        }
        catch (Exception ex)
        {
            return $"Kill failed: PID {pid} - {ex.Message}";
        }
    }

    public string QuarantineFile(string filePath, AnalysisResult? analysis = null)
    {
        try
        {
            if (!File.Exists(filePath)) return $"File not found: {filePath}";

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string originalName = Path.GetFileName(filePath);
            string quarantineName = $"{timestamp}_{originalName}.quarantined";
            string quarantinePath = Path.Combine(_config.QuarantinePath, quarantineName);

            // Save metadata
            var metadata = new
            {
                OriginalPath = filePath,
                QuarantinedAt = DateTime.Now.ToString("o"),
                Score = analysis?.TotalScore ?? 0,
                Verdict = analysis?.Verdict ?? "Unknown",
                Hashes = analysis?.StaticResults?.Hashes,
                MitreTechniques = analysis?.MitreMappings.Select(m => m.TechniqueId).ToArray()
            };
            string metaPath = quarantinePath + ".meta.json";
            File.WriteAllText(metaPath, JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }));

            // Move file
            File.Move(filePath, quarantinePath);

            Logger.Critical($"QUARANTINED: {filePath} -> {quarantinePath}");
            return $"File quarantined: {originalName}";
        }
        catch (Exception ex)
        {
            return $"Quarantine failed: {ex.Message}";
        }
    }

    public void RestoreFromQuarantine(string fileName)
    {
        string quarantinePath = Path.Combine(_config.QuarantinePath, fileName);
        string metaPath = quarantinePath + ".meta.json";

        if (!File.Exists(metaPath))
        {
            Console.WriteLine($"Metadata not found for: {fileName}");
            return;
        }

        string json = File.ReadAllText(metaPath);
        using var doc = JsonDocument.Parse(json);
        string? originalPath = doc.RootElement.GetProperty("OriginalPath").GetString();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"Restoring: {fileName}");
        Console.WriteLine($"  Original path: {originalPath}");
        Console.ResetColor();
        Console.Write("Are you sure? (yes/no): ");

        if (Console.ReadLine()?.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase) == true && originalPath != null)
        {
            File.Move(quarantinePath, originalPath);
            File.Delete(metaPath);
            Logger.Warn($"RESTORED from quarantine: {originalPath}");
        }
        else
        {
            Console.WriteLine("Restore cancelled.");
        }
    }

    public string BlockConnection(string remoteAddress)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall add rule name=\"EDR_Block_{remoteAddress}\" dir=out action=block remoteip={remoteAddress}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit(5000);

            // Inbound too
            psi.Arguments = $"advfirewall firewall add rule name=\"EDR_Block_{remoteAddress}_In\" dir=in action=block remoteip={remoteAddress}";
            using var proc2 = System.Diagnostics.Process.Start(psi);
            proc2?.WaitForExit(5000);

            Logger.Critical($"BLOCKED: Network connection to {remoteAddress}");
            return $"Network blocked: {remoteAddress}";
        }
        catch (Exception ex)
        {
            return $"Block failed: {ex.Message}";
        }
    }

    public void ListQuarantined()
    {
        if (!Directory.Exists(_config.QuarantinePath))
        {
            Console.WriteLine("No quarantine directory.");
            return;
        }

        var files = Directory.GetFiles(_config.QuarantinePath, "*.quarantined");
        if (files.Length == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No quarantined files.");
            Console.ResetColor();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n══ Quarantined Files ══");
        Console.ResetColor();

        foreach (string f in files)
        {
            string name = Path.GetFileName(f);
            string metaPath = f + ".meta.json";
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  {name}");
            Console.ResetColor();

            if (File.Exists(metaPath))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
                    var root = doc.RootElement;
                    Console.WriteLine($"    Original: {root.GetProperty("OriginalPath").GetString()}");
                    Console.WriteLine($"    Score: {root.GetProperty("Score")} | Verdict: {root.GetProperty("Verdict").GetString()}");
                    Console.WriteLine($"    Quarantined: {root.GetProperty("QuarantinedAt").GetString()}");
                }
                catch { }
            }
        }
    }

    private string GenerateAlert(AnalysisResult analysis, int score, string verdict)
    {
        string alertId = Guid.NewGuid().ToString("N")[..8];
        var alert = new
        {
            AlertId = alertId,
            Timestamp = DateTime.Now.ToString("o"),
            Score = score,
            Verdict = verdict,
            Target = analysis.FilePath ?? $"PID:{analysis.ProcessId}",
            CommandLine = analysis.CommandLine,
            Mitre = analysis.MitreMappings.Select(m => $"{m.TechniqueId}:{m.TechniqueName}").ToArray(),
            YaraRules = analysis.YaraMatches.Select(m => m.RuleName).ToArray()
        };

        string alertDir = Path.Combine(_config.LogPath, "Alerts");
        Directory.CreateDirectory(alertDir);
        string alertFile = Path.Combine(alertDir, $"{alertId}_{DateTime.Now:yyyyMMdd_HHmmss}.json");

        try
        {
            File.WriteAllText(alertFile, JsonSerializer.Serialize(alert, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* best effort */ }

        return alertId;
    }
}
