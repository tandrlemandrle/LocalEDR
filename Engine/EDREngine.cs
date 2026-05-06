using System.Management;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class EDREngine
{
    private readonly EDRConfig _config;
    private readonly StaticAnalyzer _static = new();
    private readonly BehaviorEngine _behavior = new();
    private readonly YaraEngine _yara = new();
    private readonly List<AnalysisResult> _alertHistory = [];
    private readonly Dictionary<int, DateTime> _processTracker = new();
    private ManagementEventWatcher? _processWatcher;
    private readonly List<FileSystemWatcher> _fileWatchers = [];
    private bool _monitoring;

    public MitreMapper MitreMapper { get; } = new();
    public NetworkMonitor Network { get; } = new();
    public ScoringEngine Scoring { get; } = new();
    public ResponseEngine Response { get; }
    public PseudoSandbox Sandbox { get; } = new();

    public EDREngine(EDRConfig config)
    {
        _config = config;
        Response = new ResponseEngine(config);

        Logger.Initialize(config.LogPath);
        Directory.CreateDirectory(config.QuarantinePath);
        Directory.CreateDirectory(config.RulesPath);

        _yara.Initialize();

        // Load custom rules if present
        string customRules = Path.Combine(config.RulesPath, "custom_rules.json");
        if (File.Exists(customRules)) _yara.LoadRulesFromJson(customRules);

        // Self-protection: hash our own files so the EDR never quarantines itself
        RegisterSelfHashes();
    }

    /// <summary>
    /// Compute SHA256 of every file in the EDR's own directory and register
    /// them with the ScoringEngine so they always score Clean.
    /// </summary>
    private void RegisterSelfHashes()
    {
        var selfHashes = new List<string>();
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        try
        {
            foreach (string file in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
            {
                // Skip logs, quarantine, and rules — those change at runtime
                string rel = file[baseDir.Length..];
                if (rel.StartsWith("Logs", StringComparison.OrdinalIgnoreCase) ||
                    rel.StartsWith("Quarantine", StringComparison.OrdinalIgnoreCase) ||
                    rel.StartsWith("Rules", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    byte[] bytes = File.ReadAllBytes(file);
                    string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
                    selfHashes.Add(sha256);
                }
                catch { /* skip files we can't read */ }
            }
            ScoringEngine.RegisterSelfHashes(selfHashes);
            Logger.Info($"Self-protection: registered {selfHashes.Count} EDR file hashes");
        }
        catch (Exception ex)
        {
            Logger.Warn($"Self-hash registration failed: {ex.Message}");
        }
    }

    // ── Full analysis pipeline ────────────────────────────────
    public async Task<AnalysisResult> RunFullAnalysis(string? filePath, int processId = 0, string? commandLine = null)
    {
        var result = new AnalysisResult
        {
            FilePath = filePath,
            ProcessId = processId,
            CommandLine = commandLine
        };

        Logger.Info($"Analysis [{result.AnalysisId}] File={filePath} PID={processId}");

        // Stage 1: Static
        if (filePath != null && File.Exists(filePath))
        {
            Logger.Info($"[{result.AnalysisId}] Stage 1: Static Analysis");
            result.StaticResults = _static.Analyze(filePath);
        }

        // Stage 2: Behavior
        if (processId > 0 || commandLine != null)
        {
            Logger.Info($"[{result.AnalysisId}] Stage 2: Behavior Analysis");
            result.BehaviorResults = _behavior.Analyze(processId, commandLine, filePath);
        }

        // Stage 3: YARA
        Logger.Info($"[{result.AnalysisId}] Stage 3: YARA Rules");
        result.YaraMatches = _yara.Scan(filePath, commandLine);

        // Stage 4: MITRE
        Logger.Info($"[{result.AnalysisId}] Stage 4: MITRE Mapping");
        result.MitreMappings = MitreMapper.Map(result.BehaviorResults, result.StaticResults, commandLine);

        // Stage 5: Network
        if (_config.EnableNetwork && processId > 0)
        {
            Logger.Info($"[{result.AnalysisId}] Stage 5: Network Analysis");
            result.NetworkResults = Network.Analyze(processId);
        }

        // Stage 6: Scoring
        Logger.Info($"[{result.AnalysisId}] Stage 6: Scoring");
        var scoreResult = Scoring.Calculate(result);
        result.TotalScore = scoreResult.TotalScore;
        result.Verdict = scoreResult.Verdict;
        result.Confidence = scoreResult.Confidence;

        // Stage 7: Response
        Logger.Info($"[{result.AnalysisId}] Stage 7: Response (Score={result.TotalScore} Verdict={result.Verdict})");
        result.ResponseTaken = Response.Execute(result, result.TotalScore, result.Verdict);

        // Log final
        string logLevel = result.Verdict switch
        {
            "Critical" => "CRITICAL",
            "Malicious" => "ALERT",
            "Suspicious" => "WARN",
            _ => "INFO"
        };
        string mitreIds = string.Join(",", result.MitreMappings.Select(m => m.TechniqueId));
        string msg = $"[{result.AnalysisId}] COMPLETE: Score={result.TotalScore} Verdict={result.Verdict} MITRE=[{mitreIds}] Response={result.ResponseTaken}";

        switch (logLevel)
        {
            case "CRITICAL": Logger.Critical(msg); break;
            case "ALERT": Logger.Alert(msg); break;
            case "WARN": Logger.Warn(msg); break;
            default: Logger.Info(msg); break;
        }

        _alertHistory.Add(result);
        return result;
    }

    // ── Scan file or directory ─────────────────────────────────
    public async Task<AnalysisResult> ScanPath(string path)
    {
        if (Directory.Exists(path))
        {
            Logger.Info($"Scanning directory: {path}");
            AnalysisResult? worst = null;
            foreach (string file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                var r = await RunFullAnalysis(file);
                if (worst == null || r.TotalScore > worst.TotalScore) worst = r;
            }
            return worst ?? new AnalysisResult { FilePath = path };
        }

        if (File.Exists(path))
        {
            Logger.Info($"Scanning file: {path}");
            return await RunFullAnalysis(path);
        }

        Logger.Warn($"Path not found: {path}");
        return new AnalysisResult { FilePath = path };
    }

    // ── Real-time monitoring ──────────────────────────────────
    public void StartRealTimeMonitoring()
    {
        if (_monitoring) { Logger.Warn("Already monitoring."); return; }
        _monitoring = true;

        Logger.Info("Starting real-time process monitor");
        try
        {
            _processWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _processWatcher.EventArrived += OnProcessCreated;
            _processWatcher.Start();
            Logger.Info("Process monitor active");
        }
        catch (Exception ex)
        {
            Logger.Error($"Process monitor failed (need admin?): {ex.Message}");
        }

        // File watchers
        string[] riskyExtensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".scr", ".msi"];
        foreach (string watchPath in _config.WatchPaths)
        {
            if (!Directory.Exists(watchPath)) continue;
            try
            {
                var watcher = new FileSystemWatcher(watchPath)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true
                };

                watcher.Created += (_, e) =>
                {
                    string ext = Path.GetExtension(e.FullPath).ToLower();
                    if (riskyExtensions.Contains(ext))
                    {
                        Logger.Warn($"New file detected: {e.FullPath}");
                        Task.Delay(500).ContinueWith(_ => RunFullAnalysis(e.FullPath));
                    }
                };

                _fileWatchers.Add(watcher);
                Logger.Info($"File monitor active for: {watchPath}");
            }
            catch (Exception ex)
            {
                Logger.Debug($"File watcher failed for {watchPath}: {ex.Message}");
            }
        }

        if (_config.EnableNetwork) Network.StartMonitoring();
    }

    public void StopRealTimeMonitoring()
    {
        if (!_monitoring) return;
        _monitoring = false;

        _processWatcher?.Stop();
        _processWatcher?.Dispose();
        _processWatcher = null;

        foreach (var w in _fileWatchers) w.Dispose();
        _fileWatchers.Clear();

        Network.StopMonitoring();
        Logger.Info("All monitors stopped");
    }

    private void OnProcessCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
            string name = e.NewEvent["ProcessName"]?.ToString() ?? "";

            _processTracker[pid] = DateTime.Now;

            // Get command line
            string? cmdLine = null;
            string? exePath = null;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    cmdLine = obj["CommandLine"]?.ToString();
                    exePath = obj["ExecutablePath"]?.ToString();
                }
            }
            catch { }

            _ = RunFullAnalysis(exePath, pid, cmdLine);
        }
        catch (Exception ex)
        {
            Logger.Debug($"Process event error: {ex.Message}");
        }
    }

    // ── Dashboard ─────────────────────────────────────────────
    public void PrintDashboard()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║                   LOCAL EDR DASHBOARD                       ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n── Active Monitors ──");
        Console.ResetColor();
        Console.WriteLine($"  Monitoring active : {_monitoring}");
        Console.WriteLine($"  Processes tracked : {_processTracker.Count}");
        Console.WriteLine($"  Total alerts      : {_alertHistory.Count}");
        Console.WriteLine($"  Auto-response     : {(Response.AutoResponseEnabled ? "ON" : "OFF")}");
        Console.WriteLine($"  YARA rules loaded : {_yara.Rules.Count}");

        PrintAlerts(10);

        // MITRE summary
        var allMitre = _alertHistory
            .SelectMany(a => a.MitreMappings)
            .GroupBy(m => m.TechniqueId)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToList();

        if (allMitre.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n── Top MITRE Techniques Observed ──");
            Console.ResetColor();
            foreach (var t in allMitre)
            {
                string name = t.First().TechniqueName;
                Console.WriteLine($"  {t.Key} ({name}) - {t.Count()} hits");
            }
        }
    }

    public void PrintAlerts(int count = 10)
    {
        var recent = _alertHistory
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToList();

        if (recent.Count == 0) return;

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\n── Recent Alerts (last {count}) ──");
        Console.ResetColor();

        foreach (var alert in recent)
        {
            ConsoleColor color = alert.Verdict switch
            {
                "Critical" => ConsoleColor.Red,
                "Malicious" => ConsoleColor.DarkRed,
                "Suspicious" => ConsoleColor.Yellow,
                _ => ConsoleColor.Gray
            };

            string mitre = string.Join(",", alert.MitreMappings.Select(m => m.TechniqueId));
            string target = alert.FilePath ?? alert.CommandLine ?? $"PID:{alert.ProcessId}";
            if (target.Length > 60) target = "..." + target[^57..];

            Console.ForegroundColor = color;
            Console.WriteLine($"  [{alert.Timestamp:HH:mm:ss}] Score={alert.TotalScore,-3} Verdict={alert.Verdict,-11} MITRE=[{mitre}] {target}");
        }
        Console.ResetColor();
    }
}
