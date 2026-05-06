using LocalEDR.Core;
using Microsoft.Win32;

namespace LocalEDR.Engine;

public class PseudoSandbox
{
    public async Task<SandboxResult> Execute(string filePath, int timeoutSeconds = 30)
    {
        var result = new SandboxResult
        {
            FilePath = filePath,
            StartTime = DateTime.Now
        };

        if (!File.Exists(filePath))
        {
            Logger.Warn($"Sandbox: File not found: {filePath}");
            return result;
        }

        Logger.Info($"Sandbox: Starting analysis of {filePath} (timeout={timeoutSeconds}s)");

        // Snapshot before
        var netBefore = GetCurrentConnections();
        var regBefore = SnapshotRegistry();

        // Set up file watcher on temp
        string tempPath = Path.GetTempPath();
        using var watcher = new FileSystemWatcher(tempPath)
        {
            IncludeSubdirectories = true,
            EnableRaisingEvents = true
        };

        watcher.Created += (_, e) => result.FilesCreated.Add(e.FullPath);
        watcher.Changed += (_, e) => result.FilesModified.Add(e.FullPath);
        watcher.Deleted += (_, e) => result.FilesDeleted.Add(e.FullPath);

        // Track child processes
        System.Diagnostics.Process? targetProcess = null;
        var processMonitorCts = new CancellationTokenSource();

        try
        {
            // Launch the file
            string ext = Path.GetExtension(filePath).ToLower();
            var psi = ext switch
            {
                ".exe" => new System.Diagnostics.ProcessStartInfo(filePath),
                ".ps1" => new System.Diagnostics.ProcessStartInfo("powershell.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -File \"{filePath}\""),
                ".bat" or ".cmd" => new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c \"{filePath}\""),
                ".vbs" or ".js" => new System.Diagnostics.ProcessStartInfo("cscript.exe", $"//nologo \"{filePath}\""),
                _ => null
            };

            if (psi == null)
            {
                Logger.Warn($"Sandbox: Unsupported file type: {ext}");
                result.EndTime = DateTime.Now;
                return result;
            }

            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            targetProcess = System.Diagnostics.Process.Start(psi);
            if (targetProcess != null)
            {
                Logger.Info($"Sandbox: Launched PID {targetProcess.Id}");

                // Monitor child processes in background
                _ = Task.Run(() => MonitorChildProcesses(targetProcess.Id, result, processMonitorCts.Token));
            }

            // Wait for timeout
            Logger.Info($"Sandbox: Observing for {timeoutSeconds} seconds...");
            await Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));
        }
        catch (Exception ex)
        {
            Logger.Warn($"Sandbox: Launch failed: {ex.Message}");
        }
        finally
        {
            processMonitorCts.Cancel();

            // Kill target if still running
            if (targetProcess != null && !targetProcess.HasExited)
            {
                try
                {
                    targetProcess.Kill(true);
                    Logger.Info($"Sandbox: Terminated PID {targetProcess.Id}");
                }
                catch { }
            }
        }

        // Snapshot after
        var netAfter = GetCurrentConnections();
        var regAfter = SnapshotRegistry();

        // Diff network
        foreach (var conn in netAfter)
        {
            if (!netBefore.Any(b => b.RemoteAddress == conn.RemoteAddress &&
                                     b.RemotePort == conn.RemotePort))
            {
                result.NetworkConnections.Add(conn);
            }
        }

        // Diff registry
        foreach (var (path, entries) in regAfter)
        {
            if (!regBefore.TryGetValue(path, out var beforeEntries)) beforeEntries = new();
            foreach (var (name, value) in entries)
            {
                if (!beforeEntries.TryGetValue(name, out var beforeValue) || beforeValue != value)
                {
                    result.RegistryChanges.Add(new SandboxRegistryChange
                    {
                        Path = path, Name = name, Value = value, Type = "Added/Modified"
                    });
                }
            }
        }

        result.EndTime = DateTime.Now;
        result.DurationSeconds = (result.EndTime - result.StartTime).TotalSeconds;

        // Score behavior
        ScoreBehavior(result);

        Logger.Info($"Sandbox: Complete. Score={result.BehaviorScore} Flags={result.BehaviorFlags.Count}");
        return result;
    }

    private static async Task MonitorChildProcesses(int parentPid, SandboxResult result, CancellationToken ct)
    {
        var seen = new HashSet<int> { parentPid };
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId, Name, ParentProcessId, CommandLine FROM Win32_Process WHERE ParentProcessId = {parentPid}");
                foreach (var obj in searcher.Get())
                {
                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    if (seen.Add(pid))
                    {
                        result.ProcessesCreated.Add(new SandboxProcessInfo
                        {
                            PID = pid,
                            Name = obj["Name"]?.ToString() ?? "",
                            ParentPID = parentPid,
                            CommandLine = obj["CommandLine"]?.ToString()
                        });
                    }
                }
            }
            catch { }

            await Task.Delay(500, ct).ConfigureAwait(false);
        }
    }

    private static List<ConnectionInfo> GetCurrentConnections()
    {
        var results = new List<ConnectionInfo>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\StandardCimv2",
                "SELECT RemoteAddress, RemotePort, OwningProcess FROM MSFT_NetTCPConnection");
            foreach (var obj in searcher.Get())
            {
                results.Add(new ConnectionInfo
                {
                    RemoteAddress = obj["RemoteAddress"]?.ToString() ?? "",
                    RemotePort = Convert.ToInt32(obj["RemotePort"])
                });
            }
        }
        catch { }
        return results;
    }

    private static Dictionary<string, Dictionary<string, string?>> SnapshotRegistry()
    {
        var snapshot = new Dictionary<string, Dictionary<string, string?>>();
        string[] paths =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ];

        foreach (string path in paths)
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                string fullPath = $"{hive.Name}\\{path}";
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;
                    var entries = new Dictionary<string, string?>();
                    foreach (string name in key.GetValueNames())
                        entries[name] = key.GetValue(name)?.ToString();
                    snapshot[fullPath] = entries;
                }
                catch { }
            }
        }

        return snapshot;
    }

    private static void ScoreBehavior(SandboxResult result)
    {
        // Process creation
        if (result.ProcessesCreated.Count > 0)
        {
            result.BehaviorScore += result.ProcessesCreated.Count * 10;
            result.BehaviorFlags.Add($"Spawned {result.ProcessesCreated.Count} child process(es)");

            string[] suspiciousChildren = ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe"];
            foreach (var child in result.ProcessesCreated)
            {
                if (suspiciousChildren.Contains(child.Name.ToLower()))
                {
                    result.BehaviorScore += 30;
                    result.BehaviorFlags.Add($"Spawned suspicious child: {child.Name}");
                }
            }
        }

        // File activity
        if (result.FilesCreated.Count > 0)
        {
            result.BehaviorScore += result.FilesCreated.Count * 5;
            result.BehaviorFlags.Add($"Created {result.FilesCreated.Count} file(s)");

            string[] exeExtensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr"];
            int exeDrops = result.FilesCreated.Count(f => exeExtensions.Contains(Path.GetExtension(f).ToLower()));
            if (exeDrops > 0)
            {
                result.BehaviorScore += exeDrops * 25;
                result.BehaviorFlags.Add($"Dropped {exeDrops} executable file(s)");
            }
        }

        if (result.FilesDeleted.Count > 5)
        {
            result.BehaviorScore += 20;
            result.BehaviorFlags.Add($"Deleted {result.FilesDeleted.Count} file(s)");
        }

        // Registry
        if (result.RegistryChanges.Count > 0)
        {
            result.BehaviorScore += result.RegistryChanges.Count * 20;
            result.BehaviorFlags.Add($"Modified {result.RegistryChanges.Count} registry value(s)");

            foreach (var reg in result.RegistryChanges)
            {
                if (reg.Path.Contains("Run", StringComparison.OrdinalIgnoreCase))
                {
                    result.BehaviorScore += 30;
                    result.BehaviorFlags.Add("Added persistence via registry Run key");
                    result.MitreTechniques.Add("T1547.001");
                }
            }
        }

        // Network
        if (result.NetworkConnections.Count > 0)
        {
            result.BehaviorScore += result.NetworkConnections.Count * 15;
            result.BehaviorFlags.Add($"Made {result.NetworkConnections.Count} network connection(s)");
        }
    }

    public void PrintReport(SandboxResult result)
    {
        ConsoleColor color = result.BehaviorScore > 80 ? ConsoleColor.Red :
                             result.BehaviorScore > 40 ? ConsoleColor.Yellow : ConsoleColor.Green;

        Console.ForegroundColor = color;
        Console.WriteLine("\n╔══════════════════════════════════════════╗");
        Console.WriteLine("║        PSEUDO-SANDBOX REPORT             ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine($"\n  File    : {result.FilePath}");
        Console.WriteLine($"  Duration: {result.DurationSeconds:F1}s");
        Console.ForegroundColor = color;
        Console.WriteLine($"  Score   : {result.BehaviorScore}");
        Console.ResetColor();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n  ── Activity Summary ──");
        Console.ResetColor();
        Console.WriteLine($"    Processes spawned : {result.ProcessesCreated.Count}");
        Console.WriteLine($"    Files created     : {result.FilesCreated.Count}");
        Console.WriteLine($"    Files modified    : {result.FilesModified.Count}");
        Console.WriteLine($"    Files deleted     : {result.FilesDeleted.Count}");
        Console.WriteLine($"    Registry changes  : {result.RegistryChanges.Count}");
        Console.WriteLine($"    Network conns     : {result.NetworkConnections.Count}");

        if (result.BehaviorFlags.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n  ── Behavior Flags ──");
            Console.ResetColor();
            foreach (var flag in result.BehaviorFlags)
                Console.WriteLine($"    ⚠ {flag}");
        }

        if (result.ProcessesCreated.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n  ── Child Processes ──");
            Console.ResetColor();
            foreach (var p in result.ProcessesCreated)
            {
                Console.WriteLine($"    PID {p.PID}: {p.Name}");
                if (p.CommandLine != null)
                {
                    string cmd = p.CommandLine.Length > 100 ? p.CommandLine[..100] + "..." : p.CommandLine;
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine($"      CMD: {cmd}");
                    Console.ResetColor();
                }
            }
        }

        if (result.RegistryChanges.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  ── Registry Changes ──");
            foreach (var r in result.RegistryChanges)
                Console.WriteLine($"    {r.Path}\\{r.Name} = {r.Value}");
            Console.ResetColor();
        }

        if (result.NetworkConnections.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  ── Network Connections ──");
            foreach (var n in result.NetworkConnections)
                Console.WriteLine($"    -> {n.RemoteAddress}:{n.RemotePort}");
            Console.ResetColor();
        }
    }
}
