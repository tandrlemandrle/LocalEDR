using System.Net;
using System.Net.NetworkInformation;
using LocalEDR.Core;

namespace LocalEDR.Engine;

public class NetworkMonitor
{
    private Timer? _timer;
    private readonly Dictionary<string, List<DateTime>> _beaconTracker = new();
    private readonly List<ConnectionInfo> _connectionHistory = [];

    private static readonly HashSet<int> SuspiciousPorts =
    [
        4444, 5555, 6666, 6667, 8080, 8443, 9001, 9050, 9090,
        1337, 31337, 12345, 20000, 4443, 8888, 1234, 5900,
        3389, 445, 135, 139
    ];

    private static readonly string[] SuspiciousDomainPatterns =
    [
        @"\.onion$", @"\.bit$", @"pastebin\.com", @"raw\.githubusercontent\.com",
        @"ngrok\.io", @"serveo\.net", @"portmap\.io", @"duckdns\.org",
        @"no-ip\.", @"dyndns\.", @"hopto\.org", @"zapto\.org"
    ];

    public NetworkResult Analyze(int processId)
    {
        var result = new NetworkResult { ProcessId = processId };

        try
        {
            var connections = GetTcpConnections()
                .Where(c => c.OwningProcess == processId &&
                            c.RemoteAddress != "0.0.0.0" &&
                            c.RemoteAddress != "::" &&
                            c.RemoteAddress != "127.0.0.1" &&
                            c.RemoteAddress != "::1")
                .ToList();

            foreach (var conn in connections)
            {
                var connInfo = new ConnectionInfo
                {
                    RemoteAddress = conn.RemoteAddress,
                    RemotePort = conn.RemotePort,
                    LocalPort = conn.LocalPort,
                    State = conn.State
                };

                // Check suspicious ports
                if (SuspiciousPorts.Contains(conn.RemotePort))
                {
                    connInfo.IsSuspicious = true;
                    connInfo.Reasons.Add($"Suspicious port: {conn.RemotePort}");
                    result.Score += 20;
                }

                // High port check
                if (conn.RemotePort > 10000 && conn.RemotePort != 443 && conn.RemotePort != 8443)
                {
                    connInfo.Reasons.Add($"High port: {conn.RemotePort}");
                    result.Score += 5;
                }

                // Reverse DNS
                try
                {
                    var hostEntry = Dns.GetHostEntry(conn.RemoteAddress);
                    string hostname = hostEntry.HostName;
                    foreach (string pattern in SuspiciousDomainPatterns)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(hostname, pattern,
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                        {
                            connInfo.IsSuspicious = true;
                            connInfo.Reasons.Add($"Suspicious domain: {hostname}");
                            result.Score += 30;
                        }
                    }
                }
                catch { /* no reverse DNS */ }

                // Track for beaconing
                string remoteKey = $"{conn.RemoteAddress}:{conn.RemotePort}";
                if (!_beaconTracker.ContainsKey(remoteKey))
                    _beaconTracker[remoteKey] = [];
                _beaconTracker[remoteKey].Add(DateTime.Now);

                if (connInfo.IsSuspicious)
                    result.SuspiciousConnections.Add(connInfo);
                result.Connections.Add(connInfo);
                _connectionHistory.Add(connInfo);
            }

            // Beaconing detection
            var beaconResult = DetectBeaconing();
            if (beaconResult.Count > 0)
            {
                result.BeaconingDetected = true;
                result.BeaconTargets = beaconResult;
                result.Score += 40;
                result.Indicators.Add($"Beaconing detected to: {string.Join(", ", beaconResult)}");
            }

            // Connection volume
            if (connections.Count > 20)
            {
                result.Score += 15;
                result.Indicators.Add($"High connection count: {connections.Count}");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Network analysis error for PID {processId}: {ex.Message}");
        }

        return result;
    }

    public void StartMonitoring()
    {
        _timer = new Timer(MonitorCallback, null, 0, 10000);
        Logger.Info("Network monitor started (10s interval)");
    }

    public void StopMonitoring()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void MonitorCallback(object? state)
    {
        try
        {
            var connections = GetTcpConnections()
                .Where(c => c.State == "Established" &&
                            c.RemoteAddress != "127.0.0.1" &&
                            c.RemoteAddress != "::1" &&
                            c.RemoteAddress != "0.0.0.0");

            foreach (var conn in connections)
            {
                string remoteKey = $"{conn.RemoteAddress}:{conn.RemotePort}";
                if (!_beaconTracker.ContainsKey(remoteKey))
                    _beaconTracker[remoteKey] = [];
                _beaconTracker[remoteKey].Add(DateTime.Now);

                if (SuspiciousPorts.Contains(conn.RemotePort))
                {
                    string procName = "Unknown";
                    try { procName = System.Diagnostics.Process.GetProcessById(conn.OwningProcess).ProcessName; } catch { }
                    Logger.Alert($"Suspicious connection: PID={conn.OwningProcess} ({procName}) -> {remoteKey}");
                }
            }

            // Prune old beacon data
            var cutoff = DateTime.Now.AddMinutes(-5);
            foreach (var key in _beaconTracker.Keys.ToList())
            {
                _beaconTracker[key] = _beaconTracker[key].Where(t => t > cutoff).ToList();
                if (_beaconTracker[key].Count == 0) _beaconTracker.Remove(key);
            }
        }
        catch { /* silently continue */ }
    }

    private List<string> DetectBeaconing()
    {
        var targets = new List<string>();

        foreach (var (key, timestamps) in _beaconTracker)
        {
            if (timestamps.Count < 4) continue;

            var sorted = timestamps.OrderBy(t => t).ToList();
            var intervals = new List<double>();
            for (int i = 1; i < sorted.Count; i++)
                intervals.Add((sorted[i] - sorted[i - 1]).TotalSeconds);

            if (intervals.Count < 3) continue;

            double avg = intervals.Average();
            if (avg <= 0) continue;

            double variance = intervals.Average(x => Math.Pow(x - avg, 2));
            double stdDev = Math.Sqrt(variance);
            double cv = stdDev / avg;

            // Low coefficient of variation + short interval = beaconing
            if (cv < 0.3 && avg < 300)
            {
                targets.Add($"{key} (interval ~{avg:F1}s, CV={cv:F3})");
            }
        }

        return targets;
    }

    public void PrintReport()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n══ Network Activity Report ══");
        Console.ResetColor();

        var connections = GetTcpConnections()
            .Where(c => c.State == "Established" &&
                        c.RemoteAddress != "127.0.0.1" &&
                        c.RemoteAddress != "::1")
            .ToList();

        Console.WriteLine($"\n  Active connections: {connections.Count}");

        // Top processes
        var byProcess = connections.GroupBy(c => c.OwningProcess)
            .OrderByDescending(g => g.Count())
            .Take(10);

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n  ── Top Processes by Connection Count ──");
        Console.ResetColor();
        foreach (var p in byProcess)
        {
            string name = "Unknown";
            try { name = System.Diagnostics.Process.GetProcessById(p.Key).ProcessName; } catch { }
            Console.WriteLine($"    PID {p.Key} ({name}): {p.Count()} connections");
        }

        // Suspicious
        var suspicious = connections.Where(c => SuspiciousPorts.Contains(c.RemotePort)).ToList();
        if (suspicious.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  ── Suspicious Connections ──");
            foreach (var sc in suspicious)
            {
                string name = "Unknown";
                try { name = System.Diagnostics.Process.GetProcessById(sc.OwningProcess).ProcessName; } catch { }
                Console.WriteLine($"    PID {sc.OwningProcess} ({name}) -> {sc.RemoteAddress}:{sc.RemotePort}");
            }
            Console.ResetColor();
        }

        // Beaconing
        var beacons = DetectBeaconing();
        if (beacons.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  ── Beaconing Detected ──");
            foreach (var b in beacons) Console.WriteLine($"    {b}");
            Console.ResetColor();
        }
    }

    // ── TCP connection helper ─────────────────────────────────
    private record TcpConnectionEntry(string RemoteAddress, int RemotePort, int LocalPort, string State, int OwningProcess);

    private static List<TcpConnectionEntry> GetTcpConnections()
    {
        var results = new List<TcpConnectionEntry>();
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConnections = properties.GetActiveTcpConnections();
            // GetActiveTcpConnections doesn't give PID, so use netstat via WMI
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT RemoteAddress, RemotePort, LocalPort, State, OwningProcess FROM MSFT_NetTCPConnection",
                new System.Management.EnumerationOptions
                {
                    Timeout = TimeSpan.FromSeconds(5)
                });
            searcher.Scope = new System.Management.ManagementScope(@"root\StandardCimv2");

            foreach (var obj in searcher.Get())
            {
                results.Add(new TcpConnectionEntry(
                    obj["RemoteAddress"]?.ToString() ?? "",
                    Convert.ToInt32(obj["RemotePort"]),
                    Convert.ToInt32(obj["LocalPort"]),
                    obj["State"]?.ToString() ?? "",
                    Convert.ToInt32(obj["OwningProcess"])
                ));
            }
        }
        catch
        {
            // Fallback: parse netstat
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netstat", Arguments = "-ano",
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return results;
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                foreach (string line in output.Split('\n'))
                {
                    string trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP")) continue;
                    var parts = trimmed.Split([' '], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;

                    string[] remote = parts[2].Split(':');
                    if (remote.Length < 2) continue;

                    results.Add(new TcpConnectionEntry(
                        string.Join(":", remote[..^1]),
                        int.TryParse(remote[^1], out int rp) ? rp : 0,
                        0,
                        parts[3],
                        int.TryParse(parts[4], out int pid) ? pid : 0
                    ));
                }
            }
            catch { /* give up */ }
        }

        return results;
    }
}
