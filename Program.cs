using LocalEDR.Core;
using LocalEDR.Engine;

namespace LocalEDR;

internal static class Program
{
    static async Task Main(string[] args)
    {
        Console.Title = "Local EDR - VirusTotal-Style Threat Analysis";
        PrintBanner();

        var config = EDRConfig.Default;
        var engine = new EDREngine(config);

        if (args.Length > 0)
        {
            await HandleCommandLine(engine, args);
            return;
        }

        await RunInteractive(engine);
    }

    static async Task HandleCommandLine(EDREngine engine, string[] args)
    {
        switch (args[0].ToLower())
        {
            case "scan" when args.Length > 1:
                var result = await engine.ScanPath(args[1]);
                engine.Scoring.PrintReport(result);
                break;
            case "monitor":
                engine.StartRealTimeMonitoring();
                Logger.Info("Press Ctrl+C to stop.");
                await Task.Delay(Timeout.Infinite, CreateCancellationToken());
                break;
            case "sandbox" when args.Length > 1:
                int timeout = args.Length > 2 && int.TryParse(args[2], out var t) ? t : 30;
                var sbResult = await engine.Sandbox.Execute(args[1], timeout);
                engine.Sandbox.PrintReport(sbResult);
                break;
            default:
                PrintUsage();
                break;
        }
    }

    static async Task RunInteractive(EDREngine engine)
    {
        Logger.Info("Local EDR ready. Type 'help' for commands.");
        Console.WriteLine();

        while (true)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("EDR> ");
            Console.ResetColor();

            string? input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input)) continue;

            string[] parts = input.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            string cmd = parts[0].ToLower();
            string arg = parts.Length > 1 ? parts[1] : "";

            try
            {
                switch (cmd)
                {
                    case "scan":
                        if (string.IsNullOrEmpty(arg)) { Console.WriteLine("Usage: scan <path>"); break; }
                        var scanResult = await engine.ScanPath(arg);
                        engine.Scoring.PrintReport(scanResult);
                        break;

                    case "monitor":
                        engine.StartRealTimeMonitoring();
                        Logger.Info("Real-time monitoring started. Type 'stop' to end.");
                        break;

                    case "stop":
                        engine.StopRealTimeMonitoring();
                        Logger.Info("Monitoring stopped.");
                        break;

                    case "sandbox":
                        if (string.IsNullOrEmpty(arg)) { Console.WriteLine("Usage: sandbox <filepath> [timeout_sec]"); break; }
                        string[] sbParts = arg.Split(' ', 2);
                        int sbTimeout = sbParts.Length > 1 && int.TryParse(sbParts[1], out var st) ? st : 30;
                        var sbRes = await engine.Sandbox.Execute(sbParts[0], sbTimeout);
                        engine.Sandbox.PrintReport(sbRes);
                        break;

                    case "dashboard":
                        engine.PrintDashboard();
                        break;

                    case "mitre":
                        engine.MitreMapper.PrintReport();
                        break;

                    case "network":
                        engine.Network.PrintReport();
                        break;

                    case "quarantine":
                        engine.Response.ListQuarantined();
                        break;

                    case "restore" when !string.IsNullOrEmpty(arg):
                        engine.Response.RestoreFromQuarantine(arg);
                        break;

                    case "autoresponse":
                        bool enable = arg.Equals("on", StringComparison.OrdinalIgnoreCase);
                        engine.Response.AutoResponseEnabled = enable;
                        Logger.Warn($"Auto-response {(enable ? "ENABLED" : "DISABLED")}");
                        break;

                    case "alerts":
                        engine.PrintAlerts();
                        break;

                    case "help":
                        PrintHelp();
                        break;

                    case "exit" or "quit":
                        engine.StopRealTimeMonitoring();
                        return;

                    default:
                        Console.WriteLine($"Unknown command: {cmd}. Type 'help' for commands.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Command failed: {ex.Message}");
            }

            Console.WriteLine();
        }
    }

    static CancellationToken CreateCancellationToken()
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        return cts.Token;
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
        Console.WriteLine("    VirusTotal-Style Local Threat Analysis Engine");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void PrintUsage()
    {
        Console.WriteLine("Usage: LocalEDR.exe [command] [args]");
        Console.WriteLine("  scan <path>              Scan a file or directory");
        Console.WriteLine("  monitor                  Start real-time monitoring");
        Console.WriteLine("  sandbox <file> [timeout] Run file in pseudo-sandbox");
        Console.WriteLine("  (no args)                Interactive mode");
    }

    static void PrintHelp()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("═══ Commands ═══");
        Console.ResetColor();
        Console.WriteLine("  scan <path>              Scan file or directory");
        Console.WriteLine("  monitor                  Start real-time process/file monitoring");
        Console.WriteLine("  stop                     Stop real-time monitoring");
        Console.WriteLine("  sandbox <file> [sec]     Run file in pseudo-sandbox");
        Console.WriteLine("  dashboard                Show EDR status dashboard");
        Console.WriteLine("  mitre                    Show MITRE ATT&CK report");
        Console.WriteLine("  network                  Show network activity report");
        Console.WriteLine("  alerts                   Show recent alerts");
        Console.WriteLine("  quarantine               List quarantined files");
        Console.WriteLine("  restore <filename>       Restore quarantined file");
        Console.WriteLine("  autoresponse on|off      Toggle auto-response");
        Console.WriteLine("  help                     Show this help");
        Console.WriteLine("  exit                     Quit");
    }
}
