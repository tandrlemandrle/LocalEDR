namespace LocalEDR.Core;

public static class Logger
{
    private static readonly object Lock = new();
    private static string? _logDirectory;

    public static void Initialize(string logDirectory)
    {
        _logDirectory = logDirectory;
        Directory.CreateDirectory(logDirectory);
    }

    public static void Info(string message) => Log("INFO", message, ConsoleColor.Cyan);
    public static void Warn(string message) => Log("WARN", message, ConsoleColor.DarkYellow);
    public static void Alert(string message) => Log("ALERT", message, ConsoleColor.Yellow);
    public static void Critical(string message) => Log("CRITICAL", message, ConsoleColor.Red);
    public static void Debug(string message) => Log("DEBUG", message, ConsoleColor.Gray);
    public static void Error(string message) => Log("ERROR", message, ConsoleColor.Red);

    private static void Log(string level, string message, ConsoleColor color)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var entry = $"[{timestamp}] [{level}] {message}";

        lock (Lock)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(entry);
            Console.ResetColor();

            if (_logDirectory == null) return;
            try
            {
                var logFile = Path.Combine(_logDirectory, $"edr_{DateTime.Now:yyyyMMdd}.log");
                File.AppendAllText(logFile, entry + Environment.NewLine);
            }
            catch { /* don't crash on log failure */ }
        }
    }
}
