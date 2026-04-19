namespace LocalEDR.Core;

public class EDRConfig
{
    public string LogPath { get; set; } = "";
    public string QuarantinePath { get; set; } = "";
    public string RulesPath { get; set; } = "";
    public string[] WatchPaths { get; set; } = [];
    public bool EnableRealTime { get; set; } = true;
    public bool EnableNetwork { get; set; } = true;
    public int SandboxTimeoutSec { get; set; } = 30;

    // Scoring thresholds
    public int AlertThreshold { get; set; } = 50;
    public int AutoBlockThreshold { get; set; } = 80;
    public int AutoQuarantineThreshold { get; set; } = 100;
    public int AutoKillThreshold { get; set; } = 120;

    public static EDRConfig Default
    {
        get
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return new EDRConfig
            {
                LogPath = Path.Combine(baseDir, "Logs"),
                QuarantinePath = Path.Combine(baseDir, "Quarantine"),
                RulesPath = Path.Combine(baseDir, "Rules"),
                WatchPaths =
                [
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    Path.GetTempPath(),
                    @"C:\Windows\Temp"
                ]
            };
        }
    }
}
