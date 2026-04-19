namespace LocalEDR.Core;

// ── Full analysis result (the "VirusTotal report") ────────────
public class AnalysisResult
{
    public string AnalysisId { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string? FilePath { get; set; }
    public int ProcessId { get; set; }
    public string? CommandLine { get; set; }
    public StaticAnalysisResult? StaticResults { get; set; }
    public BehaviorResult? BehaviorResults { get; set; }
    public List<MitreMapping> MitreMappings { get; set; } = [];
    public List<YaraMatch> YaraMatches { get; set; } = [];
    public NetworkResult? NetworkResults { get; set; }
    public int TotalScore { get; set; }
    public string Verdict { get; set; } = "Clean";
    public string Confidence { get; set; } = "Low";
    public string ResponseTaken { get; set; } = "None";
}

// ── Static analysis ───────────────────────────────────────────
public class StaticAnalysisResult
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string FileType { get; set; } = "";
    public Dictionary<string, string> Hashes { get; set; } = new();
    public double Entropy { get; set; }
    public bool IsPacked { get; set; }
    public bool IsSigned { get; set; }
    public string? SignerName { get; set; }
    public List<StringFinding> SuspiciousStrings { get; set; } = [];
    public List<ImportFinding> SuspiciousImports { get; set; } = [];
    public PEInfo? PEInfo { get; set; }
    public int Score { get; set; }
    public List<string> Indicators { get; set; } = [];
}

public class StringFinding
{
    public string Label { get; set; } = "";
    public string Match { get; set; } = "";
}

public class ImportFinding
{
    public string Import { get; set; } = "";
    public string Risk { get; set; } = "";
}

public class PEInfo
{
    public bool IsPE { get; set; }
    public bool Is64Bit { get; set; }
    public DateTime? TimeDateStamp { get; set; }
    public List<PESection> Sections { get; set; } = [];
}

public class PESection
{
    public string Name { get; set; } = "";
    public uint VirtualSize { get; set; }
    public uint RawSize { get; set; }
    public double Entropy { get; set; }
}

// ── Behavior analysis ─────────────────────────────────────────
public class BehaviorResult
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string ParentName { get; set; } = "";
    public int ParentPID { get; set; }
    public string? CommandLine { get; set; }
    public bool IsLOLBin { get; set; }
    public LOLBinDetail? LOLBinDetails { get; set; }
    public ParentChildFlag? ParentChildFlag { get; set; }
    public List<HeuristicFlag> CommandFlags { get; set; } = [];
    public List<string> InjectionIndicators { get; set; } = [];
    public List<string> PersistenceIndicators { get; set; } = [];
    public List<string> EvasionIndicators { get; set; } = [];
    public int Score { get; set; }
    public List<string> Indicators { get; set; } = [];
}

public class LOLBinDetail
{
    public string Binary { get; set; } = "";
    public string Risk { get; set; } = "";
    public List<string> MatchedArgs { get; set; } = [];
}

public class ParentChildFlag
{
    public string Parent { get; set; } = "";
    public string Child { get; set; } = "";
    public string Description { get; set; } = "";
    public int Score { get; set; }
}

public class HeuristicFlag
{
    public string Flag { get; set; } = "";
    public int Score { get; set; }
}

// ── MITRE mapping ─────────────────────────────────────────────
public class MitreMapping
{
    public string TechniqueId { get; set; } = "";
    public string TechniqueName { get; set; } = "";
    public string Tactic { get; set; } = "";
    public string Confidence { get; set; } = "Low";
    public string MatchedOn { get; set; } = "";
}

// ── YARA matches ──────────────────────────────────────────────
public class YaraMatch
{
    public string RuleName { get; set; } = "";
    public string Description { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "Medium";
    public int Score { get; set; }
    public int HitCount { get; set; }
    public List<string> HitPatterns { get; set; } = [];
}

// ── Network analysis ──────────────────────────────────────────
public class NetworkResult
{
    public int ProcessId { get; set; }
    public List<ConnectionInfo> Connections { get; set; } = [];
    public List<ConnectionInfo> SuspiciousConnections { get; set; } = [];
    public bool BeaconingDetected { get; set; }
    public List<string> BeaconTargets { get; set; } = [];
    public int Score { get; set; }
    public List<string> Indicators { get; set; } = [];
}

public class ConnectionInfo
{
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public int LocalPort { get; set; }
    public string State { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public List<string> Reasons { get; set; } = [];
}

// ── Sandbox result ────────────────────────────────────────────
public class SandboxResult
{
    public string FilePath { get; set; } = "";
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public double DurationSeconds { get; set; }
    public List<SandboxProcessInfo> ProcessesCreated { get; set; } = [];
    public List<string> FilesCreated { get; set; } = [];
    public List<string> FilesModified { get; set; } = [];
    public List<string> FilesDeleted { get; set; } = [];
    public List<SandboxRegistryChange> RegistryChanges { get; set; } = [];
    public List<ConnectionInfo> NetworkConnections { get; set; } = [];
    public int BehaviorScore { get; set; }
    public List<string> BehaviorFlags { get; set; } = [];
    public List<string> MitreTechniques { get; set; } = [];
}

public class SandboxProcessInfo
{
    public int PID { get; set; }
    public string Name { get; set; } = "";
    public int ParentPID { get; set; }
    public string? CommandLine { get; set; }
}

public class SandboxRegistryChange
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Value { get; set; }
    public string Type { get; set; } = "Added";
}

// ── Scoring breakdown ─────────────────────────────────────────
public class ScoreBreakdown
{
    public int StaticScore { get; set; }
    public int BehaviorScore { get; set; }
    public int YaraScore { get; set; }
    public int MitreScore { get; set; }
    public int NetworkScore { get; set; }
    public int Adjustments { get; set; }
    public int TotalScore { get; set; }
    public string Verdict { get; set; } = "Clean";
    public string Confidence { get; set; } = "Low";
    public List<string> Details { get; set; } = [];
}

// ── YARA rule definition ──────────────────────────────────────
public class YaraRule
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "Medium";
    public int Score { get; set; }
    public string[] StringPatterns { get; set; } = [];
    public string Condition { get; set; } = "any";
    public bool Enabled { get; set; } = true;
}
