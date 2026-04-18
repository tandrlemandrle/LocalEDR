using LocalEDR.Core;

namespace LocalEDR.Engine;

public class ScoringEngine
{
    // Weight multipliers
    private const double StaticWeight = 1.0;
    private const double BehaviorWeight = 1.5;
    private const double YaraWeight = 1.3;
    private const double MitreWeight = 0.8;
    private const double NetworkWeight = 1.2;

    private static readonly string[] TrustedPublishers =
        ["Microsoft", "Google", "Mozilla", "Adobe", "Oracle", "Apple"];

    private static readonly HashSet<string> KnownSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "csrss", "lsass", "services", "smss", "wininit",
        "winlogon", "dwm", "explorer", "taskhostw", "sihost"
    };

    public ScoreBreakdown Calculate(AnalysisResult analysis)
    {
        var breakdown = new ScoreBreakdown();

        // Static
        if (analysis.StaticResults != null)
        {
            breakdown.StaticScore = Math.Min(analysis.StaticResults.Score, 100);
            if (breakdown.StaticScore > 0)
                breakdown.Details.Add($"Static: {breakdown.StaticScore} pts");
        }

        // Behavior
        if (analysis.BehaviorResults != null)
        {
            breakdown.BehaviorScore = Math.Min(analysis.BehaviorResults.Score, 150);
            if (breakdown.BehaviorScore > 0)
                breakdown.Details.Add($"Behavior: {breakdown.BehaviorScore} pts");
        }

        // YARA
        if (analysis.YaraMatches.Count > 0)
        {
            int yaraTotal = analysis.YaraMatches.Sum(m => m.Score);
            breakdown.YaraScore = Math.Min(yaraTotal, 120);
            if (analysis.YaraMatches.Any(m => m.Severity == "Critical"))
                breakdown.YaraScore = (int)Math.Min(breakdown.YaraScore * 1.3, 150);
            breakdown.Details.Add($"YARA: {breakdown.YaraScore} pts ({analysis.YaraMatches.Count} rules)");
        }

        // MITRE
        if (analysis.MitreMappings.Count > 0)
        {
            int mitreBase = analysis.MitreMappings.Count * 8;
            int highConf = analysis.MitreMappings.Count(m => m.Confidence == "High");
            mitreBase += highConf * 5;

            int uniqueTactics = analysis.MitreMappings.Select(m => m.Tactic).Distinct().Count();
            if (uniqueTactics >= 3) mitreBase = (int)(mitreBase * 1.3);

            breakdown.MitreScore = Math.Min(mitreBase, 80);
            breakdown.Details.Add($"MITRE: {breakdown.MitreScore} pts ({analysis.MitreMappings.Count} techniques, {uniqueTactics} tactics)");
        }

        // Network
        if (analysis.NetworkResults != null)
        {
            int netScore = Math.Min(analysis.NetworkResults.Score, 80);
            if (analysis.NetworkResults.BeaconingDetected) netScore += 30;
            breakdown.NetworkScore = Math.Min(netScore, 100);
            if (breakdown.NetworkScore > 0)
                breakdown.Details.Add($"Network: {breakdown.NetworkScore} pts");
        }

        // Adjustments
        breakdown.Adjustments = CalculateAdjustments(analysis);
        if (breakdown.Adjustments != 0)
            breakdown.Details.Add($"Adjustments: {breakdown.Adjustments} pts");

        // Weighted total
        double weighted =
            breakdown.StaticScore * StaticWeight +
            breakdown.BehaviorScore * BehaviorWeight +
            breakdown.YaraScore * YaraWeight +
            breakdown.MitreScore * MitreWeight +
            breakdown.NetworkScore * NetworkWeight +
            breakdown.Adjustments;

        breakdown.TotalScore = Math.Max(0, (int)Math.Round(weighted));

        // Verdict
        breakdown.Verdict = breakdown.TotalScore switch
        {
            >= 120 => "Critical",
            >= 80 => "Malicious",
            >= 50 => "Suspicious",
            >= 25 => "Low",
            _ => "Clean"
        };

        // Confidence
        int signalCount = new[]
        {
            breakdown.StaticScore > 0,
            breakdown.BehaviorScore > 0,
            breakdown.YaraScore > 0,
            breakdown.MitreScore > 0,
            breakdown.NetworkScore > 0
        }.Count(x => x);

        breakdown.Confidence = signalCount switch
        {
            >= 4 => "High",
            >= 2 => "Medium",
            _ => "Low"
        };

        return breakdown;
    }

    private static int CalculateAdjustments(AnalysisResult analysis)
    {
        int adjustment = 0;

        // Signed binary bonus
        if (analysis.StaticResults is { IsSigned: true })
        {
            adjustment -= 20;
            if (analysis.StaticResults.SignerName != null &&
                TrustedPublishers.Any(p => analysis.StaticResults.SignerName.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                adjustment -= 30;
            }
        }

        // Known system process from expected path
        if (analysis.BehaviorResults != null &&
            KnownSystemProcesses.Contains(analysis.BehaviorResults.ProcessName) &&
            analysis.FilePath != null &&
            analysis.FilePath.Contains(@"C:\Windows\System32", StringComparison.OrdinalIgnoreCase))
        {
            adjustment -= 15;
        }

        // Multi-source corroboration
        int sources = 0;
        if (analysis.StaticResults is { Score: > 20 }) sources++;
        if (analysis.BehaviorResults is { Score: > 20 }) sources++;
        if (analysis.YaraMatches.Count > 0) sources++;
        if (analysis.NetworkResults is { Score: > 10 }) sources++;
        if (sources >= 3) adjustment += 25;

        return adjustment;
    }

    public void PrintReport(AnalysisResult analysis)
    {
        var score = Calculate(analysis);

        ConsoleColor verdictColor = score.Verdict switch
        {
            "Critical" => ConsoleColor.Red,
            "Malicious" => ConsoleColor.DarkRed,
            "Suspicious" => ConsoleColor.Yellow,
            "Low" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Green
        };

        Console.ForegroundColor = verdictColor;
        Console.WriteLine("\n╔══════════════════════════════════════════╗");
        Console.WriteLine("║         THREAT SCORE REPORT              ║");
        Console.WriteLine("╚══════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine($"\n  Target    : {analysis.FilePath ?? analysis.CommandLine ?? $"PID:{analysis.ProcessId}"}");
        Console.ForegroundColor = verdictColor;
        Console.WriteLine($"  Score     : {score.TotalScore}");
        Console.WriteLine($"  Verdict   : {score.Verdict}");
        Console.ResetColor();
        Console.WriteLine($"  Confidence: {score.Confidence}");

        // Hashes
        if (analysis.StaticResults?.Hashes.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"\n  SHA256: {analysis.StaticResults.Hashes.GetValueOrDefault("SHA256", "N/A")}");
            Console.ResetColor();
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n  ── Score Breakdown ──");
        Console.ResetColor();
        Console.WriteLine($"    Static Analysis : {score.StaticScore}");
        Console.WriteLine($"    Behavior Engine : {score.BehaviorScore}");
        Console.WriteLine($"    YARA Rules      : {score.YaraScore}");
        Console.WriteLine($"    MITRE Mapping   : {score.MitreScore}");
        Console.WriteLine($"    Network         : {score.NetworkScore}");
        Console.WriteLine($"    Adjustments     : {score.Adjustments}");
        Console.WriteLine($"    ─────────────────");
        Console.ForegroundColor = verdictColor;
        Console.WriteLine($"    Weighted Total  : {score.TotalScore}");
        Console.ResetColor();

        // MITRE techniques
        if (analysis.MitreMappings.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n  ── MITRE ATT&CK ──");
            Console.ResetColor();
            foreach (var m in analysis.MitreMappings)
                Console.WriteLine($"    [{m.Confidence[0]}] {m.TechniqueId} - {m.TechniqueName} ({m.Tactic})");
        }

        // YARA matches
        if (analysis.YaraMatches.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n  ── YARA Matches ──");
            Console.ResetColor();
            foreach (var y in analysis.YaraMatches)
                Console.WriteLine($"    [{y.Severity}] {y.RuleName}: {y.Description}");
        }

        // Indicators
        var allIndicators = new List<string>();
        if (analysis.StaticResults != null) allIndicators.AddRange(analysis.StaticResults.Indicators);
        if (analysis.BehaviorResults != null) allIndicators.AddRange(analysis.BehaviorResults.Indicators);

        if (allIndicators.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("\n  ── Indicators ──");
            Console.ResetColor();
            foreach (var ind in allIndicators.Take(15))
                Console.WriteLine($"    • {ind}");
            if (allIndicators.Count > 15)
                Console.WriteLine($"    ... and {allIndicators.Count - 15} more");
        }

        Console.WriteLine($"\n  Response: {analysis.ResponseTaken}");
    }
}
