using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetProbe.Services;

public sealed class Settings
{
    public string Theme { get; set; } = "System";          // System | Light | Dark
    public bool AutoDiscoverOnLink { get; set; } = true;     // start LLDP/CDP listen when a cable is plugged in
    public int DiscoverSeconds { get; set; } = 65;
    public string TechName { get; set; } = Environment.UserName;
    public string SiteName { get; set; } = "";
    // Where Save PDF / HTML / JSON write. Empty = Documents\NetProbe (created automatically).
    public string ReportFolder { get; set; } = "";
    // Keep a timestamped capture + JSON report of every Discover / Port Health run in <report folder>\History.
    public bool KeepHistory { get; set; } = true;

    public static string DefaultReportFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "NetProbe");

    /// <summary>The folder reports actually go to: the custom one if set, otherwise Documents\NetProbe.</summary>
    [JsonIgnore]
    public string ResolvedReportFolder =>
        string.IsNullOrWhiteSpace(ReportFolder) ? DefaultReportFolder : Environment.ExpandEnvironmentVariables(ReportFolder.Trim());

    [JsonIgnore]
    public string HistoryFolder => Path.Combine(ResolvedReportFolder, "History");

    // Remote upload (optional): POSTs the JSON report. Leave UploadUrl empty to disable.
    public string UploadUrl { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public bool AutoUpload { get; set; }
    // Updates from GitHub Releases, e.g. "yourname/NetProbe". Empty = update checks off.
    public string UpdateRepo { get; set; } = "tylorfaber-arch/NetProbe";
    public bool CheckUpdatesOnLaunch { get; set; } = true;
    public string SkippedVersion { get; set; } = "";

    private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetProbe", "settings.json");

    public static Settings Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) ?? new(); }
        catch { }
        return new();
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}
