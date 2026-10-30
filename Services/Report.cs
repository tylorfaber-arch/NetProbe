using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetProbe.Services;

/// <summary>Everything NetProbe knows at a point in time. Serialized as the upload/JSON format.</summary>
public sealed class ReportData
{
    public string Tool { get; set; } = "NetProbe";
    public string Version { get; set; } = App.Version;
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string Computer { get; set; } = Environment.MachineName;
    public string Tech { get; set; } = "";
    public string Site { get; set; } = "";
    public Dictionary<string, string> Adapter { get; set; } = new();
    public List<Dictionary<string, string>> SwitchPorts { get; set; } = new();
    public List<TestRow> Tests { get; set; } = new();
    public Dictionary<string, string> Latency { get; set; } = new();
    public List<ScanRow> LanScan { get; set; } = new();

    public sealed record TestRow(string Result, string Test, string Detail);
    public sealed record ScanRow(string Ip, string Mac, string Hostname, string Ping, string Note);

    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);
}

public static class ReportWriter
{
    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static string ToHtml(ReportData r)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!doctype html><html><head><meta charset="utf-8"><title>NetProbe report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;color:#1b1f24;margin:32px;font-size:13px}
h1{font-size:22px;margin:0 0 4px} .sub{color:#5b6470;margin-bottom:20px}
h2{font-size:15px;margin:22px 0 8px;padding-bottom:4px;border-bottom:2px solid #0067c0;color:#0067c0}
table{border-collapse:collapse;width:100%} td,th{padding:5px 8px;border-bottom:1px solid #e3e6ea;text-align:left;vertical-align:top}
th{background:#f3f5f8;font-weight:600} td.k{width:200px;color:#5b6470}
.cards{display:flex;gap:12px;margin:8px 0 4px}.card{flex:1;border:1px solid #e3e6ea;border-radius:8px;padding:10px 12px;border-left:5px solid #9aa3ad}
.card b{display:block;font-size:11px;color:#5b6470;text-transform:uppercase;letter-spacing:.04em}.card span{font-size:16px;font-weight:600}
.pass{color:#107c10}.fail{color:#c42b1c}.warn{color:#9d5d00}.c-pass{border-left-color:#107c10}.c-fail{border-left-color:#c42b1c}.c-warn{border-left-color:#9d5d00}
.muted{color:#8a929c}
</style></head><body>
""");
        sb.Append($"<h1>NetProbe network report</h1><div class=sub>{H(r.TimestampUtc.ToLocalTime().ToString("f"))} &middot; {H(r.Computer)}");
        if (!string.IsNullOrEmpty(r.Tech)) sb.Append($" &middot; Tech: {H(r.Tech)}");
        if (!string.IsNullOrEmpty(r.Site)) sb.Append($" &middot; Site: {H(r.Site)}");
        sb.Append("</div>");

        // summary cards
        var link = r.Adapter.GetValueOrDefault("Link", "?");
        var sw = r.SwitchPorts.FirstOrDefault();
        int fails = r.Tests.Count(t => t.Result == "FAIL");
        sb.Append("<div class=cards>");
        Card(sb, "Link", link == "Up" ? $"Up {r.Adapter.GetValueOrDefault("Link speed")}" : link, link == "Up" ? "pass" : "fail");
        Card(sb, "IP address", r.Adapter.GetValueOrDefault("IPv4 address", "none").Split(' ')[0], r.Adapter.ContainsKey("WARNING") ? "fail" : r.Adapter.ContainsKey("IPv4 address") ? "pass" : "warn");
        Card(sb, "Switch / port", sw != null ? $"{sw.GetValueOrDefault("Switch Name", sw.GetValueOrDefault("Chassis ID"))} {sw.GetValueOrDefault("Port ID")}" : "not discovered", sw != null ? "pass" : "warn");
        Card(sb, "VLAN", sw?.GetValueOrDefault("VLAN (native/untagged)") ?? "-", sw?.ContainsKey("VLAN (native/untagged)") == true ? "pass" : "warn");
        Card(sb, "Tests", r.Tests.Count == 0 ? "not run" : fails == 0 ? "all passed" : $"{fails} failed", r.Tests.Count == 0 ? "warn" : fails == 0 ? "pass" : "fail");
        sb.Append("</div>");

        Section(sb, "Link / IP", r.Adapter);
        if (r.SwitchPorts.Count == 0) sb.Append("<h2>Switch port</h2><p class=muted>No LLDP/CDP neighbor discovered.</p>");
        for (int i = 0; i < r.SwitchPorts.Count; i++) Section(sb, r.SwitchPorts.Count > 1 ? $"Switch port (neighbor {i + 1})" : "Switch port", r.SwitchPorts[i]);

        if (r.Tests.Count > 0)
        {
            sb.Append("<h2>Connectivity tests</h2><table><tr><th>Result</th><th>Test</th><th>Detail</th></tr>");
            foreach (var t in r.Tests)
                sb.Append($"<tr><td class={t.Result.ToLowerInvariant()}><b>{H(t.Result)}</b></td><td>{H(t.Test)}</td><td>{H(t.Detail)}</td></tr>");
            sb.Append("</table>");
        }
        if (r.Latency.Count > 0) Section(sb, "Latency", r.Latency);
        if (r.LanScan.Count > 0)
        {
            sb.Append($"<h2>LAN scan ({r.LanScan.Count} devices)</h2><table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Ping</th><th>Note</th></tr>");
            foreach (var s in r.LanScan) sb.Append($"<tr><td>{H(s.Ip)}</td><td>{H(s.Mac)}</td><td>{H(s.Hostname)}</td><td>{H(s.Ping)}</td><td>{H(s.Note)}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append($"<p class=muted style='margin-top:28px'>Generated by NetProbe {H(r.Version)}</p></body></html>");
        return sb.ToString();
    }

    private static void Card(StringBuilder sb, string title, string? value, string cls) =>
        sb.Append($"<div class='card c-{cls}'><b>{H(title)}</b><span>{H(value)}</span></div>");

    private static void Section(StringBuilder sb, string title, Dictionary<string, string> d)
    {
        sb.Append($"<h2>{H(title)}</h2><table>");
        foreach (var (k, v) in d) sb.Append($"<tr><td class=k>{H(k)}</td><td>{H(v)}</td></tr>");
        sb.Append("</table>");
    }

    /// <summary>Renders HTML to PDF with Edge in headless mode (installed on every Windows 10/11 PC).</summary>
    public static async Task SavePdfAsync(string html, string pdfPath)
    {
        var edge = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe")
        }.FirstOrDefault(File.Exists) ?? throw new InvalidOperationException("Microsoft Edge not found - save as HTML instead.");
        var tmp = Path.Combine(Path.GetTempPath(), $"netprobe-report-{Guid.NewGuid():N}.html");
        await File.WriteAllTextAsync(tmp, html);
        var profile = Path.Combine(Path.GetTempPath(), "NetProbe", "edge-pdf");
        try
        {
            File.Delete(pdfPath);
            var psi = new ProcessStartInfo(edge,
                $"--headless --disable-gpu --no-first-run --user-data-dir=\"{profile}\" --no-pdf-header-footer --print-to-pdf=\"{pdfPath}\" \"{new Uri(tmp).AbsoluteUri}\"")
            { UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
            // Edge's launcher can exit before its child finishes writing the file
            for (int i = 0; i < 60 && !IsComplete(pdfPath); i++) await Task.Delay(500);
            if (!IsComplete(pdfPath)) throw new InvalidOperationException("Edge did not produce a PDF.");
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    private static bool IsComplete(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length == 0) return false;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return true;
        }
        catch (IOException) { return false; }
    }
}

/// <summary>Optional remote upload: POSTs the JSON report to a configured URL with a bearer API key.</summary>
public static class Uploader
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static async Task<string> UploadAsync(Settings s, ReportData r)
    {
        if (string.IsNullOrWhiteSpace(s.UploadUrl)) throw new InvalidOperationException("No upload URL set (Settings).");
        using var req = new HttpRequestMessage(HttpMethod.Post, s.UploadUrl)
        {
            Content = new StringContent(r.ToJson(), Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrWhiteSpace(s.ApiKey)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s.ApiKey);
        req.Headers.UserAgent.ParseAdd($"NetProbe/{App.Version}");
        using var resp = await Http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Server returned HTTP {(int)resp.StatusCode}: {body[..Math.Min(body.Length, 200)]}");
        return $"Uploaded (HTTP {(int)resp.StatusCode})";
    }
}

/// <summary>Checks GitHub Releases for a newer version and runs the new installer.</summary>
public static class Updater
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("NetProbe-Updater");
        c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return c;
    }

    public sealed record Release(Version Version, string Tag, string Notes, string? InstallerUrl, string PageUrl);

    public static async Task<Release?> CheckAsync(string repo)
    {
        if (string.IsNullOrWhiteSpace(repo) || !repo.Contains('/')) return null;
        using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://api.github.com/repos/{repo.Trim()}/releases/latest"));
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var v)) return null;
        string? url = null;
        foreach (var a in root.GetProperty("assets").EnumerateArray())
        {
            var name = a.GetProperty("name").GetString() ?? "";
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && name.Contains("Setup", StringComparison.OrdinalIgnoreCase))
                url = a.GetProperty("browser_download_url").GetString();
        }
        var rel = new Release(v, tag, root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "", url,
            root.GetProperty("html_url").GetString() ?? "");
        return v > Assembly.GetExecutingAssembly().GetName().Version ? rel : null;
    }

    /// <summary>Downloads the installer and starts it; the caller should then exit the app.</summary>
    public static async Task DownloadAndRunAsync(Release r, IProgress<int>? progress)
    {
        if (r.InstallerUrl == null) throw new InvalidOperationException("This release has no Setup .exe attached.");
        var path = Path.Combine(Path.GetTempPath(), $"NetProbe-Setup-{r.Version}.exe");
        using (var resp = await Http.GetAsync(r.InstallerUrl, HttpCompletionOption.ResponseHeadersRead))
        {
            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength ?? 0;
            await using var src = await resp.Content.ReadAsStreamAsync();
            await using var dst = File.Create(path);
            var buf = new byte[81920];
            long got = 0;
            int n;
            while ((n = await src.ReadAsync(buf)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n));
                got += n;
                if (total > 0) progress?.Report((int)(100 * got / total));
            }
        }
        // Inno Setup: close the running app, install silently-ish, relaunch
        Process.Start(new ProcessStartInfo(path, "/SILENT /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS") { UseShellExecute = true });
    }
}
