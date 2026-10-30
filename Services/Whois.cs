using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace NetProbe.Services;

/// <summary>
/// WHOIS for domains and IP addresses. Uses RDAP (the JSON successor to WHOIS, via rdap.org's bootstrap redirect)
/// and falls back to classic port-43 WHOIS with an IANA referral if RDAP has nothing.
/// </summary>
public static class Whois
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd($"NetProbe/{App.Version}");
        c.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        return c;
    }

    public static async IAsyncEnumerable<string> LookupAsync(string input, [EnumeratorCancellation] CancellationToken ct)
    {
        var q = Clean(input);
        if (q.Length == 0) { yield return "Enter a domain or IP address."; yield break; }
        bool isIp = IPAddress.TryParse(q, out _);

        // domains: try "www.example.co.uk" -> "example.co.uk" -> "co.uk" until the registry knows it
        var candidates = isIp ? new List<string> { q } : DomainCandidates(q);
        JsonDocument? doc = null;
        string? used = null, err = null;
        foreach (var c in candidates)
        {
            try
            {
                using var resp = await Http.GetAsync($"https://rdap.org/{(isIp ? "ip" : "domain")}/{c}", ct);
                if (resp.StatusCode == HttpStatusCode.NotFound) continue;
                resp.EnsureSuccessStatusCode();
                doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                used = c;
                break;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e) { err = e.Message; break; }
        }

        if (doc != null)
        {
            using (doc)
            {
                yield return $"RDAP record for {used}";
                foreach (var line in isIp ? FormatIp(doc.RootElement) : FormatDomain(doc.RootElement))
                    if (line.Length > 0) yield return line;
            }
            yield return "--- done";
            yield break;
        }

        yield return err != null ? $"RDAP lookup failed ({err}) - trying classic WHOIS..." : "No RDAP record - trying classic WHOIS...";
        string raw;
        try { raw = await ClassicAsync(isIp ? q : candidates.Count > 1 ? candidates[^2] : q, ct); }
        catch (Exception e) { raw = "WHOIS failed: " + e.Message; }
        foreach (var line in raw.Split('\n'))
        {
            var l = line.TrimEnd('\r');
            if (l.StartsWith('%') || l.StartsWith('#') || string.IsNullOrWhiteSpace(l)) continue;
            yield return l;
        }
        yield return "--- done";
    }

    private static string Clean(string s)
    {
        s = s.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var u) && u.Host.Length > 0) s = u.Host;
        return s.Trim('/', '.').ToLowerInvariant();
    }

    private static List<string> DomainCandidates(string host)
    {
        var parts = host.Split('.');
        var list = new List<string>();
        for (int i = 0; i <= parts.Length - 2; i++) list.Add(string.Join('.', parts[i..]));
        return list;
    }

    // ------------------------------------------------------------------ RDAP formatting

    private static IEnumerable<string> FormatDomain(JsonElement r)
    {
        yield return Row("Domain", Str(r, "ldhName")?.ToLowerInvariant());
        var registrar = Entities(r).FirstOrDefault(e => HasRole(e, "registrar"));
        if (registrar.ValueKind != JsonValueKind.Undefined) yield return Row("Registrar", VcardName(registrar));
        foreach (var e in Events(r)) yield return Row(e.Label, e.Date);
        if (r.TryGetProperty("status", out var st)) yield return Row("Status", string.Join(", ", st.EnumerateArray().Select(x => x.GetString())));
        if (r.TryGetProperty("nameservers", out var ns))
            foreach (var n in ns.EnumerateArray()) yield return Row("Name server", Str(n, "ldhName")?.ToLowerInvariant());
        if (r.TryGetProperty("secureDNS", out var sd) && sd.TryGetProperty("delegationSigned", out var ds))
            yield return Row("DNSSEC", ds.GetBoolean() ? "signed" : "unsigned");
        foreach (var line in Contacts(r)) yield return line;
    }

    private static IEnumerable<string> FormatIp(JsonElement r)
    {
        yield return Row("Network name", Str(r, "name"));
        yield return Row("Range", $"{Str(r, "startAddress")} - {Str(r, "endAddress")}");
        if (r.TryGetProperty("cidr0_cidrs", out var cidrs))
            foreach (var c in cidrs.EnumerateArray())
                yield return Row("CIDR", $"{Str(c, "v4prefix") ?? Str(c, "v6prefix")}/{(c.TryGetProperty("length", out var l) ? l.GetInt32() : 0)}");
        yield return Row("Handle", Str(r, "handle"));
        yield return Row("Type", Str(r, "type"));
        yield return Row("Country", Str(r, "country"));
        yield return Row("Parent", Str(r, "parentHandle"));
        foreach (var e in Events(r)) yield return Row(e.Label, e.Date);
        foreach (var line in Contacts(r)) yield return line;
    }

    private static IEnumerable<string> Contacts(JsonElement r)
    {
        foreach (var e in AllEntities(r))
        {
            var roles = e.TryGetProperty("roles", out var rr) ? rr.EnumerateArray().Select(x => x.GetString() ?? "").ToList() : new();
            if (roles.Contains("registrar")) continue;
            var name = VcardName(e);
            var email = Vcard(e, "email");
            var phone = Vcard(e, "tel");
            if (name == null && email == null) continue;
            var label = roles.Count > 0 ? string.Join("/", roles.Select(Title)) : "Contact";
            var val = string.Join("  ", new[] { name, email, phone }.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct());
            yield return Row(label, val);
        }
    }

    private static string Title(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    private static IEnumerable<(string Label, string Date)> Events(JsonElement r)
    {
        if (!r.TryGetProperty("events", out var ev)) yield break;
        foreach (var e in ev.EnumerateArray())
        {
            var action = Str(e, "eventAction") ?? "";
            var date = Str(e, "eventDate") ?? "";
            if (action.Contains("rdap", StringComparison.OrdinalIgnoreCase)) continue;
            var label = action switch
            {
                "registration" => "Created",
                "expiration" => "Expires",
                "last changed" => "Last changed",
                "last update of RDAP database" => "",
                _ => Title(action)
            };
            if (label == "") continue;
            yield return (label, DateTime.TryParse(date, out var d) ? d.ToString("yyyy-MM-dd") : date);
        }
    }

    private static IEnumerable<JsonElement> Entities(JsonElement r) =>
        r.TryGetProperty("entities", out var e) ? e.EnumerateArray() : Enumerable.Empty<JsonElement>();

    private static IEnumerable<JsonElement> AllEntities(JsonElement r)
    {
        foreach (var e in Entities(r))
        {
            yield return e;
            foreach (var sub in AllEntities(e)) yield return sub;
        }
    }

    private static bool HasRole(JsonElement e, string role) =>
        e.TryGetProperty("roles", out var r) && r.EnumerateArray().Any(x => x.GetString() == role);

    private static string? VcardName(JsonElement e) => Vcard(e, "fn") ?? Str(e, "handle");

    private static string? Vcard(JsonElement e, string field)
    {
        if (!e.TryGetProperty("vcardArray", out var va) || va.GetArrayLength() < 2) return null;
        foreach (var item in va[1].EnumerateArray())
        {
            if (item.GetArrayLength() < 4 || item[0].GetString() != field) continue;
            var v = item[3];
            var s = v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString();
            if (!string.IsNullOrWhiteSpace(s)) return s.Replace("tel:", "").Replace("mailto:", "");
        }
        return null;
    }

    private static string? Str(JsonElement e, string prop) =>
        e.TryGetProperty(prop, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    // empty string = nothing to show (filtered by the caller)
    private static string Row(string k, string? v) => string.IsNullOrWhiteSpace(v) || v.Trim() == "-" ? "" : $"  {k,-16} {v}";

    // ------------------------------------------------------------------ classic port-43 WHOIS

    private static async Task<string> ClassicAsync(string query, CancellationToken ct)
    {
        var iana = await Port43("whois.iana.org", query, ct);
        var refer = iana.Split('\n').Select(l => l.Trim())
            .FirstOrDefault(l => l.StartsWith("refer:", StringComparison.OrdinalIgnoreCase) || l.StartsWith("whois:", StringComparison.OrdinalIgnoreCase));
        if (refer == null) return iana;
        var server = refer[(refer.IndexOf(':') + 1)..].Trim();
        var q = server.Contains("arin.net") ? "n + " + query : query;
        return $"(from {server})\n" + await Port43(server, q, ct);
    }

    private static async Task<string> Port43(string server, string query, CancellationToken ct)
    {
        using var tcp = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(12));
        await tcp.ConnectAsync(server, 43, cts.Token);
        await using var s = tcp.GetStream();
        await s.WriteAsync(Encoding.ASCII.GetBytes(query + "\r\n"), cts.Token);
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms, cts.Token);
        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
