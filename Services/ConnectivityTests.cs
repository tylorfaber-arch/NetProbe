using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;

namespace NetProbe.Services;

/// <summary>Gateway, DNS, internet, captive portal, HTTPS and public IP checks.</summary>
public static class ConnectivityTests
{
    private static readonly HttpClient Http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(6) };

    private static async Task<(int Ok, double Avg)> PingN(string host, int n = 4)
    {
        using var p = new Ping();
        var t = new List<long>();
        for (int i = 0; i < n; i++)
        {
            try { var r = await p.SendPingAsync(host, 1000); if (r.Status == IPStatus.Success) t.Add(r.RoundtripTime); } catch { }
        }
        return (t.Count, t.Count > 0 ? t.Average() : 0);
    }

    public static async IAsyncEnumerable<TestResult> RunAsync(string? gateway, IReadOnlyList<string> dns, [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (gateway == null) yield return new(Sev.Fail, "Default gateway", "None configured on this adapter");
        else
        {
            var (ok, avg) = await PingN(gateway);
            yield return ok > 0
                ? new(Sev.Pass, $"Ping gateway {gateway}", $"{ok}/4 replies, avg {avg:0.#} ms")
                : new(Sev.Fail, $"Ping gateway {gateway}", "No replies (gateway may block ping)");
        }

        foreach (var d in dns)
        {
            if (ct.IsCancellationRequested) yield break;
            var sw = Stopwatch.StartNew();
            TestResult res;
            try
            {
                var recs = await Task.Run(() => Native.Query("www.google.com", "A", IPAddress.Parse(d)), ct);
                var a = recs.FirstOrDefault(r => r.Type == "A");
                res = new(Sev.Pass, $"DNS server {d}", $"Resolved www.google.com -> {a?.Value} in {sw.ElapsedMilliseconds} ms");
            }
            catch (Exception e) { res = new(Sev.Fail, $"DNS server {d}", e.Message); }
            yield return res;
        }

        foreach (var h in new[] { "1.1.1.1", "8.8.8.8" })
        {
            var (ok, avg) = await PingN(h);
            yield return ok > 0 ? new(Sev.Pass, $"Ping internet {h}", $"{ok}/4 replies, avg {avg:0.#} ms") : new(Sev.Fail, $"Ping internet {h}", "No replies");
        }

        {
            var sw = Stopwatch.StartNew();
            TestResult res;
            try
            {
                var ips = await Dns.GetHostAddressesAsync("www.microsoft.com", ct);
                res = new(Sev.Pass, "System DNS lookup", $"www.microsoft.com -> {ips[0]} in {sw.ElapsedMilliseconds} ms");
            }
            catch (Exception e) { res = new(Sev.Fail, "System DNS lookup", e.Message); }
            yield return res;
        }

        {
            TestResult res;
            try
            {
                using var r = await Http.GetAsync("http://www.msftconnecttest.com/connecttest.txt", ct);
                var body = (await r.Content.ReadAsStringAsync(ct)).Trim();
                res = (int)r.StatusCode == 200 && body == "Microsoft Connect Test"
                    ? new(Sev.Pass, "HTTP internet check", "No captive portal / proxy interference")
                    : new(Sev.Warn, "HTTP internet check", $"Unexpected response (HTTP {(int)r.StatusCode}) - captive portal or web filter?");
            }
            catch (Exception e) { res = new(Sev.Warn, "HTTP internet check", "Blocked: " + e.Message); }
            yield return res;
        }

        {
            var sw = Stopwatch.StartNew();
            TestResult res;
            try
            {
                using var r = await Http.GetAsync("https://www.google.com/generate_204", ct);
                res = new(Sev.Pass, "HTTPS check", $"HTTP {(int)r.StatusCode} from google.com in {sw.ElapsedMilliseconds} ms");
            }
            catch (Exception e) { res = new(Sev.Fail, "HTTPS check", e.Message); }
            yield return res;
        }

        {
            TestResult res;
            try { res = new(Sev.Info, "Public IP", (await Http.GetStringAsync("https://api.ipify.org", ct)).Trim()); }
            catch { res = new(Sev.Warn, "Public IP", "Could not reach api.ipify.org"); }
            yield return res;
        }
    }
}
