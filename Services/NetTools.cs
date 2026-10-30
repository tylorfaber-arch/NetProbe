using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace NetProbe.Services;

/// <summary>Ping, traceroute, DNS lookup and TCP port check. Each streams output lines.</summary>
public static class NetTools
{
    public static async IAsyncEnumerable<string> PingAsync(string host, int count, [EnumeratorCancellation] CancellationToken ct)
    {
        using var p = new Ping();
        int sent = 0, ok = 0;
        var times = new List<long>();
        yield return $"Pinging {host} ...";
        while (count <= 0 || sent < count)
        {
            if (ct.IsCancellationRequested) break;
            sent++;
            string line;
            try
            {
                var r = await p.SendPingAsync(host, 2000);
                if (r.Status == IPStatus.Success)
                {
                    ok++;
                    times.Add(r.RoundtripTime);
                    line = $"Reply from {r.Address}: time={r.RoundtripTime}ms TTL={r.Options?.Ttl}";
                }
                else line = r.Status.ToString();
            }
            catch (Exception e) { line = "Error: " + (e.InnerException?.Message ?? e.Message); count = sent; }
            yield return line;
            try { await Task.Delay(800, ct); } catch (OperationCanceledException) { break; }
        }
        var loss = sent > 0 ? 100 * (sent - ok) / sent : 0;
        yield return $"--- {sent} sent, {ok} received, {loss}% loss" +
                     (times.Count > 0 ? $", min/avg/max = {times.Min()}/{times.Average():0.#}/{times.Max()} ms" : "");
    }

    public static async IAsyncEnumerable<string> TraceAsync(string host, [EnumeratorCancellation] CancellationToken ct)
    {
        IPAddress target;
        string? err = null;
        try { target = IPAddress.TryParse(host, out var ip) ? ip : (await Dns.GetHostAddressesAsync(host, ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork); }
        catch (Exception e) { target = IPAddress.None; err = e.Message; }
        if (err != null) { yield return "Cannot resolve: " + err; yield break; }
        yield return $"Tracing route to {host} [{target}], max 30 hops";
        using var p = new Ping();
        var buf = new byte[32];
        for (int ttl = 1; ttl <= 30 && !ct.IsCancellationRequested; ttl++)
        {
            var cols = new List<string>();
            IPAddress? hop = null;
            bool reached = false;
            for (int i = 0; i < 3; i++)
            {
                var sw = Stopwatch.StartNew();
                try
                {
                    var r = await p.SendPingAsync(target, 1000, buf, new PingOptions(ttl, true));
                    sw.Stop();
                    if (r.Status is IPStatus.Success or IPStatus.TtlExpired)
                    {
                        hop = r.Address;
                        cols.Add($"{Math.Max(1, sw.ElapsedMilliseconds),4} ms");
                        if (r.Status == IPStatus.Success) reached = true;
                    }
                    else cols.Add("   * ");
                }
                catch { cols.Add("   * "); }
            }
            yield return $"{ttl,3}  {string.Join("  ", cols)}  {(hop?.ToString() ?? "Request timed out.")}";
            if (reached) break;
        }
        yield return "--- trace complete";
    }

    public static async IAsyncEnumerable<string> DnsLookupAsync(string host, [EnumeratorCancellation] CancellationToken ct)
    {
        var isIp = IPAddress.TryParse(host, out var ip);
        var types = isIp ? new[] { "PTR" } : new[] { "A", "AAAA", "CNAME", "MX", "NS", "TXT" };
        var name = isIp ? Native.ReverseName(ip!) : host;
        int found = 0;
        foreach (var t in types)
        {
            if (ct.IsCancellationRequested) break;
            List<Native.DnsRecord> recs;
            try { recs = await Task.Run(() => Native.Query(name, t), ct); }
            catch { continue; }
            foreach (var r in recs.Where(r => r.Type == t || t == "A" && r.Type == "CNAME"))
            {
                found++;
                yield return $"{r.Type,-6} {r.Name,-34} {r.Value}   (ttl {r.Ttl})";
            }
        }
        yield return found == 0 ? "--- no records found" : $"--- {found} record(s)";
    }

    private static readonly Dictionary<int, string> PortNames = new()
    {
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns", [80] = "http", [110] = "pop3",
        [135] = "msrpc", [139] = "netbios", [143] = "imap", [161] = "snmp", [389] = "ldap", [443] = "https", [445] = "smb",
        [515] = "lpd", [554] = "rtsp", [631] = "ipp", [636] = "ldaps", [993] = "imaps", [1433] = "mssql", [3306] = "mysql",
        [3389] = "rdp", [5060] = "sip", [5900] = "vnc", [8080] = "http-alt", [8443] = "https-alt", [9100] = "printer"
    };

    public static List<int> ParsePorts(string spec)
    {
        var ports = new List<int>();
        foreach (var part in spec.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var dash = part.Split('-');
            if (dash.Length == 2 && int.TryParse(dash[0], out var a) && int.TryParse(dash[1], out var b))
                for (int p = a; p <= b && p <= 65535; p++) ports.Add(p);
            else if (int.TryParse(part, out var single) && single is > 0 and <= 65535) ports.Add(single);
        }
        return ports.Distinct().ToList();
    }

    public static async IAsyncEnumerable<string> PortCheckAsync(string host, string spec, [EnumeratorCancellation] CancellationToken ct)
    {
        var ports = ParsePorts(spec);
        IPAddress? ip = null;
        try { ip = IPAddress.TryParse(host, out var x) ? x : (await Dns.GetHostAddressesAsync(host, ct)).OrderBy(a => a.AddressFamily != AddressFamily.InterNetwork).First(); }
        catch { }
        if (ip == null) { yield return "Cannot resolve " + host; yield break; }
        yield return $"Checking {ports.Count} TCP port(s) on {host} ({ip}) ...";
        int open = 0;
        foreach (var batch in ports.Chunk(200))
        {
            if (ct.IsCancellationRequested) break;
            var tasks = batch.Select(async port =>
            {
                using var c = new TcpClient();
                try { await c.ConnectAsync(ip, port).WaitAsync(TimeSpan.FromMilliseconds(1500), ct); return (port, "OPEN"); }
                catch (SocketException) { return (port, "closed"); }
                catch { return (port, "filtered/timeout"); }
            }).ToList();
            var results = await Task.WhenAll(tasks);
            foreach (var (port, state) in results)
            {
                if (state == "OPEN") open++;
                if (state == "OPEN" || ports.Count <= 30)
                    yield return $"  {port,5}/tcp  {state,-16} {PortNames.GetValueOrDefault(port, "")}";
            }
        }
        yield return $"--- {open} open";
    }
}
