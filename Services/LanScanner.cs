using System.Net;
using System.Net.NetworkInformation;

namespace NetProbe.Services;

/// <summary>Ping sweep + ARP + reverse DNS for a subnet (/20 to /30).</summary>
public static class LanScanner
{
    public static async Task<List<ScanHost>> ScanAsync(string cidr, IProgress<string> progress, CancellationToken ct)
    {
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var baseIp) || !int.TryParse(parts[1], out var pfx))
            throw new ArgumentException("Enter a subnet like 192.168.1.0/24");
        if (pfx is < 20 or > 30) throw new ArgumentException("Subnet must be between /20 and /30");

        uint size = 1u << (32 - pfx);
        uint net = AdapterInfo.ToUInt(baseIp) & ~(size - 1);
        var all = Enumerable.Range(1, (int)size - 2).Select(i => AdapterInfo.FromUInt(net + (uint)i)).ToList();

        var rtt = new Dictionary<string, string>();
        int done = 0;
        foreach (var batch in all.Chunk(128))
        {
            ct.ThrowIfCancellationRequested();
            var tasks = batch.Select(async ip =>
            {
                using var p = new Ping();
                try { var r = await p.SendPingAsync(ip, 900); return (ip, r.Status == IPStatus.Success ? r.RoundtripTime : -1); }
                catch { return (ip, -1L); }
            });
            foreach (var (ip, t) in await Task.WhenAll(tasks))
                if (t >= 0) rtt[ip.ToString()] = $"{t} ms";
            done += batch.Length;
            progress.Report($"Pinging... {done} / {all.Count}   ({rtt.Count} found)");
        }

        // ARP: finds hosts that block ping. Full ARP sweep only on small subnets (it is slow for absent hosts).
        var arpTargets = all.Count <= 1022 ? all : all.Where(ip => rtt.ContainsKey(ip.ToString())).ToList();
        var macs = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
        int arpDone = 0;
        await Parallel.ForEachAsync(arpTargets, new ParallelOptions { MaxDegreeOfParallelism = 64, CancellationToken = ct }, (ip, _) =>
        {
            var m = Native.ArpLookup(ip);
            if (m != null) macs[ip.ToString()] = m;
            var n = Interlocked.Increment(ref arpDone);
            if (n % 16 == 0) progress.Report($"ARP check... {n} / {arpTargets.Count}");
            return ValueTask.CompletedTask;
        });

        var localIps = NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(u => (u.Address.ToString(), n)))
            .GroupBy(x => x.Item1).ToDictionary(g => g.Key, g => g.First().n);

        var hosts = rtt.Keys.Union(macs.Keys).Union(localIps.Keys.Where(k => all.Any(a => a.ToString() == k))).Distinct().ToList();
        progress.Report($"Found {hosts.Count} devices - looking up names...");

        var names = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
        var lookups = hosts.Select(async h =>
        {
            try
            {
                var e = await Dns.GetHostEntryAsync(h).WaitAsync(TimeSpan.FromSeconds(3), ct);
                if (e.HostName != h) names[h] = e.HostName;
            }
            catch { }
        });
        await Task.WhenAll(lookups);

        return hosts.Select(h =>
        {
            string mac = macs.GetValueOrDefault(h, "");
            string ping = rtt.GetValueOrDefault(h, "no reply (ARP only)");
            string note = "";
            if (localIps.TryGetValue(h, out var nic))
            {
                ping = "this laptop";
                mac = string.Join("-", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
            }
            if (mac.Length >= 2 && "26AE".Contains(char.ToUpperInvariant(mac[1]))) note = "randomized/private MAC";
            return new ScanHost(h, mac, names.GetValueOrDefault(h, ""), ping, AdapterInfo.ToUInt(IPAddress.Parse(h)), note);
        }).OrderBy(h => h.Sort).ToList();
    }
}
