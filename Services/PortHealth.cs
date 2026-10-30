using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace NetProbe.Services;

public sealed record HealthItem(Sev Sev, string Check, string Result, string Explain)
{
    public string Badge => Sev switch { Sev.Pass => "OK", Sev.Fail => "PROBLEM", Sev.Warn => "WARNING", _ => "INFO" };
}

/// <summary>What the analyzer needs to know about this laptop to read a capture.</summary>
public sealed class HealthContext
{
    public string OurMac = "";            // "c8:53:09:ec:08:5d"
    public string? OurIp, Gateway;
    public string Nonce = "";             // loop-probe payload marker; probes are "<nonce>B<n>." (broadcast) and "<nonce>U<n>." (unicast to gateway)
    public int ProbesSent, UnicastSent;
    public uint DhcpXid;
    public double Seconds = 30;
}

/// <summary>
/// "Port Health": listens on the port and flags switch-side problems a laptop can see -
/// loops, broadcast storms, spanning-tree churn, rogue DHCP, duplicate IP, speed/duplex mismatch,
/// extra devices in the path, NIC errors and link flaps.
/// </summary>
public static class PortHealth
{
    // ------------------------------------------------------------------ live run

    public static async Task<List<HealthItem>> RunAsync(AdapterSnapshot snap, IReadOnlyList<Neighbor> neighbors, int linkFlaps,
        int seconds, IProgress<string>? progress, CancellationToken stopEarly)
    {
        var items = new List<HealthItem>();
        var nic = AdapterInfo.Find(snap.Id);
        var before = nic?.GetIPStatistics();
        var ctx = new HealthContext
        {
            OurMac = snap.Mac.Replace('-', ':').ToLowerInvariant(),
            OurIp = snap.IPv4.FirstOrDefault()?.Split('/')[0],
            Gateway = snap.Gateway,
            Nonce = "NETPROBE-LOOP-" + Guid.NewGuid().ToString("N")[..12],
            DhcpXid = (uint)Random.Shared.Next(1, int.MaxValue)
        };

        string? pcap = null;
        if (!App.IsAdmin)
            items.Add(new(Sev.Info, "Packet checks", "Skipped", "Loop, storm, spanning-tree and DHCP checks need Administrator. Use Restart as Admin."));
        else if (!snap.IsUp)
            items.Add(new(Sev.Fail, "Link", "Down", "No link on this adapter - nothing to listen to."));
        else
        {
            var sw = Stopwatch.StartNew();
            pcap = await Task.Run(() => Capture(snap, ctx, seconds, progress, stopEarly));
            ctx.Seconds = Math.Max(1, sw.Elapsed.TotalSeconds);
        }

        var after = AdapterInfo.Find(snap.Id)?.GetIPStatistics();
        progress?.Report("Analyzing...");
        if (pcap != null) items.AddRange(Analyze(pcap, ctx, neighbors));
        items.AddRange(LocalChecks(snap, neighbors, linkFlaps, before, after, await Task.Run(() => ReadDuplex(snap.Name))));
        return items.OrderBy(i => i.Sev switch { Sev.Fail => 0, Sev.Warn => 1, Sev.Pass => 2, _ => 3 }).ToList();
    }

    private static string? Capture(AdapterSnapshot snap, HealthContext ctx, int seconds, IProgress<string>? progress, CancellationToken stop)
    {
        var dir = LinkDiscovery.WorkDir;
        Directory.CreateDirectory(dir);
        var etl = Path.Combine(dir, "health.etl");
        var pcap = Path.Combine(dir, "health.pcapng");
        File.Delete(etl);
        File.Delete(pcap);

        LinkDiscovery.Run("stop");
        LinkDiscovery.Run("filter remove");
        LinkDiscovery.Run("filter add H-bcast -m FF-FF-FF-FF-FF-FF");
        LinkDiscovery.Run("filter add H-stp -m 01-80-C2-00-00-00");
        LinkDiscovery.Run("filter add H-pvst -m 01-00-0C-CC-CC-CD");
        LinkDiscovery.Run("filter add H-lldp -m 01-80-C2-00-00-0E");
        LinkDiscovery.Run("filter add H-cdp -m 01-00-0C-CC-CC-CC");
        LinkDiscovery.Run("filter add H-arp -d ARP");
        LinkDiscovery.Run("filter add H-dhcps -t UDP -p 67");
        LinkDiscovery.Run("filter add H-dhcpc -t UDP -p 68");
        LinkDiscovery.Run("filter add H-probe -t UDP -p 9");
        var comp = LinkDiscovery.ComponentIdFor(snap.Mac);
        var start = LinkDiscovery.Run($"start --capture --comp {comp ?? "nics"} --pkt-size 0 --file-name \"{etl}\"");
        if (start.Code != 0) start = LinkDiscovery.Run($"start --capture --pkt-size 0 --file-name \"{etl}\"");
        if (start.Code != 0) { LinkDiscovery.Run("filter remove"); throw new InvalidOperationException("pktmon failed to start: " + start.Output); }
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(seconds);
            int tick = 0;
            while (DateTime.UtcNow < deadline && !stop.IsCancellationRequested)
            {
                // loop probes in the first seconds, DHCP discovers at ~2 s and ~12 s
                if (tick < 5) { SendProbe(ctx); }
                if (tick == 4 || tick == 24) SendDhcpDiscover(snap, ctx);
                progress?.Report($"Listening... {(int)Math.Ceiling((deadline - DateTime.UtcNow).TotalSeconds)} s left");
                tick++;
                stop.WaitHandle.WaitOne(500);
            }
        }
        finally
        {
            LinkDiscovery.Run("stop");
            LinkDiscovery.Run("filter remove");
        }
        LinkDiscovery.Run($"etl2pcap \"{etl}\" --out \"{pcap}\"");
        return File.Exists(pcap) ? pcap : null;
    }

    /// <summary>
    /// One tagged broadcast (a loop sends it back) plus one tagged unicast to the gateway (a loop can't).
    /// pktmon logs each packet more than once, so the unicast copies tell us the normal count per packet.
    /// </summary>
    private static void SendProbe(HealthContext ctx)
    {
        if (ctx.OurIp == null) return;
        try
        {
            using var u = new UdpClient(new IPEndPoint(IPAddress.Parse(ctx.OurIp), 0)) { EnableBroadcast = true };
            var b = Encoding.ASCII.GetBytes($"{ctx.Nonce}B{ctx.ProbesSent}.");
            u.Send(b, b.Length, new IPEndPoint(IPAddress.Broadcast, 9));
            ctx.ProbesSent++;
            if (ctx.Gateway != null)
            {
                var g = Encoding.ASCII.GetBytes($"{ctx.Nonce}U{ctx.UnicastSent}.");
                u.Send(g, g.Length, new IPEndPoint(IPAddress.Parse(ctx.Gateway), 9));
                ctx.UnicastSent++;
            }
        }
        catch { }
    }

    /// <summary>DHCPDISCOVER with the broadcast flag set, so every DHCP server's offer comes back as a broadcast we can see.</summary>
    private static void SendDhcpDiscover(AdapterSnapshot snap, HealthContext ctx)
    {
        if (ctx.OurIp == null) return;
        try
        {
            var p = new byte[300];
            p[0] = 1; p[1] = 1; p[2] = 6;                                  // BOOTREQUEST, Ethernet, hlen 6
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder((int)ctx.DhcpXid)).CopyTo(p, 4);
            p[10] = 0x80;                                                  // broadcast flag
            var mac = snap.Mac.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();
            mac.CopyTo(p, 28);
            new byte[] { 99, 130, 83, 99 }.CopyTo(p, 236);                // magic cookie
            int o = 240;
            p[o++] = 53; p[o++] = 1; p[o++] = 1;                          // DHCP DISCOVER
            p[o++] = 55; p[o++] = 3; p[o++] = 1; p[o++] = 3; p[o++] = 6;  // ask for mask, router, DNS
            p[o++] = 255;
            using var u = new UdpClient(new IPEndPoint(IPAddress.Parse(ctx.OurIp), 0)) { EnableBroadcast = true };
            u.Send(p, p.Length, new IPEndPoint(IPAddress.Broadcast, 67));
        }
        catch { }
    }

    private static string? ReadDuplex(string adapterName)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -Command \"(Get-NetAdapter -Name '{adapterName.Replace("'", "''")}').FullDuplex\"")
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(10000);
            return o switch { "True" => "Full", "False" => "Half", _ => null };
        }
        catch { return null; }
    }

    // ------------------------------------------------------------------ capture analysis (testable on a saved pcap)

    private sealed class Bpdu
    {
        public string Kind = "", Root = "", Bridge = "";
        public bool Tc;
        public int RootCost;
    }

    public static List<HealthItem> Analyze(string pcapPath, HealthContext ctx, IReadOnlyList<Neighbor>? knownNeighbors = null)
    {
        var items = new List<HealthItem>();
        int frames = 0, bcastRx = 0;
        var probeCopies = new Dictionary<string, int>();   // "B0" -> copies seen
        var bpdus = new List<Bpdu>();
        var dhcpServers = new Dictionary<string, string>();   // server id -> offered ip
        var dupIpMacs = new HashSet<string>();
        var neighborMacs = new HashSet<string>(knownNeighbors?.Select(n => n.Get("Source MAC") ?? "").Where(s => s != "") ?? Enumerable.Empty<string>());
        var nonce = Encoding.ASCII.GetBytes(ctx.Nonce);

        foreach (var f in LinkDiscovery.ReadFrames(pcapPath))
        {
            if (f.Length < 14) continue;
            frames++;
            var dst = Mac(f, 0);
            var src = Mac(f, 6);
            int o = 12, et = U16(f, o);
            while ((et == 0x8100 || et == 0x88A8) && o + 6 <= f.Length) { o += 4; et = U16(f, o); }
            int payload = o + 2;

            if (nonce.Length > 0 && IndexOf(f, nonce) is var at && at >= 0)
            {
                var tag = new StringBuilder();
                for (int i = at + nonce.Length; i < f.Length && f[i] != '.' && tag.Length < 6; i++) tag.Append((char)f[i]);
                probeCopies[tag.ToString()] = probeCopies.GetValueOrDefault(tag.ToString()) + 1;
                continue;
            }
            if (dst == "ff:ff:ff:ff:ff:ff" && src != ctx.OurMac) bcastRx++;

            if (et == 0x0806 && f.Length >= payload + 28)
            {
                // ARP: sender MAC at +8, sender IP at +14
                var smac = Mac(f, payload + 8);
                var sip = $"{f[payload + 14]}.{f[payload + 15]}.{f[payload + 16]}.{f[payload + 17]}";
                if (ctx.OurIp != null && sip == ctx.OurIp && smac != ctx.OurMac) dupIpMacs.Add(smac);
            }
            else if (et == 0x0800 && f.Length >= payload + 28)
            {
                int ihl = (f[payload] & 0x0F) * 4;
                if (f[payload + 9] == 17)
                {
                    int u = payload + ihl;
                    if (f.Length >= u + 8 + 240 && U16(f, u) == 67 && U16(f, u + 2) == 68 && f[u + 8] == 2)
                    {
                        int b = u + 8;
                        var offered = $"{f[b + 16]}.{f[b + 17]}.{f[b + 18]}.{f[b + 19]}";
                        var server = $"{f[payload + 12]}.{f[payload + 13]}.{f[payload + 14]}.{f[payload + 15]}";
                        int type = 0;
                        for (int p = b + 240; p + 2 <= f.Length && f[p] != 255;)
                        {
                            if (f[p] == 0) { p++; continue; }
                            int code = f[p], len = f[p + 1];
                            if (p + 2 + len > f.Length) break;
                            if (code == 53 && len >= 1) type = f[p + 2];
                            if (code == 54 && len == 4) server = $"{f[p + 2]}.{f[p + 3]}.{f[p + 4]}.{f[p + 5]}";
                            p += 2 + len;
                        }
                        if (type == 2) dhcpServers[server] = offered;   // OFFER
                    }
                }
            }
            else if (et <= 1500 && dst == "01:80:c2:00:00:00" && f.Length >= payload + 3 + 35 && f[payload] == 0x42 && f[payload + 1] == 0x42)
            {
                if (ParseBpdu(f, payload + 3, "STP") is { } b) bpdus.Add(b);
            }
            else if (et <= 1500 && dst == "01:00:0c:cc:cc:cd" && f.Length >= payload + 8 + 35 && f[payload] == 0xAA)
            {
                if (ParseBpdu(f, payload + 8, "PVST+") is { } b) bpdus.Add(b);
            }
            else if (LinkDiscovery.ParseFrame(f) is { } n && n.Get("Source MAC") is { } nm)
            {
                neighborMacs.Add(nm);
            }
        }

        // copies the capture logs for one packet (pktmon records packets at more than one point in the driver)
        var bcastProbes = Enumerable.Range(0, ctx.ProbesSent).Select(i => probeCopies.GetValueOrDefault($"B{i}")).ToList();
        var uniProbes = Enumerable.Range(0, ctx.UnicastSent).Select(i => probeCopies.GetValueOrDefault($"U{i}")).Where(c => c > 0).ToList();
        int perPacket = Math.Max(1, uniProbes.Count > 0 ? uniProbes.Min() : bcastProbes.Where(c => c > 0).DefaultIfEmpty(1).Min());

        // --- loop
        if (ctx.ProbesSent > 0)
        {
            var returns = bcastProbes.Where(c => c > 0).Select(c => c / perPacket - 1).ToList();
            int looped = returns.Count(r => r >= 1);
            if (bcastProbes.All(c => c == 0))
                items.Add(new(Sev.Info, "Loop test", "Inconclusive", "The test packets weren't seen in the capture, so a loop couldn't be checked."));
            else if (looped * 2 > returns.Count)
                items.Add(new(Sev.Fail, "Loop test", $"Possible loop - test broadcasts came back (up to {returns.Max()}x each)",
                    $"{looped} of {returns.Count} tagged broadcasts returned to the port that sent them. That usually means a cable loop (two jacks patched together, or a loop through a small switch) or spanning tree not blocking."));
            else if (looped > 0)
                items.Add(new(Sev.Warn, "Loop test", $"{looped} of {returns.Count} test broadcasts came back",
                    "A few test packets returned to this port. Could be a brief loop or a device reflecting broadcasts - run the check again."));
            else
                items.Add(new(Sev.Pass, "Loop test", "No loop detected", $"None of the {ctx.ProbesSent} tagged test broadcasts came back to this port."));
        }

        // --- broadcast storm
        bcastRx /= perPacket;
        double pps = bcastRx / Math.Max(1, ctx.Seconds);
        items.Add(pps >= 1000
            ? new(Sev.Fail, "Broadcast traffic", $"{pps:0} packets/s - broadcast storm", "This much broadcast traffic swamps devices and is a classic sign of a loop or a misbehaving device.")
            : pps >= 100
                ? new(Sev.Warn, "Broadcast traffic", $"{pps:0} packets/s - high", "Higher than normal. Can be a very large VLAN, a chatty device, or the start of a storm.")
                : new(Sev.Pass, "Broadcast traffic", $"{pps:0.#} packets/s - normal", $"{bcastRx} broadcasts in {ctx.Seconds:0} s."));

        // --- spanning tree
        if (bpdus.Count == 0)
            items.Add(new(Sev.Info, "Spanning tree", "No BPDUs heard", "The switch isn't sending spanning-tree packets on this port (STP off, BPDU filter, or an unmanaged switch)."));
        else
        {
            var roots = bpdus.Select(b => b.Root).Distinct().ToList();
            int tc = bpdus.Count(b => b.Tc);
            var kinds = string.Join("/", bpdus.Select(b => b.Kind).Distinct());
            if (roots.Count > 1 && bpdus.Select(b => b.Kind).Distinct().Count() == 1 && kinds != "PVST+")
                items.Add(new(Sev.Fail, "Spanning tree", $"Root bridge changing ({roots.Count} roots seen)",
                    "The spanning-tree root moved during the test. The network is re-converging - look for a flapping uplink or a switch with a lower priority being plugged in."));
            else if (tc > 0)
                items.Add(new(Sev.Warn, "Spanning tree", $"Topology change in progress ({tc} of {bpdus.Count} BPDUs)",
                    "Something on the network recently went up or down. Constant topology changes point to a flapping link or a loop elsewhere. Run the check again in a minute; if it persists, check the switch logs."));
            else
                items.Add(new(Sev.Pass, "Spanning tree", $"{kinds}, stable", $"Root bridge {roots[0]}, path cost {bpdus[0].RootCost}."));
        }

        // --- DHCP
        if (dhcpServers.Count > 1)
            items.Add(new(Sev.Fail, "DHCP servers", $"{dhcpServers.Count} DHCP servers answered",
                string.Join(";  ", dhcpServers.Select(kv => $"{kv.Key} offered {kv.Value}")) + ". Only one should answer - the extra one is probably a home router or misconfigured device (rogue DHCP)."));
        else if (dhcpServers.Count == 1)
        {
            var (srv, ip) = dhcpServers.First();
            items.Add(new(Sev.Pass, "DHCP servers", $"One server ({srv})", $"Offered {ip}. No rogue DHCP server seen."));
        }
        else if (ctx.DhcpXid != 0)
            items.Add(new(Sev.Info, "DHCP servers", "No offer seen", "No DHCP server answered the test request. Normal if this port uses a static IP, or the server ignores repeat requests."));

        // --- duplicate IP (passive ARP)
        if (dupIpMacs.Count > 0)
            items.Add(new(Sev.Fail, "Duplicate IP", $"{ctx.OurIp} is also used by {string.Join(", ", dupIpMacs)}",
                "Another device is claiming this laptop's IP address. Expect dropped connections until one of them changes."));

        // --- devices in the path
        if (neighborMacs.Count > 1)
            items.Add(new(Sev.Warn, "Devices on this port", $"{neighborMacs.Count} devices advertising LLDP/CDP",
                "More than one network device is visible on this jack - usually a small switch or IP phone between you and the wall port."));

        if (frames == 0 && ctx.ProbesSent == 0)
            items.Add(new(Sev.Info, "Capture", "No packets captured", "Nothing was captured - check that the cable is plugged in."));
        return items;
    }

    private static Bpdu? ParseBpdu(byte[] f, int o, string kind)
    {
        if (o + 4 > f.Length || U16(f, o) != 0) return null;
        int version = f[o + 2], type = f[o + 3];
        if (type == 0x80) return new Bpdu { Kind = "STP", Tc = true, Root = "?", Bridge = "?" }; // TCN
        if (o + 35 > f.Length) return null;
        int flags = f[o + 4];
        string Id(int p) => $"{U16(f, p)}/{Mac(f, p + 2)}";
        return new Bpdu
        {
            Kind = kind == "PVST+" ? "PVST+" : version >= 2 ? (version == 3 ? "MSTP" : "RSTP") : "STP",
            Tc = (flags & 0x01) != 0,
            Root = Id(o + 5),
            RootCost = (int)((uint)f[o + 13] << 24 | (uint)f[o + 14] << 16 | (uint)f[o + 15] << 8 | f[o + 16]),
            Bridge = Id(o + 17)
        };
    }

    // ------------------------------------------------------------------ checks that don't need a capture

    private static readonly (string Prefix, long Bps)[] MauSpeeds =
        { ("10GBASE", 10_000_000_000), ("5GBASE", 5_000_000_000), ("2.5GBASE", 2_500_000_000), ("1000BASE", 1_000_000_000), ("100BASE", 100_000_000), ("10BASE", 10_000_000) };

    public static List<HealthItem> LocalChecks(AdapterSnapshot s, IReadOnlyList<Neighbor> neighbors, int linkFlaps,
        IPInterfaceStatistics? before, IPInterfaceStatistics? after, string? ourDuplex)
    {
        var items = new List<HealthItem>();
        if (!s.IsUp) return items;

        // speed
        if (!s.IsWireless && s.SpeedBps > 0 && s.SpeedBps < 1_000_000_000)
            items.Add(new(Sev.Warn, "Link speed", $"Only {s.SpeedText}",
                "Gigabit is normal today. 100 Mbps usually means a damaged cable or jack (only 2 of 4 pairs working), or an old/limited switch port."));
        else if (!s.IsWireless)
            items.Add(new(Sev.Pass, "Link speed", s.SpeedText, "Negotiated at full speed."));

        // speed / duplex vs what the switch says
        var n = neighbors.FirstOrDefault();
        var mau = n?.Get("Switch port speed");
        if (mau != null)
        {
            var sw = MauSpeeds.FirstOrDefault(m => mau.StartsWith(m.Prefix, StringComparison.OrdinalIgnoreCase));
            string? swDuplex = mau.Contains(" FD") ? "Full" : mau.Contains(" HD") ? "Half" : null;
            if (sw.Bps > 0 && s.SpeedBps > 0 && sw.Bps != s.SpeedBps)
                items.Add(new(Sev.Fail, "Speed mismatch", $"Laptop {s.SpeedText}, switch {mau}", "The two ends disagree on speed - usually one side is hard-set. Set both to auto-negotiate."));
            else if (swDuplex != null && ourDuplex != null && swDuplex != ourDuplex)
                items.Add(new(Sev.Fail, "Duplex mismatch", $"Laptop {ourDuplex} duplex, switch {swDuplex} duplex",
                    "A duplex mismatch causes slow speeds, late collisions and CRC errors. Set both sides to auto-negotiate."));
            else
                items.Add(new(Sev.Pass, "Speed / duplex", $"Matches switch ({mau})", "Laptop and switch agree."));
        }
        else if (n?.Get("Duplex") is { } cdpDuplex && ourDuplex != null && cdpDuplex != ourDuplex)
            items.Add(new(Sev.Fail, "Duplex mismatch", $"Laptop {ourDuplex}, switch {cdpDuplex}", "Set both sides to auto-negotiate."));
        else if (ourDuplex == "Half")
            items.Add(new(Sev.Warn, "Duplex", "Half duplex", "Modern links run full duplex. Half duplex usually means the other side is hard-set or very old."));

        // PoE
        if (n?.Get("PoE") is { } poe)
        {
            var m = System.Text.RegularExpressions.Regex.Match(poe, @"requested ([\d.]+) W, allocated ([\d.]+) W");
            if (m.Success && double.Parse(m.Groups[2].Value) + 0.05 < double.Parse(m.Groups[1].Value))
                items.Add(new(Sev.Warn, "PoE power", poe, "The switch is giving less power than requested - the device may not fully power up. The switch may be out of PoE budget."));
        }

        // NIC errors during the test
        if (before != null && after != null)
        {
            long rxErr = after.IncomingPacketsWithErrors - before.IncomingPacketsWithErrors;
            long rxDrop = after.IncomingPacketsDiscarded - before.IncomingPacketsDiscarded;
            long txErr = after.OutgoingPacketsWithErrors - before.OutgoingPacketsWithErrors;
            items.Add(rxErr + txErr > 0
                ? new(Sev.Fail, "Port errors", $"{rxErr} receive / {txErr} send errors during test", "Errors on the link point to a bad cable, a bad jack/patch, or a duplex mismatch.")
                : rxDrop > 50
                    ? new(Sev.Warn, "Port errors", $"{rxDrop} packets dropped during test", "Packets were discarded - often a burst of unwanted traffic, or the laptop was too busy.")
                    : new(Sev.Pass, "Port errors", "No errors during test", $"Since connect: {after.IncomingPacketsWithErrors} receive errors, {after.OutgoingPacketsWithErrors} send errors."));
        }

        // link flaps
        if (linkFlaps > 0)
            items.Add(new(linkFlaps >= 3 ? Sev.Fail : Sev.Warn, "Link stability", $"Link dropped {linkFlaps} time(s) since NetProbe started",
                "A link that goes up and down is usually a loose/damaged cable, a bad jack, or the switch shutting the port (port-security, err-disable)."));

        // duplicate IP detected by Windows
        var ip = AdapterInfo.Find(s.Id)?.GetIPProperties().UnicastAddresses
            .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork && u.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Duplicate);
        if (ip != null)
            items.Add(new(Sev.Fail, "Duplicate IP", $"Windows flagged {ip.Address} as a duplicate", "Another device on the network has the same IP address."));

        if (s.Apipa)
            items.Add(new(Sev.Fail, "DHCP", "No address from DHCP", "The laptop gave itself a 169.254.x.x address. The port may be on the wrong VLAN, or the DHCP server/relay isn't reachable."));
        return items;
    }

    // ------------------------------------------------------------------ helpers

    private static int U16(byte[] f, int o) => f[o] << 8 | f[o + 1];
    private static string Mac(byte[] f, int o) => string.Join(":", f[o..(o + 6)].Select(x => x.ToString("x2")));

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= hay.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && hay[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }
}
