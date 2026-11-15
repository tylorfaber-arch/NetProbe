using System.Net;
using System.Text.RegularExpressions;

namespace NetProbe.Services;

public enum PortLink { Unknown, Up, Down, Disabled }

public sealed class SwitchPort
{
    public int IfIndex;
    public string Name = "", Descr = "", Alias = "";
    public PortLink Link = PortLink.Unknown;
    public long SpeedMbps;
    public bool IsUplink;            // SFP / fiber / uplink-module port, drawn in its own group
    public bool IsLocal;             // the port this PC is plugged into
    public int? Pvid;                // untagged / native VLAN
    public List<int> Tagged = new(); // tagged VLANs (trunk)
    public string Unit = "";         // stack member / chassis unit
    public int Number;               // port number shown on the faceplate

    public bool IsTrunk => Tagged.Count > 0;
    public string Label => string.IsNullOrEmpty(Name) ? Descr : Name;
    public string SpeedText => SpeedMbps <= 0 ? "" : SpeedMbps >= 1000 ? $"{SpeedMbps / 1000.0:0.#}G" : $"{SpeedMbps}M";

    public string Describe()
    {
        var lines = new List<string> { Label + (IsLocal ? "   (this PC)" : "") };
        if (!string.IsNullOrWhiteSpace(Alias)) lines.Add("Description: " + Alias);
        lines.Add("Link: " + Link switch
        {
            PortLink.Up => "up" + (SpeedMbps > 0 ? $", {AdapterSnapshot.FormatSpeed(SpeedMbps * 1_000_000)}" : ""),
            PortLink.Down => "down (no cable / device off)",
            PortLink.Disabled => "administratively disabled",
            _ => "unknown"
        });
        lines.Add("Untagged VLAN: " + (Pvid?.ToString() ?? "unknown"));
        lines.Add("Tagged VLANs: " + (Tagged.Count == 0 ? "none" : SwitchPorts.Ranges(Tagged)));
        return string.Join("\n", lines);
    }
}

public sealed class SwitchFaceplate
{
    public string Title = "";
    public string Source = "";          // how the data was gathered, shown under the faceplate
    public bool Generic;                // true = drawn from LLDP/CDP only, only the local port is real
    public List<SwitchPort> Ports = new();
}

/// <summary>Builds the faceplate model: every port over SNMP when possible, otherwise a generic layout from LLDP/CDP.</summary>
public static class SwitchPorts
{
    // IF-MIB
    private const string IfDescr = "1.3.6.1.2.1.2.2.1.2", IfType = "1.3.6.1.2.1.2.2.1.3",
        IfAdmin = "1.3.6.1.2.1.2.2.1.7", IfOper = "1.3.6.1.2.1.2.2.1.8",
        IfName = "1.3.6.1.2.1.31.1.1.1.1", IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15", IfAlias = "1.3.6.1.2.1.31.1.1.1.18";
    // BRIDGE-MIB / Q-BRIDGE-MIB
    private const string BasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2", Pvid = "1.3.6.1.2.1.17.7.1.4.5.1.1",
        CurEgress = "1.3.6.1.2.1.17.7.1.4.2.1.4", CurUntagged = "1.3.6.1.2.1.17.7.1.4.2.1.5",
        StaticEgress = "1.3.6.1.2.1.17.7.1.4.3.1.2", StaticUntagged = "1.3.6.1.2.1.17.7.1.4.3.1.4",
        FdbPort = "1.3.6.1.2.1.17.4.3.1.2";
    // Cisco (IOS doesn't fill Q-BRIDGE): access VLAN, trunk state, native VLAN, allowed VLANs
    private const string CiscoVmVlan = "1.3.6.1.4.1.9.9.68.1.2.2.1.2", CiscoTrunkState = "1.3.6.1.4.1.9.9.46.1.6.1.1.14",
        CiscoNative = "1.3.6.1.4.1.9.9.46.1.6.1.1.5", CiscoAllowed = "1.3.6.1.4.1.9.9.46.1.6.1.1.4";

    private static readonly Regex NotPhysical = new(@"^(vlan|vl\d|port-?channel|po\d|lag|ae\d|bond|trk|cpu|lo|loopback|null|nu\d|tunnel|tu\d|mgmt|management|me\d|oob|stack|bridge|br\d|ip interface|vif|sup-|switch)", RegexOptions.IgnoreCase);
    private static readonly Regex UplinkName = new(@"^(te|tw|twe|fo|hu|xe|xg|et-|sfp|ten|forty|hundred|twentyfive|fiftygig|tengig|qsfp)", RegexOptions.IgnoreCase);

    /// <summary>Reads every physical port from the switch over SNMPv2c.</summary>
    public static async Task<SwitchFaceplate> ReadAsync(IPAddress ip, string community, Neighbor? local, string? localMac, IProgress<string>? progress, CancellationToken ct, int port = 161)
    {
        using var snmp = new SnmpClient(ip, community, port: port);
        progress?.Report("Contacting switch...");
        SnmpValue? sysName;
        try { sysName = await snmp.GetAsync("1.3.6.1.2.1.1.5.0", ct); }
        catch (TimeoutException)
        {
            throw new InvalidOperationException($"No SNMP reply from {ip}. Check the community string, that SNMP v2c is on, and that the switch allows SNMP from this PC.");
        }
        var sysDescr = await snmp.GetAsync("1.3.6.1.2.1.1.1.0", ct);

        progress?.Report("Reading interfaces...");
        var descr = await snmp.WalkAsync(IfDescr, ct);
        var type = await snmp.WalkAsync(IfType, ct);
        var admin = await snmp.WalkAsync(IfAdmin, ct);
        var oper = await snmp.WalkAsync(IfOper, ct);
        var name = await snmp.WalkAsync(IfName, ct);
        var speed = await snmp.WalkAsync(IfHighSpeed, ct);
        var alias = await snmp.WalkAsync(IfAlias, ct);

        var ports = new Dictionary<int, SwitchPort>();
        foreach (var (idx, d) in descr)
        {
            if (!int.TryParse(idx, out var i)) continue;
            int t = type.TryGetValue(idx, out var tv) ? (int)tv.AsLong() : 6;
            if (t is not (6 or 62 or 69 or 117)) continue;                         // ethernet types only
            var p = new SwitchPort
            {
                IfIndex = i,
                Descr = d.AsString(),
                Name = name.TryGetValue(idx, out var nv) ? nv.AsString() : "",
                Alias = alias.TryGetValue(idx, out var av) ? av.AsString() : "",
                SpeedMbps = speed.TryGetValue(idx, out var sv) ? sv.AsLong() : 0,
            };
            if (NotPhysical.IsMatch(p.Label) || NotPhysical.IsMatch(p.Descr)) continue;
            long a = admin.TryGetValue(idx, out var adv) ? adv.AsLong() : 1, o = oper.TryGetValue(idx, out var ov) ? ov.AsLong() : 0;
            p.Link = a == 2 ? PortLink.Disabled : o == 1 ? PortLink.Up : PortLink.Down;
            if (p.Link != PortLink.Up) p.SpeedMbps = 0;   // ifHighSpeed of a down port is the max speed, not a link speed
            ports[i] = p;
        }
        if (ports.Count == 0) throw new InvalidOperationException("The switch answered SNMP but listed no Ethernet ports.");

        progress?.Report("Reading VLANs...");
        var bridgeToIf = new Dictionary<int, int>();
        foreach (var (k, v) in await snmp.WalkAsync(BasePortIfIndex, ct))
            if (int.TryParse(k, out var bp)) bridgeToIf[bp] = (int)v.AsLong();
        int IfOf(int bridgePort) => bridgeToIf.TryGetValue(bridgePort, out var i) ? i : bridgePort;

        foreach (var (k, v) in await snmp.WalkAsync(Pvid, ct))
            if (int.TryParse(k, out var bp) && ports.TryGetValue(IfOf(bp), out var p)) p.Pvid = (int)v.AsLong();

        // per-VLAN port bitmaps: current (includes dynamic) first, static config as fallback
        var egress = await snmp.WalkAsync(CurEgress, ct);
        var untagged = await snmp.WalkAsync(CurUntagged, ct);
        if (egress.Count == 0)
        {
            egress = await snmp.WalkAsync(StaticEgress, ct);
            untagged = await snmp.WalkAsync(StaticUntagged, ct);
        }
        foreach (var (k, eg) in egress)
        {
            if (!int.TryParse(k.Split('.')[^1], out var vlan)) continue;           // current table index is TimeMark.VlanIndex
            untagged.TryGetValue(k, out var ut);
            var egSet = Bits(eg.Raw);
            var utSet = ut.Raw == null ? new HashSet<int>() : Bits(ut.Raw);
            foreach (var bp in egSet)
            {
                if (!ports.TryGetValue(IfOf(bp), out var p)) continue;
                if (utSet.Contains(bp)) p.Pvid ??= vlan;
                else if (!p.Tagged.Contains(vlan)) p.Tagged.Add(vlan);
            }
        }

        bool anyVlan = ports.Values.Any(p => p.Pvid != null || p.Tagged.Count > 0);
        var src = "SNMP (IF-MIB, Q-BRIDGE-MIB)";
        if (!anyVlan || (sysDescr?.AsString() ?? "").Contains("Cisco", StringComparison.OrdinalIgnoreCase))
        {
            var vm = await snmp.WalkAsync(CiscoVmVlan, ct);
            var trunk = await snmp.WalkAsync(CiscoTrunkState, ct);
            if (vm.Count > 0 || trunk.Count > 0)
            {
                src = "SNMP (IF-MIB, Cisco VLAN MIBs)";
                var native = await snmp.WalkAsync(CiscoNative, ct);
                var allowed = await snmp.WalkAsync(CiscoAllowed, ct);
                foreach (var (k, v) in vm)
                    if (int.TryParse(k, out var i) && ports.TryGetValue(i, out var p)) { p.Pvid = (int)v.AsLong(); p.Tagged.Clear(); }
                foreach (var (k, v) in trunk)
                {
                    if (v.AsLong() != 1 || !int.TryParse(k, out var i) || !ports.TryGetValue(i, out var p)) continue;
                    if (native.TryGetValue(k, out var nv)) p.Pvid = (int)nv.AsLong();
                    p.Tagged = allowed.TryGetValue(k, out var al)
                        ? Bits(al.Raw).Select(b => b - 1).Where(x => x >= 1 && x != p.Pvid).ToList()   // bit 0 = VLAN 0
                        : new List<int>();
                }
            }
        }
        foreach (var p in ports.Values) p.Tagged.Sort();

        var list = ports.Values.ToList();
        Arrange(list);
        var fp = new SwitchFaceplate
        {
            Title = (sysName?.AsString() is { Length: > 0 } sn ? sn : ip.ToString()) + "   " + ShortModel(sysDescr?.AsString()),
            Source = $"{list.Count} ports read from {ip} over {src}.",
            Ports = list
        };

        // which port is this PC on: LLDP/CDP port name first, then the switch's MAC table
        if (local != null && MatchLocal(list, local) is { } lp) lp.IsLocal = true;
        else if (localMac != null && MacBytes(localMac) is { } mb)
        {
            try
            {
                var fdb = await snmp.GetAsync(FdbPort + "." + string.Join(".", mb), ct);
                if (fdb != null && ports.TryGetValue(IfOf((int)fdb.Value.AsLong()), out var p)) p.IsLocal = true;
            }
            catch (TimeoutException) { }
        }
        return fp;
    }

    /// <summary>Faceplate drawn from LLDP/CDP alone: a stock 8/24/48-port layout where only this PC's port is known.</summary>
    public static SwitchFaceplate FromNeighbor(Neighbor n, long localSpeedBps)
    {
        var port = n.Get("Port ID") ?? "";
        if (Regex.IsMatch(port, @"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", RegexOptions.IgnoreCase)) port = n.Get("Port Description") ?? port;
        var nums = Numbers(port);
        int number = nums.Count > 0 ? nums[^1] : 0;
        bool uplink = IsUplinkName(port, nums);
        int copper = number > 24 && !uplink ? 48 : number > 8 || uplink || number == 0 ? 24 : 8;
        int sfp = copper == 8 ? 2 : 4;

        var ports = new List<SwitchPort>();
        for (int i = 1; i <= copper; i++) ports.Add(new SwitchPort { Number = i, Name = $"Port {i}" });
        for (int i = 1; i <= sfp; i++) ports.Add(new SwitchPort { Number = i, Name = $"Uplink {i}", IsUplink = true });

        var me = ports.FirstOrDefault(p => p.IsUplink == uplink && p.Number == (uplink && number > sfp ? 1 : number));
        if (me != null)
        {
            me.Name = port;
            me.Alias = n.Get("Port Description") is { } pd && pd != port ? pd : "";
            me.IsLocal = true;
            me.Link = PortLink.Up;
            me.SpeedMbps = localSpeedBps / 1_000_000;
            if (int.TryParse(n.Vlan, out var v)) me.Pvid = v;
            // a tagged voice VLAN is the only tagged VLAN LLDP-MED / CDP tells us about
            if (n.VoiceVlan is { } vv && Regex.Match(vv, @"^\d+") is { Success: true } m && !vv.Contains("untagged"))
                me.Tagged.Add(int.Parse(m.Value));
        }
        return new SwitchFaceplate
        {
            Title = n.SwitchName + (n.Get("Platform") is { } pl ? "   " + pl : ""),
            Source = me == null
                ? $"Generic layout. Couldn't place port \"{port}\"; add the SNMP community to read every port."
                : $"Generic layout from {n.Protocol}: only this PC's port is known. Add the SNMP community to read every port, VLAN and link.",
            Generic = true,
            Ports = ports
        };
    }

    // ------------------------------------------------------------------ helpers

    private static List<int> Numbers(string s) => Regex.Matches(s, @"\d+").Select(m => int.Parse(m.Value)).ToList();

    private static bool IsUplinkName(string name, List<int> nums) =>
        UplinkName.IsMatch(name) || name.Contains("SFP", StringComparison.OrdinalIgnoreCase) ||
        (nums.Count == 3 && nums[1] != 0 && Regex.IsMatch(name, @"^(gi|ge|gigabit)", RegexOptions.IgnoreCase));   // Cisco Gi1/1/x module

    /// <summary>Sets Unit, Number and IsUplink from the port names and sorts ports into faceplate order.</summary>
    private static void Arrange(List<SwitchPort> ports)
    {
        var speeds = ports.Select(p => p.SpeedMbps).Where(s => s > 0).DefaultIfEmpty(1000).OrderBy(s => s).ToList();
        long typical = speeds[speeds.Count / 2];
        foreach (var p in ports)
        {
            var nums = Numbers(p.Label);
            p.Number = nums.Count > 0 ? nums[^1] : p.IfIndex;
            p.Unit = nums.Count >= 2 ? nums[0].ToString() : "";
            p.IsUplink = IsUplinkName(p.Label, nums) || IsUplinkName(p.Descr, Numbers(p.Descr)) ||
                         p.Descr.Contains("fiber", StringComparison.OrdinalIgnoreCase);
        }
        // switches that number every port 1..N: the last few faster ports are the uplinks
        if (!ports.Any(p => p.IsUplink) && ports.Count > 8 && typical <= 1000)
            foreach (var p in ports.Where(p => p.SpeedMbps >= 10000)) p.IsUplink = true;

        ports.Sort((a, b) =>
        {
            int c = string.CompareOrdinal(a.Unit.PadLeft(4), b.Unit.PadLeft(4));
            if (c != 0) return c;
            c = a.IsUplink.CompareTo(b.IsUplink);
            if (c != 0) return c;
            var na = Numbers(a.Label); var nb = Numbers(b.Label);
            for (int i = 0; i < Math.Min(na.Count, nb.Count); i++) if (na[i] != nb[i]) return na[i].CompareTo(nb[i]);
            return a.IfIndex.CompareTo(b.IfIndex);
        });
    }

    private static SwitchPort? MatchLocal(List<SwitchPort> ports, Neighbor n)
    {
        var ids = new[] { n.Get("Port ID"), n.Get("Port Description") }.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!.Trim()).ToList();
        foreach (var id in ids)
        {
            var hit = ports.FirstOrDefault(p => id.Equals(p.Name, StringComparison.OrdinalIgnoreCase) ||
                                                id.Equals(p.Descr, StringComparison.OrdinalIgnoreCase) ||
                                                id.Equals(p.Alias, StringComparison.OrdinalIgnoreCase));
            if (hit != null) return hit;
        }
        // "GigabitEthernet1/0/14" vs "Gi1/0/14": same first two letters and the same number path
        string Key(string s) => (Regex.Match(s, @"^[A-Za-z]{0,2}").Value.ToLowerInvariant()) + string.Join("/", Numbers(s));
        foreach (var id in ids)
        {
            var k = Key(id);
            var hit = ports.FirstOrDefault(p => Key(p.Label) == k || Key(p.Descr) == k);
            if (hit != null) return hit;
            if (int.TryParse(id, out var num))
            {
                hit = ports.FirstOrDefault(p => p.IfIndex == num) ?? (ports.Select(p => p.Unit).Distinct().Count() == 1 ? ports.FirstOrDefault(p => p.Number == num && !p.IsUplink) : null);
                if (hit != null) return hit;
            }
        }
        return null;
    }

    private static int[]? MacBytes(string mac)
    {
        var hex = Regex.Replace(mac, "[^0-9A-Fa-f]", "");
        return hex.Length == 12 ? Enumerable.Range(0, 6).Select(i => Convert.ToInt32(hex.Substring(i * 2, 2), 16)).ToArray() : null;
    }

    /// <summary>Port bitmap (first byte's high bit = port 1) to a set of port numbers.</summary>
    private static HashSet<int> Bits(byte[] raw)
    {
        var set = new HashSet<int>();
        for (int i = 0; i < raw.Length; i++)
            for (int j = 0; j < 8; j++)
                if ((raw[i] & (0x80 >> j)) != 0) set.Add(i * 8 + j + 1);
        return set;
    }

    private static string ShortModel(string? sysDescr)
    {
        if (string.IsNullOrWhiteSpace(sysDescr)) return "";
        var s = Regex.Replace(sysDescr, @"\s+", " ").Trim();
        var first = s.Split(new[] { ',', ';' }, 2)[0];
        return first.Length > 60 ? first[..60] + "..." : first;
    }

    /// <summary>"10,20,21,22,30" -> "10, 20-22, 30"</summary>
    public static string Ranges(IEnumerable<int> values)
    {
        var v = values.Distinct().OrderBy(x => x).ToList();
        var parts = new List<string>();
        for (int i = 0; i < v.Count;)
        {
            int j = i;
            while (j + 1 < v.Count && v[j + 1] == v[j] + 1) j++;
            parts.Add(j == i ? v[i].ToString() : $"{v[i]}-{v[j]}");
            i = j + 1;
        }
        return string.Join(", ", parts);
    }
}
