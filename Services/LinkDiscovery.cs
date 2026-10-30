using System.Diagnostics;
using System.Net;
using System.Text;

namespace NetProbe.Services;

/// <summary>
/// Switch port discovery: captures LLDP and Cisco CDP frames with Windows' built-in pktmon,
/// converts to pcapng and decodes the neighbor TLVs. Needs Administrator.
/// </summary>
public static class LinkDiscovery
{
    private static readonly string[] Macs = { "01-80-C2-00-00-0E", "01-80-C2-00-00-03", "01-80-C2-00-00-00", "01-00-0C-CC-CC-CC" };

    public static string WorkDir { get; } = Path.Combine(Path.GetTempPath(), "NetProbe");
    public static string LastCapture => Path.Combine(WorkDir, "lldp.pcapng");

    private static string PktMon => Path.Combine(Environment.SystemDirectory, "PktMon.exe");

    public static bool Available => File.Exists(PktMon);

    private static (int Code, string Output) Run(string args)
    {
        var psi = new ProcessStartInfo(PktMon, args)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
        };
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30000);
        return (p.ExitCode, o.Trim());
    }

    /// <summary>
    /// Listen for up to <paramref name="seconds"/>. The capture is checked every few seconds and returns as soon as
    /// a neighbor is heard. Cancelling <paramref name="stopEarly"/> ends listening early but still decodes.
    /// progress receives remaining seconds.
    /// </summary>
    public static Task<List<Neighbor>> CaptureAsync(int seconds, IProgress<int>? progress, CancellationToken stopEarly) => Task.Run(async () =>
    {
        if (!Available) throw new InvalidOperationException("pktmon.exe not found (needs Windows 10 version 2004 or newer).");
        Directory.CreateDirectory(WorkDir);
        File.Delete(LastCapture);
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        var found = new List<Neighbor>();
        var seen = new HashSet<string>();

        Run("stop");
        Run("filter remove");
        for (int i = 0; i < Macs.Length; i++) Run($"filter add NP{i} -m {Macs[i]}");
        try
        {
            // pktmon can't be read while running, so capture in short segments and decode each one
            for (int seg = 0; ; seg++)
            {
                var etl = Path.Combine(WorkDir, $"lldp{seg % 2}.etl");
                File.Delete(etl);
                var start = Run($"start --capture --comp nics --pkt-size 0 --file-name \"{etl}\"");
                if (start.Code != 0) start = Run($"start --capture --pkt-size 0 --file-name \"{etl}\"");
                if (start.Code != 0) throw new InvalidOperationException("pktmon failed to start: " + start.Output);

                var segEnd = DateTime.UtcNow.AddSeconds(seg == 0 ? 6 : 8);
                if (segEnd > deadline) segEnd = deadline;
                while (DateTime.UtcNow < segEnd && !stopEarly.IsCancellationRequested)
                {
                    progress?.Report(Math.Max(1, (int)Math.Ceiling((deadline - DateTime.UtcNow).TotalSeconds)));
                    try { await Task.Delay(500, stopEarly); } catch (OperationCanceledException) { }
                }
                Run("stop");

                var pcap = Path.Combine(WorkDir, "segment.pcapng");
                File.Delete(pcap);
                Run($"etl2pcap \"{etl}\" --out \"{pcap}\"");
                if (File.Exists(pcap))
                {
                    var got = ParseCapture(pcap);
                    if (got.Count > 0 || !File.Exists(LastCapture)) File.Copy(pcap, LastCapture, true);
                    foreach (var n in got) if (seen.Add(n.Key)) found.Add(n);
                }
                if (found.Count > 0 || DateTime.UtcNow >= deadline || stopEarly.IsCancellationRequested) break;
            }
        }
        finally
        {
            progress?.Report(0);
            Run("stop");
            Run("filter remove");
        }
        return found;
    });

    // ------------------------------------------------------------------ capture file parsing

    public static List<Neighbor> ParseCapture(string path)
    {
        var seen = new HashSet<string>();
        var list = new List<Neighbor>();
        foreach (var f in ReadFrames(path))
        {
            Neighbor? n = null;
            try { n = ParseFrame(f); } catch { }
            if (n != null && seen.Add(n.Key)) list.Add(n);
        }
        return list;
    }

    public static IEnumerable<byte[]> ReadFrames(string path)
    {
        var b = File.ReadAllBytes(path);
        if (b.Length < 24) yield break;
        uint magic = BitConverter.ToUInt32(b, 0);
        if (magic is 0xA1B2C3D4 or 0xA1B23C4D)
        {
            int o = 24;
            while (o + 16 <= b.Length)
            {
                int incl = (int)BitConverter.ToUInt32(b, o + 8);
                o += 16;
                if (incl < 0 || o + incl > b.Length) yield break;
                yield return b[o..(o + incl)];
                o += incl;
            }
        }
        else if (magic == 0x0A0D0D0A)
        {
            int o = 0;
            var linkTypes = new List<int>();
            while (o + 12 <= b.Length)
            {
                uint type = BitConverter.ToUInt32(b, o);
                int len = (int)BitConverter.ToUInt32(b, o + 4);
                if (len < 12 || o + len > b.Length) yield break;
                if (type == 0x0A0D0D0A) linkTypes.Clear();
                else if (type == 1) linkTypes.Add(BitConverter.ToUInt16(b, o + 8));
                else if (type == 6)
                {
                    int ifId = (int)BitConverter.ToUInt32(b, o + 8);
                    int cap = (int)BitConverter.ToUInt32(b, o + 20);
                    bool ethernet = ifId >= linkTypes.Count || linkTypes[ifId] == 1;
                    if (ethernet && cap > 0 && o + 28 + cap <= o + len) yield return b[(o + 28)..(o + 28 + cap)];
                }
                else if (type == 3)
                {
                    int cap = Math.Min((int)BitConverter.ToUInt32(b, o + 8), len - 16);
                    if (cap > 0) yield return b[(o + 12)..(o + 12 + cap)];
                }
                o += len;
            }
        }
    }

    private static int U16(byte[] f, int o) => f[o] << 8 | f[o + 1];
    private static string Mac(byte[] f, int o) => string.Join(":", f[o..(o + 6)].Select(x => x.ToString("x2")));
    private static string Str(byte[] f, int o, int l) => l <= 0 ? "" : Encoding.UTF8.GetString(f, o, l).Trim('\0', ' ', '\r', '\n');
    private static string Ip4(byte[] f, int o) => $"{f[o]}.{f[o + 1]}.{f[o + 2]}.{f[o + 3]}";

    public static Neighbor? ParseFrame(byte[] f)
    {
        if (f.Length < 22) return null;
        var src = Mac(f, 6);
        int o = 12, et = U16(f, o);
        while ((et == 0x8100 || et == 0x88A8) && o + 6 <= f.Length) { o += 4; et = U16(f, o); }
        if (et == 0x88CC) return ParseLldp(f, o + 2, src);
        if (et <= 1500 && f.Length >= o + 14 && f[o + 2] == 0xAA && f[o + 3] == 0xAA &&
            f[o + 5] == 0 && f[o + 6] == 0 && f[o + 7] == 0x0C && U16(f, o + 8) == 0x2000)
            return ParseCdp(f, o + 10, src);
        return null;
    }

    private static readonly Dictionary<int, string> MauTypes = new()
    {
        [10] = "10BASE-T HD", [11] = "10BASE-T FD", [15] = "100BASE-TX HD", [16] = "100BASE-TX FD",
        [29] = "1000BASE-T HD", [30] = "1000BASE-T FD", [54] = "2.5GBASE-T", [55] = "5GBASE-T", [110] = "10GBASE-T"
    };

    private static string LldpId(byte[] f, int v, int l, bool chassis)
    {
        int st = f[v];
        if ((chassis && st == 4 || !chassis && st == 3) && l >= 7) return Mac(f, v + 1);
        if ((chassis && st == 5 || !chassis && st == 4) && l >= 6 && f[v + 1] == 1) return Ip4(f, v + 2);
        return Str(f, v + 1, l - 1);
    }

    private static Neighbor ParseLldp(byte[] f, int o, string src)
    {
        var r = new Neighbor { Protocol = "LLDP" };
        while (o + 2 <= f.Length)
        {
            int hdr = U16(f, o), t = hdr >> 9, l = hdr & 0x1FF, v = o + 2;
            if (t == 0 || v + l > f.Length) break;
            switch (t)
            {
                case 1: r.Add("Chassis ID", LldpId(f, v, l, true)); break;
                case 2: r.Add("Port ID", LldpId(f, v, l, false)); break;
                case 4: r.Add("Port Description", Str(f, v, l)); break;
                case 5: r.Add("Switch Name", Str(f, v, l)); break;
                case 6: r.Add("System Description", System.Text.RegularExpressions.Regex.Replace(Str(f, v, l), @"\s+", " ")); break;
                case 7 when l >= 4:
                {
                    int en = U16(f, v + 2);
                    string[] names = { "Other", "Repeater", "Bridge", "WLAN AP", "Router", "Phone", "DOCSIS", "Station", "C-VLAN", "S-VLAN", "TPMR" };
                    r.Add("Capabilities", string.Join(", ", names.Where((_, i) => (en & (1 << i)) != 0)));
                    break;
                }
                case 8:
                {
                    int alen = f[v], st = f[v + 1];
                    if (st == 1 && alen == 5) r.Add("Management IP", Ip4(f, v + 2));
                    else if (st == 2 && alen == 17) r.Add("Management IPv6", new IPAddress(f[(v + 2)..(v + 18)]).ToString());
                    break;
                }
                case 127 when l >= 4:
                {
                    var oui = $"{f[v]:X2}{f[v + 1]:X2}{f[v + 2]:X2}";
                    int sub = f[v + 3], d = v + 4;
                    if (oui == "0080C2" && sub == 1 && l >= 6) r.Add("VLAN (native/untagged)", U16(f, d).ToString());
                    else if (oui == "0080C2" && sub == 3 && l >= 7) r.Add("VLAN names", $"{U16(f, d)}={Str(f, d + 3, f[d + 2])}");
                    else if (oui == "00120F" && sub == 1 && l >= 9)
                    {
                        int an = f[d], mau = U16(f, d + 3);
                        var mt = MauTypes.TryGetValue(mau, out var m) ? m : $"MAU type {mau}";
                        r.Add("Switch port speed", mt + ((an & 2) != 0 ? " (auto-neg on)" : " (auto-neg off)"));
                    }
                    else if (oui == "00120F" && sub == 2 && l >= 7)
                    {
                        int cap = f[d];
                        var p = (cap & 2) != 0 ? "PoE supported" : "PoE not supported";
                        if ((cap & 4) != 0) p += ", enabled";
                        if (l >= 12) p += $", requested {U16(f, d + 4) / 10.0} W, allocated {U16(f, d + 6) / 10.0} W";
                        r.Add("PoE", p);
                    }
                    else if (oui == "0012BB" && sub == 2 && l >= 8)
                    {
                        int app = f[d];
                        int val = f[d + 1] << 16 | f[d + 2] << 8 | f[d + 3];
                        int vid = (val >> 9) & 0xFFF;
                        var tagged = (val & 0x400000) != 0 ? "unknown policy" : (val & 0x200000) != 0 ? "tagged" : "untagged";
                        var name = app switch { 1 => "Voice VLAN", 2 => "Voice signaling VLAN", 5 => "Video VLAN", _ => $"Policy app {app} VLAN" };
                        r.Add(name, $"{vid} ({tagged})");
                    }
                    else if (oui == "0012BB" && sub is >= 5 and <= 7)
                        r.Add(sub == 5 ? "HW revision" : sub == 6 ? "FW revision" : "SW revision", Str(f, d, l - 4));
                    break;
                }
            }
            o = v + l;
        }
        r.Add("Source MAC", src);
        return r;
    }

    private static Neighbor ParseCdp(byte[] f, int o, string src)
    {
        var r = new Neighbor { Protocol = $"CDPv{f[o]}" };
        o += 4;
        while (o + 4 <= f.Length)
        {
            int t = U16(f, o), l = U16(f, o + 2), v = o + 4, dl = l - 4;
            if (l < 4 || o + l > f.Length) break;
            switch (t)
            {
                case 1: r.Add("Switch Name", Str(f, v, dl)); break;
                case 3: r.Add("Port ID", Str(f, v, dl)); break;
                case 5: r.Add("System Description", string.Join(" ", Str(f, v, dl).Split('\n').Take(2).Select(s => s.Trim()))); break;
                case 6: r.Add("Platform", Str(f, v, dl)); break;
                case 9: r.Add("VTP Domain", Str(f, v, dl)); break;
                case 10 when dl >= 2: r.Add("VLAN (native/untagged)", U16(f, v).ToString()); break;
                case 11 when dl >= 1: r.Add("Duplex", f[v] != 0 ? "Full" : "Half"); break;
                case 14 when dl >= 3: r.Add("Voice VLAN", U16(f, v + 1).ToString()); break;
                case 4 when dl >= 4:
                {
                    int c = f[v + 2] << 8 | f[v + 3];
                    string[] names = { "Router", "Trans-Bridge", "SR-Bridge", "Switch", "Host", "IGMP", "Repeater", "Phone" };
                    r.Add("Capabilities", string.Join(", ", names.Where((_, i) => (c & (1 << i)) != 0)));
                    break;
                }
                case 2 or 22 when dl >= 4:
                {
                    var key = t == 22 ? "Management IP" : "IP address";
                    int cnt = f[v + 2] << 8 | f[v + 3], p = v + 4;
                    for (int i = 0; i < cnt && p + 2 <= v + dl; i++)
                    {
                        int pl = f[p + 1];
                        p += 2 + pl;
                        int al = U16(f, p);
                        p += 2;
                        if (al == 4) r.Add(key, Ip4(f, p));
                        p += al;
                    }
                    break;
                }
            }
            o += l;
        }
        r.Add("Source MAC", src);
        return r;
    }

    /// <summary>Preferred display order for neighbor fields.</summary>
    public static readonly string[] FieldOrder =
    {
        "Switch Name", "Port ID", "Port Description", "VLAN (native/untagged)", "Voice VLAN", "Voice signaling VLAN", "VLAN names",
        "Management IP", "IP address", "Switch port speed", "Duplex", "PoE", "Platform", "Capabilities", "Chassis ID",
        "VTP Domain", "System Description", "Source MAC"
    };

    public static IEnumerable<KeyValuePair<string, string>> Ordered(Neighbor n) =>
        n.Fields.OrderBy(f => Array.IndexOf(FieldOrder, f.Key) is var i && i < 0 ? 999 : i);
}
