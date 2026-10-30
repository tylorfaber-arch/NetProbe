using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NetProbe.Services;

public static class AdapterInfo
{
    private static readonly Regex VirtualRx = new("Hyper-V|Virtual|TAP-|VPN|Miniport|Bluetooth|Loopback|WAN |vEthernet|AnyConnect|Wintun|WireGuard|VMware|VirtualBox", RegexOptions.IgnoreCase);

    public static bool IsVirtual(NetworkInterface n) => VirtualRx.IsMatch(n.Description) || VirtualRx.IsMatch(n.Name);

    public static bool IsWireless(NetworkInterface n) => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;

    public static bool IsWired(NetworkInterface n) =>
        !IsVirtual(n) && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.Ethernet3Megabit;

    /// <summary>Adapters worth showing, best candidates first (wired physical, then Wi-Fi, then virtual).</summary>
    public static List<NetworkInterface> List() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
            .OrderBy(n => IsWired(n) ? 0 : IsWireless(n) && !IsVirtual(n) ? 1 : 2)
            .ThenBy(n => n.OperationalStatus == OperationalStatus.Up ? 0 : 1)
            .ThenBy(n => n.Name)
            .ToList();

    public static NetworkInterface? Find(string id) => NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == id);

    public static string MaskOf(int prefix)
    {
        uint m = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        return new IPAddress(BitConverter.GetBytes(m).Reverse().ToArray()).ToString();
    }

    public static AdapterSnapshot Read(string id, bool resolveGatewayMac = true)
    {
        var n = Find(id) ?? throw new InvalidOperationException("Adapter not found");
        var s = new AdapterSnapshot
        {
            Id = n.Id, Name = n.Name, Description = n.Description,
            Mac = string.Join("-", n.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2"))),
            IsUp = n.OperationalStatus == OperationalStatus.Up,
            IsWireless = IsWireless(n),
            SpeedBps = n.Speed
        };
        var rows = s.Rows;
        rows.Add(new("Adapter", $"{n.Name}  ({n.Description})"));
        rows.Add(new("Link", s.IsUp ? "Up" : n.OperationalStatus.ToString(), s.IsUp ? Sev.Pass : Sev.Fail));
        if (s.IsUp) rows.Add(new("Link speed", s.SpeedText));
        rows.Add(new("MAC address", s.Mac));

        if (s.IsWireless && s.IsUp)
        {
            s.Wifi = ReadWifi(n.Name);
            rows.AddRange(s.Wifi);
        }

        // Windows keeps stale IP/gateway/DNS on a down adapter - don't show it
        if (!s.IsUp) return s;

        var props = n.GetIPProperties();
        try
        {
            var v4 = props.GetIPv4Properties();
            s.Mtu = v4.Mtu;
            s.DhcpEnabled = v4.IsDhcpEnabled;
        }
        catch { }
        if (s.Mtu > 0) rows.Add(new("MTU", s.Mtu.ToString()));

        foreach (var ua in props.UnicastAddresses)
        {
            if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                var ip = ua.Address.ToString();
                s.IPv4.Add($"{ip}/{ua.PrefixLength}");
                rows.Add(new("IPv4 address", $"{ip}/{ua.PrefixLength}    mask {MaskOf(ua.PrefixLength)}    ({ua.PrefixOrigin})"));
                if (ip.StartsWith("169.254."))
                {
                    s.Apipa = true;
                    rows.Add(new("WARNING", "Self-assigned 169.254.x.x address - no DHCP reply received", Sev.Fail));
                }
                if (ua.PrefixOrigin == PrefixOrigin.Dhcp)
                {
                    try { s.LeaseRemaining = TimeSpan.FromSeconds(ua.DhcpLeaseLifetime); } catch { }
                }
            }
            else if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                s.IPv6.Add($"{ua.Address}/{ua.PrefixLength}");
            }
        }

        s.Gateway = props.GatewayAddresses.Select(g => g.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))?.ToString();
        if (s.Gateway != null)
        {
            if (resolveGatewayMac) s.GatewayMac = Native.ArpLookup(IPAddress.Parse(s.Gateway));
            rows.Add(new("Default gateway", s.Gateway + (s.GatewayMac != null ? $"    (MAC {s.GatewayMac})" : "")));
        }
        else rows.Add(new("Default gateway", "none", Sev.Warn));

        if (s.DhcpEnabled)
        {
            s.DhcpServer = props.DhcpServerAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
            rows.Add(new("DHCP", "Enabled"));
            if (s.DhcpServer != null) rows.Add(new("DHCP server", s.DhcpServer));
            if (s.LeaseRemaining is { } lr && lr > TimeSpan.Zero)
                rows.Add(new("Lease expires", $"{DateTime.Now + lr:g}  (in {FormatSpan(lr)})"));
        }
        else rows.Add(new("DHCP", "Disabled (static IP)"));

        s.Dns = props.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToList();
        rows.Add(new("DNS servers", s.Dns.Count > 0 ? string.Join(", ", s.Dns) : "none", s.Dns.Count > 0 ? Sev.None : Sev.Warn));
        s.DnsSuffix = props.DnsSuffix;
        if (!string.IsNullOrEmpty(s.DnsSuffix)) rows.Add(new("DNS suffix", s.DnsSuffix));
        foreach (var v6 in s.IPv6) rows.Add(new("IPv6 address", v6));
        return s;
    }

    public static string FormatSpan(TimeSpan t) =>
        t.TotalDays >= 1 ? $"{(int)t.TotalDays}d {t.Hours}h" : t.TotalHours >= 1 ? $"{(int)t.TotalHours}h {t.Minutes}m" : $"{t.Minutes}m";

    private static List<KV> ReadWifi(string alias)
    {
        var list = new List<KV>();
        var want = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "SSID", "AP BSSID", "Band", "Channel", "Radio type", "Signal", "Rssi", "Receive rate (Mbps)", "Transmit rate (Mbps)", "Authentication" };
        try
        {
            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            bool mine = false;
            foreach (var line in text.Split('\n'))
            {
                var m = Regex.Match(line, @"^\s*(.+?)\s+:\s(.*)$");
                if (!m.Success) continue;
                var k = m.Groups[1].Value.Trim();
                var v = m.Groups[2].Value.Trim();
                if (k == "Name") mine = v == alias;
                else if (mine && want.Contains(k)) list.Add(new("Wi-Fi " + k, v));
            }
        }
        catch { }
        return list;
    }

    /// <summary>Network address in CIDR form, e.g. 192.168.1.0/24.</summary>
    public static string NetworkCidr(string cidr)
    {
        var parts = cidr.Split('/');
        int p = int.Parse(parts[1]);
        uint ip = ToUInt(IPAddress.Parse(parts[0]));
        uint mask = p == 0 ? 0 : uint.MaxValue << (32 - p);
        return $"{FromUInt(ip & mask)}/{p}";
    }

    public static uint ToUInt(IPAddress a) { var b = a.GetAddressBytes(); return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]); }
    public static IPAddress FromUInt(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
}
