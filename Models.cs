namespace NetProbe;

public enum Sev { None, Pass, Warn, Fail, Info }

public sealed record KV(string Key, string Value, Sev Sev = Sev.None);

public sealed record TestResult(Sev Sev, string Name, string Detail)
{
    public string Badge => Sev switch { Sev.Pass => "PASS", Sev.Fail => "FAIL", Sev.Warn => "WARN", _ => "INFO" };
}

public sealed record ScanHost(string IP, string Mac, string Name, string Ping, uint Sort, string Note);

public sealed class Neighbor
{
    public string Protocol { get; set; } = "";
    public List<KeyValuePair<string, string>> Fields { get; } = new();

    public string? Get(string key) => Fields.FirstOrDefault(f => f.Key == key).Value;

    public void Add(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var i = Fields.FindIndex(f => f.Key == key);
        if (i < 0) Fields.Add(new(key, value));
        else if (!Fields[i].Value.Contains(value)) Fields[i] = new(key, Fields[i].Value + ", " + value);
    }

    public string Key => $"{Protocol}|{Get("Chassis ID")}|{Get("Switch Name")}|{Get("Port ID")}";

    public string SwitchName => Get("Switch Name") ?? Get("Chassis ID") ?? "?";
    public string Port => Get("Port ID") ?? Get("Port Description") ?? "?";
    public string? Vlan => Get("VLAN (native/untagged)");
    public string? VoiceVlan => Get("Voice VLAN");
    public string? MgmtIp => Get("Management IP") ?? Get("IP address");
}

public sealed class AdapterSnapshot
{
    public string Id = "", Name = "", Description = "", Mac = "";
    public bool IsUp, IsWireless;
    public long SpeedBps;
    public List<string> IPv4 = new();      // "a.b.c.d/nn"
    public List<string> IPv6 = new();
    public string? Gateway, GatewayMac, DhcpServer, DnsSuffix;
    public List<string> Dns = new();
    public bool DhcpEnabled, Apipa;
    public TimeSpan? LeaseRemaining;
    public int Mtu;
    public List<KV> Wifi = new();
    public List<KV> Rows = new();

    public string SpeedText => FormatSpeed(SpeedBps);

    public static string FormatSpeed(long bps) => bps switch
    {
        <= 0 => "-",
        >= 1_000_000_000 => $"{bps / 1e9:0.#} Gbps",
        >= 1_000_000 => $"{bps / 1e6:0.#} Mbps",
        _ => $"{bps / 1e3:0} Kbps"
    };
}
