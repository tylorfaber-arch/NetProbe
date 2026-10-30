using System.Net;
using System.Runtime.InteropServices;

namespace NetProbe.Services;

/// <summary>Win32 helpers: ARP lookups and full DNS record queries (MX/TXT/NS/PTR, specific server).</summary>
public static class Native
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physAddrLen);

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    private static extern void DnsRecordListFree(IntPtr list, int freeType);

    public static string? ArpLookup(IPAddress ip)
    {
        var mac = new byte[6];
        int len = mac.Length;
        uint dest = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
        if (SendARP(dest, 0, mac, ref len) != 0 || len < 6) return null;
        if (mac.All(b => b == 0)) return null;
        return string.Join("-", mac.Take(len).Select(b => b.ToString("X2")));
    }

    public static readonly Dictionary<string, ushort> DnsTypes = new()
    {
        ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["PTR"] = 12, ["MX"] = 15, ["TXT"] = 16, ["AAAA"] = 28
    };

    public sealed record DnsRecord(string Type, string Name, string Value, uint Ttl);

    /// <summary>Query DNS. server = null uses the system resolvers. Throws on failure.</summary>
    public static List<DnsRecord> Query(string name, string type, IPAddress? server = null, bool bypassCache = true)
    {
        ushort qtype = DnsTypes[type];
        IntPtr extra = IntPtr.Zero;
        try
        {
            if (server != null)
            {
                // IP4_ARRAY { DWORD AddrCount; IP4_ADDRESS AddrArray[1]; }
                extra = Marshal.AllocHGlobal(8);
                Marshal.WriteInt32(extra, 0, 1);
                Marshal.WriteInt32(extra, 4, BitConverter.ToInt32(server.GetAddressBytes(), 0));
            }
            uint opts = bypassCache ? 0x8u : 0u; // DNS_QUERY_BYPASS_CACHE
            int rc = DnsQuery(name, qtype, opts, extra, out var list, IntPtr.Zero);
            if (rc != 0) throw new InvalidOperationException(DnsError(rc));
            var result = new List<DnsRecord>();
            try
            {
                // DNS_RECORD (x64): pNext 0, pName 8, wType 16, wDataLength 18, Flags 20, dwTtl 24, reserved 28, Data 32
                for (var p = list; p != IntPtr.Zero; p = Marshal.ReadIntPtr(p, 0))
                {
                    int flags = Marshal.ReadInt32(p, 20);
                    if ((flags & 0x3) != 1) continue; // answer section only
                    var rname = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 8)) ?? "";
                    ushort t = (ushort)Marshal.ReadInt16(p, 16);
                    uint ttl = (uint)Marshal.ReadInt32(p, 24);
                    string? tname = DnsTypes.FirstOrDefault(kv => kv.Value == t).Key;
                    string? val = t switch
                    {
                        1 => new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(p, 32))).ToString(),
                        28 => new IPAddress(ReadBytes(p + 32, 16)).ToString(),
                        2 or 5 or 12 => Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 32)),
                        15 => $"{(ushort)Marshal.ReadInt16(p, 40)} {Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 32))}",
                        16 => ReadTxt(p),
                        _ => null
                    };
                    if (tname != null && val != null) result.Add(new DnsRecord(tname, rname, val, ttl));
                }
            }
            finally { DnsRecordListFree(list, 1); }
            return result;
        }
        finally { if (extra != IntPtr.Zero) Marshal.FreeHGlobal(extra); }
    }

    private static string ReadTxt(IntPtr p)
    {
        int count = Marshal.ReadInt32(p, 32);
        var parts = new List<string>();
        for (int i = 0; i < count; i++) parts.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 40 + i * IntPtr.Size)) ?? "");
        return string.Join(" ", parts);
    }

    private static byte[] ReadBytes(IntPtr p, int n)
    {
        var b = new byte[n];
        Marshal.Copy(p, b, 0, n);
        return b;
    }

    private static string DnsError(int rc) => rc switch
    {
        9003 => "Name does not exist (NXDOMAIN)",
        9501 => "No records of that type",
        1460 => "Timed out",
        9002 => "Server failure",
        9005 => "Query refused",
        _ => $"DNS error {rc}"
    };

    public static string ReverseName(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return $"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa";
    }
}
