using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetProbe.Services;

/// <summary>One value from an SNMP response: its BER type tag and raw content bytes.</summary>
public readonly record struct SnmpValue(byte Type, byte[] Raw)
{
    public bool IsError => Type is 0x80 or 0x81 or 0x82 or 0x05;

    public long AsLong()
    {
        if (Raw.Length == 0) return 0;
        long v = Type == 0x02 && (Raw[0] & 0x80) != 0 ? -1 : 0;   // INTEGER is signed, counters/gauges are not
        foreach (var b in Raw) v = v << 8 | b;
        return v;
    }

    public string AsString()
    {
        if (Type == 0x40 && Raw.Length == 4) return new IPAddress(Raw).ToString();
        if (Type != 0x04) return AsLong().ToString();
        return Encoding.UTF8.GetString(Raw).Trim('\0', ' ', '\r', '\n');
    }
}

/// <summary>
/// Minimal read-only SNMPv2c client (GET and GETBULK walks over UDP 161). Enough to read IF-MIB,
/// BRIDGE-MIB and Q-BRIDGE-MIB tables from a switch without any extra package.
/// </summary>
public sealed class SnmpClient : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint _ep;
    private readonly byte[] _community;
    private readonly int _timeoutMs;
    private int _reqId = Random.Shared.Next(1, int.MaxValue / 2);

    public SnmpClient(IPAddress ip, string community, int timeoutMs = 2000, int port = 161)
    {
        _ep = new IPEndPoint(ip, port);
        _community = Encoding.ASCII.GetBytes(community);
        _timeoutMs = timeoutMs;
        _udp = new UdpClient(ip.AddressFamily);
    }

    public void Dispose() => _udp.Dispose();

    /// <summary>GET one OID. Null when the agent has no such object.</summary>
    public async Task<SnmpValue?> GetAsync(string oid, CancellationToken ct)
    {
        var r = await RequestAsync(0xA0, new[] { oid }, 0, ct);
        return r.Count > 0 && !r[0].Value.IsError ? r[0].Value : null;
    }

    /// <summary>Walks a table column/subtree. Keys are the index suffix after <paramref name="root"/> ("12" or "1.4.10").</summary>
    public async Task<Dictionary<string, SnmpValue>> WalkAsync(string root, CancellationToken ct, int maxRows = 20000)
    {
        var result = new Dictionary<string, SnmpValue>();
        var prefix = root + ".";
        var cur = root;
        while (result.Count < maxRows)
        {
            var batch = await RequestAsync(0xA5, new[] { cur }, 30, ct);
            if (batch.Count == 0) break;
            bool done = false;
            foreach (var (oid, val) in batch)
            {
                if (val.Type == 0x82 || !oid.StartsWith(prefix, StringComparison.Ordinal)) { done = true; break; }
                if (oid == cur) { done = true; break; }     // agent not advancing: stop rather than loop
                result[oid[prefix.Length..]] = val;
                cur = oid;
            }
            if (done) break;
        }
        return result;
    }

    private async Task<List<(string Oid, SnmpValue Value)>> RequestAsync(byte pduType, string[] oids, int maxRep, CancellationToken ct)
    {
        int id = Interlocked.Increment(ref _reqId);
        var vbl = new List<byte>();
        foreach (var o in oids) vbl.AddRange(Tlv(0x30, Concat(Tlv(0x06, EncodeOid(o)), new byte[] { 0x05, 0x00 })));
        // GET: request-id, error-status 0, error-index 0. GETBULK reuses those slots for non-repeaters (0) and max-repetitions.
        var pdu = Tlv(pduType, Concat(Int(id), Int(0), Int(pduType == 0xA5 ? maxRep : 0), Tlv(0x30, vbl.ToArray())));
        var msg = Tlv(0x30, Concat(Int(1), Tlv(0x04, _community), pdu));

        for (int attempt = 0; attempt < 2; attempt++)
        {
            await _udp.SendAsync(msg, _ep, ct);
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(_timeoutMs);
            try
            {
                while (true)
                {
                    var res = await _udp.ReceiveAsync(to.Token);
                    var parsed = Parse(res.Buffer, id);
                    if (parsed != null) return parsed;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        }
        throw new TimeoutException($"No SNMP reply from {_ep.Address}.");
    }

    // ------------------------------------------------------------------ BER

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static byte[] Tlv(byte tag, byte[] content)
    {
        var len = content.Length;
        byte[] l = len < 0x80 ? new[] { (byte)len }
            : len < 0x100 ? new byte[] { 0x81, (byte)len }
            : new byte[] { 0x82, (byte)(len >> 8), (byte)len };
        return Concat(new[] { tag }, l, content);
    }

    private static byte[] Int(long v)
    {
        var bytes = new List<byte>();
        do { bytes.Insert(0, (byte)v); v >>= 8; } while (v != 0 && v != -1);
        if (v == 0 && (bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
        return Tlv(0x02, bytes.ToArray());
    }

    private static byte[] EncodeOid(string oid)
    {
        var p = oid.Split('.').Select(uint.Parse).ToArray();
        var b = new List<byte> { (byte)(p[0] * 40 + p[1]) };
        foreach (var n in p.Skip(2))
        {
            var chunk = new Stack<byte>();
            uint x = n;
            chunk.Push((byte)(x & 0x7F));
            while ((x >>= 7) > 0) chunk.Push((byte)(0x80 | (x & 0x7F)));
            b.AddRange(chunk);
        }
        return b.ToArray();
    }

    private static string DecodeOid(byte[] b, int o, int len)
    {
        var sb = new StringBuilder();
        sb.Append(b[o] / 40).Append('.').Append(b[o] % 40);
        ulong v = 0;
        for (int i = o + 1; i < o + len; i++)
        {
            v = v << 7 | (uint)(b[i] & 0x7F);
            if ((b[i] & 0x80) == 0) { sb.Append('.').Append(v); v = 0; }
        }
        return sb.ToString();
    }

    private static (byte Tag, int Start, int Len) Read(byte[] b, ref int o)
    {
        byte tag = b[o++];
        int len = b[o++];
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) len = len << 8 | b[o++];
        }
        if (o + len > b.Length) throw new FormatException("truncated SNMP packet");
        var start = o;
        o += len;
        return (tag, start, len);
    }

    private static List<(string, SnmpValue)>? Parse(byte[] b, int expectId)
    {
        try
        {
            int o = 0;
            var msg = Read(b, ref o);
            o = msg.Start;
            Read(b, ref o);                    // version
            Read(b, ref o);                    // community
            var pdu = Read(b, ref o);
            if (pdu.Tag != 0xA2) return null;
            o = pdu.Start;
            var rid = Read(b, ref o);
            if (new SnmpValue(0x02, b[rid.Start..(rid.Start + rid.Len)]).AsLong() != expectId) return null;
            var err = Read(b, ref o);
            Read(b, ref o);
            if (new SnmpValue(0x02, b[err.Start..(err.Start + err.Len)]).AsLong() != 0) return new();
            var list = Read(b, ref o);
            var res = new List<(string, SnmpValue)>();
            int p = list.Start, end = list.Start + list.Len;
            while (p < end)
            {
                var vb = Read(b, ref p);
                int q = vb.Start;
                var oid = Read(b, ref q);
                var val = Read(b, ref q);
                res.Add((DecodeOid(b, oid.Start, oid.Len), new SnmpValue(val.Tag, b[val.Start..(val.Start + val.Len)])));
            }
            return res;
        }
        catch { return null; }
    }
}
