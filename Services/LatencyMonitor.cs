using System.Net.NetworkInformation;

namespace NetProbe.Services;

/// <summary>Background 1-per-second ping of two targets (gateway + internet) for the live graphs.</summary>
public sealed class LatencyMonitor
{
    public const int Capacity = 180;

    public sealed class Series
    {
        public string Target = "";
        public readonly List<double?> Samples = new(); // null = timeout
        public void Push(double? v) { lock (Samples) { Samples.Add(v); if (Samples.Count > Capacity) Samples.RemoveAt(0); } }
        public double?[] Snapshot() { lock (Samples) return Samples.ToArray(); }
        public void Clear() { lock (Samples) Samples.Clear(); }

        public string Stats()
        {
            var s = Snapshot();
            if (s.Length == 0) return "no data yet";
            var ok = s.Where(x => x.HasValue).Select(x => x!.Value).ToArray();
            var loss = 100.0 * (s.Length - ok.Length) / s.Length;
            if (ok.Length == 0) return $"100% loss ({s.Length} sent)";
            double jitter = ok.Length > 1 ? ok.Zip(ok.Skip(1), (a, b) => Math.Abs(a - b)).Average() : 0;
            return $"last {ok[^1]:0.#} ms   avg {ok.Average():0.#}   min {ok.Min():0.#}   max {ok.Max():0.#}   jitter {jitter:0.#}   loss {loss:0.#}%";
        }
    }

    public Series Gateway { get; } = new();
    public Series Internet { get; } = new() { Target = "1.1.1.1" };
    public event Action? Updated;

    private CancellationTokenSource? _cts;
    public bool Running => _cts != null;

    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _ = Task.Run(async () =>
        {
            using var p1 = new Ping();
            using var p2 = new Ping();
            while (!ct.IsCancellationRequested)
            {
                var t0 = DateTime.UtcNow;
                var a = Probe(p1, Gateway.Target);
                var b = Probe(p2, Internet.Target);
                var r = await Task.WhenAll(a, b);
                if (!string.IsNullOrEmpty(Gateway.Target)) Gateway.Push(r[0]);
                if (!string.IsNullOrEmpty(Internet.Target)) Internet.Push(r[1]);
                Updated?.Invoke();
                var wait = 1000 - (int)(DateTime.UtcNow - t0).TotalMilliseconds;
                if (wait > 0) try { await Task.Delay(wait, ct); } catch { }
            }
        }, ct);
    }

    public void Stop() { _cts?.Cancel(); _cts = null; }

    private static async Task<double?> Probe(Ping p, string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return null;
        try
        {
            var r = await p.SendPingAsync(target, 900);
            return r.Status == IPStatus.Success ? Math.Max(0.5, r.RoundtripTime) : null;
        }
        catch { return null; }
    }
}
