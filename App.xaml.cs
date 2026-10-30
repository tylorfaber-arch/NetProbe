using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using System.Windows;
using NetProbe.Services;

namespace NetProbe;

public partial class App : Application
{
    public static string Version { get; } = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "2.0.0";

    public static bool IsAdmin { get; } =
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static Settings Settings { get; } = Settings.Load();

    // Remote upload to the web portal: hidden until the portal is live. Set to true to show it again.
    public static bool RemoteUploadEnabled => false;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Self-test: NetProbe.exe --capture-test <outfile> <seconds>   (run elevated; writes decoded neighbors)
        if (e.Args.Length >= 3 && e.Args[0] == "--capture-test")
        {
            string result;
            try
            {
                var ns = LinkDiscovery.CaptureAsync(int.Parse(e.Args[2]), null, CancellationToken.None).GetAwaiter().GetResult();
                result = $"admin={IsAdmin} neighbors={ns.Count}\n" + string.Join("\n", ns.Select(n => string.Join(" | ", n.Fields.Select(f => $"{f.Key}={f.Value}"))));
                result += "\nfiles: " + string.Join(", ", Directory.GetFiles(LinkDiscovery.WorkDir).Select(f => $"{Path.GetFileName(f)} {new FileInfo(f).Length}"));
            }
            catch (Exception ex) { result = "ERROR " + ex; }
            File.WriteAllText(e.Args[1], result);
            Shutdown();
            return;
        }
        // Self-test: NetProbe.exe --health-test <outfile> <seconds> <adapter name>   (run elevated; live port health)
        if (e.Args.Length >= 4 && e.Args[0] == "--health-test")
        {
            string result;
            try
            {
                var nic = AdapterInfo.List().First(n => n.Name == e.Args[3]);
                var snap = AdapterInfo.Read(nic.Id);
                // Task.Run: blocking on the UI thread here would deadlock RunAsync's continuations
                var items = Task.Run(() => PortHealth.RunAsync(snap, Array.Empty<Neighbor>(), 0, int.Parse(e.Args[2]), null, CancellationToken.None)).GetAwaiter().GetResult();
                result = $"admin={IsAdmin} comp={LinkDiscovery.ComponentIdFor(snap.Mac)}\n" +
                         string.Join("\n", items.Select(h => $"{h.Badge,-8} {h.Check,-22} {h.Result}  |  {h.Explain}"));
            }
            catch (Exception ex) { result = "ERROR " + ex; }
            File.WriteAllText(e.Args[1], result);
            Shutdown();
            return;
        }
        // Self-test: NetProbe.exe --analyze <pcap> <outfile> <ourMac> <ourIp> <nonce> <probesSent> <unicastSent> <seconds>
        if (e.Args.Length >= 9 && e.Args[0] == "--analyze")
        {
            string result;
            try
            {
                var ctx = new HealthContext
                {
                    OurMac = e.Args[3], OurIp = e.Args[4], Nonce = e.Args[5], ProbesSent = int.Parse(e.Args[6]),
                    UnicastSent = int.Parse(e.Args[7]), Seconds = double.Parse(e.Args[8]), DhcpXid = 1
                };
                result = string.Join("\n", PortHealth.Analyze(e.Args[1], ctx).Select(h => $"{h.Badge,-8} {h.Check,-22} {h.Result}"));
            }
            catch (Exception ex) { result = "ERROR " + ex; }
            File.WriteAllText(e.Args[2], result);
            Shutdown();
            return;
        }
        bool snapshot = Environment.GetEnvironmentVariable("NETPROBE_SNAPSHOT") != null;
        // Ask for admin up front (switch port discovery needs it). If UAC is declined, keep running limited.
        if (!IsAdmin && !snapshot && !e.Args.Contains("--no-elevate"))
        {
            try
            {
                Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--no-elevate") { UseShellExecute = true, Verb = "runas" });
                Shutdown();
                return;
            }
            catch (Win32Exception) { }
        }
        ApplyTheme(Settings.Theme);
        new MainWindow().Show();
    }

    public static void ApplyTheme(string theme)
    {
        Current.ThemeMode = theme switch
        {
            "Light" => ThemeMode.Light,
            "Dark" => ThemeMode.Dark,
            _ => ThemeMode.System
        };
    }

    public static void RestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--no-elevate") { UseShellExecute = true, Verb = "runas" });
            Current.Shutdown();
        }
        catch (Win32Exception) { }
    }
}
