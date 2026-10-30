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
