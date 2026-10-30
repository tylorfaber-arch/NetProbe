using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using NetProbe.Services;

namespace NetProbe;

public partial class MainWindow : Window
{
    private readonly Settings _settings = App.Settings;
    private readonly LatencyMonitor _monitor = new();
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(3) };

    private List<NetworkInterface> _adapters = new();
    private AdapterSnapshot? _snap;
    private List<Neighbor> _neighbors = new();
    private readonly List<TestResult> _tests = new();
    private List<ScanHost> _scan = new();

    private CancellationTokenSource? _discoverStop, _toolCts, _scanCts;
    private bool _discovering, _testing, _refreshing, _loadingAdapters, _scanEdited, _pendingAutoTests;
    private bool? _wasUp;
    private DateTime _linkUpAt;
    private DateTime? _lastDiscover, _lastTests;
    private int _discoverRemaining, _testTotal, _linkFlaps;
    private string? _currentTest;
    private List<HealthItem> _health = new();
    private bool _healthRunning;
    private CancellationTokenSource? _healthStop;
    private DateTime? _lastHealth;

    private Brush B(string key) => (Brush)FindResource(key);

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = "v" + App.Version;
        DashGraph.Monitor = _monitor;
        BigGraph.Monitor = _monitor;
        _monitor.Updated += () => Dispatcher.BeginInvoke(OnLatency);
        _monitor.Start();

        AdminBadge.Background = App.IsAdmin ? B("PassBrush") : B("WarnBrush");
        AdminText.Text = App.IsAdmin ? "Administrator" : "Limited mode";
        ElevateButton.Visibility = App.IsAdmin ? Visibility.Collapsed : Visibility.Visible;

        // settings -> controls
        TechBox.Text = _settings.TechName;
        SiteBox.Text = _settings.SiteName;
        UploadUrlBox.Text = _settings.UploadUrl;
        ApiKeyBox.Password = _settings.ApiKey;
        AutoUploadBox.IsChecked = _settings.AutoUpload;
        RepoBox.Text = _settings.UpdateRepo;
        CheckUpdatesBox.IsChecked = _settings.CheckUpdatesOnLaunch;
        AutoDiscoverBox.IsChecked = _settings.AutoDiscoverOnLink;
        DiscoverSeconds.Text = _settings.DiscoverSeconds.ToString();
        ThemeBox.SelectedIndex = _settings.Theme switch { "Light" => 1, "Dark" => 2, _ => 0 };
        AboutText.Text =
            $"NetProbe {App.Version} - laptop network tester\n" +
            $"Running as: {(App.IsAdmin ? "Administrator" : "standard user (switch discovery disabled)")}\n" +
            $"Packet capture (pktmon): {(LinkDiscovery.Available ? "available" : "not found - needs Windows 10 2004+")}\n" +
            $"Last capture file: {LinkDiscovery.LastCapture}\n" +
            $"Settings: %APPDATA%\\NetProbe\\settings.json";
        UpdateUploadButton();
        if (!App.RemoteUploadEnabled)
        {
            UploadCard.Visibility = Visibility.Collapsed;
            ReportNavText.Text = ReportPageTitle.Text = "Report";
        }

        ScanCidr.PreviewKeyDown += (_, _) => _scanEdited = true;
        _refreshTimer.Tick += async (_, _) => await RefreshAdapterAsync();
        NetworkChange.NetworkAddressChanged += (_, _) => Dispatcher.BeginInvoke(new Action(async () => await RefreshAdapterAsync()));
        NetworkChange.NetworkAvailabilityChanged += (_, _) => Dispatcher.BeginInvoke(new Action(() => LoadAdapters()));
        Loaded += OnLoaded;
        Closing += (_, _) =>
        {
            _monitor.Stop();
            _discoverStop?.Cancel();
            _toolCts?.Cancel();
            _scanCts?.Cancel();
        };
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        LoadAdapters();
        await RefreshAdapterAsync();
        _refreshTimer.Start();
        if (Environment.GetEnvironmentVariable("NETPROBE_SNAPSHOT") is { } dir) { await SnapshotAsync(dir); return; }
        if (_settings.CheckUpdatesOnLaunch) await CheckForUpdatesAsync(false);
    }

    private void Status(string text) => StatusText.Text = text;

    // ================================================================== adapters / link

    private string? SelectedId => AdapterBox.SelectedIndex >= 0 && AdapterBox.SelectedIndex < _adapters.Count ? _adapters[AdapterBox.SelectedIndex].Id : null;

    private void LoadAdapters()
    {
        var keep = SelectedId;
        _loadingAdapters = true;
        try
        {
            _adapters = AdapterInfo.List();
            AdapterBox.Items.Clear();
            foreach (var n in _adapters)
            {
                var state = n.OperationalStatus == OperationalStatus.Up ? "Up  " + AdapterSnapshot.FormatSpeed(n.Speed) : n.OperationalStatus.ToString();
                AdapterBox.Items.Add($"{n.Name}   -   {state}     ({n.Description})");
            }
            int idx = keep != null ? _adapters.FindIndex(a => a.Id == keep) : -1;
            if (idx < 0 && Environment.GetEnvironmentVariable("NETPROBE_ADAPTER") is { } want) idx = _adapters.FindIndex(a => a.Name == want);
            if (idx < 0 && _adapters.Count > 0) idx = 0; // list is sorted wired-first
            AdapterBox.SelectedIndex = idx;
        }
        finally { _loadingAdapters = false; }
    }

    private async void AdapterBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingAdapters) return;
        _wasUp = null;
        _scanEdited = false;
        await RefreshAdapterAsync();
    }

    private void ReloadAdapters_Click(object sender, RoutedEventArgs e) { LoadAdapters(); _ = RefreshAdapterAsync(); }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAdapterAsync();

    private async Task RefreshAdapterAsync()
    {
        var id = SelectedId;
        if (id == null || _refreshing) return;
        _refreshing = true;
        try
        {
            var s = await Task.Run(() => AdapterInfo.Read(id));
            if (id != SelectedId) return;
            bool changed = _snap == null || _snap.Id != s.Id || !_snap.Rows.SequenceEqual(s.Rows);
            _snap = s;
            if (changed) LinkList.ItemsSource = s.Rows;
            LinkPageStatus.Text = $"Updated {DateTime.Now:T}";

            var gw = s.Gateway ?? "";
            if (_monitor.Gateway.Target != gw)
            {
                _monitor.Gateway.Target = gw;
                _monitor.Gateway.Clear();
                LatGwBox.Text = gw;
            }
            if (!_scanEdited && s.IPv4.FirstOrDefault(ip => !ip.StartsWith("169.254.")) is { } cidr)
                ScanCidr.Text = AdapterInfo.NetworkCidr(cidr);

            // NetTool-style: react to a cable being plugged in / pulled out
            var nic = _adapters.FirstOrDefault(a => a.Id == id);
            bool wired = nic != null && AdapterInfo.IsWired(nic);
            if (_wasUp != true && s.IsUp && wired && _settings.AutoDiscoverOnLink)
            {
                _linkUpAt = DateTime.Now;
                _pendingAutoTests = true;
                if (_wasUp == false) { _neighbors.Clear(); _lastDiscover = null; ShowNeighbors(); }
                if (App.IsAdmin && !_discovering && !_healthRunning) _ = PortChecksAsync();
                Status(_wasUp == false ? "Cable connected - running checks..." : "Wired link up - running checks...");
            }
            if (_wasUp == true && !s.IsUp)
            {
                _linkFlaps++;
                _health.Clear();
                HealthList.ItemsSource = null;
                _neighbors.Clear();
                _lastDiscover = null;
                _tests.Clear();
                TestsList.ItemsSource = null;
                ShowNeighbors();
                Status("Link lost.");
            }
            _wasUp = s.IsUp;

            // wait for DHCP before auto-testing (or give up waiting after 20 s so failures show)
            if (_pendingAutoTests && s.IsUp && !_testing &&
                (s.Gateway != null && !s.Apipa || DateTime.Now - _linkUpAt > TimeSpan.FromSeconds(20)))
            {
                _pendingAutoTests = false;
                _ = RunTestsAsync();
            }
            UpdateDashboard();
        }
        catch (Exception ex) { Status("Adapter read failed: " + ex.Message); }
        finally { _refreshing = false; }
    }

    private async void RenewDhcp_Click(object sender, RoutedEventArgs e)
    {
        if (_snap == null) return;
        var name = _snap.Name;
        LinkPageStatus.Text = $"Renewing DHCP lease on {name}...";
        var output = await Task.Run(() =>
        {
            Run("ipconfig", $"/release \"{name}\"");
            return Run("ipconfig", $"/renew \"{name}\"");
        });
        var err = output.Split('\n').FirstOrDefault(l => l.Contains("error", StringComparison.OrdinalIgnoreCase) || l.Contains("unable", StringComparison.OrdinalIgnoreCase));
        LinkPageStatus.Text = err != null ? "DHCP renew: " + err.Trim() : "DHCP renew finished.";
        _pendingAutoTests = true;
        _linkUpAt = DateTime.Now;
        await RefreshAdapterAsync();
    }

    private static string Run(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd();
        p.WaitForExit(60000);
        return o;
    }

    // ================================================================== dashboard

    private void SetBar(Border bar, string key) => bar.Background = B(key);

    private void UpdateDashboard()
    {
        var s = _snap;
        if (s == null) return;

        // Link
        var lines = new List<string> { $"{s.Name} · {s.Description}", "MAC " + s.Mac };
        if (s.IsUp)
        {
            SetBar(LinkBar, "PassBrush");
            LinkBig.Text = $"UP  ·  {s.SpeedText}";
            if (s.IsWireless)
            {
                string W(string k) => s.Wifi.FirstOrDefault(w => w.Key == "Wi-Fi " + k)?.Value ?? "?";
                lines.Add($"Wi-Fi {W("SSID")} · signal {W("Signal")} · {W("Band")} ch {W("Channel")}");
            }
            if (_neighbors.FirstOrDefault()?.Get("Switch port speed") is { } sps) lines.Add("Switch side: " + sps);
        }
        else
        {
            SetBar(LinkBar, "FailBrush");
            LinkBig.Text = "NO LINK";
            lines.Add(s.IsWireless ? "Not connected to Wi-Fi." : "Check the cable / wall jack / switch port.");
        }
        LinkSub.Text = string.Join("\n", lines);

        // IP / DHCP
        lines.Clear();
        if (!s.IsUp) { SetBar(NetBar, "NeutralBrush"); NetBig.Text = "-"; }
        else if (s.IPv4.Count == 0 || s.Apipa)
        {
            SetBar(NetBar, "FailBrush");
            NetBig.Text = s.Apipa ? s.IPv4[0] : "No IP yet";
            lines.Add(s.Apipa ? "No DHCP response - self-assigned 169.254.x.x" : "Waiting for DHCP...");
        }
        else
        {
            SetBar(NetBar, s.Gateway != null && s.Dns.Count > 0 ? "PassBrush" : "WarnBrush");
            NetBig.Text = s.IPv4[0];
            lines.Add($"Gateway {s.Gateway ?? "none"}" + (s.GatewayMac != null ? $"  ({s.GatewayMac})" : ""));
            lines.Add("DNS " + (s.Dns.Count > 0 ? string.Join(", ", s.Dns) : "none"));
            lines.Add(s.DhcpEnabled
                ? $"DHCP {s.DhcpServer ?? "?"}" + (s.LeaseRemaining is { } lr && lr > TimeSpan.Zero ? $" · lease {AdapterInfo.FormatSpan(lr)} left" : "")
                : "Static IP (DHCP off)");
        }
        NetSub.Text = string.Join("\n", lines);

        // Switch port
        lines.Clear();
        if (_discovering)
        {
            SetBar(SwBar, "InfoBrush");
            SwBig.Text = "Listening...";
            lines.Add(_discoverRemaining > 0 ? $"{_discoverRemaining} s left · LLDP every ~30 s, CDP every ~60 s" : "Decoding...");
        }
        else if (_neighbors.Count > 0)
        {
            var n = _neighbors[0];
            SetBar(SwBar, "PassBrush");
            SwBig.Text = $"{n.SwitchName}  ·  {n.Port}";
            var vl = $"VLAN {n.Vlan ?? "?"}";
            if (n.VoiceVlan != null) vl += $"  ·  Voice VLAN {n.VoiceVlan}";
            lines.Add(vl);
            if (n.Get("Port Description") is { } pd && pd != n.Port) lines.Add("Port desc: " + pd);
            if (n.MgmtIp != null) lines.Add("Switch IP " + n.MgmtIp);
            if (n.Get("PoE") is { } poe) lines.Add(poe);
            lines.Add($"via {n.Protocol}" + (n.Get("Platform") is { } pl ? $" · {pl}" : ""));
            if (_neighbors.Count > 1) lines.Add($"+{_neighbors.Count - 1} more neighbor(s) - see Switch Port page");
        }
        else if (_lastDiscover != null)
        {
            SetBar(SwBar, "WarnBrush");
            SwBig.Text = "No LLDP / CDP heard";
            lines.Add("The switch may have LLDP/CDP turned off, or this is an unmanaged switch / home router.");
        }
        else
        {
            SetBar(SwBar, "NeutralBrush");
            SwBig.Text = "Not discovered";
            lines.Add(!App.IsAdmin ? "Needs Administrator - use Restart as Admin (top right)."
                : s.IsWireless ? "Switch discovery needs a wired Ethernet adapter."
                : "Click Discover, or plug in a cable to start automatically.");
        }
        // port health folds into the switch card + a red banner for problems
        var problems = _health.Where(h => h.Sev == Sev.Fail).ToList();
        if (_healthRunning) lines.Insert(Math.Min(1, lines.Count), "Port health: checking...");
        else if (_lastHealth != null)
        {
            int warns = _health.Count(h => h.Sev == Sev.Warn);
            lines.Insert(Math.Min(1, lines.Count), problems.Count > 0 ? $"Port health: {problems.Count} problem(s) - {problems[0].Check}"
                : warns > 0 ? $"Port health: OK, {warns} warning(s)" : "Port health: OK");
            if (problems.Count > 0) SetBar(SwBar, "FailBrush");
            else if (warns > 0 && _neighbors.Count > 0) SetBar(SwBar, "WarnBrush");
        }
        HealthBanner.Visibility = problems.Count > 0 && !_healthRunning ? Visibility.Visible : Visibility.Collapsed;
        HealthBannerText.Text = problems.Count == 0 ? "" :
            $"{problems[0].Check}: {problems[0].Result}" + (problems.Count > 1 ? $"   (+{problems.Count - 1} more)" : "");
        SwSub.Text = string.Join("\n", lines);
        DashDiscoverBtn.IsEnabled = !_discovering;
        DashDiscoverProgress.Visibility = _discovering ? Visibility.Visible : Visibility.Collapsed;

        // Internet
        lines.Clear();
        if (_testing)
        {
            SetBar(InetBar, "InfoBrush");
            InetBig.Text = $"Testing...  {_tests.Count} / {_testTotal}";
            foreach (var t in _tests.TakeLast(_currentTest != null ? 3 : 4)) lines.Add(ResultLine(t));
            if (_currentTest != null) lines.Add($"▸  {_currentTest}...");
        }
        else if (_tests.Count == 0)
        {
            SetBar(InetBar, "NeutralBrush");
            InetBig.Text = "Not tested";
            lines.Add("Checks gateway, DNS, internet and captive portal.");
        }
        else
        {
            int fail = _tests.Count(t => t.Sev == Sev.Fail), warn = _tests.Count(t => t.Sev == Sev.Warn);
            bool online = _tests.Any(t => t.Sev == Sev.Pass && (t.Name.StartsWith("HTTPS") || t.Name.StartsWith("Ping internet")));
            InetBig.Text = fail + warn == 0 ? "ONLINE" : online ? "ONLINE · issues" : "OFFLINE";
            SetBar(InetBar, fail + warn == 0 ? "PassBrush" : online ? "WarnBrush" : "FailBrush");
            int passed = _tests.Count(t => t.Sev == Sev.Pass);
            lines.Add($"{passed} of {_tests.Count(t => t.Sev != Sev.Info)} checks passed" + (_lastTests is { } lt ? $" · {lt:t}" : ""));
            foreach (var t in _tests.Where(t => t.Sev is Sev.Fail or Sev.Warn).Take(3)) lines.Add(ResultLine(t));
            if (_tests.FirstOrDefault(t => t.Name == "Public IP" && t.Sev == Sev.Info) is { } pip) lines.Add("Public IP " + pip.Detail);
        }
        InetSub.Text = string.Join("\n", lines);
        DashTestBtn.IsEnabled = !_testing;
        DashTestProgress.Visibility = _testing ? Visibility.Visible : Visibility.Collapsed;
        DashTestProgress.Maximum = Math.Max(1, _testTotal);
        DashTestProgress.Value = _tests.Count;
    }

    private static string ResultLine(TestResult t)
    {
        var icon = t.Sev switch { Sev.Pass => "✓", Sev.Fail => "✗", Sev.Warn => "!", _ => "•" };
        var detail = t.Detail.Length > 42 ? t.Detail[..42] + "…" : t.Detail;
        return $"{icon}  {t.Name}  —  {detail}";
    }

    private void TestDetails_Click(object sender, RoutedEventArgs e) => NavTo("Tests");

    private void OnLatency()
    {
        DashGraph.InvalidateVisual();
        if (PageLatency.Visibility == Visibility.Visible)
        {
            BigGraph.InvalidateVisual();
            LatGwStats.Text = $"Gateway  {_monitor.Gateway.Target,-15} {_monitor.Gateway.Stats()}";
            LatInetStats.Text = $"Internet {_monitor.Internet.Target,-15} {_monitor.Internet.Stats()}";
        }
        DashLatencyStats.Text = $"gateway {Short(_monitor.Gateway)}    internet {Short(_monitor.Internet)}";

        static string Short(LatencyMonitor.Series s)
        {
            var a = s.Snapshot();
            if (string.IsNullOrEmpty(s.Target) || a.Length == 0) return "-";
            var last = a[^1];
            var loss = 100.0 * a.Count(x => x == null) / a.Length;
            return (last is { } v ? $"{v:0} ms" : "timeout") + $" ({loss:0}% loss)";
        }
    }

    private async void FullCheck_Click(object sender, RoutedEventArgs e) => await FullCheckAsync();

    private async Task FullCheckAsync()
    {
        FullCheckBtn.IsEnabled = false;
        DashStatus.Text = "Running full check...";
        try
        {
            await RefreshAdapterAsync();
            var tasks = new List<Task> { RunTestsAsync() };
            if (App.IsAdmin && !_discovering && !_healthRunning) tasks.Add(PortChecksAsync());
            await Task.WhenAll(tasks);
            DashStatus.Text = $"Full check finished {DateTime.Now:t}";
            if (App.RemoteUploadEnabled && _settings.AutoUpload && !string.IsNullOrWhiteSpace(_settings.UploadUrl))
            {
                try
                {
                    var res = await Uploader.UploadAsync(_settings, BuildReport());
                    DashStatus.Text = res.Message;
                    ShowPortalLink(res.Url);
                }
                catch (Exception ex) { DashStatus.Text = "Upload failed: " + ex.Message; }
            }
        }
        finally { FullCheckBtn.IsEnabled = true; }
    }

    // ================================================================== navigation / theme / admin

    private void Nav_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PageDashboard == null || Nav.SelectedItem is not ListBoxItem item) return;
        var tag = (string)item.Tag;
        foreach (var (name, page) in new (string, FrameworkElement)[]
                 {
                     ("Dashboard", PageDashboard), ("Link", PageLink), ("Switch", PageSwitch), ("Health", PageHealth), ("Tests", PageTests), ("Latency", PageLatency),
                     ("Tools", PageTools), ("Scan", PageScan), ("Report", PageReport), ("Settings", PageSettings)
                 })
            page.Visibility = name == tag ? Visibility.Visible : Visibility.Collapsed;
        if (tag == "Latency") OnLatency();
    }

    private void NavTo(string tag) =>
        Nav.SelectedItem = Nav.Items.OfType<ListBoxItem>().First(i => (string)i.Tag == tag);

    private void Elevate_Click(object sender, RoutedEventArgs e) => App.RestartElevated();

    // ================================================================== port health

    /// <summary>Switch discovery then port health - both use pktmon, so they run one after the other.</summary>
    private async Task PortChecksAsync()
    {
        await DiscoverAsync(auto: true);
        await HealthAsync(auto: true);
    }

    private async void Health_Click(object sender, RoutedEventArgs e) => await HealthAsync(auto: false);
    private void StopHealth_Click(object sender, RoutedEventArgs e) => _healthStop?.Cancel();
    private void HealthBanner_Click(object sender, System.Windows.Input.MouseButtonEventArgs e) => NavTo("Health");

    private async Task HealthAsync(bool auto)
    {
        if (_healthRunning || _discovering || _snap == null) return;
        int secs = int.TryParse(HealthSeconds.Text, out var v) ? Math.Clamp(v, 10, 300) : 30;
        _healthRunning = true;
        _healthStop = new CancellationTokenSource();
        HealthBtn.IsEnabled = false;
        DiscoverBtn.IsEnabled = DashDiscoverBtn.IsEnabled = false;
        StopHealthBtn.IsEnabled = true;
        HealthProgress.Visibility = Visibility.Visible;
        HealthSummary.Text = "Checking port health...";
        UpdateDashboard();
        try
        {
            var progress = new Progress<string>(t => { HealthHint.Text = t; if (_healthRunning) DashStatus.Text = "Port health: " + t; });
            _health = await PortHealth.RunAsync(_snap, _neighbors, _linkFlaps, secs, progress, _healthStop.Token);
            _lastHealth = DateTime.Now;
            ShowHealth();
        }
        catch (Exception ex)
        {
            HealthSummary.Text = "Health check failed";
            HealthHint.Text = ex.Message;
        }
        finally
        {
            _healthRunning = false;
            HealthBtn.IsEnabled = true;
            DiscoverBtn.IsEnabled = DashDiscoverBtn.IsEnabled = true;
            StopHealthBtn.IsEnabled = false;
            HealthProgress.Visibility = Visibility.Collapsed;
            if (DashStatus.Text.StartsWith("Port health:")) DashStatus.Text = "";
            UpdateDashboard();
        }
    }

    private void ShowHealth()
    {
        HealthList.ItemsSource = _health;
        int fail = _health.Count(h => h.Sev == Sev.Fail), warn = _health.Count(h => h.Sev == Sev.Warn);
        HealthSummary.Text = fail > 0 ? $"{fail} problem(s), {warn} warning(s)" : warn > 0 ? $"No problems, {warn} warning(s)" : "No problems found";
        HealthSummary.Foreground = fail > 0 ? B("FailBrush") : warn > 0 ? B("WarnBrush") : B("PassBrush");
        HealthHint.Text = $"Checked {_lastHealth:t}. " + (_health.FirstOrDefault(h => h.Sev == Sev.Fail) is { } f ? f.Explain : "");
        Status($"Port health: {HealthSummary.Text}");
        UpdateDashboard();
    }

    private void Theme_Click(object sender, RoutedEventArgs e) =>
        ThemeBox.SelectedIndex = Application.Current.ThemeMode == ThemeMode.Dark ? 1 : 2;

    private void ThemeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ThemeBox.SelectedItem is not ComboBoxItem it) return;
        _settings.Theme = (string)it.Content;
        App.ApplyTheme(_settings.Theme);
        _settings.Save();
        DashGraph?.InvalidateVisual();
    }

    private void SettingsChanged(object sender, RoutedEventArgs e)
    {
        if (AutoDiscoverBox == null) return;
        _settings.AutoDiscoverOnLink = AutoDiscoverBox.IsChecked == true;
        _settings.Save();
    }

    // ================================================================== switch port discovery

    private async void Discover_Click(object sender, RoutedEventArgs e) => await DiscoverAsync(auto: false);

    private void StopDiscover_Click(object sender, RoutedEventArgs e) => _discoverStop?.Cancel();

    private async Task DiscoverAsync(bool auto)
    {
        if (!App.IsAdmin)
        {
            if (!auto && MessageBox.Show(this, "Switch port discovery needs Administrator rights.\n\nRestart NetProbe as Administrator now?",
                    "NetProbe", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                App.RestartElevated();
            return;
        }
        if (_discovering || _healthRunning) return;
        int secs = int.TryParse(DiscoverSeconds.Text, out var v) ? Math.Clamp(v, 10, 300) : 65;
        if (secs != _settings.DiscoverSeconds) { _settings.DiscoverSeconds = secs; _settings.Save(); }

        _discovering = true;
        _discoverStop = new CancellationTokenSource();
        DiscoverBtn.IsEnabled = false;
        StopDiscoverBtn.IsEnabled = true;
        DiscoverProgress.Visibility = Visibility.Visible;
        DiscoverProgress.Maximum = DashDiscoverProgress.Maximum = secs;
        DiscoverProgress.Value = DashDiscoverProgress.Value = 0;
        SwitchSummary.Text = "Listening for LLDP / CDP...";
        UpdateDashboard();

        var progress = new Progress<int>(left =>
        {
            _discoverRemaining = left;
            DiscoverProgress.Value = DashDiscoverProgress.Value = secs - left;
            SwitchHint.Text = left > 0
                ? $"{left} s left. Switches send LLDP about every 30 s and CDP every 60 s - results show as soon as one arrives."
                : "Decoding...";
            UpdateDashboard();
        });
        try
        {
            _neighbors = await LinkDiscovery.CaptureAsync(secs, progress, _discoverStop.Token);
            _lastDiscover = DateTime.Now;
            ShowNeighbors();
            Status(_neighbors.Count > 0 ? $"Switch port found via {_neighbors[0].Protocol}." : "No LLDP/CDP heard.");
        }
        catch (Exception ex)
        {
            SwitchSummary.Text = "Capture failed";
            SwitchHint.Text = ex.Message;
            Status("Switch discovery failed: " + ex.Message);
        }
        finally
        {
            _discovering = false;
            DiscoverBtn.IsEnabled = true;
            StopDiscoverBtn.IsEnabled = false;
            DiscoverProgress.Visibility = Visibility.Collapsed;
            UpdateDashboard();
        }
    }

    private void ShowNeighbors()
    {
        var rows = new List<KV>();
        for (int i = 0; i < _neighbors.Count; i++)
        {
            var n = _neighbors[i];
            if (i > 0) rows.Add(new KV("", ""));
            rows.Add(new KV($"Neighbor {i + 1}", n.Protocol, Sev.Info));
            rows.AddRange(LinkDiscovery.Ordered(n).Select(f => new KV(f.Key, f.Value)));
        }
        SwitchList.ItemsSource = rows;
        if (_neighbors.Count > 0)
        {
            var n = _neighbors[0];
            SwitchSummary.Text = $"Switch {n.SwitchName}    Port {n.Port}    VLAN {n.Vlan ?? "?"}" + (n.VoiceVlan != null ? $"    Voice {n.VoiceVlan}" : "");
            SwitchHint.Text = (n.MgmtIp != null ? $"Switch management IP {n.MgmtIp}. " : "") + $"Capture saved to {LinkDiscovery.LastCapture} (opens in Wireshark).";
        }
        else if (_lastDiscover != null)
        {
            SwitchSummary.Text = "No LLDP / CDP heard";
            SwitchHint.Text = "The switch may have LLDP/CDP disabled, or this is an unmanaged switch / home router. Try listening longer (CDP is sent every 60 s).";
        }
        else
        {
            SwitchSummary.Text = App.IsAdmin ? "Plug into the switch port and click Discover." : "Switch discovery needs Administrator - click Restart as Admin.";
            SwitchHint.Text = "";
        }
        UpdateDashboard();
    }

    private void OpenCapture_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "Packet captures (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            _neighbors = LinkDiscovery.ParseCapture(dlg.FileName);
            _lastDiscover = DateTime.Now;
            ShowNeighbors();
        }
        catch (Exception ex) { MessageBox.Show(this, "Could not read capture: " + ex.Message, "NetProbe"); }
    }

    // ================================================================== tests

    private async void RunTests_Click(object sender, RoutedEventArgs e) => await RunTestsAsync();

    private async Task RunTestsAsync()
    {
        if (_testing || _snap == null) return;
        _testing = true;
        _tests.Clear();
        _testTotal = ConnectivityTests.CountFor(_snap.Dns.Count);
        var rows = new ObservableCollection<TestResult>();
        TestsList.ItemsSource = rows;
        RunTestsBtn.IsEnabled = false;
        TestsStatus.Text = "Starting...";
        UpdateDashboard();
        var running = new Progress<string>(name =>
        {
            if (!_testing) return;
            _currentTest = name;
            TestsStatus.Text = $"Running {_tests.Count + 1} of {_testTotal}:  {name}...";
            Status(TestsStatus.Text);
            UpdateDashboard();
        });
        try
        {
            await foreach (var r in ConnectivityTests.RunAsync(_snap.Gateway, _snap.Dns, running))
            {
                _currentTest = null;
                _tests.Add(r);
                rows.Add(r);
                UpdateDashboard();
            }
            _lastTests = DateTime.Now;
        }
        catch (Exception ex) { TestsStatus.Text = "Tests failed: " + ex.Message; }
        finally
        {
            _testing = false;
            _currentTest = null;
            RunTestsBtn.IsEnabled = true;
            int fail = _tests.Count(t => t.Sev == Sev.Fail);
            TestsStatus.Text = fail == 0 ? $"All checks passed ({DateTime.Now:T})." : $"{fail} check(s) failed ({DateTime.Now:T}).";
            Status("Connectivity: " + TestsStatus.Text);
            UpdateDashboard();
        }
    }

    // ================================================================== latency page

    private void LatApply_Click(object sender, RoutedEventArgs e)
    {
        _monitor.Gateway.Target = LatGwBox.Text.Trim();
        _monitor.Internet.Target = LatInetBox.Text.Trim();
        _monitor.Gateway.Clear();
        _monitor.Internet.Clear();
        OnLatency();
    }

    private void LatPause_Click(object sender, RoutedEventArgs e)
    {
        if (_monitor.Running) { _monitor.Stop(); LatPauseBtn.Content = "Resume"; }
        else { _monitor.Start(); LatPauseBtn.Content = "Pause"; }
    }

    private void LatClear_Click(object sender, RoutedEventArgs e) { _monitor.Gateway.Clear(); _monitor.Internet.Clear(); OnLatency(); }

    // ================================================================== tools

    private void Append(string line)
    {
        ToolOut.AppendText(line + Environment.NewLine);
        ToolOut.ScrollToEnd();
    }

    private async Task RunTool(Func<CancellationToken, IAsyncEnumerable<string>> producer, string title)
    {
        _toolCts?.Cancel();
        var cts = _toolCts = new CancellationTokenSource();
        Append($"{Environment.NewLine}=== {title}  [{DateTime.Now:T}] ===");
        ToolStopBtn.IsEnabled = true;
        try { await foreach (var line in producer(cts.Token)) Append(line); }
        catch (OperationCanceledException) { Append("--- stopped"); }
        catch (Exception ex) { Append("Error: " + ex.Message); }
        finally { if (_toolCts == cts) ToolStopBtn.IsEnabled = false; }
    }

    private string Host => ToolHost.Text.Trim();
    private int Count => int.TryParse(ToolCount.Text, out var c) ? c : 10;

    private async void Ping_Click(object sender, RoutedEventArgs e) => await RunTool(ct => NetTools.PingAsync(Host, Count, ct), $"Ping {Host}" + (Count <= 0 ? " (until Stop)" : ""));
    private async void Trace_Click(object sender, RoutedEventArgs e) => await RunTool(ct => NetTools.TraceAsync(Host, ct), $"Traceroute {Host}");
    private async void Dns_Click(object sender, RoutedEventArgs e) => await RunTool(ct => NetTools.DnsLookupAsync(Host, ct), $"DNS lookup {Host}");
    private async void Whois_Click(object sender, RoutedEventArgs e) => await RunTool(ct => Whois.LookupAsync(Host, ct), $"WHOIS {Host}");
    private async void Ports_Click(object sender, RoutedEventArgs e) => await RunTool(ct => NetTools.PortCheckAsync(Host, ToolPorts.Text, ct), $"TCP ports on {Host}");

    private async void PingGw_Click(object sender, RoutedEventArgs e)
    {
        if (_snap?.Gateway is not { } gw) { Append("No gateway on this adapter."); return; }
        ToolHost.Text = gw;
        await RunTool(ct => NetTools.PingAsync(gw, Count, ct), $"Ping gateway {gw}");
    }

    private void ToolStop_Click(object sender, RoutedEventArgs e) => _toolCts?.Cancel();
    private void ToolClear_Click(object sender, RoutedEventArgs e) => ToolOut.Clear();

    // ================================================================== LAN scan

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCts != null) return;
        _scanCts = new CancellationTokenSource();
        ScanBtn.IsEnabled = false;
        ScanStopBtn.IsEnabled = true;
        ScanList.ItemsSource = null;
        try
        {
            _scan = await LanScanner.ScanAsync(ScanCidr.Text, new Progress<string>(t => ScanStatus.Text = t), _scanCts.Token);
            ScanList.ItemsSource = _scan;
            ScanStatus.Text = $"{_scan.Count} devices found ({DateTime.Now:T}). Double-click a device to open it in Tools.";
        }
        catch (OperationCanceledException) { ScanStatus.Text = "Scan stopped."; }
        catch (Exception ex) { ScanStatus.Text = ex.Message; }
        finally
        {
            _scanCts = null;
            ScanBtn.IsEnabled = true;
            ScanStopBtn.IsEnabled = false;
        }
    }

    private void ScanStop_Click(object sender, RoutedEventArgs e) => _scanCts?.Cancel();

    private void ScanList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ScanList.SelectedItem is not ScanHost h) return;
        ToolHost.Text = h.IP;
        NavTo("Tools");
    }

    // ================================================================== report / upload

    private ReportData BuildReport()
    {
        _settings.TechName = TechBox.Text.Trim();
        _settings.SiteName = SiteBox.Text.Trim();
        _settings.Save();
        var r = new ReportData { Tech = _settings.TechName, Site = _settings.SiteName };
        if (_snap != null)
            foreach (var kv in _snap.Rows)
            {
                var k = kv.Key;
                for (int i = 2; r.Adapter.ContainsKey(k); i++) k = $"{kv.Key} ({i})";
                r.Adapter[k] = kv.Value;
            }
        r.SwitchPorts = _neighbors.Select(n =>
        {
            var d = new Dictionary<string, string> { ["Protocol"] = n.Protocol };
            foreach (var f in LinkDiscovery.Ordered(n)) d[f.Key] = f.Value;
            return d;
        }).ToList();
        r.Tests = _tests.Select(t => new ReportData.TestRow(t.Badge, t.Name, t.Detail)).ToList();
        r.PortHealth = _health.Select(h => new ReportData.HealthRow(h.Badge, h.Check, h.Result, h.Explain)).ToList();
        if (!string.IsNullOrEmpty(_monitor.Gateway.Target)) r.Latency[$"Gateway {_monitor.Gateway.Target}"] = _monitor.Gateway.Stats();
        if (!string.IsNullOrEmpty(_monitor.Internet.Target)) r.Latency[$"Internet {_monitor.Internet.Target}"] = _monitor.Internet.Stats();
        r.LanScan = _scan.Select(h => new ReportData.ScanRow(h.IP, h.Mac, h.Name, h.Ping, h.Note)).ToList();
        return r;
    }

    private string? AskSavePath(string ext, string filter)
    {
        var tag = string.IsNullOrWhiteSpace(SiteBox.Text) ? Environment.MachineName : string.Concat(SiteBox.Text.Split(Path.GetInvalidFileNameChars()));
        var dlg = new SaveFileDialog
        {
            Filter = filter, FileName = $"NetProbe-{tag}-{DateTime.Now:yyyyMMdd-HHmm}.{ext}",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };
        return dlg.ShowDialog(this) == true ? dlg.FileName : null;
    }

    private static void OpenFile(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch { }
    }

    private async void SavePdf_Click(object sender, RoutedEventArgs e)
    {
        if (AskSavePath("pdf", "PDF (*.pdf)|*.pdf") is not { } path) return;
        ReportStatus.Text = "Creating PDF...";
        try
        {
            await ReportWriter.SavePdfAsync(ReportWriter.ToHtml(BuildReport()), path);
            ReportStatus.Text = "Saved " + path;
            OpenFile(path);
        }
        catch (Exception ex) { ReportStatus.Text = "PDF failed: " + ex.Message; }
    }

    private void SaveHtml_Click(object sender, RoutedEventArgs e)
    {
        if (AskSavePath("html", "Web page (*.html)|*.html") is not { } path) return;
        File.WriteAllText(path, ReportWriter.ToHtml(BuildReport()));
        ReportStatus.Text = "Saved " + path;
        OpenFile(path);
    }

    private void SaveJson_Click(object sender, RoutedEventArgs e)
    {
        if (AskSavePath("json", "JSON (*.json)|*.json") is not { } path) return;
        File.WriteAllText(path, BuildReport().ToJson());
        ReportStatus.Text = "Saved " + path;
    }

    private void CopySummary_Click(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        var s = _snap;
        if (s != null)
        {
            sb.AppendLine($"Link: {(s.IsUp ? "Up " + s.SpeedText : "DOWN")} ({s.Name}, MAC {s.Mac})");
            if (s.IPv4.Count > 0) sb.AppendLine($"IP: {s.IPv4[0]}  GW: {s.Gateway ?? "none"}  DNS: {string.Join(", ", s.Dns)}  DHCP: {(s.DhcpEnabled ? s.DhcpServer : "static")}");
        }
        if (_neighbors.FirstOrDefault() is { } n)
            sb.AppendLine($"Switch: {n.SwitchName}  Port: {n.Port}  VLAN: {n.Vlan ?? "?"}" + (n.VoiceVlan != null ? $"  Voice VLAN: {n.VoiceVlan}" : "") + (n.MgmtIp != null ? $"  Switch IP: {n.MgmtIp}" : ""));
        if (_tests.Count > 0)
        {
            var fails = _tests.Where(t => t.Sev == Sev.Fail).Select(t => t.Name).ToList();
            sb.AppendLine("Tests: " + (fails.Count == 0 ? "all passed" : "FAILED - " + string.Join("; ", fails)));
        }
        if (_lastHealth != null)
        {
            var issues = _health.Where(h => h.Sev is Sev.Fail or Sev.Warn).Select(h => $"{h.Badge} {h.Check}: {h.Result}").ToList();
            sb.AppendLine("Port health: " + (issues.Count == 0 ? "no problems" : string.Join("; ", issues)));
        }
        Clipboard.SetText(sb.ToString());
        ReportStatus.Text = "Summary copied to clipboard.";
    }

    private void UpdateUploadButton() => UploadBtn.IsEnabled = !string.IsNullOrWhiteSpace(_settings.UploadUrl);

    private void SaveUpload_Click(object sender, RoutedEventArgs e)
    {
        _settings.UploadUrl = UploadUrlBox.Text.Trim();
        _settings.ApiKey = ApiKeyBox.Password;
        _settings.AutoUpload = AutoUploadBox.IsChecked == true;
        _settings.Save();
        UpdateUploadButton();
        UploadStatus.Text = string.IsNullOrEmpty(_settings.UploadUrl) ? "Saved - uploading is off." : "Saved.";
    }

    private async void Upload_Click(object sender, RoutedEventArgs e)
    {
        UploadStatus.Text = "Uploading...";
        ShowPortalLink(null);
        try
        {
            var res = await Uploader.UploadAsync(_settings, BuildReport());
            UploadStatus.Text = res.Message;
            ShowPortalLink(res.Url);
        }
        catch (Exception ex) { UploadStatus.Text = "Upload failed: " + ex.Message; }
    }

    private async void TestUpload_Click(object sender, RoutedEventArgs e)
    {
        // test what's typed in, even if not saved yet
        var s = new Settings { UploadUrl = UploadUrlBox.Text.Trim(), ApiKey = ApiKeyBox.Password };
        TestUploadBtn.IsEnabled = false;
        UploadStatus.Text = "Testing connection...";
        try { UploadStatus.Text = await Uploader.TestAsync(s); }
        catch (Exception ex) { UploadStatus.Text = "Connection failed: " + ex.Message; }
        finally { TestUploadBtn.IsEnabled = true; }
    }

    private void ShowPortalLink(string? url)
    {
        PortalLinkText.Visibility = url != null ? Visibility.Visible : Visibility.Collapsed;
        if (url != null) PortalLink.NavigateUri = new Uri(url);
    }

    private void PortalLink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true }); } catch { }
        e.Handled = true;
    }

    // ================================================================== updates

    private void SaveUpdates_Click(object sender, RoutedEventArgs e)
    {
        _settings.UpdateRepo = RepoBox.Text.Trim();
        _settings.CheckUpdatesOnLaunch = CheckUpdatesBox.IsChecked == true;
        _settings.Save();
        UpdateStatus.Text = "Saved.";
    }

    private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        SaveUpdates_Click(sender, e);
        await CheckForUpdatesAsync(true);
    }

    private async Task CheckForUpdatesAsync(bool interactive)
    {
        if (string.IsNullOrWhiteSpace(_settings.UpdateRepo))
        {
            if (interactive) UpdateStatus.Text = "Enter the GitHub repo (owner/name) first.";
            return;
        }
        try
        {
            if (interactive) UpdateStatus.Text = "Checking...";
            var rel = await Updater.CheckAsync(_settings.UpdateRepo);
            if (rel == null) { if (interactive) UpdateStatus.Text = $"You're up to date (v{App.Version})."; return; }
            if (!interactive && rel.Tag == _settings.SkippedVersion) return;
            var notes = rel.Notes.Length > 700 ? rel.Notes[..700] + "..." : rel.Notes;
            var answer = MessageBox.Show(this,
                $"NetProbe {rel.Tag} is available (you have v{App.Version}).\n\n{notes}\n\nDownload and install now?\n\nYes = install now     No = remind me later     Cancel = skip this version",
                "Update available", MessageBoxButton.YesNoCancel, MessageBoxImage.Information);
            if (answer == MessageBoxResult.Yes)
            {
                await Updater.DownloadAndRunAsync(rel, new Progress<int>(p => Status($"Downloading update... {p}%")));
                Application.Current.Shutdown();
            }
            else if (answer == MessageBoxResult.Cancel)
            {
                _settings.SkippedVersion = rel.Tag;
                _settings.Save();
            }
        }
        catch (Exception ex)
        {
            if (interactive) UpdateStatus.Text = "Update check failed: " + ex.Message;
        }
    }

    // ================================================================== screenshot self-test (NETPROBE_SNAPSHOT=folder)

    private async Task SnapshotAsync(string dir)
    {
        if (Environment.GetEnvironmentVariable("NETPROBE_THEME") is { } th) App.ApplyTheme(th);
        if (Environment.GetEnvironmentVariable("NETPROBE_FAKE_CAPTURE") is { } cap && File.Exists(cap))
        {
            _neighbors = LinkDiscovery.ParseCapture(cap);
            _lastDiscover = DateTime.Now;
            ShowNeighbors();
        }
        var prefix = Environment.GetEnvironmentVariable("NETPROBE_THEME") ?? "default";
        if (Environment.GetEnvironmentVariable("NETPROBE_FAKE_HEALTH") is { } hp && File.Exists(hp))
        {
            _health = PortHealth.Analyze(hp, new HealthContext
            {
                OurMac = "c8:53:09:ec:08:5d", OurIp = "192.168.86.106", Nonce = "NETPROBE-LOOP-test1234abcd",
                ProbesSent = 5, UnicastSent = 5, Seconds = 30, DhcpXid = 1
            });
            _lastHealth = DateTime.Now;
            ShowHealth();
        }
        while (_testing) await Task.Delay(100);
        var trace = new List<string> { $"before: testing={_testing} snap={_snap != null}" };
        var tests = RunTestsAsync();
        bool shot = false;
        while (!tests.IsCompleted)
        {
            var line = $"{InetBig.Text} | {InetSub.Text.Replace("\n", " / ")}";
            if (trace[^1] != line) trace.Add(line);
            if (!shot && _tests.Count >= 3) { SavePng(Path.Combine(dir, $"{prefix}-testing.png")); shot = true; }
            await Task.Delay(50);
        }
        await tests;
        File.WriteAllLines(Path.Combine(dir, $"{prefix}-testing-trace.txt"), trace);
        await Task.Delay(6000);
        var html = ReportWriter.ToHtml(BuildReport());
        File.WriteAllText(Path.Combine(dir, $"{prefix}-report.html"), html);
        try { await ReportWriter.SavePdfAsync(html, Path.Combine(dir, $"{prefix}-report.pdf")); }
        catch (Exception ex) { File.WriteAllText(Path.Combine(dir, $"{prefix}-report-error.txt"), ex.ToString()); }
        for (int i = 0; i < Nav.Items.Count; i++)
        {
            Nav.SelectedIndex = i;
            if (i == 5)
            {
                ToolHost.Text = "www.google.com";
                await RunTool(ct => Whois.LookupAsync("www.google.com", ct), "WHOIS www.google.com");
                await RunTool(ct => Whois.LookupAsync("8.8.8.8", ct), "WHOIS 8.8.8.8");
            }
            await Task.Delay(400);
            SavePng(Path.Combine(dir, $"{prefix}-{i}-{((ListBoxItem)Nav.Items[i]).Tag}.png"));
        }
        Close();
    }

    private void SavePng(string path)
    {
        UpdateLayout();
        var dpi = VisualTreeHelper.GetDpi(this);
        var content = (FrameworkElement)Content;
        int w = (int)(content.ActualWidth * dpi.DpiScaleX), h = (int)(content.ActualHeight * dpi.DpiScaleY);
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            var bg = TryFindResource("ApplicationBackgroundBrush") as Brush ?? Background ?? Brushes.White;
            dc.DrawRectangle(bg, null, new Rect(0, 0, content.ActualWidth, content.ActualHeight));
            dc.DrawRectangle(new VisualBrush(content), null, new Rect(0, 0, content.ActualWidth, content.ActualHeight));
        }
        var rtb = new RenderTargetBitmap(w, h, dpi.PixelsPerInchX, dpi.PixelsPerInchY, PixelFormats.Pbgra32);
        rtb.Render(dv);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(path);
        enc.Save(fs);
    }
}
