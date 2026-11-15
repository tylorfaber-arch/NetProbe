using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using NetProbe.Services;

namespace NetProbe.Controls;

/// <summary>
/// Draws a switch front panel from port data: copper ports in odd-over-even pairs, grouped in 12s,
/// SFP / uplink ports to the right, one row per stack member. No images, so it fits any switch.
/// </summary>
public sealed class FaceplateView : FrameworkElement
{
    private SwitchFaceplate? _plate;
    public SwitchFaceplate? Plate { get => _plate; set { _plate = value; Selected = null; _hover = null; InvalidateMeasure(); InvalidateVisual(); } }

    private bool _byVlan;
    public bool ColorByVlan { get => _byVlan; set { _byVlan = value; InvalidateVisual(); } }

    public SwitchPort? Selected { get; private set; }
    public event Action<SwitchPort?>? SelectedChanged;

    private SwitchPort? _hover;
    private double _scale = 1;
    private List<(SwitchPort Port, Rect Rect, bool Top)> _hits = new();

    private const double PW = 30, PH = 24, ColGap = 4, RowGap = 8, GroupGap = 12, UplinkGap = 28, Pad = 14, LabelH = 13, UnitGap = 10, LegendH = 30;

    private static readonly Color Green = Color.FromRgb(0x2E, 0xA0, 0x43), Amber = Color.FromRgb(0xD2, 0x99, 0x22),
        Gray = Color.FromRgb(0x8B, 0x94, 0x9E), Blue = Color.FromRgb(0x3B, 0x82, 0xF6), Red = Color.FromRgb(0xE5, 0x53, 0x4B);

    // distinct VLAN hues (no pure green/amber so they don't read as link states)
    private static readonly Color[] VlanColors =
    {
        Color.FromRgb(0x3B, 0x82, 0xF6), Color.FromRgb(0xA8, 0x55, 0xF7), Color.FromRgb(0x14, 0xB8, 0xA6), Color.FromRgb(0xEC, 0x48, 0x99),
        Color.FromRgb(0xF9, 0x73, 0x16), Color.FromRgb(0x06, 0xB6, 0xD4), Color.FromRgb(0x84, 0xCC, 0x16), Color.FromRgb(0x63, 0x66, 0xF1),
        Color.FromRgb(0xB4, 0x53, 0x09), Color.FromRgb(0xF4, 0x3F, 0x5E), Color.FromRgb(0x0E, 0xA5, 0xE9), Color.FromRgb(0xD9, 0x46, 0xEF)
    };

    public FaceplateView()
    {
        ToolTipService.SetInitialShowDelay(this, 150);
        ToolTipService.SetShowDuration(this, 60000);
        Cursor = Cursors.Arrow;
    }

    // ------------------------------------------------------------------ layout

    private sealed record UnitBox(string Label, Rect Box);

    private (List<(SwitchPort, Rect, bool)> Ports, List<UnitBox> Units, Size Size) Layout()
    {
        var ports = new List<(SwitchPort, Rect, bool)>();
        var units = new List<UnitBox>();
        if (_plate == null || _plate.Ports.Count == 0) return (ports, units, new Size(0, 0));

        var groups = _plate.Ports.GroupBy(p => p.Unit).ToList();
        bool multi = groups.Count > 1;
        double unitH = Pad + LabelH + PH + RowGap + PH + LabelH + Pad - 6;
        double y = 0, maxW = 0;
        foreach (var g in groups)
        {
            double x = Pad + (multi ? 22 : 0);
            void Place(List<SwitchPort> list, bool uplink)
            {
                for (int i = 0; i < list.Count; i++)
                {
                    int col = i / 2;
                    bool top = i % 2 == 0;
                    if (!uplink && col > 0 && col % 6 == 0 && top) x += GroupGap;
                    double px = x, py = y + Pad + LabelH + (top ? 0 : PH + RowGap);
                    ports.Add((list[i], new Rect(px, py, PW, PH), top));
                    if (!top || i == list.Count - 1) x += PW + ColGap;
                }
            }
            var copper = g.Where(p => !p.IsUplink).ToList();
            var up = g.Where(p => p.IsUplink).ToList();
            Place(copper, false);
            if (up.Count > 0) { if (copper.Count > 0) x += UplinkGap - ColGap; Place(up, true); }
            double w = x - ColGap + Pad;
            units.Add(new UnitBox(multi ? g.Key : "", new Rect(0, y, w, unitH)));
            maxW = Math.Max(maxW, w);
            y += unitH + UnitGap;
        }
        // all chassis the same width, like a real stack
        for (int i = 0; i < units.Count; i++) units[i] = units[i] with { Box = new Rect(units[i].Box.X, units[i].Box.Y, maxW, units[i].Box.Height) };
        return (ports, units, new Size(Math.Max(maxW, 560), y - UnitGap + LegendH + 6));
    }

    protected override Size MeasureOverride(Size available)
    {
        var size = Layout().Size;
        if (size.Width == 0) return new Size(0, 0);
        double s = double.IsInfinity(available.Width) ? 1 : Math.Min(1.35, available.Width / size.Width);
        return new Size(double.IsInfinity(available.Width) ? size.Width : available.Width, size.Height * s);
    }

    // ------------------------------------------------------------------ drawing

    private Color VlanColor(int? vlan)
    {
        if (vlan == null || _plate == null) return Gray;
        var all = _plate.Ports.Where(p => p.Pvid != null).Select(p => p.Pvid!.Value).Distinct().OrderBy(v => v).ToList();
        int i = all.IndexOf(vlan.Value);
        return VlanColors[(i < 0 ? vlan.Value : i) % VlanColors.Length];
    }

    private static SolidColorBrush Br(Color c, double a = 1) { var b = new SolidColorBrush(Color.FromArgb((byte)(a * 255), c.R, c.G, c.B)); b.Freeze(); return b; }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        var (ports, units, size) = Layout();
        if (size.Width == 0) return;
        _scale = Math.Min(1.35, w / size.Width);
        var fg = (Brush)GetValue(TextElement.ForegroundProperty) ?? Brushes.Gray;
        var fgColor = (fg as SolidColorBrush)?.Color ?? Gray;
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        dc.PushTransform(new ScaleTransform(_scale, _scale));
        foreach (var u in units)
        {
            dc.DrawRoundedRectangle(Br(fgColor, 0.06), new Pen(Br(fgColor, 0.18), 1), u.Box, 8, 8);
            if (u.Label.Length > 0)
            {
                var ft = Text(u.Label, 13, fg, dpi, FontWeights.SemiBold);
                dc.DrawText(ft, new Point(u.Box.X + 10, u.Box.Y + u.Box.Height / 2 - ft.Height / 2));
            }
        }

        foreach (var (p, r, top) in ports) DrawPort(dc, p, r, top, fg, fgColor, dpi);
        _hits = ports.Select(t => (t.Item1, new Rect(t.Item2.X * _scale, t.Item2.Y * _scale, t.Item2.Width * _scale, t.Item2.Height * _scale), t.Item3)).ToList();

        DrawLegend(dc, new Point(2, size.Height - LegendH + 8), fg, fgColor, dpi);
        dc.Pop();
    }

    private void DrawPort(DrawingContext dc, SwitchPort p, Rect r, bool top, Brush fg, Color fgColor, double dpi)
    {
        Color baseColor = _byVlan ? VlanColor(p.Pvid) : p.SpeedMbps is > 0 and < 1000 ? Amber : Green;
        Brush fill; Pen stroke;
        switch (p.Link)
        {
            case PortLink.Up: fill = Br(baseColor); stroke = new Pen(Br(baseColor, 1), 1); break;
            case PortLink.Down:
                fill = _byVlan && p.Pvid != null ? Br(baseColor, 0.28) : Br(fgColor, 0.08);
                stroke = new Pen(Br(_byVlan && p.Pvid != null ? baseColor : fgColor, 0.45), 1); break;
            case PortLink.Disabled: fill = Br(fgColor, 0.18); stroke = new Pen(Br(fgColor, 0.35), 1); break;
            default: fill = Br(fgColor, 0.03); stroke = new Pen(Br(fgColor, 0.25), 1) { DashStyle = DashStyles.Dash }; break;
        }

        // RJ45 body with latch tab toward the outside edge; SFP cage is a plain box with an inner slot
        Geometry shape;
        if (p.IsUplink)
        {
            shape = new RectangleGeometry(new Rect(r.X, r.Y + 3, r.Width, r.Height - 6), 2, 2);
        }
        else
        {
            double tw = r.Width * 0.42, th = 4, tx = r.X + (r.Width - tw) / 2;
            var body = new RectangleGeometry(top ? new Rect(r.X, r.Y + th, r.Width, r.Height - th) : new Rect(r.X, r.Y, r.Width, r.Height - th), 2, 2);
            var tab = new RectangleGeometry(top ? new Rect(tx, r.Y, tw, th + 1) : new Rect(tx, r.Bottom - th - 1, tw, th + 1));
            shape = new CombinedGeometry(GeometryCombineMode.Union, body, tab);
        }
        dc.DrawGeometry(fill, stroke, shape);
        if (p.IsUplink) dc.DrawRectangle(null, new Pen(Br(fgColor, 0.25), 1), new Rect(r.X + 4, r.Y + 7, r.Width - 8, r.Height - 14));

        if (p.Link == PortLink.Disabled)
            dc.DrawLine(new Pen(Br(Red, 0.85), 1.6), new Point(r.X + 5, r.Bottom - 5), new Point(r.Right - 5, r.Y + 5));

        // inside text: VLAN in VLAN mode, link speed in status mode
        var inside = _byVlan ? p.Pvid?.ToString() : p.Link == PortLink.Up ? p.SpeedText : null;
        if (!string.IsNullOrEmpty(inside))
        {
            var light = p.Link == PortLink.Up;
            var ft = Text(inside, inside.Length > 3 ? 8.5 : 10, light ? Brushes.White : fg, dpi, FontWeights.SemiBold);
            double cy = p.IsUplink ? r.Y + r.Height / 2 : top ? r.Y + 4 + (r.Height - 4) / 2 : r.Y + (r.Height - 4) / 2;
            dc.DrawText(ft, new Point(r.X + (r.Width - ft.Width) / 2, cy - ft.Height / 2));
        }

        // tagged VLANs: corner flag
        if (p.IsTrunk)
        {
            double s = 9, cy = top || p.IsUplink ? r.Bottom : r.Y;
            var tri = new StreamGeometry();
            using (var g = tri.Open())
            {
                g.BeginFigure(new Point(r.Right, cy), true, true);
                g.LineTo(new Point(r.Right - s, cy), true, false);
                g.LineTo(new Point(r.Right, top || p.IsUplink ? cy - s : cy + s), true, false);
            }
            tri.Freeze();
            dc.DrawGeometry(fg, null, tri);
        }

        if (p.IsLocal) dc.DrawRoundedRectangle(null, new Pen(Br(Blue), 2.5), Inflate(r, 3), 4, 4);
        if (ReferenceEquals(p, Selected) || ReferenceEquals(p, _hover)) dc.DrawRoundedRectangle(null, new Pen(fg, 1.5), Inflate(r, ReferenceEquals(p, Selected) ? 5.5 : 2), 5, 5);

        // port number: above the top row, below the bottom row
        var num = Text(p.Number.ToString(), 9.5, fg, dpi, FontWeights.Normal);
        dc.PushOpacity(p.IsLocal ? 1 : 0.6);
        double off = p.IsLocal || ReferenceEquals(p, Selected) ? 4 : 1;   // clear of the highlight ring
        dc.DrawText(num, new Point(r.X + (r.Width - num.Width) / 2, top ? r.Y - num.Height - off : r.Bottom + off));
        dc.Pop();
    }

    private void DrawLegend(DrawingContext dc, Point at, Brush fg, Color fgColor, double dpi)
    {
        double x = at.X, y = at.Y;
        void Chip(Brush fill, Pen? pen, string label, bool flag = false, bool local = false)
        {
            var r = new Rect(x, y + 2, 14, 11);
            dc.DrawRoundedRectangle(fill, pen, r, 2, 2);
            if (flag)
            {
                var tri = new StreamGeometry();
                using (var g = tri.Open()) { g.BeginFigure(new Point(r.Right, r.Bottom), true, true); g.LineTo(new Point(r.Right - 7, r.Bottom), true, false); g.LineTo(new Point(r.Right, r.Bottom - 7), true, false); }
                dc.DrawGeometry(fg, null, tri);
            }
            if (local) dc.DrawRoundedRectangle(null, new Pen(Br(Blue), 2), Inflate(r, 1.5), 3, 3);
            var ft = Text(label, 11.5, fg, dpi, FontWeights.Normal);
            dc.DrawText(ft, new Point(x + 19, y + 7.5 - ft.Height / 2));
            x += 19 + ft.Width + 16;
        }
        var dim = Br(fgColor, 0.08);
        if (_byVlan && _plate != null)
        {
            var vlans = _plate.Ports.Where(p => p.Pvid != null).Select(p => p.Pvid!.Value).Distinct().OrderBy(v => v).ToList();
            foreach (var v in vlans.Take(10)) Chip(Br(VlanColor(v)), null, $"VLAN {v}");
            if (vlans.Count > 10) Chip(dim, null, $"+{vlans.Count - 10} more");
            if (vlans.Count == 0) Chip(dim, new Pen(Br(fgColor, 0.4), 1), "VLAN unknown");
        }
        else
        {
            Chip(Br(Green), null, "Up 1G+");
            Chip(Br(Amber), null, "Up 10/100");
            Chip(dim, new Pen(Br(fgColor, 0.45), 1), "Down");
            Chip(Br(fgColor, 0.18), null, "Disabled");
        }
        Chip(dim, new Pen(Br(fgColor, 0.45), 1), "Tagged VLANs", flag: true);
        Chip(dim, null, "This PC", local: true);
        if (_plate?.Generic == true) Chip(Br(fgColor, 0.03), new Pen(Br(fgColor, 0.25), 1) { DashStyle = DashStyles.Dash }, "Not read");
    }

    private static Rect Inflate(Rect r, double d) { r.Inflate(d, d); return r; }

    private static FormattedText Text(string s, double size, Brush b, double dpi, FontWeight weight) =>
        new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal), size, b, dpi);

    // ------------------------------------------------------------------ interaction

    private SwitchPort? HitTest(Point pt) => _hits.FirstOrDefault(h => Inflate(h.Rect, 2 * _scale).Contains(pt)).Port;

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var p = HitTest(e.GetPosition(this));
        if (ReferenceEquals(p, _hover)) return;
        _hover = p;
        ToolTip = p == null ? null : p.Describe();
        Cursor = p == null ? Cursors.Arrow : Cursors.Hand;
        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        if (_hover == null) return;
        _hover = null;
        InvalidateVisual();
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        var p = HitTest(e.GetPosition(this));
        Selected = ReferenceEquals(p, Selected) ? null : p;
        SelectedChanged?.Invoke(Selected);
        InvalidateVisual();
    }

    public void SelectLocal()
    {
        Selected = _plate?.Ports.FirstOrDefault(p => p.IsLocal);
        SelectedChanged?.Invoke(Selected);
        InvalidateVisual();
    }
}
