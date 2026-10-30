using System.Globalization;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using NetProbe.Services;

namespace NetProbe.Controls;

/// <summary>Live line graph of gateway + internet ping times. Timeouts are drawn as red ticks.</summary>
public sealed class LatencyGraph : FrameworkElement
{
    public LatencyMonitor? Monitor { get; set; }
    public bool ShowLegend { get; set; } = true;

    public static readonly Color GatewayColor = Color.FromRgb(0x3B, 0x82, 0xF6);
    public static readonly Color InternetColor = Color.FromRgb(0xF5, 0x9E, 0x0B);
    private static readonly Brush TimeoutBrush = Frozen(new SolidColorBrush(Color.FromRgb(0xE5, 0x53, 0x4B)));
    private static readonly Pen GridPen = Frozen(new Pen(Frozen(new SolidColorBrush(Color.FromArgb(0x40, 0x80, 0x80, 0x80))), 1));

    private static T Frozen<T>(T f) where T : Freezable { f.Freeze(); return f; }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        if (Monitor == null || w < 60 || h < 40) return;

        var text = (Brush)GetValue(TextElement.ForegroundProperty) ?? Brushes.Gray;
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        const double left = 44, top = 22, bottom = 6, right = 8;
        double pw = w - left - right, ph = h - top - bottom;

        var g = Monitor.Gateway.Snapshot();
        var i = Monitor.Internet.Snapshot();
        double max = g.Concat(i).Where(x => x.HasValue).Select(x => x!.Value).DefaultIfEmpty(10).Max();
        double scale = NiceCeiling(Math.Max(10, max * 1.15));

        for (int k = 0; k <= 4; k++)
        {
            double y = top + ph - ph * k / 4.0;
            dc.DrawLine(GridPen, new Point(left, y), new Point(left + pw, y));
            var ft = Text($"{scale * k / 4:0} ms", 10.5, text, dpi);
            ft.SetForegroundBrush(text);
            dc.PushOpacity(0.65);
            dc.DrawText(ft, new Point(left - 6 - ft.Width, y - ft.Height / 2));
            dc.Pop();
        }

        DrawSeries(dc, g, GatewayColor, left, top, pw, ph, scale);
        DrawSeries(dc, i, InternetColor, left, top, pw, ph, scale);

        if (ShowLegend)
        {
            double x = left;
            x = Legend(dc, x, $"Gateway {Monitor.Gateway.Target}", GatewayColor, text, dpi);
            x = Legend(dc, x + 16, $"Internet {Monitor.Internet.Target}", InternetColor, text, dpi);
            var tf = Text("timeout", 11, text, dpi);
            dc.DrawRectangle(TimeoutBrush, null, new Rect(x + 16, 6, 3, 11));
            dc.DrawText(tf, new Point(x + 23, 3));
        }
    }

    private static double Legend(DrawingContext dc, double x, string label, Color c, Brush text, double dpi)
    {
        dc.DrawRectangle(new SolidColorBrush(c), null, new Rect(x, 9, 14, 4));
        var ft = Text(label, 11, text, dpi);
        dc.DrawText(ft, new Point(x + 19, 3));
        return x + 19 + ft.Width;
    }

    private static void DrawSeries(DrawingContext dc, double?[] s, Color c, double left, double top, double pw, double ph, double scale)
    {
        if (s.Length == 0) return;
        double step = pw / (LatencyMonitor.Capacity - 1);
        double x0 = left + pw - step * (s.Length - 1);
        var pen = new Pen(new SolidColorBrush(c), 1.8) { LineJoin = PenLineJoin.Round };
        pen.Freeze();
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            bool open = false;
            for (int k = 0; k < s.Length; k++)
            {
                double x = x0 + k * step;
                if (s[k] is not { } v)
                {
                    open = false;
                    dc.DrawRectangle(TimeoutBrush, null, new Rect(x - 1, top + ph - 10, 2.5, 10));
                    continue;
                }
                var p = new Point(x, top + ph - ph * Math.Min(v, scale) / scale);
                if (!open) { ctx.BeginFigure(p, false, false); open = true; }
                else ctx.LineTo(p, true, true);
            }
        }
        geo.Freeze();
        dc.DrawGeometry(null, pen, geo);
    }

    private static double NiceCeiling(double v)
    {
        double mag = Math.Pow(10, Math.Floor(Math.Log10(v)));
        foreach (var m in new[] { 1, 2, 2.5, 5, 10 }) if (m * mag >= v) return m * mag;
        return 10 * mag;
    }

    private static FormattedText Text(string s, double size, Brush b, double dpi) =>
        new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), size, b, dpi);
}
