# Generates Assets\netprobe.ico (Ethernet jack on a blue rounded tile). Run with Windows PowerShell.
param([string]$Out = (Join-Path $PSScriptRoot '..\Assets\netprobe.ico'))
Add-Type -AssemblyName System.Drawing

function New-Frame([int]$s) {
    $bmp = New-Object Drawing.Bitmap $s, $s
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'
    $k = $s / 256.0
    # rounded tile with gradient
    $r = 56 * $k; $rect = New-Object Drawing.RectangleF (8 * $k), (8 * $k), (240 * $k), (240 * $k)
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc($rect.Right - $d, $rect.Y, $d, $d, 270, 90)
    $path.AddArc($rect.Right - $d, $rect.Bottom - $d, $d, $d, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush $rect, ([Drawing.Color]::FromArgb(255, 59, 130, 246)), ([Drawing.Color]::FromArgb(255, 0, 84, 166)), 60
    $g.FillPath($br, $path)
    # RJ45 jack: outline with latch notch at the bottom
    $w = [Drawing.Color]::White
    $pen = New-Object Drawing.Pen $w, ([Math]::Max(1.5, 16 * $k))
    $pen.LineJoin = 'Round'
    $pts = @(
        @(60, 70), @(196, 70), @(196, 170), @(160, 170), @(160, 196), @(96, 196), @(96, 170), @(60, 170)
    ) | ForEach-Object { New-Object Drawing.PointF ($_[0] * $k), ($_[1] * $k) }
    $g.DrawPolygon($pen, [Drawing.PointF[]]$pts)
    # contact pins
    if ($s -ge 32) {
        $pin = New-Object Drawing.SolidBrush $w
        for ($i = 0; $i -lt 4; $i++) { $g.FillRectangle($pin, (84 + $i * 26) * $k, 92 * $k, 12 * $k, 34 * $k) }
    }
    # green "link" LED
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 74, 222, 128))), 176 * $k, 26 * $k, 34 * $k, 34 * $k)
    $g.Dispose()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$frames = foreach ($s in $sizes) { , (New-Frame $s) }
$ms = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter $ms
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $b = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$b); $bw.Write([byte]$b); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$frames[$i].Length); $bw.Write([uint32]$offset)
    $offset += $frames[$i].Length
}
foreach ($f in $frames) { $bw.Write($f) }
$bw.Flush()
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
[IO.File]::WriteAllBytes($Out, $ms.ToArray())
# also a PNG preview for docs
[IO.File]::WriteAllBytes((Join-Path (Split-Path $Out) 'netprobe-256.png'), $frames[-1])
"Wrote $Out"
