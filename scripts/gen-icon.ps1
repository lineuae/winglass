# Generate a 1024x1024 source PNG for the winglass app icon.
# Drawn with System.Drawing so no external image tooling is required.
# Design: dark rounded square, cyan shield glyph, white checkmark — matches
# the ShieldCheck brand mark used in the top bar.

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$size = 1024
$assetsDir = Join-Path (Join-Path $PSScriptRoot "..") "assets"
New-Item -ItemType Directory -Force $assetsDir | Out-Null
$outPath = Join-Path $assetsDir "icon-source.png"

$bmp = New-Object System.Drawing.Bitmap $size, $size
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

# Background: rounded square, matches --color-surface.
$bgColor = [System.Drawing.ColorTranslator]::FromHtml('#12141a')
$borderColor = [System.Drawing.ColorTranslator]::FromHtml('#26292f')
$radius = 180
$diameter = $radius * 2
$bgPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$bgPath.AddArc(0, 0, $diameter, $diameter, 180, 90)
$bgPath.AddArc(($size - $diameter), 0, $diameter, $diameter, 270, 90)
$bgPath.AddArc(($size - $diameter), ($size - $diameter), $diameter, $diameter, 0, 90)
$bgPath.AddArc(0, ($size - $diameter), $diameter, $diameter, 90, 90)
$bgPath.CloseFigure()

$bgBrush = New-Object System.Drawing.SolidBrush $bgColor
$g.FillPath($bgBrush, $bgPath)
$borderPen = New-Object System.Drawing.Pen $borderColor, 4
$g.DrawPath($borderPen, $bgPath)

# Shield glyph — Bezier curves for smooth heraldic silhouette.
# Wide flat top with rounded corners, straight vertical sides for ~55% of the
# height, then a smooth curve tapering to a bottom point.
$shieldColor = [System.Drawing.ColorTranslator]::FromHtml('#5eb3f5')
$shield = New-Object System.Drawing.Drawing2D.GraphicsPath

$topY = 232
$sideStraightEnd = 560
$botY = 828
$leftX = 268
$rightX = 756
$midX = 512
$cornerR = 40
$curvePull = 176   # how far down the vertical control point sits

$shield.AddArc($leftX, $topY, ($cornerR * 2), ($cornerR * 2), 180, 90)
$shield.AddArc(($rightX - $cornerR * 2), $topY, ($cornerR * 2), ($cornerR * 2), 270, 90)
$shield.AddLine($rightX, ($topY + $cornerR), $rightX, $sideStraightEnd)
$shield.AddBezier(
    $rightX, $sideStraightEnd,
    $rightX, ($sideStraightEnd + $curvePull),
    ($midX + 108), $botY,
    $midX, $botY
)
$shield.AddBezier(
    $midX, $botY,
    ($midX - 108), $botY,
    $leftX, ($sideStraightEnd + $curvePull),
    $leftX, $sideStraightEnd
)
$shield.AddLine($leftX, $sideStraightEnd, $leftX, ($topY + $cornerR))
$shield.CloseFigure()

$shieldBrush = New-Object System.Drawing.SolidBrush $shieldColor
$g.FillPath($shieldBrush, $shield)

# Checkmark — bold white strokes, rounded caps.
$checkColor = [System.Drawing.Color]::FromArgb(255, 255, 255, 255)
$checkPen = New-Object System.Drawing.Pen $checkColor, 64
$checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$checkPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
$checkPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$checkPoints = @(
    [System.Drawing.PointF]::new(400, 500),
    [System.Drawing.PointF]::new(482, 588),
    [System.Drawing.PointF]::new(632, 418)
)
$g.DrawLines($checkPen, $checkPoints)

$g.Dispose()
$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

Write-Host "Icon written to $outPath ($([Math]::Round((Get-Item $outPath).Length / 1KB, 1)) KB)"
