using System.Drawing.Drawing2D;

namespace DigitalConnectPlus.Tray;

internal static class TrayIcons
{
    public static Icon CreateStatusIcon(Color badgeColor)
    {
        using var bmp = new Bitmap(32, 32);
        using (Graphics g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            // Dark rounded shield/tile background
            using var bgBrush = new LinearGradientBrush(
                new Rectangle(2, 2, 28, 28),
                Color.FromArgb(24, 34, 52),
                Color.FromArgb(14, 20, 32),
                LinearGradientMode.Vertical);

            using GraphicsPath path = RoundedRect(new Rectangle(2, 2, 28, 28), 7);
            g.FillPath(bgBrush, path);

            using var borderPen = new Pen(Color.FromArgb(70, 130, 220), 1.6f);
            g.DrawPath(borderPen, path);

            // Stylized "DC+" encrypted relay glyph
            using var wavePen = new Pen(Color.FromArgb(110, 200, 255), 2.2f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };
            g.DrawArc(wavePen, 7, 8, 14, 14, 120, 240);
            g.DrawLine(wavePen, 17, 15, 23, 15);
            g.DrawLine(wavePen, 20, 12, 20, 18);

            // Live status badge dot (bottom-right)
            using var haloBrush = new SolidBrush(Color.FromArgb(14, 20, 32));
            g.FillEllipse(haloBrush, 19, 19, 12, 12);

            using var dotBrush = new SolidBrush(badgeColor);
            g.FillEllipse(dotBrush, 21, 21, 8, 8);
        }

        IntPtr hIcon = bmp.GetHicon();
        try
        {
            using var temp = Icon.FromHandle(hIcon);
            return (Icon)temp.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    private static GraphicsPath RoundedRect(Rectangle bounds, int radius)
    {
        int d = radius * 2;
        var gp = new GraphicsPath();
        gp.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
        gp.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
        gp.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
        gp.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
        gp.CloseFigure();
        return gp;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
