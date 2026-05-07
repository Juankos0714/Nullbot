using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using NullBot.UI.Models;

namespace NullBot.UI.Controls;

public partial class ShieldGauge : UserControl
{
    // Center and radius must match the Ellipse in XAML (160px diameter, centered in 200px canvas)
    private const double Cx = 100;
    private const double Cy = 100;
    private const double R  = 75;

    public static readonly DependencyProperty StatusProperty =
        DependencyProperty.Register(nameof(Status), typeof(ProtectionLevel), typeof(ShieldGauge),
            new PropertyMetadata(ProtectionLevel.Safe, OnStatusChanged));

    public ProtectionLevel Status
    {
        get => (ProtectionLevel)GetValue(StatusProperty);
        set => SetValue(StatusProperty, value);
    }

    public ShieldGauge()
    {
        InitializeComponent();
        Loaded += (_, _) => ApplyStatus(Status);
    }

    private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((ShieldGauge)d).ApplyStatus((ProtectionLevel)e.NewValue);

    private void ApplyStatus(ProtectionLevel level)
    {
        var (color, label, pulseSec) = level switch
        {
            ProtectionLevel.Warning => (Color.FromRgb(0xF5, 0xA6, 0x23), "WARNING",  1.2),
            ProtectionLevel.Danger  => (Color.FromRgb(0xFF, 0x3B, 0x5C), "THREAT!",  0.6),
            _                       => (Color.FromRgb(0x00, 0xC8, 0x96), "PROTECTED", 2.0),
        };

        var brush = new SolidColorBrush(color);
        ArcPath.Stroke   = brush;
        GlowPath.Stroke  = brush;
        ShieldIcon.Stroke = brush;
        ShieldIcon.Fill  = new SolidColorBrush(Color.FromArgb(0x22, color.R, color.G, color.B));
        StatusLabel.Foreground = brush;
        StatusLabel.Text = label;

        // Full circle arc for the ring
        ArcPath.Data = FullCircle(Cx, Cy, R);
        GlowPath.Data = FullCircle(Cx, Cy, R);

        AnimatePulse(pulseSec);
    }

    private void AnimatePulse(double periodSec)
    {
        GlowPath.BeginAnimation(OpacityProperty, null); // stop existing

        var anim = new DoubleAnimation(0.5, 0.05, new Duration(TimeSpan.FromSeconds(periodSec / 2)))
        {
            AutoReverse        = true,
            RepeatBehavior     = RepeatBehavior.Forever,
            EasingFunction     = new SineEase { EasingMode = EasingMode.EaseInOut },
        };
        GlowPath.BeginAnimation(OpacityProperty, anim);
    }

    // WPF cannot draw a full ellipse as a PathGeometry arc, so we use two half-arcs.
    private static PathGeometry FullCircle(double cx, double cy, double r)
    {
        var top    = new Point(cx, cy - r);
        var bottom = new Point(cx, cy + r);

        var fig = new PathFigure { StartPoint = top, IsClosed = false };
        fig.Segments.Add(new ArcSegment(bottom, new Size(r, r), 0, false, SweepDirection.Clockwise, true));
        fig.Segments.Add(new ArcSegment(top,    new Size(r, r), 0, false, SweepDirection.Clockwise, true));

        return new PathGeometry([fig]);
    }
}
