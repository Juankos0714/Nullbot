using System.Windows;
using System.Windows.Controls;
using NullBot.UI.Models;

namespace NullBot.UI.Controls;

public partial class ThreatRow : UserControl
{
    public static readonly DependencyProperty ThreatNameProperty =
        DependencyProperty.Register(nameof(ThreatName), typeof(string), typeof(ThreatRow),
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty FilePathProperty =
        DependencyProperty.Register(nameof(FilePath), typeof(string), typeof(ThreatRow),
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(nameof(Severity), typeof(ThreatSeverity), typeof(ThreatRow),
            new PropertyMetadata(ThreatSeverity.Medium));

    public static readonly DependencyProperty DetectionTypeProperty =
        DependencyProperty.Register(nameof(DetectionType), typeof(DetectionType), typeof(ThreatRow),
            new PropertyMetadata(DetectionType.Signature));

    public static readonly DependencyProperty DetectedAtProperty =
        DependencyProperty.Register(nameof(DetectedAt), typeof(DateTime), typeof(ThreatRow),
            new PropertyMetadata(DateTime.UtcNow));

    public string        ThreatName    { get => (string)GetValue(ThreatNameProperty);    set => SetValue(ThreatNameProperty, value); }
    public string        FilePath      { get => (string)GetValue(FilePathProperty);      set => SetValue(FilePathProperty, value); }
    public ThreatSeverity Severity     { get => (ThreatSeverity)GetValue(SeverityProperty); set => SetValue(SeverityProperty, value); }
    public DetectionType DetectionType { get => (DetectionType)GetValue(DetectionTypeProperty); set => SetValue(DetectionTypeProperty, value); }
    public DateTime      DetectedAt    { get => (DateTime)GetValue(DetectedAtProperty);  set => SetValue(DetectedAtProperty, value); }

    public ThreatRow() => InitializeComponent();
}
