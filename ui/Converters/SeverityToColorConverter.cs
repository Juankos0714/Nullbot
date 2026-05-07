using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using NullBot.UI.Models;

namespace NullBot.UI.Converters;

[ValueConversion(typeof(ThreatSeverity), typeof(Brush))]
public sealed class SeverityToColorConverter : IValueConverter
{
    private static readonly SolidColorBrush Low      = new(Color.FromRgb(0x00, 0xD4, 0xFF));
    private static readonly SolidColorBrush Medium   = new(Color.FromRgb(0xF5, 0xA6, 0x23));
    private static readonly SolidColorBrush High     = new(Color.FromRgb(0xFF, 0x6B, 0x2C));
    private static readonly SolidColorBrush Critical = new(Color.FromRgb(0xFF, 0x3B, 0x5C));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is ThreatSeverity severity
            ? severity switch
            {
                ThreatSeverity.Low      => Low,
                ThreatSeverity.Medium   => Medium,
                ThreatSeverity.High     => High,
                ThreatSeverity.Critical => Critical,
                _                       => Low,
            }
            : Low;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
