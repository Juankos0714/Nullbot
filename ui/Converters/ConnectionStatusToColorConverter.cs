using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using NullBot.UI.Models;

namespace NullBot.UI.Converters;

[ValueConversion(typeof(ConnectionStatus), typeof(Brush))]
public sealed class ConnectionStatusToColorConverter : IValueConverter
{
    private static readonly SolidColorBrush Clean      = new(Color.FromRgb(0x00, 0xC8, 0x96));
    private static readonly SolidColorBrush Suspicious = new(Color.FromRgb(0xF5, 0xA6, 0x23));
    private static readonly SolidColorBrush Malicious  = new(Color.FromRgb(0xFF, 0x3B, 0x5C));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is ConnectionStatus status
            ? status switch
            {
                ConnectionStatus.Clean      => Clean,
                ConnectionStatus.Suspicious => Suspicious,
                ConnectionStatus.Malicious  => Malicious,
                _                           => Clean,
            }
            : Clean;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
