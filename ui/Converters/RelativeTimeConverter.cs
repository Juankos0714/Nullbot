using System.Globalization;
using System.Windows.Data;

namespace NullBot.UI.Converters;

[ValueConversion(typeof(DateTime?), typeof(string))]
public sealed class RelativeTimeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not DateTime dt) return "Never";
        var delta = DateTime.UtcNow - dt.ToUniversalTime();

        return delta.TotalSeconds switch
        {
            < 60      => "just now",
            < 3600    => $"{(int)delta.TotalMinutes}m ago",
            < 86400   => $"{(int)delta.TotalHours}h ago",
            < 604800  => $"{(int)delta.TotalDays}d ago",
            _         => dt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
