using System.Globalization;
using System.Windows.Data;

namespace NullBot.UI.Converters;

[ValueConversion(typeof(long), typeof(string))]
public sealed class BytesToSizeConverter : IValueConverter
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB"];

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not long bytes) return "0 B";
        double size = bytes;
        int unit = 0;
        while (size >= 1024 && unit < Units.Length - 1) { size /= 1024; unit++; }
        return unit == 0
            ? $"{bytes} {Units[unit]}"
            : $"{size:F1} {Units[unit]}";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
