using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace NullBot.UI.ViewModels;

// Converter instances exposed as statics for {x:Static} binding in ScanView.xaml.
// Each instance converts ScanMode ↔ bool for a specific target mode.
public sealed class ScanModeConverter : IValueConverter
{
    private readonly ScanMode _target;

    private ScanModeConverter(ScanMode target) => _target = target;

    public static readonly ScanModeConverter QuickConverter  = new(ScanMode.Quick);
    public static readonly ScanModeConverter FullConverter   = new(ScanMode.Full);
    public static readonly ScanModeConverter CustomConverter = new(ScanMode.Custom);

    // Visibility converter: Visible only when ScanMode == Custom
    public static readonly ScanModeVisibilityConverter CustomVisibilityConverter = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is ScanMode mode && mode == _target;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? _target : (object)Binding.DoNothing;
}

public sealed class ScanModeVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is ScanMode.Custom ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
