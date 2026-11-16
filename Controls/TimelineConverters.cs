using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace NetProbe.Controls;

/// <summary>
/// Hides the timeline connector under the last item. Bound with (item, owning ItemsControl, Items.Count)
/// so it re-evaluates as rows stream in.
/// </summary>
public sealed class NotLastToVisibility : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length < 2 || values[1] is not ItemsControl ic) return Visibility.Visible;
        int i = ic.Items.IndexOf(values[0]);
        return i >= 0 && i < ic.Items.Count - 1 ? Visibility.Visible : Visibility.Hidden;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
