using System.Text.RegularExpressions;

namespace ValkyrieSamlBridge.Core.Apps;

public static partial class AppSlug
{
    public static bool IsValid(string slug) => SlugPattern().IsMatch(slug);

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex SlugPattern();
}
