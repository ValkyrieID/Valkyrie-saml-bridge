using System.Collections;
using System.Globalization;
using System.Text.Json;

namespace ValkyrieSamlBridge.Core.OpenIdConnect;

// Turns ID token claims into string lists, so the claim mapper handles one shape.
// Scalars become one value; arrays (roles, groups) become several.
public static class ClaimValues
{
    public static Dictionary<string, IReadOnlyList<string>> FromTokenClaims(IReadOnlyDictionary<string, object> claims)
    {
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (name, value) in claims)
        {
            result[name] = Normalize(value);
        }
        return result;
    }

    // auth_time is a NumericDate (OIDC Core §2). It's required to set AuthnInstant, so a missing or
    // malformed value is refused by the caller.
    public static long? AuthTime(IReadOnlyDictionary<string, object> claims) =>
        claims.TryGetValue("auth_time", out var value) && value is IConvertible convertible &&
        value is not string && long.TryParse(Convert.ToString(convertible, CultureInfo.InvariantCulture), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            ? seconds
            : null;

    private static List<string> Normalize(object? value)
    {
        switch (value)
        {
            case null:
                return [];
            case string text:
                return [text];
            case bool flag:
                return [flag ? "true" : "false"];
            case JsonElement element:
                return element.ValueKind == JsonValueKind.Array
                    ? element.EnumerateArray().Select(FromJsonScalar).Where(v => v is not null).Cast<string>().ToList()
                    : FromJsonScalar(element) is { } scalar ? [scalar] : [];
            case IEnumerable items:
                return items.Cast<object?>().Select(i => Normalize(i)).SelectMany(v => v).ToList();
            default:
                return [Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty];
        }
    }

    private static string? FromJsonScalar(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Number => element.GetRawText(),
        _ => null,
    };
}

