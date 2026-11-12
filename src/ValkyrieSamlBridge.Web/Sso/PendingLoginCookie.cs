using System.Security.Cryptography;
using ValkyrieSamlBridge.Core.Configuration;

namespace ValkyrieSamlBridge.Web.Sso;

public static class PendingLoginCookie
{
    public const string Name = "__Host-saml-pending";

    public static string NewId() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static void Set(HttpContext context, string id, BridgeOptions options) =>
        context.Response.Cookies.Append(Name, id, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            MaxAge = options.PendingLoginLifetime,
        });

    public static void Clear(HttpContext context) =>
        context.Response.Cookies.Delete(Name, new CookieOptions { Secure = true, SameSite = SameSiteMode.Lax, Path = "/", HttpOnly = true });
}
