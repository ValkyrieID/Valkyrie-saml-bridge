using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ValkyrieSamlBridge.Web.Sso;

// Each page sends its own strict CSP and frame-ancestors 'none'.
public static class Pages
{
    // The auto-submit script. Its SHA-256 hash is the only inline script the CSP allows.
    public const string AutoSubmitScript = "document.forms[0].submit();";

    public static readonly string AutoSubmitScriptHash =
        "sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(AutoSubmitScript)));

    public static IResult AutoPost(HttpContext context, string acsUrl, string samlXml, string? relayState)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlXml));
        var relay = relayState is null
            ? string.Empty
            : $"<input type=\"hidden\" name=\"RelayState\" value=\"{WebUtility.HtmlEncode(relayState)}\">";

        var html = $$"""
            <!doctype html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Signing you in</title></head>
            <body>
            <form method="post" action="{{WebUtility.HtmlEncode(acsUrl)}}">
            <input type="hidden" name="SAMLResponse" value="{{encoded}}">
            {{relay}}
            <noscript><p>Your browser has JavaScript turned off. Select Continue to sign in.</p></noscript>
            <button type="submit">Continue</button>
            </form>
            <script>{{AutoSubmitScript}}</script>
            </body>
            </html>
            """;

        // form-action is limited to the exact ACS URL, so the form can't be pointed anywhere else.
        SetHeaders(context, $"default-src 'none'; script-src '{AutoSubmitScriptHash}'; form-action {acsUrl}; frame-ancestors 'none'; base-uri 'none'");
        return Results.Content(html, "text/html; charset=utf-8");
    }

    public static IResult Error()
    {
        const string html = """
            <!doctype html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Sign-in could not be completed</title></head>
            <body>
            <h1>Sign-in could not be completed</h1>
            <p>The sign-in request was refused. Go back to the application and try again.</p>
            </body>
            </html>
            """;
        return Results.Content(html, "text/html; charset=utf-8", statusCode: StatusCodes.Status400BadRequest);
    }

    private static void SetHeaders(HttpContext context, string csp)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.ContentSecurityPolicy = csp;
    }
}
