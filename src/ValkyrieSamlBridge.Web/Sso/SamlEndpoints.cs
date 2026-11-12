using Microsoft.AspNetCore.Http;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Web.Sso;

public static class SamlEndpoints
{
    public static void MapSamlEndpoints(this WebApplication app)
    {
        app.MapGet(BridgeOptions.SsoPath, (HttpContext context, SpSsoService sso, CancellationToken cancellationToken) =>
            sso.HandleAuthnRequestAsync(context, redirectBinding: true, cancellationToken));

        // Intentionally reachable cross-site: the HTTP-POST binding needs the user agent to POST cross-site (SAML Bindings 2.0 §3.5.5).
        // Not covered by antiforgery. Adding an antiforgery opt-out here needs a security review first.
        app.MapPost(BridgeOptions.SsoPath, (HttpContext context, SpSsoService sso, CancellationToken cancellationToken) =>
            sso.HandleAuthnRequestAsync(context, redirectBinding: false, cancellationToken));

        app.MapGet(BridgeOptions.CallbackPath, (HttpContext context, LoginCallbackService callback, CancellationToken cancellationToken) =>
            callback.HandleCallbackAsync(context, cancellationToken));

        app.MapGet(BridgeOptions.IdpPathPrefix + "{slug}", (string slug, HttpContext context, IdpSsoService idp, CancellationToken cancellationToken) =>
            idp.HandleStartAsync(context, slug, cancellationToken));

        app.MapGet(BridgeOptions.MetadataPath, (BridgeOptions options, SigningIdentity identity) =>
        {
            var xml = IdpMetadata.Build(options, identity.Published);
            return Results.Content(xml, "application/samlmetadata+xml");
        });
    }
}
