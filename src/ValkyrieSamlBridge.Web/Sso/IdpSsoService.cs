using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Web.Sso;

// The IdP-initiated flow. It starts from a per-app URL, so there is no AuthnRequest. The
// response's ACS, audience, and entity ID come only from the app's stored settings, never from the
// request. Every refusal here is the local error page: nothing is sent anywhere.
public sealed class IdpSsoService(
    AppStore apps,
    PendingLoginStore pendingLogins,
    OidcClient oidc,
    BridgeOptions options,
    TimeProvider time)
{
    public async Task<IResult> HandleStartAsync(HttpContext context, string slug, CancellationToken cancellationToken)
    {
        // An unknown slug and a disabled app get the same page.
        if (!AppSlug.IsValid(slug))
        {
            return Pages.Error();
        }
        var registration = await apps.FindRegistrationBySlugAsync(slug, cancellationToken);
        if (registration is null || !registration.Enabled || registration.DefaultAcs is not { } acs)
        {
            return Pages.Error();
        }

        // RelayState is kept only when it's on the app's allow-list. Otherwise it's dropped, not refused.
        var relayValues = context.Request.Query["RelayState"];
        if (relayValues.Count > 1)
        {
            return Pages.Error();
        }
        var requestedRelay = relayValues.FirstOrDefault();
        var relayState = requestedRelay is not null && requestedRelay.Length <= BridgeOptions.MaxRelayStateLength && registration.RelayStates.Contains(requestedRelay, StringComparer.Ordinal)
            ? requestedRelay
            : null;

        // The same OIDC steps as SP-initiated, starting with prompt=none.
        AuthorizationRequest authorization;
        try
        {
            authorization = await oidc.CreateAuthorizationRequestAsync(ClaimMapper.ScopeFor(registration), "none", cancellationToken);
        }
        catch (OidcException)
        {
            // A refused provider gets the local page. Nothing is sent to the ACS.
            return Pages.Error();
        }

        var pendingId = PendingLoginCookie.NewId();
        if (!await pendingLogins.PutAsync(new PendingLogin
        {
            Id = pendingId,
            Flow = LoginFlows.IdpInitiated,
            AppEntityId = registration.EntityId,
            AcsUrl = acs.Location,
            RequestId = null,
            RelayState = relayState,
            OidcState = authorization.State,
            Nonce = authorization.Nonce,
            CodeVerifier = authorization.CodeVerifier,
            SilentAttemptPending = true,
            IsPassive = false,
            ForceAuthn = false,
            RequestedClasses = string.Empty,
            RequestedComparison = null,
            CreatedAt = time.GetUtcNow(),
            ExpiresAtUnixMs = (time.GetUtcNow() + options.PendingLoginLifetime).ToUnixTimeMilliseconds(),
        }, cancellationToken))
        {
            return Pages.Error();
        }

        PendingLoginCookie.Set(context, pendingId, options);
        return Results.Redirect(authorization.Url.AbsoluteUri);
    }
}
