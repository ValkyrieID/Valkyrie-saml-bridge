using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Web.Sso;

// The OIDC callback for both flows. Every refusal is either the
// local error page, or a SAML error response to the ACS for an SP-initiated login. An IdP-initiated
// login has no request to answer, so its refusals are always the local page.
public sealed class LoginCallbackService(
    AppStore apps,
    PendingLoginStore pendingLogins,
    OidcClient oidc,
    ResponseBuilder responses,
    BridgeOptions options)
{
    public async Task<IResult> HandleCallbackAsync(HttpContext context, CancellationToken cancellationToken)
    {
        if (!context.Request.Cookies.TryGetValue(PendingLoginCookie.Name, out var pendingId) || string.IsNullOrEmpty(pendingId))
        {
            return Pages.Error();
        }

        // Single use: the row stays consumed until it expires, whatever happens next.
        var login = await pendingLogins.TakeAsync(pendingId, cancellationToken);
        PendingLoginCookie.Clear(context);
        if (login is null)
        {
            return Pages.Error();
        }

        var registration = await apps.FindRegistrationByEntityIdAsync(login.AppEntityId, cancellationToken);
        if (registration is null || !registration.Enabled)
        {
            return Pages.Error();
        }

        var expected = new AuthorizationRequest(new Uri(options.CallbackUrl), login.OidcState, login.Nonce, login.CodeVerifier);
        var callbackUri = new Uri(options.CallbackUrl + context.Request.QueryString.Value);

        ValidatedIdToken token;
        try
        {
            token = await oidc.CompleteAuthorizationAsync(callbackUri, expected, cancellationToken);
        }
        catch (OidcException error) when (error.ErrorCode is not null)
        {
            var noSignIn = error.ErrorCode is "login_required" or "interaction_required";
            if (login.SilentAttemptPending && noSignIn)
            {
                // No session at the OIDC provider, so ask again with the sign-in page.
                AuthorizationRequest retry;
                try
                {
                    retry = await oidc.CreateAuthorizationRequestAsync(ClaimMapper.ScopeFor(registration), null, cancellationToken);
                }
                catch (OidcException)
                {
                    // The provider now refuses. The same refusal as a failed sign-in, which is the local page for IdP-initiated logins.
                    return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
                }
                login.OidcState = retry.State;
                login.Nonce = retry.Nonce;
                login.CodeVerifier = retry.CodeVerifier;
                login.SilentAttemptPending = false;
                if (!await pendingLogins.ResumeAsync(login, cancellationToken))
                {
                    return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
                }
                PendingLoginCookie.Set(context, pendingId, options);
                return Results.Redirect(retry.Url.AbsoluteUri);
            }

            var status = login.IsPassive && noSignIn ? SamlNames.StatusNoPassive : SamlNames.StatusAuthnFailed;
            return Failure(login, SamlNames.StatusResponder, status, context);
        }
        catch (OidcCallbackRejectedException)
        {
            // RFC 9207 §2.4: a response with a wrong iss or state, or a repeated parameter, may not be this login's.
            // It gets the local page, never a SAML response, even for an SP-initiated login.
            return Pages.Error();
        }
        catch (OidcException)
        {
            // A refusal after the response was checked: discovery, token, ID token, or nonce.
            // Failure() sends a SAML error to the validated ACS for an SP-initiated login, and the local page otherwise.
            return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
        }

        if (ClaimValues.AuthTime(token.Claims) is not { } authTime)
        {
            // AuthnInstant comes from auth_time, and the OIDC provider always sends it. Without it, refuse.
            return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
        }

        if (login.ForceAuthn && DateTimeOffset.FromUnixTimeSeconds(authTime) < login.CreatedAt - options.ClockSkew)
        {
            // SAML Core §3.4.1.1: ForceAuthn needs a fresh sign-in. A session older than the request isn't one, so refuse.
            return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
        }

        var idClaims = ClaimValues.FromTokenClaims(token.Claims);

        try
        {
            var identity = ClaimMapper.Map(registration, idClaims);
            var amr = idClaims.TryGetValue("amr", out var values) ? values : [];
            var authnClass = AuthnContextMapper.FromAmr(amr);
            var requested = login.RequestedClasses.Length == 0
                ? []
                : login.RequestedClasses.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (!AuthnContextMapper.Satisfies(requested, authnClass))
            {
                return Failure(login, SamlNames.StatusResponder, SamlNames.StatusNoAuthnContext, context);
            }

            var built = responses.BuildAuthnResponse(new AssertionContent(
                NameId: identity.NameId,
                NameIdFormat: identity.NameIdFormat,
                Attributes: identity.Attributes,
                AuthnContextClass: authnClass,
                AuthnInstant: DateTimeOffset.FromUnixTimeSeconds(authTime),
                InResponseTo: login.RequestId,
                Audience: registration.EntityId,
                AcsUrl: login.AcsUrl));

            return Pages.AutoPost(context, login.AcsUrl, built.Xml, login.RelayState);
        }
        catch (Exception error) when (error is SamlException or OidcException)
        {
            // A required claim is missing. The SP gets a generic failure, never a partial assertion.
            return Failure(login, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, context);
        }
    }

    // SAML error for SP-initiated logins only. An IdP-initiated login gets the local page.
    private IResult Failure(PendingLogin login, string topLevel, string secondLevel, HttpContext context)
    {
        if (login.Flow == LoginFlows.IdpInitiated)
        {
            return Pages.Error();
        }

        var built = responses.BuildErrorResponse(topLevel, secondLevel, login.AcsUrl, login.RequestId);
        return Pages.AutoPost(context, login.AcsUrl, built.Xml, login.RelayState);
    }
}
