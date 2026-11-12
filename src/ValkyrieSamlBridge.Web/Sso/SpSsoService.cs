using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Web.Sso;

// The SP-initiated flow's request side. The callback is LoginCallbackService.
// Every refusal is either a local error page, when the ACS isn't validated, or a SAML error response
// to the validated ACS. Nothing is redirected or posted to a URL that wasn't validated.
public sealed class SpSsoService(
    AppStore apps,
    PendingLoginStore pendingLogins,
    OidcClient oidc,
    ResponseBuilder responses,
    BridgeOptions options,
    TimeProvider time)
{
    public async Task<IResult> HandleAuthnRequestAsync(HttpContext context, bool redirectBinding, CancellationToken cancellationToken)
    {
        var request = context.Request;
        string? encoded;
        string? relayState;
        string? rawRedirectQuery = null;
        if (redirectBinding)
        {
            if (request.Query["SAMLRequest"].Count != 1 || request.Query["RelayState"].Count > 1)
            {
                return Pages.Error();
            }
            encoded = request.Query["SAMLRequest"][0];
            relayState = request.Query["RelayState"].FirstOrDefault();
            rawRedirectQuery = request.QueryString.Value;
        }
        else
        {
            if (!request.HasFormContentType)
            {
                return Pages.Error();
            }
            if (request.ContentLength > BridgeOptions.MaxSsoRequestBytes)
            {
                return TooLarge();
            }
            // Kestrel enforces the cap while the form is read, so a chunked body can't exceed it either.
            if (request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
            {
                limit.MaxRequestBodySize = BridgeOptions.MaxSsoRequestBytes;
            }
            IFormCollection form;
            try
            {
                form = await request.ReadFormAsync(cancellationToken);
            }
            catch (BadHttpRequestException error) when (error.StatusCode == StatusCodes.Status413PayloadTooLarge)
            {
                return TooLarge();
            }
            if (form["SAMLRequest"].Count != 1 || form["RelayState"].Count > 1)
            {
                return Pages.Error();
            }
            encoded = form["SAMLRequest"][0];
            relayState = form["RelayState"].FirstOrDefault();
        }

        if (string.IsNullOrEmpty(encoded) || relayState?.Length > BridgeOptions.MaxRelayStateLength)
        {
            return Pages.Error();
        }

        AuthnRequestMessage message;
        System.Xml.XmlDocument document;
        try
        {
            var xml = redirectBinding ? SamlMessageEncoding.InflateRedirect(encoded) : SamlMessageEncoding.DecodePost(encoded);
            document = SafeXml.Parse(xml);
            message = AuthnRequestParser.Parse(document);
        }
        catch (Exception error) when (error is SamlException or SamlRequestException)
        {
            return Pages.Error();
        }

        var registration = await apps.FindRegistrationByEntityIdAsync(message.Issuer, cancellationToken);
        if (registration is null)
        {
            return Pages.Error();
        }

        ValidatedAuthnRequest validated;
        try
        {
            validated = AuthnRequestValidator.Validate(message, document, rawRedirectQuery, registration, relayState, options, time.GetUtcNow());
        }
        catch (SamlRequestException error)
        {
            return ErrorResponse(error.AcsUrl, error.RequestId, SamlNames.StatusRequester, null, relayState, context);
        }
        if (message.ForceAuthn && message.IsPassive)
        {
            return ErrorResponse(validated.AcsUrl, message.Id, SamlNames.StatusRequester, null, relayState, context);
        }

        // Each request ID is accepted once. The unique RequestId index refuses a second pending login
        // for it, and the SP gets the local page, not a SAML response.
        // Prompt is prompt=none first, unless the SP forced re-authentication (ForceAuthn).
        var prompt = message.ForceAuthn ? "login" : "none";
        AuthorizationRequest authorization;
        try
        {
            authorization = await oidc.CreateAuthorizationRequestAsync(ClaimMapper.ScopeFor(registration), prompt, cancellationToken);
        }
        catch (OidcException)
        {
            // A provider that fails the compliance checks is refused. The SP gets the same error as a failed sign-in.
            return ErrorResponse(validated.AcsUrl, message.Id, SamlNames.StatusResponder, SamlNames.StatusAuthnFailed, relayState, context);
        }

        var pendingId = PendingLoginCookie.NewId();
        if (!await pendingLogins.PutAsync(new PendingLogin
        {
            Id = pendingId,
            Flow = LoginFlows.SpInitiated,
            AppEntityId = registration.EntityId,
            AcsUrl = validated.AcsUrl,
            RequestId = message.Id,
            RelayState = validated.RelayState,
            OidcState = authorization.State,
            Nonce = authorization.Nonce,
            CodeVerifier = authorization.CodeVerifier,
            SilentAttemptPending = !message.ForceAuthn && !message.IsPassive,
            IsPassive = message.IsPassive,
            ForceAuthn = message.ForceAuthn,
            RequestedClasses = string.Join('\n', message.RequestedContextClasses),
            RequestedComparison = message.RequestedComparison,
            CreatedAt = time.GetUtcNow(),
            ExpiresAtUnixMs = (time.GetUtcNow() + options.PendingLoginLifetime).ToUnixTimeMilliseconds(),
        }, cancellationToken))
        {
            return Pages.Error();
        }

        PendingLoginCookie.Set(context, pendingId, options);
        return Results.Redirect(authorization.Url.AbsoluteUri);
    }

    private IResult ErrorResponse(string? acsUrl, string? requestId, string topLevel, string? secondLevel, string? relayState, HttpContext context)
    {
        // Without a validated ACS there's nowhere safe to send the error.
        if (acsUrl is null)
        {
            return Pages.Error();
        }

        var built = responses.BuildErrorResponse(topLevel, secondLevel, acsUrl, requestId);
        return Pages.AutoPost(context, acsUrl, built.Xml, relayState);
    }

    // An oversized request has no validated ACS, so it gets a status code and no response (fail closed).
    private static IResult TooLarge() => Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
}
