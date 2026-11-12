using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using ValkyrieSamlBridge.Core.Apps;

namespace ValkyrieSamlBridge.Core.Saml;

// Maps the OIDC amr values of a sign-in to a SAML AuthnContextClassRef.
// Unknown combinations map to "unspecified", so the bridge never claims more than the sign-in used.
public static class AuthnContextMapper
{
    public static string FromAmr(IEnumerable<string> amr)
    {
        var set = amr.ToHashSet(StringComparer.Ordinal);
        if (set.SetEquals(["pwd", "otp", "mfa"]))
        {
            return SamlNames.AcMobileTwoFactor;
        }
        // "pwd" alone, or "pwd mfa" for a recovery code (no standard class fits a recovery code).
        if (set.SetEquals(["pwd"]) || set.SetEquals(["pwd", "mfa"]))
        {
            return SamlNames.AcPassword;
        }
        return SamlNames.AcUnspecified;
    }

    // The bridge satisfies a request only when its class is one the SP listed. Other comparisons (minimum, better, maximum)
    // are treated the same way. That can refuse a login the SP would have accepted, which is the safe direction.
    public static bool Satisfies(IReadOnlyList<string> requested, string achieved) =>
        requested.Count == 0 || requested.Contains(achieved, StringComparer.Ordinal);
}

// Maps OIDC claims to the NameID and attributes an app asked for. Missing required
// claims refuse the login. Optional claims that are missing are left out, never sent empty.
public static class ClaimMapper
{
    // Claims an admin can change, so using them as NameID creates a new account at the app.
    public static readonly IReadOnlySet<string> MutableClaims = new HashSet<string>(StringComparer.Ordinal)
    {
        "preferred_username", "email", "name", "given_name", "family_name", "roles", "groups",
    };

    // The scope each claim needs at the OIDC provider (OIDC Core §5.4). A claim with no scope returns null.
    public static string? ScopeForClaim(string claim) => claim switch
    {
        "preferred_username" or "name" or "given_name" or "family_name" => "profile",
        "email" or "email_verified" => "email",
        "roles" => "roles",
        "groups" => "groups",
        _ => null,
    };

    // Claim names: letters, digits, and underscores; starts with a letter; 1 to 64 characters. \z (not $) refuses a trailing newline.
    private static readonly Regex ClaimNamePattern = new("^[A-Za-z][A-Za-z0-9_]{0,63}\\z", RegexOptions.CultureInvariant);

    public static bool IsValidClaimName(string name) => ClaimNamePattern.IsMatch(name);

    // Scope names an admin may request per app with `apps set --scope`. There's no list: any name in this
    // charset is accepted, and the charset keeps the scope string safe to put in a request. openid is always requested.
    private static readonly Regex ScopeNamePattern = new("^[A-Za-z0-9_.:\\-]{1,64}\\z", RegexOptions.CultureInvariant);

    public static bool IsValidScopeName(string scope) => ScopeNamePattern.IsMatch(scope);

    private static readonly string[] ScopeOrder = ["openid", "profile", "email", "roles", "groups"];

    // The scopes a login asks for. With no configured list, the default is openid plus profile and email, as the
    // claims need. roles and groups are only requested when an admin configures them.
    public static IReadOnlySet<string> GrantedScopes(string? configured, IEnumerable<string> claims)
    {
        var granted = new HashSet<string>(StringComparer.Ordinal) { "openid" };
        if (configured is null)
        {
            foreach (var claim in claims)
            {
                if (ScopeForClaim(claim) is { } scope and not ("roles" or "groups"))
                {
                    granted.Add(scope);
                }
            }
        }
        else
        {
            granted.UnionWith(configured.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        }
        return granted;
    }

    public static string ScopeFor(AppRegistration app)
    {
        var claims = new List<string>();
        if (app.NameId is { } nameId)
        {
            claims.Add(nameId.Claim);
        }
        claims.AddRange(app.Attributes.Select(a => a.Claim));
        var granted = GrantedScopes(app.RequestedScopes, claims);
        var custom = granted.Where(s => !ScopeOrder.Contains(s)).Order(StringComparer.Ordinal);
        return string.Join(' ', ScopeOrder.Where(granted.Contains).Concat(custom));
    }

    public static MappedIdentity Map(
        AppRegistration app,
        IReadOnlyDictionary<string, IReadOnlyList<string>> idTokenClaims)
    {
        var nameId = app.NameId ?? throw new SamlException("The app has no NameID claim configured.");
        var nameIdValues = Values(nameId.Claim, idTokenClaims);
        if (nameIdValues.Count != 1)
        {
            throw new SamlException("The NameID claim is missing or has more than one value.");
        }

        var attributes = new List<SamlAttributeData>();
        foreach (var setting in app.Attributes)
        {
            var values = Values(setting.Claim, idTokenClaims);
            if (values.Count == 0)
            {
                if (setting.Required)
                {
                    throw new SamlException("A required attribute claim is missing.");
                }
                continue;
            }
            attributes.Add(new SamlAttributeData(setting.Name, values));
        }

        return new MappedIdentity(nameIdValues[0], nameId.Format, attributes);
    }

    private static List<string> Values(string claim, IReadOnlyDictionary<string, IReadOnlyList<string>> idTokenClaims)
    {
        // Fail closed: only a name that follows the claim name rule is read.
        if (!IsValidClaimName(claim))
        {
            throw new SamlException("The mapped claim name is not valid.");
        }

        return idTokenClaims.TryGetValue(claim, out var fromIdToken) ? fromIdToken.Where(v => v.Length > 0).ToList() : [];
    }
}

public sealed record MappedIdentity(string NameId, string NameIdFormat, IReadOnlyList<SamlAttributeData> Attributes);

public sealed record SamlAttributeData(string Name, IReadOnlyList<string> Values);

public static class SigningCertificate
{
    public const int KeySize = 2048;
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(5 * 365);

    public static (byte[] PrivateKeyPkcs8, byte[] CertificateDer) Create(TimeProvider time, string commonName)
    {
        using var rsa = RSA.Create(KeySize);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = time.GetUtcNow();
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now + Lifetime);
        return (rsa.ExportPkcs8PrivateKey(), certificate.Export(X509ContentType.Cert));
    }

    public static X509Certificate2 Load(byte[] privateKeyPkcs8, byte[] certificateDer)
    {
        using var certificate = X509CertificateLoader.LoadCertificate(certificateDer);
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKeyPkcs8, out _);
        return certificate.CopyWithPrivateKey(rsa);
    }
}

