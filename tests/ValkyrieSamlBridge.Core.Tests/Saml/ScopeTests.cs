using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Core.Tests.Saml;

// The bridge asks the OIDC provider only for the scopes an app's mappings need.
public sealed class ScopeForTests
{
    [Fact]
    public void ASubjectOnlyAppRequestsOnlyOpenId()
    {
        Assert.Equal("openid", ClaimMapper.ScopeFor(SamlTestData.Registration()));
    }

    [Fact]
    public void AnEmailAttributeAddsTheEmailScopeOnly()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("mail", "email", Required: false)]);

        Assert.Equal("openid email", ClaimMapper.ScopeFor(app));
    }

    [Fact]
    public void ProfileClaimsAddTheProfileScope()
    {
        var app = SamlTestData.Registration(nameId: new NameIdSetting("preferred_username", SamlNames.NameIdPersistent));

        Assert.Equal("openid profile", ClaimMapper.ScopeFor(app));
    }

    [Fact]
    public void RolesAndGroupsAddNoScopeByDefault()
    {
        var app = SamlTestData.Registration(attributes:
        [
            new AttributeSetting("groups", "groups", Required: false),
            new AttributeSetting("roles", "roles", Required: false),
        ]);

        Assert.Equal("openid", ClaimMapper.ScopeFor(app));
    }

    // An admin can request roles and groups for one app. The configured list is used as set.
    [Fact]
    public void AConfiguredScopeListIsRequestedAsSet()
    {
        var app = SamlTestData.Registration(requestedScopes: "roles groups", attributes:
        [
            new AttributeSetting("groups", "groups", Required: false),
            new AttributeSetting("roles", "roles", Required: false),
        ]);

        Assert.Equal("openid roles groups", ClaimMapper.ScopeFor(app));
    }
}

public sealed class ScopeNameTests
{
    // A scope the admin adds is requested after the standard scopes.
    [Fact]
    public void ACustomScopeIsRequestedAfterTheStandardScopes()
    {
        var app = SamlTestData.Registration(
            attributes: [new AttributeSetting("mail", "email", Required: false)],
            requestedScopes: "department email");

        Assert.Equal("openid email department", ClaimMapper.ScopeFor(app));
    }

    [Theory]
    [InlineData("department")]
    [InlineData("dept:read")]
    [InlineData("a.b-c_d")]
    [InlineData("x")]
    public void ValidScopeNamesAreAccepted(string scope) => Assert.True(ClaimMapper.IsValidScopeName(scope));

    // Attack: a scope is put into the authorization request, so spaces, quotes, and other punctuation are refused.
    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("quo\"te")]
    [InlineData("semi;colon")]
    [InlineData("slash/path")]
    [InlineData("new\nline")]
    [InlineData("a&b")]
    public void InvalidScopeNamesAreRefused(string scope) => Assert.False(ClaimMapper.IsValidScopeName(scope));

    [Fact]
    public void AScopeOfSixtyFourCharactersIsAcceptedAndSixtyFiveIsRefused()
    {
        Assert.True(ClaimMapper.IsValidScopeName(new string('s', 64)));
        Assert.False(ClaimMapper.IsValidScopeName(new string('s', 65)));
    }
}
