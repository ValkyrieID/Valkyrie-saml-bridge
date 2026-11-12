using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Core.Tests.Saml;

// A claim name is letters, digits, and underscores, starts with a letter, and is 1 to 64 characters.
// `apps set` refuses any other name, and the login never reads one.
public sealed class ClaimNameTests
{
    [Theory]
    [InlineData("email")]
    [InlineData("A")]
    [InlineData("department")]
    [InlineData("cost_center")]
    [InlineData("x1_2")]
    public void ValidClaimNamesAreAccepted(string name) => Assert.True(ClaimMapper.IsValidClaimName(name));

    // Attack: a name that could be a path, a header, or a number is refused.
    [Theory]
    [InlineData("")]
    [InlineData("1st")]
    [InlineData("_private")]
    [InlineData("cost-center")]
    [InlineData("dept.code")]
    [InlineData("has space")]
    [InlineData("trailing\n")]
    public void InvalidClaimNamesAreRefused(string name) => Assert.False(ClaimMapper.IsValidClaimName(name));

    [Fact]
    public void ASixtyFourCharacterNameIsAcceptedAndSixtyFiveIsRefused()
    {
        Assert.True(ClaimMapper.IsValidClaimName("a" + new string('b', 63)));
        Assert.False(ClaimMapper.IsValidClaimName("a" + new string('b', 64)));
    }

    [Fact]
    public void AnArbitraryValidClaimNameIsMappedFromTheIdToken()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("cc", "cost_center", Required: true)]);
        var idToken = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["sub"] = ["user-1"], ["cost_center"] = ["42"] };

        var identity = ClaimMapper.Map(app, idToken);

        Assert.Equal(["42"], identity.Attributes[0].Values);
    }

    // Attack: a mapped name that breaks the rule is refused at login, even when the ID token carries a value for it.
    [Fact]
    public void AMappedNameThatBreaksTheRuleIsRefused()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("cc", "cost-center", Required: false)]);
        var idToken = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["cost-center"] = ["42"] };

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, idToken));
    }
}
