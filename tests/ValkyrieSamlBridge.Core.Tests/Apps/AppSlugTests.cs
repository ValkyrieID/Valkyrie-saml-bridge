using ValkyrieSamlBridge.Core.Apps;

namespace ValkyrieSamlBridge.Core.Tests.Apps;

public sealed class AppSlugTests
{
    [Theory]
    [InlineData("payroll")]
    [InlineData("hr-portal")]
    [InlineData("a")]
    [InlineData("app2")]
    public void LowercaseSlugsWithInnerHyphensAreValid(string slug) =>
        Assert.True(AppSlug.IsValid(slug));

    [Theory]
    [InlineData("")]
    [InlineData("-payroll")]
    [InlineData("payroll-")]
    [InlineData("Payroll")]
    [InlineData("pay/roll")]
    [InlineData("pay roll")]
    [InlineData("pay..roll")]
    public void AnythingElseIsRefused(string slug) =>
        Assert.False(AppSlug.IsValid(slug));

    [Fact]
    public void SlugsLongerThan64CharactersAreRefused() =>
        Assert.False(AppSlug.IsValid(new string('a', 65)));
}
