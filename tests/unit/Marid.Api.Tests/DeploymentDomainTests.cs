namespace Marid.Api.Tests;

public sealed class DeploymentDomainTests
{
    [Theory]
    [InlineData("soc.example.com", "soc.example.com")]
    [InlineData("SECURITY.Example.COM.", "security.example.com")]
    [InlineData("marid.example.com", "marid.example.com")]
    [InlineData("example.com:443", null)]
    [InlineData("localhost", null)]
    [InlineData("127.0.0.1", null)]
    [InlineData("a..example.com", null)]
    [InlineData("-a.example.com", null)]
    [InlineData("evil.example.internal", null)]
    [InlineData("*.example.com", null)]
    public void Public_hostname_validation(string input, string? expected) =>
        Assert.Equal(expected, DeploymentDomains.NormalizeHostname(input));

    [Fact]
    public void Txt_challenge_must_match_one_complete_record()
    {
        const string token = "abc123";
        Assert.True(DeploymentDomains.MatchesTxt(
            new[] { new[] { "marid-domain-", "verification=abc123" } }, token));
        Assert.False(DeploymentDomains.MatchesTxt(
            new[] { new[] { "marid-domain-verification=abc123-extra" } }, token));
        Assert.False(DeploymentDomains.MatchesTxt(
            new[] { new[] { "abc123" } }, token));
    }
}
