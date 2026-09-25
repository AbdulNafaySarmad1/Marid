using System.Net;
using System.Text;
using Marid.Api;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Marid.Api.Tests;

public sealed class TurnstileTests
{
    [Fact]
    public void Configuration_rejects_silent_degradation()
    {
        var invalid = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["TURNSTILE_ENABLED"] = "perhaps" }).Build();
        Assert.Throws<InvalidOperationException>(() => TurnstileConfiguration.Read(invalid, false));
        var missing = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["TURNSTILE_ENABLED"] = "true" }).Build();
        Assert.Throws<InvalidOperationException>(() => TurnstileConfiguration.Read(missing, false));
    }

    [Fact]
    public async Task Valid_siteverify_response_requires_correct_host_and_action()
    {
        var now = DateTimeOffset.UtcNow;
        var body = $"{{\"success\":true,\"hostname\":\"soc.example.com\",\"action\":\"contact\",\"challenge_ts\":\"{now:O}\"}}";
        var verifier = Create(body);
        Assert.Equal(TurnstileOutcome.Valid,
            await verifier.VerifyAsync("sample-token", "contact", IPAddress.Loopback, default));
    }

    [Theory]
    [InlineData("{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\"]}", TurnstileOutcome.Invalid)]
    [InlineData("{\"success\":true,\"hostname\":\"other.example.com\"}", TurnstileOutcome.HostnameMismatch)]
    [InlineData("{\"success\":true,\"hostname\":\"soc.example.com\",\"challenge_ts\":\"2020-01-01T00:00:00Z\",\"action\":\"contact\"}", TurnstileOutcome.Expired)]
    [InlineData("not-json", TurnstileOutcome.Malformed)]
    public async Task Invalid_or_malformed_provider_results_fail_closed(
        string body, TurnstileOutcome expected)
    {
        Assert.Equal(expected,
            await Create(body).VerifyAsync("sample-token", "contact", null, default));
    }

    [Fact]
    public async Task Provider_failure_and_oversized_tokens_fail_closed()
    {
        var verifier = Create("unavailable", HttpStatusCode.ServiceUnavailable);
        Assert.Equal(TurnstileOutcome.Unavailable,
            await verifier.VerifyAsync("sample-token", null, null, default));
        Assert.Equal(TurnstileOutcome.Invalid,
            await verifier.VerifyAsync(new string('x', 2049), null, null, default));
    }

    private static TurnstileVerifier Create(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var client = new HttpClient(new StubHandler(body, status));
        var settings = new TurnstileSettings("public-site-key", "/run/secrets/marid/turnstile",
            new HashSet<string>(StringComparer.Ordinal) { "soc.example.com" });
        return new TurnstileVerifier(client, settings,
            (_, _) => Task.FromResult("server-side-secret"), TimeProvider.System,
            NullLogger<TurnstileVerifier>.Instance);
    }

    private sealed class StubHandler(string body, HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.Equal(TurnstileVerifier.SiteverifyUri, request.RequestUri);
            Assert.Equal(HttpMethod.Post, request.Method);
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }
}
