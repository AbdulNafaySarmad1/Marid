using System.Net;
using System.Text.Json;

namespace Marid.Api;

public sealed record TurnstileSettings(string SiteKey, string SecretRef,
    IReadOnlySet<string> ExpectedHostnames);

public static class TurnstileConfiguration
{
    public static TurnstileSettings? Read(IConfiguration config, bool development)
    {
        var enabledText = config["TURNSTILE_ENABLED"];
        if (enabledText is null) return null;
        if (!bool.TryParse(enabledText, out var enabled))
            throw new InvalidOperationException("TURNSTILE_ENABLED must be true or false.");
        if (!enabled) return null;
        var siteKey = config["TURNSTILE_SITE_KEY"];
        var secretRef = config["TURNSTILE_SECRET_REF"];
        var hosts = (config["TURNSTILE_EXPECTED_HOSTNAMES"] ?? "")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(host => host.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(siteKey) || siteKey.Length > 200 ||
            string.IsNullOrWhiteSpace(secretRef) || !Path.IsPathFullyQualified(secretRef) ||
            (!development && !secretRef.StartsWith("/run/secrets/", StringComparison.Ordinal)) ||
            hosts.Count == 0 || hosts.Any(host => host.Length > 253 ||
                host.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-')))
            throw new InvalidOperationException("Turnstile configuration is incomplete or unsafe.");
        return new TurnstileSettings(siteKey, secretRef, hosts);
    }
}

public enum TurnstileOutcome
{
    Valid, Invalid, HostnameMismatch, Expired, Malformed, Unavailable
}

public sealed class TurnstileVerifier(HttpClient client, TurnstileSettings settings,
    Func<string, CancellationToken, Task<string>> readSecret,
    TimeProvider timeProvider, ILogger<TurnstileVerifier> logger)
{
    public static readonly Uri SiteverifyUri =
        new("https://challenges.cloudflare.com/turnstile/v0/siteverify");

    public async Task<TurnstileOutcome> VerifyAsync(string? token,
        string? expectedAction, IPAddress? remoteIp, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 2048)
            return Record(TurnstileOutcome.Invalid);
        try
        {
            var secret = (await readSecret(settings.SecretRef, ct)).Trim();
            if (secret.Length is < 1 or > 512) return Record(TurnstileOutcome.Unavailable);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            using var request = new HttpRequestMessage(HttpMethod.Post, SiteverifyUri);
            var fields = new Dictionary<string, string>
            {
                ["secret"] = secret,
                ["response"] = token,
                ["idempotency_key"] = Guid.NewGuid().ToString()
            };
            if (remoteIp is not null) fields["remoteip"] = remoteIp.ToString();
            request.Content = new FormUrlEncodedContent(fields);
            using var response = await client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode) return Record(TurnstileOutcome.Unavailable);
            await response.Content.LoadIntoBufferAsync(8192, timeout.Token);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var document = await JsonDocument.ParseAsync(stream,
                new JsonDocumentOptions { MaxDepth = 16 }, timeout.Token);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("success", out var success) ||
                success.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return Record(TurnstileOutcome.Malformed);
            if (success.ValueKind == JsonValueKind.False)
                return Record(TurnstileOutcome.Invalid);
            if (!root.TryGetProperty("hostname", out var hostname) ||
                hostname.ValueKind != JsonValueKind.String ||
                !settings.ExpectedHostnames.Contains(hostname.GetString()!.ToLowerInvariant()))
                return Record(TurnstileOutcome.HostnameMismatch);
            if (!root.TryGetProperty("challenge_ts", out var challenge) ||
                challenge.ValueKind != JsonValueKind.String ||
                !DateTimeOffset.TryParse(challenge.GetString(), out var timestamp))
                return Record(TurnstileOutcome.Malformed);
            var age = timeProvider.GetUtcNow() - timestamp;
            if (age < TimeSpan.FromSeconds(-30) || age > TimeSpan.FromMinutes(5))
                return Record(TurnstileOutcome.Expired);
            if (expectedAction is not null &&
                (!root.TryGetProperty("action", out var action) ||
                 action.ValueKind != JsonValueKind.String ||
                 action.GetString() != expectedAction))
                return Record(TurnstileOutcome.Invalid);
            return Record(TurnstileOutcome.Valid);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Record(TurnstileOutcome.Unavailable);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or
                                   UnauthorizedAccessException)
        {
            return Record(ex is JsonException ? TurnstileOutcome.Malformed : TurnstileOutcome.Unavailable);
        }
    }

    private TurnstileOutcome Record(TurnstileOutcome outcome)
    {
        if (outcome != TurnstileOutcome.Valid)
            logger.LogWarning("Turnstile validation outcome {Outcome}", outcome);
        return outcome;
    }
}
