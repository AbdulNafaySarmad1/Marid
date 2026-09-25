using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Marid.Api;

public static class EdgeSecurity
{
    public static IPAddress[] ParseTrustedProxies(string? value, bool development)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            if (development) return [];
            throw new InvalidOperationException("MARID_TRUSTED_PROXY_IPS must list exact edge proxy IPs.");
        }
        var parts = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length is < 1 or > 16 ||
            parts.Any(part => !IPAddress.TryParse(part, out _)))
            throw new InvalidOperationException("MARID_TRUSTED_PROXY_IPS contains an invalid IP address.");
        return parts.Select(IPAddress.Parse).Distinct().ToArray();
    }

    public static void ConfigureForwardedHeaders(ForwardedHeadersOptions options,
        IEnumerable<IPAddress> trustedProxies)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                                   ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = 1;
        options.RequireHeaderSymmetry = true;
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();
        foreach (var proxy in trustedProxies) options.KnownProxies.Add(proxy);
    }

    public static string ApiContentSecurityPolicy =>
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
}
