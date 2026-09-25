using System.Net;
using Marid.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace Marid.Api.Tests;

public sealed class EdgeSecurityTests
{
    [Fact]
    public void Production_requires_explicit_proxy_addresses()
    {
        Assert.Throws<InvalidOperationException>(() =>
            EdgeSecurity.ParseTrustedProxies(null, development: false));
        Assert.Throws<InvalidOperationException>(() =>
            EdgeSecurity.ParseTrustedProxies("0.0.0.0/0", development: false));
        Assert.Equal(IPAddress.Loopback,
            EdgeSecurity.ParseTrustedProxies("127.0.0.1", development: false)[0]);
    }

    [Fact]
    public void Forwarded_headers_trust_only_configured_exact_ips()
    {
        var options = new ForwardedHeadersOptions();
        EdgeSecurity.ConfigureForwardedHeaders(options, [IPAddress.Parse("10.8.0.7")]);
        Assert.Single(options.KnownProxies);
        Assert.Empty(options.KnownIPNetworks);
        Assert.Equal(1, options.ForwardLimit);
        Assert.Equal(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            options.ForwardedHeaders);
    }

    [Fact]
    public void Api_csp_disallows_dynamic_content()
    {
        Assert.Contains("default-src 'none'", EdgeSecurity.ApiContentSecurityPolicy);
        Assert.Contains("frame-ancestors 'none'", EdgeSecurity.ApiContentSecurityPolicy);
    }
}
