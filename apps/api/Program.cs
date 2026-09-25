using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.HttpOverrides;
using Marid.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 1_048_576);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
});
var oidcAuthority = builder.Configuration["MARID_OIDC_AUTHORITY"]
    ?? throw new InvalidOperationException("MARID_OIDC_AUTHORITY must be configured.");
var connectionString = builder.Configuration.GetConnectionString("Marid")
    ?? throw new InvalidOperationException("ConnectionStrings__Marid must be configured.");
ProductionConfigurationValidator.Validate(builder.Environment.IsDevelopment(),
    oidcAuthority, connectionString);
var trustedProxies = EdgeSecurity.ParseTrustedProxies(
    builder.Configuration["MARID_TRUSTED_PROXY_IPS"], builder.Environment.IsDevelopment());
var turnstileSettings = TurnstileConfiguration.Read(
    builder.Configuration, builder.Environment.IsDevelopment());
if (turnstileSettings is not null)
{
    builder.Services.AddSingleton(turnstileSettings);
    builder.Services.AddSingleton(new HttpClient());
    builder.Services.AddSingleton(sp => new TurnstileVerifier(
        sp.GetRequiredService<HttpClient>(), turnstileSettings,
        File.ReadAllTextAsync, TimeProvider.System,
        sp.GetRequiredService<ILogger<TurnstileVerifier>>()));
}
builder.Services.Configure<ForwardedHeadersOptions>(options =>
    EdgeSecurity.ConfigureForwardedHeaders(options, trustedProxies));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = oidcAuthority;
        options.Audience = builder.Configuration["MARID_OIDC_AUDIENCE"] ?? "marid-api";
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.MapInboundClaims = false;
    });
builder.Services.AddAuthorization(options =>
{
    foreach (var scope in new[] { "events.ingest", "incidents.read", "incidents.write",
                                 "response.read", "response.propose", "deployment.domains.read" })
        options.AddPolicy(scope, policy => policy.RequireAuthenticatedUser()
            .RequireAssertion(context => ScopeAuthorizer.HasScope(context.User, scope)));
    options.AddPolicy("response.approve", policy => policy.RequireAuthenticatedUser()
        .RequireAssertion(context => ScopeAuthorizer.HasScope(context.User, "response.approve") &&
                                     context.User.FindFirstValue("actor_type") == "human"));
});

builder.Services.AddSingleton(NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton<TenantStore>();
builder.Services.AddSingleton<PolicyEngine>();
builder.Services.AddSingleton<DecisionStore>();
builder.Services.AddSingleton<TenantAuthorization>();
builder.Services.AddSingleton<DomainIssuanceStore>();
builder.Services.AddSingleton<DeploymentDomainStore>();

var app = builder.Build();
app.UseForwardedHeaders();
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Content-Security-Policy"] = EdgeSecurity.ApiContentSecurityPolicy;
    context.Response.Headers["Cache-Control"] = "no-store";
    if (context.Request.IsHttps &&
        builder.Configuration["MARID_HSTS_ENABLED"] == "true")
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";
    await next(context);
});
app.Use(async (context, next) =>
{
    var requested = context.Request.Headers["X-Correlation-ID"].ToString();
    var correlationId = Guid.TryParse(requested, out var parsed) ? parsed : Guid.NewGuid();
    context.Items["CorrelationId"] = correlationId.ToString();
    context.Response.Headers["X-Correlation-ID"] = correlationId.ToString();
    await next(context);
});
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
// Called only by the co-located TLS edge. The public reverse proxy denies /internal/*.
app.MapGet("/internal/tls/allow", async (string? domain,
    DomainIssuanceStore domains, CancellationToken ct) =>
    await domains.IsAllowedAsync(domain, ct) ? Results.Ok() : Results.NotFound());
app.MapGet("/health/ready", async (NpgsqlDataSource dataSource, CancellationToken ct) =>
{
    try
    {
        return await DatabaseAuthorityValidator.IsValidAsync(dataSource, ct)
            ? Results.Ok(new { status = "ready" })
            : Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
    catch (Exception)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});

var api = app.MapGroup("/v1");
api.MapGet("/deployment/domains", async (ClaimsPrincipal user,
    DeploymentDomainStore domains, TenantAuthorization authorization, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "deployment.domains.read", ct))
        return Results.Forbid();
    return Results.Ok(await domains.ListAsync(context, ct));
}).RequireAuthorization("deployment.domains.read");
api.MapPost("/events", async (SecurityEventInput input, ClaimsPrincipal user,
    TenantStore store, TenantAuthorization authorization, HttpContext http, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "events.ingest", ct)) return Results.Forbid();
    var errors = EventValidator.Validate(input);
    if (errors.Count > 0) return Results.ValidationProblem(errors);
    var result = await store.IngestEventAsync(context, input,
        System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier,
        (string)http.Items["CorrelationId"]!, ct);
    if (result.ConflictingDuplicate)
        return Results.Conflict(new { reason = "Source event ID is already used for different content." });
    return result.Created
        ? Results.Created($"/v1/events/{result.EventId}", result)
        : Results.Ok(result);
}).RequireAuthorization("events.ingest");

api.MapGet("/incidents", async (ClaimsPrincipal user, TenantStore store,
    TenantAuthorization authorization, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "incidents.read", ct)) return Results.Forbid();
    return Results.Ok(await store.ListIncidentsAsync(context, ct));
}).RequireAuthorization("incidents.read");

api.MapPost("/incidents", async (CreateIncidentInput input, ClaimsPrincipal user,
    TenantStore store, TenantAuthorization authorization, HttpContext http, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "incidents.write", ct)) return Results.Forbid();
    if (string.IsNullOrWhiteSpace(input.Title) || input.Title.Length > 200)
        return Results.ValidationProblem(new Dictionary<string, string[]> {
            ["title"] = ["Title must have 1 to 200 characters."]
        });
    if (!Enum.TryParse<IncidentSeverity>(input.Severity, true, out var severity) ||
        !Enum.GetNames<IncidentSeverity>().Any(name =>
            name.Equals(input.Severity, StringComparison.OrdinalIgnoreCase)))
        return Results.ValidationProblem(new Dictionary<string, string[]> {
            ["severity"] = ["Severity must be Low, Medium, High, or Critical."]
        });
    var incident = await store.CreateIncidentAsync(context, input.Title.Trim(), severity,
        (string)http.Items["CorrelationId"]!,
        System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
    return Results.Created($"/v1/incidents/{incident.Id}", incident);
}).RequireAuthorization("incidents.write");

api.MapPost("/response/proposals", async (ResponseProposalInput input,
    ClaimsPrincipal user, DecisionStore store, TenantAuthorization authorization,
    HttpContext http, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "response.propose", ct)) return Results.Forbid();
    var errors = ProposalValidator.Validate(input);
    if (errors.Count > 0) return Results.ValidationProblem(errors);
    var result = await store.ProposeAsync(context, input,
        (string)http.Items["CorrelationId"]!,
        System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
    return result.ProposalId is Guid id
        ? Results.Created($"/v1/response/proposals/{id}", result)
        : Results.Ok(result);
}).RequireAuthorization("response.propose");

api.MapGet("/response/proposals", async (ClaimsPrincipal user, DecisionStore store,
    TenantAuthorization authorization, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "response.read", ct)) return Results.Forbid();
    return Results.Ok(await store.ListAsync(context, ct));
}).RequireAuthorization("response.read");

api.MapPost("/response/proposals/{proposalId:guid}/decisions", async (
    Guid proposalId, ApprovalInput input, ClaimsPrincipal user, DecisionStore store,
    TenantAuthorization authorization, HttpContext http, CancellationToken ct) =>
{
    if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
    if (!await authorization.IsAllowedAsync(context, "response.approve", ct)) return Results.Forbid();
    var choice = input.Decision switch
    {
        "APPROVE" => ApprovalChoice.Approve,
        "REJECT" => ApprovalChoice.Reject,
        "REQUEST_MORE_EVIDENCE" => ApprovalChoice.RequestMoreEvidence,
        _ => (ApprovalChoice?)null
    };
    if (choice is null)
        return Results.ValidationProblem(new Dictionary<string, string[]> {
            ["decision"] = ["Use APPROVE, REJECT, or REQUEST_MORE_EVIDENCE."]
        });
    var result = await store.DecideAsync(context, proposalId, choice.Value,
        (string)http.Items["CorrelationId"]!,
        System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
    return result.Status switch
    {
        ApprovalWriteStatus.Created => Results.Created(
            $"/v1/response/proposals/{proposalId}/decisions/{result.Value!.Id}", result.Value),
        ApprovalWriteStatus.NotFound => Results.NotFound(),
        _ => Results.Conflict(new { reason = result.Reason })
    };
}).RequireAuthorization("response.approve");

await DatabaseAuthorityValidator.EnsureAsync(
    app.Services.GetRequiredService<NpgsqlDataSource>(), CancellationToken.None);
app.Run();

public partial class Program;
