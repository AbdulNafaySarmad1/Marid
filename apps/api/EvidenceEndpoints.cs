using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Features;

namespace Marid.Api;

public static class EvidenceEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/evidence", Upload).RequireAuthorization("evidence.ingest");
        api.MapGet("/evidence/{id:guid}", Get).RequireAuthorization("evidence.read");
        api.MapGet("/evidence/{id:guid}/content", Download)
            .RequireAuthorization("evidence.download");
    }

    private static async Task<IResult> Upload(HttpContext http,
        ClaimsPrincipal user, EvidenceStore store, IObjectStore objects,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "evidence.ingest", ct))
            return Results.Forbid();
        if (!objects.IsAvailable) return Results.StatusCode(503);
        var request = http.Request;
        if (request.ContentLength > EvidenceStore.MaxUploadBytes)
            return Results.StatusCode(413);
        var sizeFeature = http.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
            sizeFeature.MaxRequestBodySize = EvidenceStore.MaxUploadBytes;
        if (!DateTimeOffset.TryParse(request.Query["sourceAt"],
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var sourceAt) ||
            sourceAt.Offset != TimeSpan.Zero)
            return Results.BadRequest(new { reason = "sourceAt must be a UTC timestamp." });
        var input = new EvidenceUpload(request.Query["source"].ToString(),
            request.Query["sourceEventId"].ToString(), sourceAt,
            request.Query["sensorIdentity"].ToString(),
            request.ContentType ?? "", request.Query["parserVersion"].ToString(),
            request.Query["retentionClass"].ToString() is { Length: > 0 } value
                ? value : "RAW");
        if (!EvidenceStore.IsValid(input))
            return Results.BadRequest(new { reason = "Invalid evidence metadata." });
        try
        {
            var result = await store.UploadAsync(context, input, request.Body,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            if (result.Conflict)
                return Results.Conflict(new { reason = "Source event ID has different evidence." });
            return result.Created
                ? Results.Created($"/v1/evidence/{result.Summary.Id}", result.Summary)
                : Results.Ok(result.Summary);
        }
        catch (InvalidDataException error)
        {
            return Results.BadRequest(new { reason = error.Message });
        }
    }

    private static async Task<IResult> Get(Guid id, ClaimsPrincipal user,
        EvidenceStore store, TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "evidence.read", ct))
            return Results.Forbid();
        var item = await store.GetAsync(context, id, ct);
        return item is null ? Results.NotFound() : Results.Ok(item);
    }

    private static async Task<IResult> Download(Guid id, HttpContext http,
        ClaimsPrincipal user, EvidenceStore store, IObjectStore objects,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "evidence.download", ct))
            return Results.Forbid();
        if (!objects.IsAvailable) return Results.StatusCode(503);
        try
        {
            var item = await store.OpenAsync(context, id,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            return item is null ? Results.NotFound() : Results.Stream(item.Value.Content,
                item.Value.Metadata.ContentType, $"evidence-{id:N}.bin");
        }
        catch (Exception error) when (error is IOException or InvalidDataException)
        {
            return Results.StatusCode(503);
        }
    }
}
