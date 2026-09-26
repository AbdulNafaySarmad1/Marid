using System.Security.Claims;

namespace Marid.Api;

public static class ExportEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/exports", Create).RequireAuthorization("exports.create");
        api.MapGet("/exports", List).RequireAuthorization("exports.read");
        api.MapGet("/exports/{id:guid}", Get).RequireAuthorization("exports.read");
        api.MapGet("/exports/{id:guid}/artifacts", Artifacts)
            .RequireAuthorization("exports.read");
        api.MapGet("/exports/{id:guid}/manifest", Manifest)
            .RequireAuthorization("exports.download");
        api.MapGet("/exports/{id:guid}/artifacts/{artifactId:guid}", Download)
            .RequireAuthorization("exports.download");
    }

    private static async Task<IResult> Create(ExportRequest input, HttpContext http,
        ClaimsPrincipal user, ExportStore store, IObjectStore objects,
        TenantAuthorization authorization, IConfiguration configuration, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.create", ct))
            return Results.Forbid();
        if (!objects.IsAvailable ||
            string.IsNullOrWhiteSpace(configuration["MARID_WORKER_CONNECTION"]))
            return Results.StatusCode(503);
        if (!ExportStore.IsValid(input))
            return Results.BadRequest(new { reason = "Use a completed UTC interval and an idempotency key." });
        var result = await store.CreateAsync(context, input,
            (string)http.Items["CorrelationId"]!,
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
        if (result.Conflict) return Results.Conflict(new { reason = "Idempotency key belongs to another interval." });
        return result.Created
            ? Results.Accepted($"/v1/exports/{result.Job.Id}", result.Job)
            : Results.Ok(result.Job);
    }

    private static async Task<IResult> List(ClaimsPrincipal user, ExportStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.read", ct))
            return Results.Forbid();
        return Results.Ok(await store.ListAsync(context, ct));
    }

    private static async Task<IResult> Get(Guid id, ClaimsPrincipal user,
        ExportStore store, TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.read", ct))
            return Results.Forbid();
        var job = await store.GetAsync(context, id, ct);
        return job is null ? Results.NotFound() : Results.Ok(job);
    }

    private static async Task<IResult> Artifacts(Guid id, ClaimsPrincipal user,
        ExportStore store, TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.read", ct))
            return Results.Forbid();
        var items = await store.ArtifactsAsync(context, id, ct);
        return items is null ? Results.NotFound() : Results.Ok(items);
    }

    private static Task<IResult> Manifest(Guid id, HttpContext http,
        ClaimsPrincipal user, ExportStore store, IObjectStore objects,
        TenantAuthorization authorization, CancellationToken ct) =>
        Open(id, null, http, user, store, objects, authorization, ct);

    private static Task<IResult> Download(Guid id, Guid artifactId,
        HttpContext http, ClaimsPrincipal user, ExportStore store,
        IObjectStore objects, TenantAuthorization authorization,
        CancellationToken ct) =>
        Open(id, artifactId, http, user, store, objects, authorization, ct);

    private static async Task<IResult> Open(Guid id, Guid? artifactId,
        HttpContext http, ClaimsPrincipal user, ExportStore store,
        IObjectStore objects, TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.download", ct))
            return Results.Forbid();
        if (!objects.IsAvailable) return Results.StatusCode(503);
        try
        {
            var item = await store.OpenArtifactAsync(context, id, artifactId,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            if (item is null) return Results.NotFound();
            var completed = false;
            http.Response.OnCompleted(async () =>
                await store.RecordDeliveryAsync(context, id, item.Value.Name,
                    completed, CancellationToken.None));
            return Results.Stream(async output =>
            {
                await using var input = item.Value.Content;
                await input.CopyToAsync(output, http.RequestAborted);
                completed = true;
            },
                item.Value.Name.EndsWith(".ndjson", StringComparison.Ordinal)
                    ? "application/x-ndjson" : item.Value.Name.EndsWith(".md", StringComparison.Ordinal)
                        ? "text/markdown; charset=utf-8" : "application/json",
                Path.GetFileName(item.Value.Name));
        }
        catch (Exception error) when (error is IOException or InvalidDataException)
        {
            return Results.StatusCode(503);
        }
    }
}
