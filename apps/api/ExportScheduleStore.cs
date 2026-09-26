using System.Security.Claims;
using Npgsql;

namespace Marid.Api;

public sealed record ExportScheduleInput(bool Enabled, int DayOfMonth);
public sealed record ExportScheduleSummary(bool Enabled, int DayOfMonth,
    DateOnly? LastEnqueuedPeriod);

public sealed class ExportScheduleStore(TenantDb tenantDb)
{
    public async Task<ExportScheduleSummary?> GetAsync(TenantContext context,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT enabled, day_of_month, last_enqueued_period
            FROM export_schedules WHERE tenant_id = @tenant_id
            """, connection, transaction);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct)
            ? new ExportScheduleSummary(reader.GetBoolean(0), reader.GetInt32(1),
                reader.IsDBNull(2) ? null : DateOnly.FromDateTime(reader.GetDateTime(2)))
            : null;
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task SetAsync(TenantContext context, ExportScheduleInput input,
        string correlationId, string traceId, CancellationToken ct)
    {
        if (input.DayOfMonth is < 1 or > 28)
            throw new ArgumentException("Day of month must be from 1 to 28.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            INSERT INTO export_schedules (tenant_id, enabled, day_of_month)
            VALUES (@tenant_id, @enabled, @day)
            ON CONFLICT (tenant_id) DO UPDATE
            SET enabled = EXCLUDED.enabled, day_of_month = EXCLUDED.day_of_month,
                updated_at = now()
            """, connection, transaction);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("enabled", input.Enabled);
        command.Parameters.AddWithValue("day", input.DayOfMonth);
        await command.ExecuteNonQueryAsync(ct);
        await AuditLedger.WriteAsync(connection, transaction, context,
            "export.schedule_changed", context.TenantId, correlationId,
            traceId, ct, outcome: input.Enabled ? "ENABLED" : "DISABLED");
        await transaction.CommitAsync(ct);
    }
}

public static class ExportScheduleEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/exports/schedule", Get).RequireAuthorization("exports.read");
        api.MapPut("/exports/schedule", Set).RequireAuthorization("exports.admin");
    }

    private static async Task<IResult> Get(ClaimsPrincipal user,
        ExportScheduleStore store, TenantAuthorization authorization,
        CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "exports.read", ct))
            return Results.Forbid();
        var schedule = await store.GetAsync(context, ct);
        return schedule is null ? Results.NotFound() : Results.Ok(schedule);
    }

    private static async Task<IResult> Set(ExportScheduleInput input,
        ClaimsPrincipal user, HttpContext http, ExportScheduleStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.Kind != PrincipalKind.Human ||
            !await authorization.IsAllowedAsync(context, "exports.admin", ct))
            return Results.Forbid();
        try
        {
            await store.SetAsync(context, input,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            return Results.NoContent();
        }
        catch (ArgumentException) { return Results.BadRequest(); }
    }
}
