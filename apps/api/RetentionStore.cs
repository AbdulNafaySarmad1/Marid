using System.Security.Claims;
using Npgsql;

namespace Marid.Api;

public sealed record RetentionPolicySummary(string Category, int RetainDays,
    DateTimeOffset UpdatedAt);
public sealed record RetentionPolicyInput(int RetainDays);
public sealed record LegalHoldInput(string Reason);
public sealed record LegalHoldSummary(Guid Id, Guid EvidenceId, string Reason,
    string CreatedBy, DateTimeOffset CreatedAt, DateTimeOffset? ReleasedAt);

public sealed class RetentionStore(TenantDb tenantDb)
{
    public static bool ValidCategory(string category) => category is
        "TELEMETRY" or "RAW" or "AUDIT" or "INCIDENT" or "EXPORT";

    public async Task<IReadOnlyList<RetentionPolicySummary>> PoliciesAsync(
        TenantContext context, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT category, retain_days, updated_at FROM retention_policies
            ORDER BY category
            """, connection, transaction);
        var result = new List<RetentionPolicySummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            result.Add(new(reader.GetString(0), reader.GetInt32(1),
                new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task SetPolicyAsync(TenantContext context, string category,
        int retainDays, string correlationId, string traceId, CancellationToken ct)
    {
        if (!ValidCategory(category) || retainDays is < 30 or > 36500)
            throw new ArgumentException("Invalid retention policy.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            INSERT INTO retention_policies (tenant_id, category, retain_days)
            VALUES (@tenant_id, @category, @days)
            ON CONFLICT (tenant_id, category) DO UPDATE
            SET retain_days = EXCLUDED.retain_days, updated_at = now()
            """, connection, transaction);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("category", category);
        command.Parameters.AddWithValue("days", retainDays);
        await command.ExecuteNonQueryAsync(ct);
        await AuditLedger.WriteAsync(connection, transaction, context,
            "retention.policy_changed", context.TenantId, correlationId,
            traceId, ct, target: category, outcome: retainDays.ToString());
        await transaction.CommitAsync(ct);
    }

    public async Task<LegalHoldSummary?> HoldAsync(TenantContext context,
        Guid evidenceId, string reason, string correlationId, string traceId,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) ||
            !AuditLedger.SafeText(reason, 3, 1000))
            throw new ArgumentException("Legal hold reason must have 3 to 1000 printable characters.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var evidence = new NpgsqlCommand(
            "SELECT marid_lock_live_evidence(@id)",
            connection, transaction);
        evidence.Parameters.AddWithValue("id", evidenceId);
        if (await evidence.ExecuteScalarAsync(ct) is not true) return null;
        var id = Guid.NewGuid();
        await using var command = new NpgsqlCommand("""
            INSERT INTO legal_holds
                (id, tenant_id, evidence_id, reason, created_by)
            VALUES (@id, @tenant_id, @evidence_id, @reason, @created_by)
            ON CONFLICT (tenant_id, evidence_id) WHERE released_at IS NULL
            DO NOTHING RETURNING created_at
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("evidence_id", evidenceId);
        command.Parameters.AddWithValue("reason", reason);
        command.Parameters.AddWithValue("created_by", context.ActorId);
        var created = await command.ExecuteScalarAsync(ct);
        if (created is DateTime timestamp)
            await AuditLedger.WriteAsync(connection, transaction, context,
                "evidence.legal_hold_applied", evidenceId, correlationId,
                traceId, ct, reason: reason, highPriority: true);
        else
        {
            await using var prior = new NpgsqlCommand("""
                SELECT id, reason, created_by, created_at FROM legal_holds
                WHERE evidence_id = @evidence_id AND released_at IS NULL
                """, connection, transaction);
            prior.Parameters.AddWithValue("evidence_id", evidenceId);
            await using var reader = await prior.ExecuteReaderAsync(ct);
            await reader.ReadAsync(ct);
            id = reader.GetGuid(0);
            reason = reader.GetString(1);
            var createdBy = reader.GetString(2);
            timestamp = reader.GetDateTime(3);
            await reader.DisposeAsync();
            await transaction.CommitAsync(ct);
            return new(id, evidenceId, reason, createdBy,
                new DateTimeOffset(timestamp, TimeSpan.Zero), null);
        }
        await transaction.CommitAsync(ct);
        return new(id, evidenceId, reason, context.ActorId,
            new DateTimeOffset((DateTime)created!, TimeSpan.Zero), null);
    }

    public async Task<bool> ReleaseAsync(TenantContext context, Guid evidenceId,
        Guid holdId, string correlationId, string traceId, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            UPDATE legal_holds SET released_at = now()
            WHERE id = @id AND evidence_id = @evidence_id AND released_at IS NULL
            """, connection, transaction);
        command.Parameters.AddWithValue("id", holdId);
        command.Parameters.AddWithValue("evidence_id", evidenceId);
        if (await command.ExecuteNonQueryAsync(ct) != 1) return false;
        await AuditLedger.WriteAsync(connection, transaction, context,
            "evidence.legal_hold_released", evidenceId, correlationId,
            traceId, ct, target: holdId.ToString(), highPriority: true);
        await transaction.CommitAsync(ct);
        return true;
    }
}

public static class RetentionEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/retention/policies", Policies)
            .RequireAuthorization("retention.read");
        api.MapPut("/retention/policies/{category}", SetPolicy)
            .RequireAuthorization("retention.admin");
        api.MapPost("/evidence/{evidenceId:guid}/holds", Hold)
            .RequireAuthorization("retention.admin");
        api.MapPost("/evidence/{evidenceId:guid}/holds/{holdId:guid}/release", Release)
            .RequireAuthorization("retention.admin");
    }

    private static async Task<IResult> Policies(ClaimsPrincipal user,
        RetentionStore store, TenantAuthorization authorization,
        CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (!await authorization.IsAllowedAsync(context, "retention.read", ct))
            return Results.Forbid();
        return Results.Ok(await store.PoliciesAsync(context, ct));
    }

    private static async Task<IResult> SetPolicy(string category,
        RetentionPolicyInput input, ClaimsPrincipal user, HttpContext http,
        RetentionStore store, TenantAuthorization authorization,
        CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.Kind != PrincipalKind.Human ||
            !await authorization.IsAllowedAsync(context, "retention.admin", ct))
            return Results.Forbid();
        try
        {
            await store.SetPolicyAsync(context, category, input.RetainDays,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            return Results.NoContent();
        }
        catch (ArgumentException) { return Results.BadRequest(); }
    }

    private static async Task<IResult> Hold(Guid evidenceId, LegalHoldInput input,
        ClaimsPrincipal user, HttpContext http, RetentionStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.Kind != PrincipalKind.Human ||
            !await authorization.IsAllowedAsync(context, "retention.admin", ct))
            return Results.Forbid();
        try
        {
            var hold = await store.HoldAsync(context, evidenceId, input.Reason,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
            return hold is null ? Results.NotFound()
                : Results.Created($"/v1/evidence/{evidenceId}/holds/{hold.Id}", hold);
        }
        catch (ArgumentException) { return Results.BadRequest(); }
    }

    private static async Task<IResult> Release(Guid evidenceId, Guid holdId,
        ClaimsPrincipal user, HttpContext http, RetentionStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.Kind != PrincipalKind.Human ||
            !await authorization.IsAllowedAsync(context, "retention.admin", ct))
            return Results.Forbid();
        return await store.ReleaseAsync(context, evidenceId, holdId,
            (string)http.Items["CorrelationId"]!,
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct)
            ? Results.NoContent() : Results.NotFound();
    }
}
