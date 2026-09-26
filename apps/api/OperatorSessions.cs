using System.Net;
using System.Security.Claims;
using Npgsql;
using NpgsqlTypes;

namespace Marid.Api;

public sealed record OperatorSessionInput(string Role, string Reason,
    string TicketRef, bool BreakGlass);
public sealed record OperatorActionInput(string Action, string Resource,
    string Outcome, string? ParametersSha256);
public sealed record OperatorSessionSummary(Guid Id, string Role, string Reason,
    string TicketRef, bool BreakGlass, DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt);

public sealed class OperatorSessionStore(TenantDb tenantDb)
{
    public static bool IsValid(OperatorSessionInput value) =>
        value.Role is "AUDITOR" or "RESPONDER" or "INCIDENT_MANAGER" &&
        Safe(value.Reason, 3, 1000) && Safe(value.TicketRef, 1, 200);

    public async Task<OperatorSessionSummary> StartAsync(TenantContext context,
        OperatorSessionInput input, IPAddress? sourceIp, string correlationId,
        string traceId, CancellationToken ct)
    {
        if (context.Kind != PrincipalKind.Human ||
            context.EffectiveActorType != "NOCTURNE_ENGINEER" || !IsValid(input))
            throw new ArgumentException("Invalid engineer session request.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var id = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO operator_sessions
                (id, tenant_id, actor_id, service_id, role, reason, ticket_ref,
                 break_glass, source_ip, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @actor_id, @service_id, @role, @reason,
                    @ticket_ref, @break_glass, @source_ip, @correlation_id, @trace_id)
            RETURNING started_at
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("actor_id", context.ActorId);
        insert.Parameters.AddWithValue("service_id", context.ServiceId);
        insert.Parameters.AddWithValue("role", input.Role);
        insert.Parameters.AddWithValue("reason", input.Reason);
        insert.Parameters.AddWithValue("ticket_ref", input.TicketRef);
        insert.Parameters.AddWithValue("break_glass", input.BreakGlass);
        insert.Parameters.Add(new NpgsqlParameter("source_ip", NpgsqlDbType.Inet)
            { Value = (object?)sourceIp ?? DBNull.Value });
        insert.Parameters.AddWithValue("correlation_id", correlationId);
        insert.Parameters.AddWithValue("trace_id", traceId);
        var started = (DateTime)(await insert.ExecuteScalarAsync(ct))!;
        await AuditLedger.WriteAsync(connection, transaction, context,
            input.BreakGlass ? "operator.break_glass_started" : "operator.session_started",
            id, correlationId, traceId, ct, id, input.Role, input.Reason,
            input.TicketRef, highPriority: input.BreakGlass);
        await transaction.CommitAsync(ct);
        return new(id, input.Role, input.Reason, input.TicketRef,
            input.BreakGlass, new DateTimeOffset(started, TimeSpan.Zero), null);
    }

    public async Task<OperatorSessionSummary?> ActiveAsync(TenantContext context,
        Guid id, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT role, reason, ticket_ref, break_glass, started_at
            FROM operator_sessions
            WHERE id = @id AND actor_id = @actor_id AND service_id = @service_id
              AND ended_at IS NULL
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct)
            ? new OperatorSessionSummary(id, reader.GetString(0), reader.GetString(1),
                reader.GetString(2), reader.GetBoolean(3),
                new DateTimeOffset(reader.GetDateTime(4), TimeSpan.Zero), null)
            : null;
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<bool> EndAsync(TenantContext context, Guid id,
        string correlationId, string traceId, CancellationToken ct)
    {
        var active = await ActiveAsync(context, id, ct);
        if (active is null) return false;
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            UPDATE operator_sessions SET ended_at = now()
            WHERE id = @id AND actor_id = @actor_id AND service_id = @service_id
              AND ended_at IS NULL
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        if (await command.ExecuteNonQueryAsync(ct) != 1) return false;
        await AuditLedger.WriteAsync(connection, transaction, context,
            "operator.session_ended", id, correlationId, traceId, ct,
            id, active.Role, active.Reason, active.TicketRef,
            highPriority: active.BreakGlass);
        await transaction.CommitAsync(ct);
        return true;
    }

    public async Task<bool> RecordActionAsync(TenantContext context, Guid id,
        OperatorActionInput input, string correlationId, string traceId,
        CancellationToken ct)
    {
        if (!Safe(input.Action, 3, 160) || !Safe(input.Resource, 1, 500) ||
            !Safe(input.Outcome, 1, 160) ||
            (input.ParametersSha256 is not null &&
             (input.ParametersSha256.Length != 64 ||
              input.ParametersSha256.Any(c => !Uri.IsHexDigit(c)))))
            throw new ArgumentException("Invalid operator action metadata.");
        var active = await ActiveAsync(context, id, ct);
        if (active is null) return false;
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, actor_type, role, action,
                 object_id, session_id, reason, ticket_ref, target_resource,
                 parameters_sha256, outcome, correlation_id, trace_id, severity)
            VALUES (@id, @tenant_id, @actor_id, @service_id,
                    'NOCTURNE_ENGINEER', @role, @action, @object_id, @session_id,
                    @reason, @ticket_ref, @target, @parameters_sha256,
                    @outcome, @correlation_id, @trace_id, @severity)
            """, connection, transaction);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        command.Parameters.AddWithValue("role", active.Role);
        command.Parameters.AddWithValue("action", input.Action);
        command.Parameters.AddWithValue("object_id", id);
        command.Parameters.AddWithValue("session_id", id);
        command.Parameters.AddWithValue("reason", active.Reason);
        command.Parameters.AddWithValue("ticket_ref", active.TicketRef);
        command.Parameters.AddWithValue("target", input.Resource);
        command.Parameters.Add(new NpgsqlParameter("parameters_sha256", NpgsqlDbType.Char)
            { Value = (object?)input.ParametersSha256?.ToLowerInvariant() ?? DBNull.Value });
        command.Parameters.AddWithValue("outcome", input.Outcome);
        command.Parameters.AddWithValue("correlation_id", correlationId);
        command.Parameters.AddWithValue("trace_id", traceId);
        command.Parameters.AddWithValue("severity", active.BreakGlass ? "HIGH" : "INFO");
        await command.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return true;
    }

    public async Task AuditHttpAsync(TenantContext context,
        OperatorSessionSummary session, string action, string path,
        int statusCode, string correlationId, string traceId,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await AuditLedger.WriteAsync(connection, transaction, context, action,
            session.Id, correlationId, traceId, ct, session.Id,
            session.Role, session.Reason, session.TicketRef,
            path.Length <= 500 ? path : path[..500],
            statusCode.ToString(), session.BreakGlass);
        await transaction.CommitAsync(ct);
    }

    private static bool Safe(string value, int min, int max) =>
        !string.IsNullOrWhiteSpace(value) && AuditLedger.SafeText(value, min, max);
}

public static class OperatorEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/operator/sessions", Start)
            .RequireAuthorization("operator.session");
        api.MapPost("/operator/sessions/{id:guid}/end", End)
            .RequireAuthorization("operator.session");
        api.MapPost("/operator/sessions/{id:guid}/actions", Action)
            .RequireAuthorization("operator.session");
    }

    private static async Task<IResult> Start(OperatorSessionInput input,
        ClaimsPrincipal user, HttpContext http, OperatorSessionStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.EffectiveActorType != "NOCTURNE_ENGINEER" ||
            !await authorization.IsAllowedAsync(context, "operator.session", ct))
            return Results.Forbid();
        if (!OperatorSessionStore.IsValid(input)) return Results.BadRequest();
        if (!await authorization.IsAllowedAsync(context,
                "operator.session." + input.Role, ct)) return Results.Forbid();
        var session = await store.StartAsync(context, input,
            http.Connection.RemoteIpAddress,
            (string)http.Items["CorrelationId"]!,
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
        return Results.Created($"/v1/operator/sessions/{session.Id}", session);
    }

    private static async Task<IResult> End(Guid id, ClaimsPrincipal user,
        HttpContext http, OperatorSessionStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.EffectiveActorType != "NOCTURNE_ENGINEER" ||
            !await authorization.IsAllowedAsync(context, "operator.session", ct))
            return Results.Forbid();
        return await store.EndAsync(context, id,
            (string)http.Items["CorrelationId"]!,
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct)
            ? Results.NoContent() : Results.NotFound();
    }

    private static async Task<IResult> Action(Guid id, OperatorActionInput input,
        ClaimsPrincipal user, HttpContext http, OperatorSessionStore store,
        TenantAuthorization authorization, CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.EffectiveActorType != "NOCTURNE_ENGINEER" ||
            !await authorization.IsAllowedAsync(context, "operator.session", ct))
            return Results.Forbid();
        try
        {
            return await store.RecordActionAsync(context, id, input,
                (string)http.Items["CorrelationId"]!,
                System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct)
                ? Results.NoContent() : Results.NotFound();
        }
        catch (ArgumentException) { return Results.BadRequest(); }
    }
}
