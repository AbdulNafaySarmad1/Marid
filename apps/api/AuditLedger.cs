using Npgsql;

namespace Marid.Api;

public static class AuditLedger
{
    private static readonly string[] SecretMarkers =
    [
        "bearer ", "password=", "password:", "passwd=", "secret=",
        "secret:", "token=", "token:", "api_key=", "api-key=",
        "authorization:"
    ];

    public static bool SafeText(string? value, int min, int max) =>
        value is not null && value.Length >= min && value.Length <= max &&
        !value.Any(char.IsControl) &&
        !SecretMarkers.Any(marker => value.Contains(marker,
            StringComparison.OrdinalIgnoreCase));

    public static async Task WriteAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, TenantContext context, string action,
        Guid objectId, string correlationId, string traceId, CancellationToken ct,
        Guid? sessionId = null, string? role = null, string? reason = null,
        string? ticketRef = null, string? target = null, string? outcome = null,
        bool highPriority = false)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, actor_type, action, object_id,
                 correlation_id, trace_id, session_id, role, reason, ticket_ref,
                 target_resource, outcome, severity)
            VALUES (@id, @tenant_id, @actor_id, @service_id, @actor_type, @action,
                    @object_id, @correlation_id, @trace_id, @session_id, @role,
                    @reason, @ticket_ref, @target, @outcome, @severity)
            """, connection, transaction);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        command.Parameters.AddWithValue("actor_type", context.EffectiveActorType);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("object_id", objectId);
        command.Parameters.AddWithValue("correlation_id", correlationId);
        command.Parameters.AddWithValue("trace_id", traceId);
        command.Parameters.AddWithValue("session_id", (object?)sessionId ?? DBNull.Value);
        command.Parameters.AddWithValue("role", (object?)role ?? DBNull.Value);
        command.Parameters.AddWithValue("reason", (object?)reason ?? DBNull.Value);
        command.Parameters.AddWithValue("ticket_ref", (object?)ticketRef ?? DBNull.Value);
        command.Parameters.AddWithValue("target", (object?)target ?? DBNull.Value);
        command.Parameters.AddWithValue("outcome", (object?)outcome ?? DBNull.Value);
        command.Parameters.AddWithValue("severity", highPriority ? "HIGH" : "INFO");
        await command.ExecuteNonQueryAsync(ct);
    }
}
