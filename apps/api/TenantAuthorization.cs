using Npgsql;

namespace Marid.Api;

public static class PermissionMap
{
    private static readonly Dictionary<string, string[]> AllowedRoles = new(StringComparer.Ordinal)
    {
        ["events.ingest"] = ["EVENT_INGESTOR"],
        ["incidents.read"] = ["ANALYST", "INCIDENT_MANAGER", "RESPONDER", "APPROVER", "AUDITOR"],
        ["incidents.write"] = ["INCIDENT_MANAGER"],
        ["response.read"] = ["RESPONDER", "APPROVER", "AUDITOR"],
        ["response.propose"] = ["RESPONDER"],
        ["response.approve"] = ["APPROVER"],
        ["deployment.domains.read"] = ["AUDITOR", "INCIDENT_MANAGER"]
    };

    public static bool Allows(string permission, string role) =>
        AllowedRoles.TryGetValue(permission, out var roles) &&
        roles.Contains(role, StringComparer.Ordinal);
}

public sealed class TenantAuthorization(NpgsqlDataSource dataSource)
{
    public async Task<bool> IsAllowedAsync(TenantContext context, string permission,
        CancellationToken ct)
    {
        if (!Enum.IsDefined(context.Kind)) return false;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var setTenant = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant_id, true)", connection, transaction))
        {
            setTenant.Parameters.AddWithValue("tenant_id", context.TenantId.ToString());
            await setTenant.ExecuteNonQueryAsync(ct);
        }
        await using var command = new NpgsqlCommand("""
            SELECT g.role
            FROM tenant_principals p
            JOIN tenant_role_grants g
              ON g.tenant_id = p.tenant_id
             AND g.subject_id = p.subject_id
             AND g.service_id = p.service_id
            WHERE p.tenant_id = @tenant_id
              AND p.subject_id = @actor_id
              AND p.service_id = @service_id
              AND p.kind = @kind
              AND p.enabled
              AND (g.expires_at IS NULL OR g.expires_at > now())
            """, connection, transaction);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        command.Parameters.AddWithValue("kind", context.Kind == PrincipalKind.Human ? "HUMAN" : "SERVICE");
        var allowed = false;
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            allowed |= PermissionMap.Allows(permission, reader.GetString(0));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return allowed;
    }
}
