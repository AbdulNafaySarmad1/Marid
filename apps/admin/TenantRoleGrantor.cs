using Npgsql;

public static class TenantRoleGrantor
{
    private static readonly HashSet<string> Roles = new(StringComparer.Ordinal)
    {
        "EVENT_INGESTOR", "ANALYST", "INCIDENT_MANAGER",
        "RESPONDER", "APPROVER", "AUDITOR"
    };

    public static bool IsValidRole(string? role) => role is not null && Roles.Contains(role);
    public static bool IsValidIdentity(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 200 && !value.Any(char.IsControl);

    public static async Task<Guid> GrantAsync(NpgsqlConnection connection, Guid tenantId,
        string subjectId, string serviceId, string kind, string role,
        DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        if (tenantId == Guid.Empty || !IsValidIdentity(subjectId) ||
            !IsValidIdentity(serviceId) || kind is not ("HUMAN" or "SERVICE") ||
            !IsValidRole(role) || expiresAt <= DateTimeOffset.UtcNow ||
            expiresAt > DateTimeOffset.UtcNow.AddDays(30))
            throw new ArgumentException("Invalid tenant role grant.");

        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var setTenant = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant_id, true)", connection, transaction))
        {
            setTenant.Parameters.AddWithValue("tenant_id", tenantId.ToString());
            await setTenant.ExecuteNonQueryAsync(ct);
        }
        await using (var principal = new NpgsqlCommand("""
            INSERT INTO tenant_principals (tenant_id, subject_id, service_id, kind)
            VALUES (@tenant_id, @subject_id, @service_id, @kind)
            ON CONFLICT (tenant_id, subject_id, service_id) DO NOTHING
            """, connection, transaction))
        {
            principal.Parameters.AddWithValue("tenant_id", tenantId);
            principal.Parameters.AddWithValue("subject_id", subjectId);
            principal.Parameters.AddWithValue("service_id", serviceId);
            principal.Parameters.AddWithValue("kind", kind);
            await principal.ExecuteNonQueryAsync(ct);
        }
        await using (var verify = new NpgsqlCommand("""
            SELECT kind, enabled FROM tenant_principals
            WHERE tenant_id = @tenant_id AND subject_id = @subject_id AND service_id = @service_id
            """, connection, transaction))
        {
            verify.Parameters.AddWithValue("tenant_id", tenantId);
            verify.Parameters.AddWithValue("subject_id", subjectId);
            verify.Parameters.AddWithValue("service_id", serviceId);
            await using var reader = await verify.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || reader.GetString(0) != kind || !reader.GetBoolean(1))
                throw new InvalidOperationException("Existing principal is disabled or has a different kind.");
        }

        var grantId = Guid.NewGuid();
        await using (var grant = new NpgsqlCommand("""
            INSERT INTO tenant_role_grants
                (id, tenant_id, subject_id, service_id, role, granted_by, expires_at)
            VALUES (@id, @tenant_id, @subject_id, @service_id, @role, @granted_by, @expires_at)
            ON CONFLICT (tenant_id, subject_id, service_id, role) DO NOTHING
            RETURNING id
            """, connection, transaction))
        {
            grant.Parameters.AddWithValue("id", grantId);
            grant.Parameters.AddWithValue("tenant_id", tenantId);
            grant.Parameters.AddWithValue("subject_id", subjectId);
            grant.Parameters.AddWithValue("service_id", serviceId);
            grant.Parameters.AddWithValue("role", role);
            grant.Parameters.AddWithValue("granted_by", Environment.UserName);
            grant.Parameters.AddWithValue("expires_at", expiresAt.ToUniversalTime());
            if (await grant.ExecuteScalarAsync(ct) is not Guid)
                throw new InvalidOperationException("Role is already granted; extensions require a reviewed change.");
        }
        await using (var audit = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, action, object_id, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @actor_id, 'marid-admin-cli', 'role.granted',
                    @object_id, @correlation_id, @trace_id)
            """, connection, transaction))
        {
            audit.Parameters.AddWithValue("id", Guid.NewGuid());
            audit.Parameters.AddWithValue("tenant_id", tenantId);
            audit.Parameters.AddWithValue("actor_id", Environment.UserName);
            audit.Parameters.AddWithValue("object_id", grantId);
            audit.Parameters.AddWithValue("correlation_id", Guid.NewGuid().ToString());
            audit.Parameters.AddWithValue("trace_id", Guid.NewGuid().ToString("N"));
            await audit.ExecuteNonQueryAsync(ct);
        }
        await transaction.CommitAsync(ct);
        Console.WriteLine($"Granted {role} to {subjectId} for tenant {tenantId} until {expiresAt:O}");
        return grantId;
    }

    public static async Task<Guid> RevokeAsync(NpgsqlConnection connection, Guid tenantId,
        string subjectId, string serviceId, string role, CancellationToken ct = default)
    {
        if (tenantId == Guid.Empty || !IsValidIdentity(subjectId) ||
            !IsValidIdentity(serviceId) || !IsValidRole(role))
            throw new ArgumentException("Invalid tenant role revocation.");

        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var setTenant = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant_id, true)", connection, transaction))
        {
            setTenant.Parameters.AddWithValue("tenant_id", tenantId.ToString());
            await setTenant.ExecuteNonQueryAsync(ct);
        }
        await using var revoke = new NpgsqlCommand("""
            UPDATE tenant_role_grants SET expires_at = now()
            WHERE tenant_id = @tenant_id AND subject_id = @subject_id
              AND service_id = @service_id AND role = @role
              AND (expires_at IS NULL OR expires_at > now())
            RETURNING id
            """, connection, transaction);
        revoke.Parameters.AddWithValue("tenant_id", tenantId);
        revoke.Parameters.AddWithValue("subject_id", subjectId);
        revoke.Parameters.AddWithValue("service_id", serviceId);
        revoke.Parameters.AddWithValue("role", role);
        var grantId = await revoke.ExecuteScalarAsync(ct) is Guid id
            ? id : throw new InvalidOperationException("No active matching role grant exists.");
        await using var audit = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, action, object_id, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @actor_id, 'marid-admin-cli', 'role.revoked',
                    @object_id, @correlation_id, @trace_id)
            """, connection, transaction);
        audit.Parameters.AddWithValue("id", Guid.NewGuid());
        audit.Parameters.AddWithValue("tenant_id", tenantId);
        audit.Parameters.AddWithValue("actor_id", Environment.UserName);
        audit.Parameters.AddWithValue("object_id", grantId);
        audit.Parameters.AddWithValue("correlation_id", Guid.NewGuid().ToString());
        audit.Parameters.AddWithValue("trace_id", Guid.NewGuid().ToString("N"));
        await audit.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        Console.WriteLine($"Revoked {role} for {subjectId} in tenant {tenantId}");
        return grantId;
    }
}
