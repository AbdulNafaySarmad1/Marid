using System.Text.RegularExpressions;
using Npgsql;

public static class TenantCreator
{
    public static async Task<Guid> CreateAsync(NpgsqlConnection connection, string slug,
        string displayName, CancellationToken cancellationToken = default)
    {
        if (!TenantNameValidator.IsValidSlug(slug) ||
            !TenantNameValidator.IsValidDisplayName(displayName))
            throw new ArgumentException("Invalid tenant name or slug.");

        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var tenantId = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO tenants (id, slug, display_name)
            VALUES (@id, @slug, @display_name)
            ON CONFLICT (slug) DO NOTHING
            RETURNING id
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", tenantId);
        insert.Parameters.AddWithValue("slug", slug);
        insert.Parameters.AddWithValue("display_name", displayName.Trim());
        var created = await insert.ExecuteScalarAsync(cancellationToken);
        if (created is Guid newId)
        {
            await using var setTenant = new NpgsqlCommand(
                "SELECT set_config('app.tenant_id', @tenant_id, true)", connection, transaction);
            setTenant.Parameters.AddWithValue("tenant_id", newId.ToString());
            await setTenant.ExecuteNonQueryAsync(cancellationToken);
            await using var control = new NpgsqlCommand("""
                INSERT INTO tenant_controls (tenant_id, autonomy, kill_mode)
                VALUES (@tenant_id, 'OBSERVE', 'READ_ONLY')
                """, connection, transaction);
            control.Parameters.AddWithValue("tenant_id", newId);
            await control.ExecuteNonQueryAsync(cancellationToken);
            await using var schedule = new NpgsqlCommand(
                "INSERT INTO export_schedules (tenant_id) VALUES (@tenant_id)",
                connection, transaction);
            schedule.Parameters.AddWithValue("tenant_id", newId);
            await schedule.ExecuteNonQueryAsync(cancellationToken);
            await using var retention = new NpgsqlCommand("""
                INSERT INTO retention_policies (tenant_id, category, retain_days)
                VALUES (@tenant_id, 'TELEMETRY', 365), (@tenant_id, 'RAW', 365),
                       (@tenant_id, 'AUDIT', 2555), (@tenant_id, 'INCIDENT', 2555),
                       (@tenant_id, 'EXPORT', 365)
                """, connection, transaction);
            retention.Parameters.AddWithValue("tenant_id", newId);
            await retention.ExecuteNonQueryAsync(cancellationToken);
            await using var audit = new NpgsqlCommand("""
                INSERT INTO audit_events
                    (id, tenant_id, actor_id, service_id, action, object_id, correlation_id, trace_id)
                VALUES (@id, @tenant_id, @actor_id, 'marid-admin-cli', 'tenant.created',
                        @object_id, @correlation_id, @trace_id)
                """, connection, transaction);
            audit.Parameters.AddWithValue("id", Guid.NewGuid());
            audit.Parameters.AddWithValue("tenant_id", newId);
            audit.Parameters.AddWithValue("actor_id", Environment.UserName);
            audit.Parameters.AddWithValue("object_id", newId);
            audit.Parameters.AddWithValue("correlation_id", Guid.NewGuid().ToString());
            audit.Parameters.AddWithValue("trace_id", Guid.NewGuid().ToString("N"));
            await audit.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            Console.WriteLine($"Created tenant {slug}: {newId}");
            return newId;
        }

        await using var lookup = new NpgsqlCommand(
            "SELECT id FROM tenants WHERE slug = @slug", connection, transaction);
        lookup.Parameters.AddWithValue("slug", slug);
        var existing = (Guid)(await lookup.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Existing tenant was not found."));
        await transaction.CommitAsync(cancellationToken);
        Console.WriteLine($"Tenant {slug} already exists: {existing}");
        return existing;
    }
}

public static class TenantNameValidator
{
    public static bool IsValidSlug(string? value) =>
        value is not null && Regex.IsMatch(value, "^[a-z0-9][a-z0-9-]{2,62}$");

    public static bool IsValidDisplayName(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Trim().Length <= 200 &&
        !value.Any(char.IsControl);
}
