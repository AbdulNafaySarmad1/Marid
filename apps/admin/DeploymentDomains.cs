using System.Security.Cryptography;
using DnsClient;
using Npgsql;

public static class DeploymentDomains
{
    public static string? NormalizeHostname(string? value)
    {
        if (value is null) return null;
        var host = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length is < 4 or > 230 || host == "localhost") return null;
        var labels = host.Split('.');
        if (labels.Length < 2 || labels[^1].Length < 2) return null;
        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-')
                return null;
            if (label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                return null;
        }
        if (labels[^1].All(char.IsDigit) ||
            labels[^1] is "local" or "internal" or "localhost" or "test" or "invalid")
            return null;
        return host;
    }

    public static string TxtName(string hostname) => "_marid-verification." + hostname;
    public static string TxtValue(string token) => "marid-domain-verification=" + token;
    public static bool MatchesTxt(IEnumerable<IEnumerable<string>> records, string token) =>
        records.Any(parts => string.Concat(parts) == TxtValue(token));

    public static async Task<Guid> RegisterAsync(NpgsqlConnection connection,
        Guid tenantId, string hostname, CancellationToken ct = default)
    {
        var normalized = NormalizeHostname(hostname);
        if (tenantId == Guid.Empty || normalized is null)
            throw new ArgumentException("A valid tenant UUID and public DNS hostname are required.");
        var id = Guid.NewGuid();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO deployment_domains (id, tenant_id, hostname, verification_token)
            VALUES (@id, @tenant_id, @hostname, @token)
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("tenant_id", tenantId);
            insert.Parameters.AddWithValue("hostname", normalized);
            insert.Parameters.AddWithValue("token", token);
            await insert.ExecuteNonQueryAsync(ct);
        }
        await AuditAsync(connection, transaction, tenantId, "domain.registered", id, ct);
        await transaction.CommitAsync(ct);
        Console.WriteLine($"Registered {normalized} for tenant {tenantId}.");
        Console.WriteLine($"Create DNS TXT {TxtName(normalized)} with value {TxtValue(token)}");
        return id;
    }

    public static async Task<bool> VerifyAsync(NpgsqlConnection connection,
        Guid tenantId, string hostname, CancellationToken ct = default)
    {
        var normalized = NormalizeHostname(hostname);
        if (tenantId == Guid.Empty || normalized is null)
            throw new ArgumentException("A valid tenant UUID and public DNS hostname are required.");
        string token;
        Guid id;
        await using (var find = new NpgsqlCommand("""
            SELECT id, verification_token FROM deployment_domains
            WHERE tenant_id = @tenant_id AND hostname = @hostname AND removed_at IS NULL
            """, connection))
        {
            find.Parameters.AddWithValue("tenant_id", tenantId);
            find.Parameters.AddWithValue("hostname", normalized);
            await using var reader = await find.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                throw new InvalidOperationException("No matching domain registration exists.");
            id = reader.GetGuid(0);
            token = reader.GetString(1);
        }
        bool verified;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var result = await new LookupClient().QueryAsync(
                TxtName(normalized), QueryType.TXT, cancellationToken: timeout.Token);
            verified = MatchesTxt(result.Answers.TxtRecords().Select(record => record.Text), token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            verified = false;
        }
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var update = new NpgsqlCommand("""
            UPDATE deployment_domains SET
                verification_status = CASE WHEN @verified THEN 'VERIFIED' ELSE 'FAILED' END,
                first_verified_at = CASE WHEN @verified THEN coalesce(first_verified_at, now())
                                         ELSE first_verified_at END,
                last_verified_at = CASE WHEN @verified THEN now() ELSE last_verified_at END,
                last_checked_at = now(), active = CASE WHEN @verified THEN active ELSE false END,
                is_primary = CASE WHEN @verified THEN is_primary ELSE false END,
                updated_at = now()
            WHERE id = @id AND tenant_id = @tenant_id AND verification_token = @token
              AND removed_at IS NULL
            """, connection, transaction))
        {
            update.Parameters.AddWithValue("verified", verified);
            update.Parameters.AddWithValue("id", id);
            update.Parameters.AddWithValue("tenant_id", tenantId);
            update.Parameters.AddWithValue("token", token);
            if (await update.ExecuteNonQueryAsync(ct) != 1)
                throw new InvalidOperationException("Domain registration changed during verification.");
        }
        await AuditAsync(connection, transaction, tenantId,
            verified ? "domain.verified" : "domain.verification_failed", id, ct);
        await transaction.CommitAsync(ct);
        Console.WriteLine(verified ? $"Verified {normalized}." : $"DNS TXT verification failed for {normalized}.");
        return verified;
    }

    public static async Task RemoveAsync(NpgsqlConnection connection,
        Guid tenantId, string hostname, CancellationToken ct = default)
    {
        var normalized = NormalizeHostname(hostname);
        if (tenantId == Guid.Empty || normalized is null)
            throw new ArgumentException("A valid tenant UUID and public DNS hostname are required.");
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var update = new NpgsqlCommand("""
            UPDATE deployment_domains
            SET removed_at = now(), active = false, is_primary = false, updated_at = now()
            WHERE tenant_id = @tenant_id AND hostname = @hostname AND removed_at IS NULL
              AND NOT active AND NOT is_primary
            RETURNING id
            """, connection, transaction);
        update.Parameters.AddWithValue("tenant_id", tenantId);
        update.Parameters.AddWithValue("hostname", normalized);
        var id = await update.ExecuteScalarAsync(ct) is Guid value ? value :
            throw new InvalidOperationException("Domain is absent or still active; deactivate it before removal.");
        await AuditAsync(connection, transaction, tenantId, "domain.removed", id, ct);
        await transaction.CommitAsync(ct);
        Console.WriteLine($"Removed inactive domain {normalized}.");
    }

    public static async Task ListAsync(NpgsqlConnection connection, Guid tenantId,
        CancellationToken ct = default)
    {
        if (tenantId == Guid.Empty) throw new ArgumentException("Valid tenant UUID required.");
        await using var command = new NpgsqlCommand("""
            SELECT hostname, verification_status, active, is_primary,
                   certificate_status, certificate_expires_at
            FROM deployment_domains WHERE tenant_id = @tenant_id AND removed_at IS NULL
            ORDER BY hostname
            """, connection);
        command.Parameters.AddWithValue("tenant_id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            Console.WriteLine($"{reader.GetString(0)}\t{reader.GetString(1)}\tactive={reader.GetBoolean(2)}\tprimary={reader.GetBoolean(3)}\tcert={reader.GetString(4)}\texpires={(reader.IsDBNull(5) ? "-" : reader.GetFieldValue<DateTimeOffset>(5).ToString("O"))}");
    }

    private static async Task AuditAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, Guid tenantId, string action, Guid objectId,
        CancellationToken ct)
    {
        await using var audit = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, action, object_id, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @actor_id, 'marid-admin-cli', @action,
                    @object_id, @correlation_id, @trace_id)
            """, connection, transaction);
        audit.Parameters.AddWithValue("id", Guid.NewGuid());
        audit.Parameters.AddWithValue("tenant_id", tenantId);
        audit.Parameters.AddWithValue("actor_id", Environment.UserName);
        audit.Parameters.AddWithValue("action", action);
        audit.Parameters.AddWithValue("object_id", objectId);
        audit.Parameters.AddWithValue("correlation_id", Guid.NewGuid().ToString());
        audit.Parameters.AddWithValue("trace_id", Guid.NewGuid().ToString("N"));
        await audit.ExecuteNonQueryAsync(ct);
    }
}
