using Npgsql;

namespace Marid.Api;

public sealed record DeploymentDomainStatus(string Hostname, string VerificationStatus,
    DateTimeOffset? LastVerifiedAt, bool Active, bool IsPrimary,
    string CertificateStatus, DateTimeOffset? CertificateExpiresAt);

public sealed class DeploymentDomainStore(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<DeploymentDomainStatus>> ListAsync(
        TenantContext context, CancellationToken ct)
    {
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var setTenant = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant_id, true)", connection, transaction))
        {
            setTenant.Parameters.AddWithValue("tenant_id", context.TenantId.ToString());
            await setTenant.ExecuteNonQueryAsync(ct);
        }
        await using var command = new NpgsqlCommand("""
            SELECT hostname, verification_status, last_verified_at, active,
                   is_primary, certificate_status, certificate_expires_at
            FROM deployment_domains
            WHERE tenant_id = @tenant_id AND removed_at IS NULL
            ORDER BY hostname
            """, connection, transaction);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        var domains = new List<DeploymentDomainStatus>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            domains.Add(new DeploymentDomainStatus(
                reader.GetString(0), reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetFieldValue<DateTimeOffset>(2),
                reader.GetBoolean(3), reader.GetBoolean(4), reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return domains;
    }
}
