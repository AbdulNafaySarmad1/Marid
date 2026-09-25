using Npgsql;

namespace Marid.Api;

public sealed class DomainIssuanceStore(NpgsqlDataSource dataSource)
{
    public async Task<bool> IsAllowedAsync(string? hostname, CancellationToken ct)
    {
        if (hostname is null || hostname.Length is < 4 or > 253 ||
            hostname.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-'))
            return false;
        await using var connection = await dataSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT marid_domain_issuance_allowed(@hostname)", connection);
        command.Parameters.AddWithValue("hostname", hostname);
        return await command.ExecuteScalarAsync(ct) is true;
    }
}
