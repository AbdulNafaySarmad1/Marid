using Npgsql;

namespace Marid.Api;

public sealed class TenantDb(NpgsqlDataSource dataSource)
{
    public async Task<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)> OpenAsync(
        TenantContext context, CancellationToken ct)
    {
        var connection = await dataSource.OpenConnectionAsync(ct);
        try
        {
            var transaction = await connection.BeginTransactionAsync(ct);
            await using var command = new NpgsqlCommand(
                "SELECT set_config('app.tenant_id', @tenant_id, true), set_config('app.actor_id', @actor_id, true)",
                connection, transaction);
            command.Parameters.AddWithValue("tenant_id", context.TenantId.ToString());
            command.Parameters.AddWithValue("actor_id", context.ActorId);
            await command.ExecuteNonQueryAsync(ct);
            return (connection, transaction);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
