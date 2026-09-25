using Npgsql;

namespace Marid.Api;

public static class DatabaseAuthorityValidator
{
    private const string Sql = """
        SELECT NOT r.rolsuper
           AND NOT r.rolbypassrls
           AND r.rolcanlogin
           AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
           AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
           AND NOT has_table_privilege(current_user, 'public.security_events', 'UPDATE')
           AND NOT has_table_privilege(current_user, 'public.security_events', 'DELETE')
           AND NOT has_table_privilege(current_user, 'public.approval_decisions', 'UPDATE')
           AND NOT has_table_privilege(current_user, 'public.approval_decisions', 'DELETE')
           AND NOT has_table_privilege(current_user, 'public.tenant_role_grants', 'INSERT')
           AND NOT has_table_privilege(current_user, 'public.deployment_domains', 'INSERT')
           AND NOT has_table_privilege(current_user, 'public.deployment_domains', 'UPDATE')
           AND (
             SELECT count(*)
             FROM pg_class c
             WHERE c.relnamespace = 'public'::regnamespace
               AND c.relname = ANY(ARRAY[
                 'security_events', 'incidents', 'audit_events', 'tenant_controls',
                 'capabilities', 'engagement_scopes', 'response_proposals',
                 'response_proposal_events', 'approval_decisions',
                 'tenant_principals', 'tenant_role_grants', 'deployment_domains'
               ])
               AND c.relrowsecurity AND c.relforcerowsecurity
               AND NOT pg_has_role(current_user, c.relowner, 'member')
           ) = 12
        FROM pg_roles r
        WHERE r.rolname = current_user
        """;

    public static async Task<bool> IsValidAsync(NpgsqlDataSource dataSource,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(Sql, connection);
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    public static async Task EnsureAsync(NpgsqlDataSource dataSource,
        CancellationToken cancellationToken)
    {
        if (!await IsValidAsync(dataSource, cancellationToken))
            throw new InvalidOperationException(
                "API database identity or tenant isolation schema failed authority validation.");
    }
}
