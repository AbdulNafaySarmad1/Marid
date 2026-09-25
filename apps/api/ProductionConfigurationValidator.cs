using Npgsql;

namespace Marid.Api;

public static class ProductionConfigurationValidator
{
    public static void Validate(bool isDevelopment, string oidcAuthority,
        string connectionString)
    {
        if (isDevelopment) return;

        if (!Uri.TryCreate(oidcAuthority, UriKind.Absolute, out var authority) ||
            authority.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(authority.Host) ||
            !string.IsNullOrEmpty(authority.UserInfo) ||
            !string.IsNullOrEmpty(authority.Query) ||
            !string.IsNullOrEmpty(authority.Fragment))
            throw new InvalidOperationException(
                "Nondevelopment OIDC authority must be a clean HTTPS URL.");

        var database = new NpgsqlConnectionStringBuilder(connectionString);
        if (database.SslMode != SslMode.VerifyFull)
            throw new InvalidOperationException(
                "Nondevelopment PostgreSQL must use SSL Mode=VerifyFull and validate its certificate.");
        if (database.Username is "postgres" or "marid_owner")
            throw new InvalidOperationException(
                "The API cannot use a database owner or superuser identity.");
        if (string.IsNullOrWhiteSpace(database.Username))
            throw new InvalidOperationException(
                "The API database identity must be explicit.");
    }
}
