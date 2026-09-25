using Npgsql;
using System.Globalization;

var migrating = args.Length is 1 or 2 && args[0] == "migrate";
var creatingTenant = args.Length == 3 && args[0] == "create-tenant" &&
    TenantNameValidator.IsValidSlug(args[1]) &&
    TenantNameValidator.IsValidDisplayName(args[2]);
var grantTenantId = Guid.Empty;
var grantExpiry = default(DateTimeOffset);
var grantingRole = args.Length == 7 && args[0] == "grant-role" &&
    Guid.TryParse(args[1], out grantTenantId) && grantTenantId != Guid.Empty &&
    TenantRoleGrantor.IsValidIdentity(args[2]) &&
    TenantRoleGrantor.IsValidIdentity(args[3]) &&
    args[4] is "HUMAN" or "SERVICE" &&
    TenantRoleGrantor.IsValidRole(args[5]) &&
    args[6].EndsWith('Z') &&
    DateTimeOffset.TryParse(args[6], CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out grantExpiry);
var revokeTenantId = Guid.Empty;
var revokingRole = args.Length == 5 && args[0] == "revoke-role" &&
    Guid.TryParse(args[1], out revokeTenantId) && revokeTenantId != Guid.Empty &&
    TenantRoleGrantor.IsValidIdentity(args[2]) &&
    TenantRoleGrantor.IsValidIdentity(args[3]) &&
    TenantRoleGrantor.IsValidRole(args[4]);
var domainTenantId = Guid.Empty;
var domainCommand = args.Length == 3 &&
    args[0] is "register-domain" or "verify-domain" or "remove-domain" &&
    Guid.TryParse(args[1], out domainTenantId) && domainTenantId != Guid.Empty &&
    DeploymentDomains.NormalizeHostname(args[2]) is not null;
var listDomainTenantId = Guid.Empty;
var listingDomains = args.Length == 2 && args[0] == "list-domains" &&
    Guid.TryParse(args[1], out listDomainTenantId) && listDomainTenantId != Guid.Empty;
if (!migrating && !creatingTenant && !grantingRole && !revokingRole &&
    !domainCommand && !listingDomains)
{
    Console.Error.WriteLine("Usage: Marid.Admin migrate [migration-directory] | create-tenant <slug> <name> | grant-role <tenant-uuid> <subject-id> <service-id> <HUMAN|SERVICE> <ROLE> <expiry-UTC-Z> | revoke-role <tenant-uuid> <subject-id> <service-id> <ROLE> | register-domain|verify-domain|remove-domain <tenant-uuid> <hostname> | list-domains <tenant-uuid>");
    return 2;
}

var host = Environment.GetEnvironmentVariable("MARID_DB_HOST") ?? "localhost";
var portValue = Environment.GetEnvironmentVariable("MARID_DB_PORT");
if (host is not ("localhost" or "127.0.0.1" or "::1") ||
    (portValue is not null && (!int.TryParse(portValue, out var configuredPort) ||
                               configuredPort is < 1 or > 65535)))
{
    Console.Error.WriteLine("This tool requires localhost and a valid MARID_DB_PORT.");
    return 2;
}
var stdinPasswordAllowed = Environment.GetEnvironmentVariable("MARID_ADMIN_PASSWORD_STDIN") == "1";
if (Console.IsInputRedirected && !stdinPasswordAllowed)
{
    Console.Error.WriteLine("Redirected password input requires MARID_ADMIN_PASSWORD_STDIN=1.");
    return 2;
}

if (!Console.IsInputRedirected) Console.Error.Write("Migration-owner database password: ");
var password = Console.IsInputRedirected ? Console.ReadLine() ?? "" : ReadPassword();
if (!Console.IsInputRedirected) Console.Error.WriteLine();
if (password.Length == 0) return 2;

var connectionString = new NpgsqlConnectionStringBuilder
{
    Host = host,
    Port = portValue is null ? 5432 : int.Parse(portValue),
    Database = Environment.GetEnvironmentVariable("MARID_DB_NAME") ?? "marid",
    Username = Environment.GetEnvironmentVariable("MARID_DB_MIGRATION_USER") ?? "marid_owner",
    Password = password,
    Pooling = false,
    SslMode = SslMode.Disable,
    ApplicationName = "Marid.Admin"
}.ConnectionString;

try
{
    await using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();
    if (migrating)
        await MigrationRunner.RunAsync(connection, args.Length == 2 ? args[1] : "migrations");
    else if (creatingTenant)
        await TenantCreator.CreateAsync(connection, args[1], args[2]);
    else if (grantingRole)
        await TenantRoleGrantor.GrantAsync(connection, grantTenantId,
            args[2], args[3], args[4], args[5], grantExpiry);
    else if (revokingRole)
        await TenantRoleGrantor.RevokeAsync(connection, revokeTenantId,
            args[2], args[3], args[4]);
    else if (listingDomains)
        await DeploymentDomains.ListAsync(connection, listDomainTenantId);
    else if (args[0] == "register-domain")
        await DeploymentDomains.RegisterAsync(connection, domainTenantId, args[2]);
    else if (args[0] == "remove-domain")
        await DeploymentDomains.RemoveAsync(connection, domainTenantId, args[2]);
    else if (!await DeploymentDomains.VerifyAsync(connection, domainTenantId, args[2]))
        return 1;
    return 0;
}
catch (PostgresException ex)
{
    Console.Error.WriteLine($"Database rejected the operation (SQLSTATE {ex.SqlState}).");
    return 1;
}
catch (NpgsqlException)
{
    Console.Error.WriteLine("Could not connect to the database or complete the operation.");
    return 1;
}
catch (IOException ex)
{
    Console.Error.WriteLine($"Migration file error: {ex.Message}");
    return 1;
}
catch (InvalidOperationException ex)
{
    Console.Error.WriteLine($"Operation rejected: {ex.Message}");
    return 1;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Operation rejected: {ex.Message}");
    return 2;
}

static string ReadPassword()
{
    var characters = new List<char>();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (characters.Count > 0) characters.RemoveAt(characters.Count - 1);
            continue;
        }
        if (!char.IsControl(key.KeyChar) && characters.Count < 1024)
            characters.Add(key.KeyChar);
    }
    var password = new string(characters.ToArray());
    characters.Clear();
    return password;
}
