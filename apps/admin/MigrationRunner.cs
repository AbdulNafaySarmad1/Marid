using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;

public static class MigrationRunner
{
    private const long AdvisoryLockId = 698_395_682_746_039_255;
    private static readonly Regex FileNamePattern = new(
        "^(?<version>[0-9]{3})_[a-z0-9_-]+\\.sql$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<MigrationFile> Discover(string directory)
    {
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException($"Migration directory not found: {directory}");
        var paths = Directory.GetFiles(directory, "*.sql");
        if (paths.Any(path => !FileNamePattern.IsMatch(Path.GetFileName(path))))
            throw new InvalidOperationException("Every SQL file must have a numbered migration name.");
        var files = paths
            .Select(path => new { Path = path, Match = FileNamePattern.Match(Path.GetFileName(path)) })
            .Select(entry => new MigrationFile(
                int.Parse(entry.Match.Groups["version"].Value),
                Path.GetFileName(entry.Path),
                entry.Path,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(entry.Path))).ToLowerInvariant()))
            .OrderBy(file => file.Version)
            .ToArray();
        if (files.Length == 0) throw new InvalidOperationException("No numbered SQL migrations found.");
        for (var index = 0; index < files.Length; index++)
        {
            if (files[index].Version != index + 1)
                throw new InvalidOperationException("Migrations must be numbered contiguously from 001.");
        }
        return files;
    }

    public static async Task RunAsync(NpgsqlConnection connection, string directory,
        CancellationToken cancellationToken = default)
    {
        var files = Discover(directory);
        await using var lockCommand = new NpgsqlCommand(
            "SELECT pg_advisory_lock(@lock_id)", connection);
        lockCommand.Parameters.AddWithValue("lock_id", AdvisoryLockId);
        await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        try
        {
            await using (var ledger = new NpgsqlCommand("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version integer PRIMARY KEY,
                    name text NOT NULL,
                    sha256 char(64) NOT NULL,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """, connection))
                await ledger.ExecuteNonQueryAsync(cancellationToken);

            await using (var missingFile = new NpgsqlCommand(
                "SELECT version FROM schema_migrations WHERE NOT (version = ANY(@versions)) LIMIT 1",
                connection))
            {
                missingFile.Parameters.AddWithValue("versions", files.Select(x => x.Version).ToArray());
                if (await missingFile.ExecuteScalarAsync(cancellationToken) is int missingVersion)
                    throw new InvalidOperationException(
                        $"Previously applied migration {missingVersion:000} is missing from disk.");
            }

            foreach (var file in files)
            {
                await using var find = new NpgsqlCommand(
                    "SELECT name, sha256 FROM schema_migrations WHERE version = @version", connection);
                find.Parameters.AddWithValue("version", file.Version);
                await using var reader = await find.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    var priorName = reader.GetString(0);
                    var priorHash = reader.GetString(1).Trim();
                    if (priorName != file.Name || priorHash != file.Sha256)
                        throw new InvalidOperationException($"Applied migration {file.Version:000} differs from the file on disk.");
                    continue;
                }
                await reader.DisposeAsync();

                await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
                var bytes = await File.ReadAllBytesAsync(file.Path, cancellationToken);
                var actualHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                if (actualHash != file.Sha256)
                    throw new InvalidOperationException($"Migration changed while being applied: {file.Name}");
                var sql = new UTF8Encoding(false, true).GetString(bytes);
                await using var migration = new NpgsqlCommand(sql, connection, transaction)
                {
                    CommandTimeout = 120
                };
                await migration.ExecuteNonQueryAsync(cancellationToken);
                await using var record = new NpgsqlCommand(
                    "INSERT INTO schema_migrations (version, name, sha256) VALUES (@version, @name, @sha256)",
                    connection, transaction);
                record.Parameters.AddWithValue("version", file.Version);
                record.Parameters.AddWithValue("name", file.Name);
                record.Parameters.AddWithValue("sha256", file.Sha256);
                await record.ExecuteNonQueryAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                Console.WriteLine($"Applied {file.Name}");
            }
        }
        finally
        {
            await using var unlock = new NpgsqlCommand("SELECT pg_advisory_unlock(@lock_id)", connection);
            unlock.Parameters.AddWithValue("lock_id", AdvisoryLockId);
            await unlock.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}

public sealed record MigrationFile(int Version, string Name, string Path, string Sha256);
