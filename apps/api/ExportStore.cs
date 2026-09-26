using Npgsql;

namespace Marid.Api;

public sealed record ExportRequest(DateTimeOffset PeriodStart, DateTimeOffset PeriodEnd,
    string IdempotencyKey);
public sealed record ExportJobSummary(Guid Id, DateTimeOffset PeriodStart,
    DateTimeOffset PeriodEnd, string Status, DateTimeOffset RequestedAt,
    DateTimeOffset? CompletedAt, long BytesTotal, string? ManifestSha256);
public sealed record ExportArtifactSummary(Guid Id, string Name, long ByteSize,
    string Sha256);
public sealed record ExportCreateResult(ExportJobSummary Job, bool Created,
    bool Conflict);

public sealed class ExportStore(TenantDb tenantDb, IObjectStore objects)
{
    public static bool IsValid(ExportRequest request) =>
        request.PeriodStart.Offset == TimeSpan.Zero &&
        request.PeriodEnd.Offset == TimeSpan.Zero &&
        request.PeriodEnd > request.PeriodStart &&
        request.PeriodEnd <= DateTimeOffset.UtcNow &&
        request.PeriodEnd <= request.PeriodStart.AddYears(1) &&
        request.IdempotencyKey.Length is >= 8 and <= 120 &&
        request.IdempotencyKey.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    public async Task<ExportCreateResult> CreateAsync(TenantContext context,
        ExportRequest request, string correlationId, string traceId,
        CancellationToken ct)
    {
        if (!IsValid(request)) throw new ArgumentException("Invalid UTC export interval or idempotency key.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var id = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO export_jobs
                (id, tenant_id, period_start, period_end, requested_by, idempotency_key)
            VALUES (@id, @tenant_id, @period_start, @period_end, @requested_by, @key)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            RETURNING id
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("period_start", request.PeriodStart);
        insert.Parameters.AddWithValue("period_end", request.PeriodEnd);
        insert.Parameters.AddWithValue("requested_by", context.ActorId);
        insert.Parameters.AddWithValue("key", request.IdempotencyKey);
        var created = await insert.ExecuteScalarAsync(ct) is Guid;
        if (!created)
        {
            await using var lookup = new NpgsqlCommand(
                "SELECT id FROM export_jobs WHERE idempotency_key = @key", connection, transaction);
            lookup.Parameters.AddWithValue("key", request.IdempotencyKey);
            id = (Guid)(await lookup.ExecuteScalarAsync(ct)
                ?? throw new InvalidOperationException("Idempotent job is not visible in this tenant."));
        }
        var job = (await LoadAsync(connection, transaction, id, ct))!;
        if (created)
            await AuditLedger.WriteAsync(connection, transaction, context,
                "export.queued", id, correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        if (created) EvidenceMetrics.ExportsQueued.Add(1);
        return new(job, created, job.PeriodStart != request.PeriodStart ||
                                 job.PeriodEnd != request.PeriodEnd);
    }

    public async Task<IReadOnlyList<ExportJobSummary>> ListAsync(TenantContext context,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT id, period_start, period_end, status, requested_at,
                   completed_at, bytes_total, manifest_sha256
            FROM export_jobs ORDER BY requested_at DESC, id LIMIT 100
            """, connection, transaction);
        var result = new List<ExportJobSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) result.Add(Read(reader));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<ExportJobSummary?> GetAsync(TenantContext context, Guid id,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var job = await LoadAsync(connection, transaction, id, ct);
        await transaction.CommitAsync(ct);
        return job;
    }

    public async Task<IReadOnlyList<ExportArtifactSummary>?> ArtifactsAsync(
        TenantContext context, Guid jobId, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        if (await LoadAsync(connection, transaction, jobId, ct) is null) return null;
        await using var command = new NpgsqlCommand("""
            SELECT id, name, byte_size, sha256 FROM export_artifacts
            WHERE job_id = @job_id ORDER BY name
            """, connection, transaction);
        command.Parameters.AddWithValue("job_id", jobId);
        var result = new List<ExportArtifactSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            result.Add(new(reader.GetGuid(0), reader.GetString(1),
                reader.GetInt64(2), reader.GetString(3).Trim()));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<(Stream Content, string Name)?> OpenArtifactAsync(
        TenantContext context, Guid jobId, Guid? artifactId, string correlationId,
        string traceId, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = artifactId is Guid
            ? new NpgsqlCommand("""
                SELECT a.object_key, a.sha256, a.name
                FROM export_artifacts a JOIN export_jobs j
                  ON j.tenant_id = a.tenant_id AND j.id = a.job_id
                WHERE j.id = @job_id AND j.status = 'COMPLETED' AND a.id = @artifact_id
                """, connection, transaction)
            : new NpgsqlCommand("""
                SELECT manifest_key, manifest_sha256, 'manifest.json'
                FROM export_jobs WHERE id = @job_id AND status = 'COMPLETED'
                """, connection, transaction);
        command.Parameters.AddWithValue("job_id", jobId);
        if (artifactId is Guid id) command.Parameters.AddWithValue("artifact_id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct) || reader.IsDBNull(0) || reader.IsDBNull(1))
            return null;
        var key = reader.GetString(0);
        var hash = reader.GetString(1).Trim();
        var name = reader.GetString(2);
        await reader.DisposeAsync();
        var stream = await objects.OpenVerifiedAsync(key, hash, ct);
        try
        {
            await AuditLedger.WriteAsync(connection, transaction, context,
                "export.download_requested", jobId, correlationId, traceId, ct,
                target: name);
            await transaction.CommitAsync(ct);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
        return (stream, name);
    }

    public async Task RecordDeliveryAsync(TenantContext context, Guid jobId,
        string name, bool succeeded, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            INSERT INTO export_deliveries
                (id, tenant_id, job_id, destination_type, outcome, receipt)
            VALUES (@id, @tenant_id, @job_id, 'API', @outcome, @receipt)
            """, connection, transaction);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("job_id", jobId);
        command.Parameters.AddWithValue("outcome", succeeded ? "SUCCEEDED" : "FAILED");
        command.Parameters.AddWithValue("receipt", name);
        await command.ExecuteNonQueryAsync(ct);
        await AuditLedger.WriteAsync(connection, transaction, context,
            succeeded ? "export.delivery_succeeded" : "export.delivery_failed",
            jobId, jobId.ToString(), jobId.ToString(), ct,
            target: name, highPriority: !succeeded);
        await transaction.CommitAsync(ct);
        if (succeeded) EvidenceMetrics.DeliverySucceeded.Add(1);
        else EvidenceMetrics.DeliveryFailed.Add(1);
    }

    private static async Task<ExportJobSummary?> LoadAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, Guid id, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT id, period_start, period_end, status, requested_at,
                   completed_at, bytes_total, manifest_sha256
            FROM export_jobs WHERE id = @id
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Read(reader) : null;
    }

    private static ExportJobSummary Read(NpgsqlDataReader reader) => new(
        reader.GetGuid(0), new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero),
        new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero), reader.GetString(3),
        new DateTimeOffset(reader.GetDateTime(4), TimeSpan.Zero),
        reader.IsDBNull(5) ? null : new DateTimeOffset(reader.GetDateTime(5), TimeSpan.Zero),
        reader.GetInt64(6), reader.IsDBNull(7) ? null : reader.GetString(7).Trim());
}
