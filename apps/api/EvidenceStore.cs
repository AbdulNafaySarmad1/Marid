using Npgsql;

namespace Marid.Api;

public sealed record EvidenceUpload(
    string Source, string SourceEventId, DateTimeOffset SourceAt,
    string SensorIdentity, string ContentType, string ParserVersion,
    string RetentionClass);

public sealed record EvidenceSummary(Guid Id, string Source, string SourceEventId,
    DateTimeOffset SourceAt, DateTimeOffset IngestedAt, string SensorIdentity,
    string ContentType, long ByteSize, string Sha256, string ParserVersion,
    string RetentionClass, string IntegrityState, string CorrelationId,
    string TraceId, bool LegalHold);

public sealed class EvidenceStore(TenantDb tenantDb, IObjectStore objects)
{
    public const long MaxUploadBytes = 64L * 1024 * 1024;

    public static bool IsValid(EvidenceUpload value) =>
        Check(value.Source, 120) && Check(value.SourceEventId, 200) &&
        Check(value.SensorIdentity, 200) && Check(value.ContentType, 120) &&
        Check(value.ParserVersion, 80) &&
        value.RetentionClass is "RAW" or "EXTENDED" &&
        value.SourceAt != default && value.SourceAt <= DateTimeOffset.UtcNow.AddMinutes(5);

    public async Task<(EvidenceSummary Summary, bool Created, bool Conflict)> UploadAsync(
        TenantContext context, EvidenceUpload input, Stream body,
        string correlationId, string traceId, CancellationToken ct)
    {
        if (!IsValid(input)) throw new ArgumentException("Invalid evidence metadata.");
        var id = Guid.NewGuid();
        var key = $"evidence/{context.TenantId:N}/{id:N}.bin";
        StoredObject stored;
        try { stored = await objects.PutAsync(key, async (output, token) =>
        {
            var buffer = new byte[131072];
            long total = 0;
            int count;
            while ((count = await body.ReadAsync(buffer, token)) > 0)
            {
                total += count;
                if (total > MaxUploadBytes) throw new InvalidDataException("Evidence exceeds 64 MiB.");
                await output.WriteAsync(buffer.AsMemory(0, count), token);
            }
        }, ct); }
        catch (Exception error) when (error is IOException or InvalidDataException)
        {
            EvidenceMetrics.StorageFailures.Add(1);
            throw;
        }
        try
        {
            var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
            await using var ownedConnection = connection;
            await using var ownedTransaction = transaction;
            await using var insert = new NpgsqlCommand("""
                INSERT INTO evidence_objects
                    (id, tenant_id, source, source_event_id, source_at,
                     sensor_identity, content_type, byte_size, object_key, sha256,
                     parser_version, correlation_id, trace_id, retention_class)
                VALUES (@id, @tenant_id, @source, @source_event_id, @source_at,
                        @sensor_identity, @content_type, @byte_size, @object_key,
                        @sha256, @parser_version, @correlation_id, @trace_id,
                        @retention_class)
                ON CONFLICT (tenant_id, source, source_event_id) DO NOTHING
                RETURNING ingested_at
                """, connection, transaction);
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("tenant_id", context.TenantId);
            insert.Parameters.AddWithValue("source", input.Source);
            insert.Parameters.AddWithValue("source_event_id", input.SourceEventId);
            insert.Parameters.AddWithValue("source_at", input.SourceAt.ToUniversalTime());
            insert.Parameters.AddWithValue("sensor_identity", input.SensorIdentity);
            insert.Parameters.AddWithValue("content_type", input.ContentType);
            insert.Parameters.AddWithValue("byte_size", stored.ByteSize);
            insert.Parameters.AddWithValue("object_key", key);
            insert.Parameters.AddWithValue("sha256", stored.Sha256);
            insert.Parameters.AddWithValue("parser_version", input.ParserVersion);
            insert.Parameters.AddWithValue("correlation_id", correlationId);
            insert.Parameters.AddWithValue("trace_id", traceId);
            insert.Parameters.AddWithValue("retention_class", input.RetentionClass);
            var createdAt = await insert.ExecuteScalarAsync(ct);
            if (createdAt is DateTime timestamp)
            {
                await AuditLedger.WriteAsync(connection, transaction, context,
                    "evidence.ingested", id, correlationId, traceId, ct);
                await transaction.CommitAsync(ct);
                EvidenceMetrics.EvidenceIngested.Add(1);
                EvidenceMetrics.EvidenceBytes.Add(stored.ByteSize);
                return (new EvidenceSummary(id, input.Source, input.SourceEventId,
                    input.SourceAt.ToUniversalTime(), new DateTimeOffset(timestamp, TimeSpan.Zero),
                    input.SensorIdentity, input.ContentType, stored.ByteSize, stored.Sha256,
                    input.ParserVersion, input.RetentionClass, "VERIFIED", correlationId, traceId,
                    false),
                    true, false);
            }
            var prior = await LoadAsync(connection, transaction, input.Source,
                input.SourceEventId, ct);
            await transaction.CommitAsync(ct);
            await objects.DeleteAsync(key, ct);
            return (prior!, false, prior!.Sha256 != stored.Sha256 ||
                prior.ByteSize != stored.ByteSize ||
                prior.SensorIdentity != input.SensorIdentity ||
                prior.ContentType != input.ContentType ||
                prior.ParserVersion != input.ParserVersion ||
                prior.RetentionClass != input.RetentionClass ||
                Math.Abs((prior.SourceAt - input.SourceAt.ToUniversalTime()).Ticks) >= 10);
        }
        catch
        {
            await objects.DeleteAsync(key, CancellationToken.None);
            throw;
        }
    }

    public async Task<EvidenceSummary?> GetAsync(TenantContext context, Guid id,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT id, source, source_event_id, source_at, ingested_at,
                   sensor_identity, content_type, byte_size, sha256,
                   parser_version, retention_class, integrity_state,
                   correlation_id, trace_id,
                   EXISTS (SELECT 1 FROM legal_holds h WHERE h.tenant_id = evidence_objects.tenant_id
                           AND h.evidence_id = evidence_objects.id AND h.released_at IS NULL)
            FROM evidence_objects WHERE id = @id AND deleted_at IS NULL
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? Read(reader) : null;
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<(Stream Content, EvidenceSummary Metadata)?> OpenAsync(
        TenantContext context, Guid id, string correlationId, string traceId,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT id, source, source_event_id, source_at, ingested_at,
                   sensor_identity, content_type, byte_size, sha256,
                   parser_version, retention_class, integrity_state,
                   correlation_id, trace_id,
                   EXISTS (SELECT 1 FROM legal_holds h WHERE h.tenant_id = evidence_objects.tenant_id
                           AND h.evidence_id = evidence_objects.id AND h.released_at IS NULL),
                   object_key
            FROM evidence_objects WHERE id = @id AND deleted_at IS NULL
            """, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        var metadata = Read(reader);
        var key = reader.GetString(15);
        await reader.DisposeAsync();
        Stream stream;
        try { stream = await objects.OpenVerifiedAsync(key, metadata.Sha256, ct); }
        catch (Exception error) when (error is IOException or InvalidDataException)
        {
            EvidenceMetrics.IntegrityFailures.Add(1);
            await using var failure = new NpgsqlCommand(
                "SELECT marid_mark_evidence_integrity_failed(@id)", connection, transaction);
            failure.Parameters.AddWithValue("id", id);
            await failure.ExecuteNonQueryAsync(ct);
            await AuditLedger.WriteAsync(connection, transaction, context,
                "evidence.integrity_failed", id, correlationId, traceId, ct,
                highPriority: true);
            await transaction.CommitAsync(ct);
            throw;
        }
        await AuditLedger.WriteAsync(connection, transaction, context,
            "evidence.download_requested", id, correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        return (stream, metadata);
    }

    private static async Task<EvidenceSummary?> LoadAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string source, string sourceEventId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT id, source, source_event_id, source_at, ingested_at,
                   sensor_identity, content_type, byte_size, sha256,
                   parser_version, retention_class, integrity_state,
                   correlation_id, trace_id,
                   EXISTS (SELECT 1 FROM legal_holds h WHERE h.tenant_id = evidence_objects.tenant_id
                           AND h.evidence_id = evidence_objects.id AND h.released_at IS NULL)
            FROM evidence_objects WHERE source = @source AND source_event_id = @source_event_id
            """, connection, transaction);
        command.Parameters.AddWithValue("source", source);
        command.Parameters.AddWithValue("source_event_id", sourceEventId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Read(reader) : null;
    }

    private static EvidenceSummary Read(NpgsqlDataReader reader) => new(
        reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
        new DateTimeOffset(reader.GetDateTime(3), TimeSpan.Zero),
        new DateTimeOffset(reader.GetDateTime(4), TimeSpan.Zero),
        reader.GetString(5), reader.GetString(6), reader.GetInt64(7),
        reader.GetString(8).Trim(), reader.GetString(9), reader.GetString(10),
        reader.GetString(11), reader.GetString(12), reader.GetString(13),
        reader.GetBoolean(14));

    private static bool Check(string value, int length) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= length &&
        !value.Any(char.IsControl);
}
