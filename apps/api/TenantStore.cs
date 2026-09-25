using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Marid.Api;

public sealed class TenantStore(NpgsqlDataSource dataSource)
{
    private async Task<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)> OpenTenantAsync(
        TenantContext context, CancellationToken ct)
    {
        var connection = await dataSource.OpenConnectionAsync(ct);
        try
        {
            var transaction = await connection.BeginTransactionAsync(ct);
            await using var setContext = new NpgsqlCommand(
                "SELECT set_config('app.tenant_id', @tenant_id, true), set_config('app.actor_id', @actor_id, true)",
                connection, transaction);
            setContext.Parameters.AddWithValue("tenant_id", context.TenantId.ToString());
            setContext.Parameters.AddWithValue("actor_id", context.ActorId);
            await setContext.ExecuteNonQueryAsync(ct);
            return (connection, transaction);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    public async Task<EventIngestResult> IngestEventAsync(TenantContext context,
        SecurityEventInput input, string requestTraceId, string correlationId, CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var id = Guid.NewGuid();
        const string sql = """
            INSERT INTO security_events
                (id, tenant_id, source, source_event_id, category, source_at, normalized_at,
                 sensor_identity, parser_version, raw_event_reference, entity_references,
                 provenance, confidence, correlation_id, trace_id, schema_version,
                 actor_id, service_id, structured_sha256)
            VALUES
                (@id, @tenant_id, @source, @source_event_id, @category, @source_at, now(),
                 @sensor_identity, @parser_version, @raw_event_reference, @entity_references,
                 @provenance, @confidence, @correlation_id, @trace_id, 1,
                 @actor_id, @service_id, @structured_sha256)
            ON CONFLICT (tenant_id, source, source_event_id) DO NOTHING
            RETURNING id
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("source", input.Source.Trim());
        command.Parameters.AddWithValue("source_event_id", input.SourceEventId.Trim());
        command.Parameters.AddWithValue("category", input.Category.Trim());
        command.Parameters.AddWithValue("source_at", input.SourceTimestamp.ToUniversalTime());
        command.Parameters.AddWithValue("sensor_identity", input.SensorIdentity.Trim());
        command.Parameters.AddWithValue("parser_version", input.ParserVersion.Trim());
        command.Parameters.AddWithValue("raw_event_reference", input.RawEventReference.Trim());
        command.Parameters.AddWithValue("entity_references", input.EntityReferences);
        command.Parameters.Add(new NpgsqlParameter("provenance", NpgsqlDbType.Jsonb)
            { Value = input.Provenance.GetRawText() });
        command.Parameters.AddWithValue("confidence", input.Confidence);
        command.Parameters.AddWithValue("correlation_id",
            string.IsNullOrWhiteSpace(input.CorrelationId) ? correlationId : input.CorrelationId);
        command.Parameters.AddWithValue("trace_id",
            string.IsNullOrWhiteSpace(input.TraceId) ? requestTraceId : input.TraceId);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        var structuredHash = Convert.ToHexString(
            SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(input))).ToLowerInvariant();
        command.Parameters.AddWithValue("structured_sha256", structuredHash);
        var inserted = await command.ExecuteScalarAsync(ct);
        if (inserted is Guid createdId)
        {
            await WriteAuditAsync(connection, transaction, context, "security_event.ingested",
                createdId, correlationId, requestTraceId, ct);
            await transaction.CommitAsync(ct);
            return new EventIngestResult(createdId, true);
        }

        await using var lookup = new NpgsqlCommand(
            "SELECT id, structured_sha256 FROM security_events WHERE tenant_id = @tenant_id AND source = @source AND source_event_id = @source_event_id",
            connection, transaction);
        lookup.Parameters.AddWithValue("tenant_id", context.TenantId);
        lookup.Parameters.AddWithValue("source", input.Source.Trim());
        lookup.Parameters.AddWithValue("source_event_id", input.SourceEventId.Trim());
        await using var reader = await lookup.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            throw new InvalidOperationException("Duplicate event was not visible in this tenant.");
        var existing = reader.GetGuid(0);
        var existingHash = reader.GetString(1).Trim();
        await reader.DisposeAsync();
        var conflicting = !ProposalValidator.HashesEqual(structuredHash, existingHash);
        if (conflicting)
            await WriteAuditAsync(connection, transaction, context,
                "security_event.duplicate_conflict", existing, correlationId, requestTraceId, ct);
        await transaction.CommitAsync(ct);
        return new EventIngestResult(existing, false, conflicting);
    }

    public async Task<IReadOnlyList<IncidentSummary>> ListIncidentsAsync(
        TenantContext context, CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand(
            "SELECT id, title, severity, status, created_at FROM incidents ORDER BY created_at DESC LIMIT 100",
            connection, transaction);
        var incidents = new List<IncidentSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            incidents.Add(new IncidentSummary(reader.GetGuid(0), reader.GetString(1),
                Enum.Parse<IncidentSeverity>(reader.GetString(2), true), reader.GetString(3),
                new DateTimeOffset(reader.GetDateTime(4), TimeSpan.Zero)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return incidents;
    }

    public async Task<IncidentSummary> CreateIncidentAsync(TenantContext context,
        string title, IncidentSeverity severity, string correlationId, string traceId,
        CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var id = Guid.NewGuid();
        await using var command = new NpgsqlCommand(
            "INSERT INTO incidents (id, tenant_id, title, severity, status) VALUES (@id, @tenant_id, @title, @severity, 'OPEN') RETURNING created_at",
            connection, transaction);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("title", title);
        command.Parameters.AddWithValue("severity", severity.ToString().ToUpperInvariant());
        var createdAtUtc = (DateTime)(await command.ExecuteScalarAsync(ct)
            ?? throw new InvalidOperationException("Incident insert did not return a timestamp."));
        await WriteAuditAsync(connection, transaction, context, "incident.created", id,
            correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        return new IncidentSummary(id, title, severity, "OPEN",
            new DateTimeOffset(createdAtUtc, TimeSpan.Zero));
    }

    private static async Task WriteAuditAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, TenantContext context, string action,
        Guid objectId, string correlationId, string traceId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "INSERT INTO audit_events (id, tenant_id, actor_id, service_id, action, object_id, correlation_id, trace_id) VALUES (@id, @tenant_id, @actor_id, @service_id, @action, @object_id, @correlation_id, @trace_id)",
            connection, transaction);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("tenant_id", context.TenantId);
        command.Parameters.AddWithValue("actor_id", context.ActorId);
        command.Parameters.AddWithValue("service_id", context.ServiceId);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("object_id", objectId);
        command.Parameters.AddWithValue("correlation_id", correlationId);
        command.Parameters.AddWithValue("trace_id", traceId);
        await command.ExecuteNonQueryAsync(ct);
    }
}
