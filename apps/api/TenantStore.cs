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
        Guid? evidenceId = null;
        if (input.RawEventReference.StartsWith("evidence:", StringComparison.Ordinal))
        {
            evidenceId = Guid.Parse(input.RawEventReference[9..]);
            await using var evidence = new NpgsqlCommand(
                "SELECT 1 FROM evidence_objects WHERE id = @id AND deleted_at IS NULL",
                connection, transaction);
            evidence.Parameters.AddWithValue("id", evidenceId.Value);
            if (await evidence.ExecuteScalarAsync(ct) is null)
                throw new EvidenceNotFoundException();
        }
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
            if (evidenceId is Guid linkedId)
            {
                await using var link = new NpgsqlCommand("""
                    INSERT INTO event_evidence_links (tenant_id, event_id, evidence_id)
                    VALUES (@tenant_id, @event_id, @evidence_id)
                    """, connection, transaction);
                link.Parameters.AddWithValue("tenant_id", context.TenantId);
                link.Parameters.AddWithValue("event_id", createdId);
                link.Parameters.AddWithValue("evidence_id", linkedId);
                await link.ExecuteNonQueryAsync(ct);
            }
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
        await using (var activity = new NpgsqlCommand("""
            INSERT INTO incident_activity
                (id, tenant_id, incident_id, kind, status, note, actor_id,
                 service_id, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @incident_id, 'CREATED', 'OPEN', @note,
                    @actor_id, @service_id, @correlation_id, @trace_id)
            """, connection, transaction))
        {
            activity.Parameters.AddWithValue("id", Guid.NewGuid());
            activity.Parameters.AddWithValue("tenant_id", context.TenantId);
            activity.Parameters.AddWithValue("incident_id", id);
            activity.Parameters.AddWithValue("note", "Incident created: " + title);
            activity.Parameters.AddWithValue("actor_id", context.ActorId);
            activity.Parameters.AddWithValue("service_id", context.ServiceId);
            activity.Parameters.AddWithValue("correlation_id", correlationId);
            activity.Parameters.AddWithValue("trace_id", traceId);
            await activity.ExecuteNonQueryAsync(ct);
        }
        await WriteAuditAsync(connection, transaction, context, "incident.created", id,
            correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        return new IncidentSummary(id, title, severity, "OPEN",
            new DateTimeOffset(createdAtUtc, TimeSpan.Zero));
    }

    public async Task<bool> LinkIncidentEventAsync(TenantContext context,
        Guid incidentId, Guid eventId, string correlationId, string traceId,
        CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var link = new NpgsqlCommand("""
            INSERT INTO incident_event_links
                (tenant_id, incident_id, event_id, linked_by)
            SELECT @tenant_id, @incident_id, @event_id, @actor_id
            WHERE EXISTS (SELECT 1 FROM incidents WHERE id = @incident_id)
              AND EXISTS (SELECT 1 FROM security_events WHERE id = @event_id)
            ON CONFLICT DO NOTHING
            RETURNING event_id
            """, connection, transaction);
        link.Parameters.AddWithValue("tenant_id", context.TenantId);
        link.Parameters.AddWithValue("incident_id", incidentId);
        link.Parameters.AddWithValue("event_id", eventId);
        link.Parameters.AddWithValue("actor_id", context.ActorId);
        var created = await link.ExecuteScalarAsync(ct) is Guid;
        if (created)
            await AuditLedger.WriteAsync(connection, transaction, context,
                "incident.event_linked", incidentId, correlationId, traceId, ct,
                target: eventId.ToString());
        await transaction.CommitAsync(ct);
        return created;
    }

    public async Task<IncidentActivitySummary?> AddIncidentActivityAsync(
        TenantContext context, Guid incidentId, string kind, string status,
        string note, string correlationId, string traceId, CancellationToken ct)
    {
        if (kind is not ("INVESTIGATION" or "REMEDIATION" or "STATUS" or "CLOSED") ||
            status is not ("OPEN" or "INVESTIGATING" or "CONTAINED" or "RESOLVED" or "CLOSED") ||
            string.IsNullOrWhiteSpace(note) || note.Length > 4000 || note.Any(char.IsControl))
            throw new ArgumentException("Invalid incident activity.");
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var current = new NpgsqlCommand(
            "SELECT status FROM incidents WHERE id = @id FOR UPDATE", connection, transaction);
        current.Parameters.AddWithValue("id", incidentId);
        var oldStatus = await current.ExecuteScalarAsync(ct) as string;
        if (oldStatus is null) return null;
        var states = new[] { "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED" };
        var oldIndex = Array.IndexOf(states, oldStatus);
        var newIndex = Array.IndexOf(states, status);
        if (newIndex < oldIndex || newIndex > oldIndex + 1 ||
            (kind == "CLOSED") != (status == "CLOSED") ||
            (kind is "INVESTIGATION" or "REMEDIATION" && status != oldStatus))
            throw new ArgumentException("Invalid incident status transition.");
        if (status != oldStatus)
        {
            await using var change = new NpgsqlCommand(
                "UPDATE incidents SET status = @status, updated_at = now() WHERE id = @id",
                connection, transaction);
            change.Parameters.AddWithValue("status", status);
            change.Parameters.AddWithValue("id", incidentId);
            await change.ExecuteNonQueryAsync(ct);
        }
        var id = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO incident_activity
                (id, tenant_id, incident_id, kind, status, note, actor_id,
                 service_id, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @incident_id, @kind, @status, @note,
                    @actor_id, @service_id, @correlation_id, @trace_id)
            RETURNING occurred_at
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("incident_id", incidentId);
        insert.Parameters.AddWithValue("kind", kind);
        insert.Parameters.AddWithValue("status", status);
        insert.Parameters.AddWithValue("note", note);
        insert.Parameters.AddWithValue("actor_id", context.ActorId);
        insert.Parameters.AddWithValue("service_id", context.ServiceId);
        insert.Parameters.AddWithValue("correlation_id", correlationId);
        insert.Parameters.AddWithValue("trace_id", traceId);
        var at = (DateTime)(await insert.ExecuteScalarAsync(ct))!;
        await AuditLedger.WriteAsync(connection, transaction, context,
            "incident.activity_recorded", incidentId, correlationId, traceId, ct,
            outcome: status);
        await transaction.CommitAsync(ct);
        return new(id, incidentId, kind, status, note,
            new DateTimeOffset(at, TimeSpan.Zero));
    }

    public async Task<IReadOnlyList<IncidentActivitySummary>?> ListIncidentActivityAsync(
        TenantContext context, Guid incidentId, CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var exists = new NpgsqlCommand(
            "SELECT 1 FROM incidents WHERE id = @id", connection, transaction);
        exists.Parameters.AddWithValue("id", incidentId);
        if (await exists.ExecuteScalarAsync(ct) is null) return null;
        await using var command = new NpgsqlCommand("""
            SELECT id, incident_id, kind, status, note, occurred_at
            FROM incident_activity WHERE incident_id = @id
            ORDER BY occurred_at, id LIMIT 1000
            """, connection, transaction);
        command.Parameters.AddWithValue("id", incidentId);
        var result = new List<IncidentActivitySummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            result.Add(new(reader.GetGuid(0), reader.GetGuid(1),
                reader.GetString(2), reader.GetString(3), reader.GetString(4),
                new DateTimeOffset(reader.GetDateTime(5), TimeSpan.Zero)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    private static Task WriteAuditAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, TenantContext context, string action,
        Guid objectId, string correlationId, string traceId, CancellationToken ct) =>
        AuditLedger.WriteAsync(connection, transaction, context, action,
            objectId, correlationId, traceId, ct);
}

public sealed class EvidenceNotFoundException : Exception;
