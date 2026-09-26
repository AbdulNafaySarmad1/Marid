using System.Text;
using System.Text.Json;
using Npgsql;

namespace Marid.Api;

public interface IManifestSigner
{
    string SignerId { get; }
    Task<byte[]> SignAsync(ReadOnlyMemory<byte> manifest, CancellationToken ct);
}

public sealed record ManifestArtifact(Guid Id, string Name, long ByteSize,
    string Sha256, long RowCount);
public sealed record ExportManifest(
    int SchemaVersion, Guid ExportId, Guid TenantId, DateTimeOffset PeriodStart,
    DateTimeOffset PeriodEnd, DateTimeOffset GeneratedAt, string MaridVersion,
    string GeneratorVersion, string? PreviousManifestSha256,
    IReadOnlyList<ManifestArtifact> Artifacts, string? SignerId,
    string? SignatureBase64);

public sealed class ExportWorker(
    NpgsqlDataSource workerSource, IObjectStore objects,
    ILogger<ExportWorker> logger, IManifestSigner? signer = null) : BackgroundService
{
    private readonly TenantDb tenantDb = new(workerSource);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private sealed record Dataset(string Name, string Table, string Timestamp,
        string Columns, string? Cutoff = null, string OrderId = "id");

    private static readonly Dataset[] Datasets =
    [
        new("security-events", "security_events", "source_at",
            "id, source, source_event_id, category, source_at, ingested_at, normalized_at, schema_version, entity_references, provenance, confidence, correlation_id, trace_id, actor_id, service_id, structured_sha256, parser_version, sensor_identity, raw_event_reference, normalization_warnings", "ingested_at"),
        new("evidence", "evidence_objects", "source_at",
            "id, source, source_event_id, source_at, ingested_at, sensor_identity, content_type, byte_size, sha256, parser_version, correlation_id, trace_id, retention_class, integrity_state, CASE WHEN deleted_at <= @cutoff THEN deleted_at ELSE NULL END AS deleted_at", "ingested_at"),
        new("incidents", "incidents", "created_at",
            "id, title, severity, created_at", "created_at"),
        new("incident-activity", "incident_activity", "occurred_at",
            "id, incident_id, kind, status, note, actor_id, service_id, occurred_at, correlation_id, trace_id", "occurred_at"),
        new("incident-event-links", "incident_event_links", "linked_at",
            "incident_id, event_id, linked_at, linked_by", "linked_at", "event_id"),
        new("event-evidence-links", "event_evidence_links", "linked_at",
            "event_id, evidence_id, linked_at", "linked_at", "evidence_id"),
        new("audit", "audit_events", "occurred_at",
            "id, actor_id, service_id, actor_type, role, capability, session_id, action, object_id, reason, ticket_ref, target_resource, parameters_sha256, outcome, approval_id, source_ip, severity, correlation_id, trace_id, occurred_at", "occurred_at"),
        new("operator-sessions", "operator_sessions", "started_at",
            "id, actor_id, service_id, role, reason, ticket_ref, break_glass, source_ip, started_at, CASE WHEN ended_at <= @cutoff THEN ended_at ELSE NULL END AS ended_at, correlation_id, trace_id", "started_at"),
        new("proposals", "response_proposals", "created_at",
            "id, capability_key, resource_id, parameters_sha256, action_sha256, risk, proposer_actor_id, proposer_service_id, policy_outcome, policy_reason, schema_version, created_at, expires_at, correlation_id, trace_id", "created_at"),
        new("proposal-event-links", "response_proposal_events e JOIN response_proposals p ON p.tenant_id = e.tenant_id AND p.id = e.proposal_id", "p.created_at",
            "e.proposal_id, e.event_id, p.created_at", "p.created_at", "e.event_id"),
        new("approvals", "approval_decisions", "decided_at",
            "id, proposal_id, decision, reviewer_actor_id, reviewer_service_id, parameters_sha256, action_sha256, schema_version, decided_at, valid_until, correlation_id, trace_id", "decided_at"),
        new("executions", "action_execution_records", "executed_at",
            "id, proposal_id, approval_id, execution_identity, result, verification_result, rollback_result, result_reference, executed_at, correlation_id, trace_id", "executed_at")
    ];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!objects.IsAvailable) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await EnqueueMonthlyAsync(stoppingToken);
                if (!await RunOnceAsync(stoppingToken))
                    await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception error)
            {
                logger.LogError(error, "Export worker cycle failed");
                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }
    }

    public async Task<bool> RunOnceAsync(CancellationToken ct)
    {
        await using var connection = await workerSource.OpenConnectionAsync(ct);
        await using var claim = new NpgsqlCommand(
            "SELECT job_id, job_tenant_id FROM marid_claim_export_job()", connection);
        await using var reader = await claim.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return false;
        var jobId = reader.GetGuid(0);
        var tenantId = reader.GetGuid(1);
        await reader.DisposeAsync();
        EvidenceMetrics.ExportsStarted.Add(1);
        var context = new TenantContext(tenantId, "marid-export-worker",
            "marid-worker", PrincipalKind.Service, "SYSTEM");
        var claimed = await LoadJobAsync(context, jobId, ct);
        if (claimed is null)
            throw new InvalidOperationException("Claimed job is not visible under its tenant context.");
        try
        {
            await GenerateAsync(context, jobId, claimed.Value, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            logger.LogError(error, "Export job {ExportId} failed", jobId);
            await MarkFailedAsync(context, jobId, claimed.Value.Attempt, ct);
        }
        return true;
    }

    private async Task EnqueueMonthlyAsync(CancellationToken ct)
    {
        await using var connection = await workerSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT marid_enqueue_due_monthly_exports()", connection);
        var count = (int)(await command.ExecuteScalarAsync(ct) ?? 0);
        if (count > 0) logger.LogInformation("Queued {Count} monthly export jobs", count);
    }

    private async Task GenerateAsync(TenantContext context, Guid jobId,
        (DateTimeOffset Start, DateTimeOffset End, DateTimeOffset Requested,
            DateTimeOffset Generated, int Attempt) job, CancellationToken ct)
    {
        var (start, end, requestedAt, generatedAt, attempt) = job;
        using var leaseStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var leaseTask = RenewLeaseAsync(context, jobId, attempt, leaseStop.Token);
        try
        {
            var counts = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var dataset in Datasets)
            {
                for (var from = start; from < end;)
                {
                    var nextMonth = new DateTimeOffset(from.Year, from.Month, 1, 0, 0, 0,
                        TimeSpan.Zero).AddMonths(1);
                    var to = nextMonth < end ? nextMonth : end;
                    var count = await WritePartitionAsync(context, jobId, dataset,
                        from, to, requestedAt, ct);
                    counts[dataset.Name] = counts.GetValueOrDefault(dataset.Name) + count;
                    from = to;
                }
            }
            var report = new
            {
                schemaVersion = 1, exportId = jobId, tenantId = context.TenantId,
                periodStart = start, periodEnd = end, generatedAt,
                executiveSummary = "Tenant security activity and accountability record",
                activityCounts = counts,
                artifactIndex = "manifest.json",
                limitations = new[] { "Raw evidence is referenced by digest; the bundle contains metadata only.",
                    "Incident state history and external action execution depend on upstream records." }
            };
            var reportBytes = JsonSerializer.SerializeToUtf8Bytes(report, JsonOptions);
            await WriteBytesAsync(context, jobId, "report.json", reportBytes, ct);
            var reportText = new StringBuilder()
                .AppendLine("# MARID security activity report")
                .AppendLine()
                .AppendLine($"Export: {jobId}")
                .AppendLine($"Tenant: {context.TenantId}")
                .AppendLine($"UTC interval: {start:O} to {end:O} (end exclusive)")
                .AppendLine($"Generated: {generatedAt:O}")
                .AppendLine()
                .AppendLine("## Activity counts")
                .AppendLine();
            foreach (var item in counts.OrderBy(item => item.Key, StringComparer.Ordinal))
                reportText.AppendLine($"- {item.Key}: {item.Value}");
            reportText.AppendLine()
                .AppendLine("The NDJSON artifacts contain the underlying event, incident, action, and audit records. Raw evidence bytes are available through the authorized evidence API while retained. Verify every downloaded artifact against manifest.json before relying on this report.");
            await WriteBytesAsync(context, jobId, "report.md",
                Encoding.UTF8.GetBytes(reportText.ToString()), ct);
            var artifacts = await LoadArtifactsAsync(context, jobId, ct);
            var manifest = new ExportManifest(1, jobId, context.TenantId,
                start, end, generatedAt, "0.2.0", "1", null, artifacts,
                signer?.SignerId, null);
            var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
            if (signer is not null)
            {
                var signature = await signer.SignAsync(manifestBytes, ct);
                manifest = manifest with { SignatureBase64 = Convert.ToBase64String(signature) };
                manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
            }
            var manifestKey = $"exports/{context.TenantId:N}/{jobId:N}/manifest.json";
            var storedManifest = await objects.PutAsync(manifestKey,
                async (output, token) => await output.WriteAsync(manifestBytes, token), ct);
            await CompleteAsync(context, jobId, attempt, storedManifest, artifacts, ct);
            EvidenceMetrics.ExportsCompleted.Add(1);
            EvidenceMetrics.ExportBytes.Add(storedManifest.ByteSize + artifacts.Sum(a => a.ByteSize));
            logger.LogInformation("Export {ExportId} completed with {ArtifactCount} artifacts and {Bytes} bytes",
                jobId, artifacts.Count, artifacts.Sum(a => a.ByteSize));
        }
        finally
        {
            await leaseStop.CancelAsync();
            try { await leaseTask; }
            catch (OperationCanceledException) when (leaseStop.IsCancellationRequested) { }
        }
    }

    private async Task<long> WritePartitionAsync(TenantContext context, Guid jobId,
        Dataset dataset, DateTimeOffset from, DateTimeOffset to,
        DateTimeOffset cutoff, CancellationToken ct)
    {
        var name = $"{dataset.Name}-{from:yyyy-MM}.ndjson";
        var existing = await FindArtifactAsync(context, jobId, name, ct);
        if (existing is not null)
        {
            await using var verified = await objects.OpenVerifiedAsync(existing.Value.Key,
                existing.Value.Hash, ct);
            return existing.Value.Count;
        }
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        // Dataset names and columns are internal constants; all values remain parameters.
        var sql = $"SELECT row_to_json(q)::text FROM (SELECT {dataset.Columns} FROM {dataset.Table} " +
                  $"WHERE {dataset.Timestamp} >= @from AND {dataset.Timestamp} < @to " +
                  (dataset.Cutoff is null ? "" : $"AND {dataset.Cutoff} <= @cutoff ") +
                  $"ORDER BY {dataset.Timestamp}, {dataset.OrderId}) q";
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("from", from);
        command.Parameters.AddWithValue("to", to);
        if (dataset.Cutoff is not null) command.Parameters.AddWithValue("cutoff", cutoff);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            await reader.DisposeAsync();
            await transaction.CommitAsync(ct);
            return 0;
        }
        long count = 0;
        var key = $"exports/{context.TenantId:N}/{jobId:N}/{dataset.Name}-{from:yyyy-MM}.ndjson";
        var stored = await objects.PutAsync(key, async (output, token) =>
        {
            await using var writer = new StreamWriter(output, new UTF8Encoding(false),
                131072, leaveOpen: true);
            do
            {
                await writer.WriteLineAsync(reader.GetString(0).AsMemory(), token);
                count++;
            } while (await reader.ReadAsync(token));
            await writer.FlushAsync(token);
        }, ct);
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        await SaveArtifactAsync(context, jobId, name, stored, count, ct);
        return count;
    }

    private async Task WriteBytesAsync(TenantContext context, Guid jobId,
        string name, byte[] bytes, CancellationToken ct)
    {
        var existing = await FindArtifactAsync(context, jobId, name, ct);
        if (existing is not null)
        {
            await using var verified = await objects.OpenVerifiedAsync(existing.Value.Key,
                existing.Value.Hash, ct);
            return;
        }
        var key = $"exports/{context.TenantId:N}/{jobId:N}/{name}";
        var stored = await objects.PutAsync(key,
            async (output, token) => await output.WriteAsync(bytes, token), ct);
        await SaveArtifactAsync(context, jobId, name, stored, 1, ct);
    }

    private async Task SaveArtifactAsync(TenantContext context, Guid jobId,
        string name, StoredObject stored, long rowCount, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var insert = new NpgsqlCommand("""
            INSERT INTO export_artifacts
                (id, tenant_id, job_id, name, object_key, byte_size, sha256, row_count)
            VALUES (@id, @tenant_id, @job_id, @name, @key, @bytes, @sha, @rows)
            ON CONFLICT (tenant_id, job_id, name) DO NOTHING
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", Guid.NewGuid());
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("job_id", jobId);
        insert.Parameters.AddWithValue("name", name);
        insert.Parameters.AddWithValue("key", stored.Key);
        insert.Parameters.AddWithValue("bytes", stored.ByteSize);
        insert.Parameters.AddWithValue("sha", stored.Sha256);
        insert.Parameters.AddWithValue("rows", rowCount);
        await insert.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        var actual = await FindArtifactAsync(context, jobId, name, ct);
        if (actual is null || actual.Value.Hash != stored.Sha256 ||
            actual.Value.Key != stored.Key)
            throw new InvalidDataException("Export artifact metadata conflicts with stored content.");
    }

    private async Task<(string Key, string Hash, long Count)?> FindArtifactAsync(
        TenantContext context, Guid jobId, string name, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT object_key, sha256, row_count FROM export_artifacts
            WHERE job_id = @job_id AND name = @name
            """, connection, transaction);
        command.Parameters.AddWithValue("job_id", jobId);
        command.Parameters.AddWithValue("name", name);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct)
            ? (reader.GetString(0), reader.GetString(1).Trim(), reader.GetInt64(2))
            : ((string, string, long)?)null;
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    private async Task<List<ManifestArtifact>> LoadArtifactsAsync(TenantContext context,
        Guid jobId, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT id, name, byte_size, sha256, row_count FROM export_artifacts
            WHERE job_id = @job_id ORDER BY name
            """, connection, transaction);
        command.Parameters.AddWithValue("job_id", jobId);
        var result = new List<ManifestArtifact>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            result.Add(new(reader.GetGuid(0), reader.GetString(1),
                reader.GetInt64(2), reader.GetString(3).Trim(), reader.GetInt64(4)));
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    private async Task<(DateTimeOffset Start, DateTimeOffset End,
        DateTimeOffset Requested, DateTimeOffset Generated, int Attempt)?> LoadJobAsync(
        TenantContext context, Guid jobId, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT period_start, period_end, requested_at, generation_at, attempts
            FROM export_jobs WHERE id = @id AND status = 'RUNNING'
            """, connection, transaction);
        command.Parameters.AddWithValue("id", jobId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct)
            ? (new DateTimeOffset(reader.GetDateTime(0), TimeSpan.Zero),
                new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero),
                new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero),
                new DateTimeOffset(reader.GetDateTime(3), TimeSpan.Zero),
                reader.GetInt32(4))
            : ((DateTimeOffset, DateTimeOffset, DateTimeOffset, DateTimeOffset, int)?)null;
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return result;
    }

    private async Task CompleteAsync(TenantContext context, Guid jobId, int attempt,
        StoredObject manifest, List<ManifestArtifact> artifacts, CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            UPDATE export_jobs
            SET status = 'COMPLETED', completed_at = now(), lease_until = NULL,
                manifest_key = @key, manifest_sha256 = @sha,
                bytes_total = @bytes
            WHERE id = @id AND status = 'RUNNING' AND attempts = @attempt
            """, connection, transaction);
        command.Parameters.AddWithValue("id", jobId);
        command.Parameters.AddWithValue("attempt", attempt);
        command.Parameters.AddWithValue("key", manifest.Key);
        command.Parameters.AddWithValue("sha", manifest.Sha256);
        command.Parameters.AddWithValue("bytes", manifest.ByteSize + artifacts.Sum(a => a.ByteSize));
        if (await command.ExecuteNonQueryAsync(ct) != 1)
            throw new InvalidOperationException("Export lease was lost before completion.");
        await AuditLedger.WriteAsync(connection, transaction, context,
            "export.completed", jobId, jobId.ToString(), jobId.ToString(), ct);
        await transaction.CommitAsync(ct);
    }

    private async Task MarkFailedAsync(TenantContext context, Guid jobId, int attempt,
        CancellationToken ct)
    {
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            UPDATE export_jobs
            SET status = 'FAILED', error_code = 'GENERATION_FAILED',
                lease_until = now() + interval '1 minute'
            WHERE id = @id AND status = 'RUNNING' AND attempts = @attempt
            """, connection, transaction);
        command.Parameters.AddWithValue("id", jobId);
        command.Parameters.AddWithValue("attempt", attempt);
        if (await command.ExecuteNonQueryAsync(ct) == 1)
        {
            await AuditLedger.WriteAsync(connection, transaction, context,
                "export.failed", jobId, jobId.ToString(), jobId.ToString(), ct,
                outcome: "GENERATION_FAILED", highPriority: true);
            EvidenceMetrics.ExportsFailed.Add(1);
        }
        await transaction.CommitAsync(ct);
    }

    private async Task RenewLeaseAsync(TenantContext context, Guid jobId,
        int attempt, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(ct))
        {
            var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
            await using var ownedConnection = connection;
            await using var ownedTransaction = transaction;
            await using var command = new NpgsqlCommand("""
                UPDATE export_jobs SET lease_until = now() + interval '30 minutes'
                WHERE id = @id AND status = 'RUNNING' AND attempts = @attempt
                """, connection, transaction);
            command.Parameters.AddWithValue("id", jobId);
            command.Parameters.AddWithValue("attempt", attempt);
            if (await command.ExecuteNonQueryAsync(ct) != 1)
                throw new InvalidOperationException("Export lease was lost.");
            await transaction.CommitAsync(ct);
        }
    }
}
