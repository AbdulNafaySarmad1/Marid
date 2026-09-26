using Npgsql;

namespace Marid.Api;

public sealed class RetentionWorker(NpgsqlDataSource workerSource,
    IObjectStore objects, ILogger<RetentionWorker> logger) : BackgroundService
{
    private readonly TenantDb tenantDb = new(workerSource);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!objects.IsAvailable) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunOnceAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception error) { logger.LogError(error, "Retention cycle failed"); }
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    public async Task RunOnceAsync(CancellationToken ct)
    {
        await using var connection = await workerSource.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand(
            "SELECT id FROM tenants ORDER BY id", connection);
        var tenants = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) tenants.Add(reader.GetGuid(0));
        await reader.DisposeAsync();
        foreach (var tenantId in tenants)
            await RunTenantAsync(tenantId, ct);
    }

    public async Task RunTenantAsync(Guid tenantId, CancellationToken ct)
    {
        var context = new TenantContext(tenantId, "marid-retention-worker",
            "marid-worker", PrincipalKind.Service, "SYSTEM");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using (connection)
        await using (transaction)
        {
            await using (var held = new NpgsqlCommand("""
                SELECT count(*) FROM evidence_objects e
                JOIN retention_policies p ON p.tenant_id = e.tenant_id
                    AND p.category = 'RAW'
                JOIN legal_holds h ON h.tenant_id = e.tenant_id
                    AND h.evidence_id = e.id AND h.released_at IS NULL
                WHERE e.deleted_at IS NULL AND e.retention_class = 'RAW'
                  AND e.ingested_at < now() - p.retain_days * interval '1 day'
                """, connection, transaction))
            {
                var skips = (long)(await held.ExecuteScalarAsync(ct) ?? 0L);
                if (skips > 0) EvidenceMetrics.LegalHoldSkips.Add(skips);
            }
            await using var candidates = new NpgsqlCommand("""
                SELECT e.id FROM evidence_objects e
                JOIN retention_policies p ON p.tenant_id = e.tenant_id
                    AND p.category = 'RAW'
                WHERE e.deleted_at IS NULL AND e.retention_class = 'RAW'
                  AND e.ingested_at < now() - p.retain_days * interval '1 day'
                  AND NOT EXISTS (
                      SELECT 1 FROM legal_holds h
                      WHERE h.tenant_id = e.tenant_id AND h.evidence_id = e.id
                        AND h.released_at IS NULL)
                  AND NOT EXISTS (
                      SELECT 1 FROM export_jobs j
                      WHERE j.tenant_id = e.tenant_id
                        AND j.period_start <= e.source_at
                        AND j.period_end > e.source_at
                        AND (j.status IN ('QUEUED', 'RUNNING') OR
                             (j.status = 'FAILED' AND j.attempts < 5)))
                ORDER BY e.ingested_at, e.id LIMIT 100
                FOR UPDATE OF e SKIP LOCKED
                """, connection, transaction);
            var ids = new List<Guid>();
            await using var reader = await candidates.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) ids.Add(reader.GetGuid(0));
            await reader.DisposeAsync();
            foreach (var id in ids)
            {
                await using var mark = new NpgsqlCommand(
                    "UPDATE evidence_objects SET deleted_at = now() WHERE id = @id",
                    connection, transaction);
                mark.Parameters.AddWithValue("id", id);
                await mark.ExecuteNonQueryAsync(ct);
                await AuditLedger.WriteAsync(connection, transaction, context,
                    "evidence.retention_tombstoned", id, id.ToString(),
                    id.ToString(), ct, highPriority: true);
            }
            await transaction.CommitAsync(ct);
            if (ids.Count > 0)
                logger.LogInformation("Tombstoned {Count} raw evidence objects for tenant {TenantId}",
                    ids.Count, tenantId);
        }

        var (pendingConnection, pendingTransaction) = await tenantDb.OpenAsync(context, ct);
        await using (pendingConnection)
        await using (pendingTransaction)
        {
            await using var pending = new NpgsqlCommand("""
                SELECT id, object_key FROM evidence_objects
                WHERE deleted_at IS NOT NULL AND storage_deleted_at IS NULL
                ORDER BY deleted_at, id LIMIT 100
                """, pendingConnection, pendingTransaction);
            var items = new List<(Guid Id, string Key)>();
            await using var reader = await pending.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                items.Add((reader.GetGuid(0), reader.GetString(1)));
            await reader.DisposeAsync();
            await pendingTransaction.CommitAsync(ct);
            foreach (var item in items)
            {
                try
                {
                    await objects.DeleteAsync(item.Key, ct);
                    var (finishConnection, finishTransaction) = await tenantDb.OpenAsync(context, ct);
                    await using var ownedConnection = finishConnection;
                    await using var ownedTransaction = finishTransaction;
                    await using var mark = new NpgsqlCommand("""
                        UPDATE evidence_objects SET storage_deleted_at = now()
                        WHERE id = @id AND deleted_at IS NOT NULL
                          AND storage_deleted_at IS NULL
                        """, finishConnection, finishTransaction);
                    mark.Parameters.AddWithValue("id", item.Id);
                    if (await mark.ExecuteNonQueryAsync(ct) == 1)
                        await AuditLedger.WriteAsync(finishConnection, finishTransaction,
                            context, "evidence.storage_deleted", item.Id,
                            item.Id.ToString(), item.Id.ToString(), ct,
                            highPriority: true);
                    await finishTransaction.CommitAsync(ct);
                    EvidenceMetrics.RetentionDeleted.Add(1);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error)
                {
                    logger.LogError(error, "Raw evidence deletion failed for {EvidenceId}", item.Id);
                }
            }
        }
    }
}
