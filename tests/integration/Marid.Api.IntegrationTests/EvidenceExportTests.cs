using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Marid.Api;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Marid.Api.IntegrationTests;

public sealed class EvidenceExportTests
{
    [Fact]
    public async Task Evidence_and_exports_remain_tenant_scoped_and_verifiable()
    {
        var ownerPassword = Required("MARID_TEST_OWNER_PASSWORD");
        var appPassword = Required("MARID_TEST_APP_PASSWORD");
        var workerPassword = Required("MARID_TEST_WORKER_PASSWORD");
        var host = Environment.GetEnvironmentVariable("MARID_TEST_DB_HOST") ?? "127.0.0.1";
        var port = int.Parse(Required("MARID_TEST_DB_PORT"));
        var connection = new NpgsqlConnectionStringBuilder
        {
            Host = host, Port = port, Database = "marid", Username = "marid_owner",
            Password = ownerPassword, Pooling = false
        };
        await using var owner = new NpgsqlConnection(connection.ConnectionString);
        await owner.OpenAsync();
        var fixture = Guid.NewGuid().ToString("N")[..12];
        var tenantA = await TenantCreator.CreateAsync(owner, $"evidence-a-{fixture}", "Evidence A");
        var tenantB = await TenantCreator.CreateAsync(owner, $"evidence-b-{fixture}", "Evidence B");
        var contextA = new TenantContext(tenantA, "sensor-a", "ingest-a", PrincipalKind.Service);
        var contextB = new TenantContext(tenantB, "sensor-b", "ingest-b", PrincipalKind.Service);
        var auditorA = new TenantContext(tenantA, "auditor-a", "portal-a", PrincipalKind.Human);
        var auditorB = new TenantContext(tenantB, "auditor-b", "portal-b", PrincipalKind.Human);
        await TenantRoleGrantor.GrantAsync(owner, tenantA, "auditor-a", "portal-a",
            "HUMAN", "AUDITOR", DateTimeOffset.UtcNow.AddHours(1));
        await TenantRoleGrantor.GrantAsync(owner, tenantB, "auditor-b", "portal-b",
            "HUMAN", "AUDITOR", DateTimeOffset.UtcNow.AddHours(1));

        connection.Username = "marid_app";
        connection.Password = appPassword;
        await using var app = NpgsqlDataSource.Create(connection.ConnectionString);
        connection.Username = "marid_worker";
        connection.Password = workerPassword;
        await using var workerDb = NpgsqlDataSource.Create(connection.ConnectionString);
        var root = Path.Combine(Path.GetTempPath(), "marid-evidence-" + Guid.NewGuid().ToString("N"));
        try
        {
            var objects = new FileObjectStore(root);
            var evidence = new EvidenceStore(new TenantDb(app), objects);
            var exports = new ExportStore(new TenantDb(app), objects);
            var yesterday = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
            var today = yesterday.AddDays(1);
            var sourceTime = yesterday.AddHours(12);
            var aBytes = Encoding.UTF8.GetBytes("tenant A raw security evidence");
            var bBytes = Encoding.UTF8.GetBytes("tenant B private raw evidence");
            var uploadA = new EvidenceUpload("syslog", "evt-" + fixture,
                sourceTime, "sensor-a", "application/json", "1", "RAW");
            var uploadB = uploadA with { SensorIdentity = "sensor-b" };
            var a = await evidence.UploadAsync(contextA, uploadA,
                new MemoryStream(aBytes), "corr-a", "trace-a", default);
            var b = await evidence.UploadAsync(contextB, uploadB,
                new MemoryStream(bBytes), "corr-b", "trace-b", default);
            Assert.True(a.Created);
            Assert.True(b.Created);
            Assert.Equal(Hash(aBytes), a.Summary.Sha256);
            Assert.Null(await evidence.GetAsync(contextA, b.Summary.Id, default));
            Assert.Null(await evidence.OpenAsync(contextA, b.Summary.Id,
                "corr", "trace", default));
            var retry = await evidence.UploadAsync(contextA, uploadA,
                new MemoryStream(aBytes), "corr-a", "trace-a", default);
            Assert.False(retry.Created);
            Assert.False(retry.Conflict);
            Assert.Equal(a.Summary.Id, retry.Summary.Id);
            var changedMetadata = await evidence.UploadAsync(contextA,
                uploadA with { ParserVersion = "2" }, new MemoryStream(aBytes),
                "corr-a", "trace-a", default);
            Assert.True(changedMetadata.Conflict);

            using var provenance = JsonDocument.Parse("{}");
            var input = new SecurityEventInput("syslog", "evt-" + fixture,
                "authentication", sourceTime, "sensor-a", "1",
                "evidence:" + a.Summary.Id, [], provenance.RootElement, 0.9m, null, null);
            var events = new TenantStore(app);
            Assert.True((await events.IngestEventAsync(contextA, input,
                "trace-a", "corr-a", default)).Created);
            await SeedEventBatchAsync(owner, tenantA, fixture, sourceTime,
                yesterday.AddDays(-2));
            await Assert.ThrowsAsync<EvidenceNotFoundException>(() =>
                events.IngestEventAsync(contextA,
                    input with { SourceEventId = "guess-" + fixture,
                        RawEventReference = "evidence:" + b.Summary.Id },
                    "trace-a", "corr-a", default));

            await SeedHistoricalAuditAsync(owner, tenantA, yesterday.AddHours(13));
            await SeedHistoricalAuditAsync(owner, tenantB, yesterday.AddHours(13));
            var request = new ExportRequest(yesterday, today, "integration-" + fixture);
            var queued = await exports.CreateAsync(auditorA, request, "corr-a", "trace-a", default);
            Assert.True(queued.Created);
            Assert.Null(await exports.GetAsync(auditorB, queued.Job.Id, default));
            Assert.Null(await exports.ArtifactsAsync(auditorB, queued.Job.Id, default));
            var same = await exports.CreateAsync(auditorA, request, "corr-a", "trace-a", default);
            Assert.False(same.Created);
            Assert.False(same.Conflict);
            Assert.Equal(queued.Job.Id, same.Job.Id);
            var worker = new ExportWorker(workerDb, objects,
                NullLogger<ExportWorker>.Instance);
            Assert.True(await worker.RunOnceAsync(default));
            Assert.False(await worker.RunOnceAsync(default));
            var job = await exports.GetAsync(auditorA, queued.Job.Id, default);
            Assert.Equal("COMPLETED", job?.Status);
            var artifacts = await exports.ArtifactsAsync(auditorA, queued.Job.Id, default);
            Assert.NotNull(artifacts);
            Assert.Contains(artifacts, item => item.Name.StartsWith("security-events-"));
            Assert.Contains(artifacts, item => item.Name.StartsWith("evidence-"));
            Assert.Contains(artifacts, item => item.Name.StartsWith("audit-"));
            Assert.Contains(artifacts, item => item.Name == "report.md");
            foreach (var artifact in artifacts)
            {
                var opened = await exports.OpenArtifactAsync(auditorA, queued.Job.Id,
                    artifact.Id, "corr-a", "trace-a", default);
                Assert.NotNull(opened);
                await using var content = opened.Value.Content;
                using var buffer = new MemoryStream();
                await content.CopyToAsync(buffer);
                Assert.Equal(artifact.Sha256, Hash(buffer.ToArray()));
                Assert.DoesNotContain(tenantB.ToString(),
                    Encoding.UTF8.GetString(buffer.ToArray()), StringComparison.OrdinalIgnoreCase);
                if (artifact.Name.StartsWith("security-events-", StringComparison.Ordinal))
                {
                    var lines = Encoding.UTF8.GetString(buffer.ToArray())
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    Assert.Equal(2049, lines.Length);
                    Assert.DoesNotContain("bulk-outside-" + fixture,
                        Encoding.UTF8.GetString(buffer.ToArray()), StringComparison.Ordinal);
                }
            }
            Assert.Null(await exports.OpenArtifactAsync(auditorB, queued.Job.Id,
                artifacts[0].Id, "corr-b", "trace-b", default));
            var manifest = await exports.OpenArtifactAsync(auditorA, queued.Job.Id,
                null, "corr-a", "trace-a", default);
            Assert.NotNull(manifest);
            await using var manifestStream = manifest.Value.Content;
            using var manifestBuffer = new MemoryStream();
            await manifestStream.CopyToAsync(manifestBuffer);
            Assert.Equal(job!.ManifestSha256, Hash(manifestBuffer.ToArray()));
            using var manifestJson = JsonDocument.Parse(manifestBuffer.ToArray());
            Assert.Equal(tenantA, manifestJson.RootElement.GetProperty("tenantId").GetGuid());
            Assert.Equal(artifacts.Count,
                manifestJson.RootElement.GetProperty("artifacts").GetArrayLength());
            File.AppendAllText(Path.Combine(root, "evidence", tenantA.ToString("N"),
                a.Summary.Id.ToString("N") + ".bin"), "tampered");
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                evidence.OpenAsync(auditorA, a.Summary.Id, "corr", "trace", default));
            Assert.Equal("FAILED", (await evidence.GetAsync(auditorA,
                a.Summary.Id, default))?.IntegrityState);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task SeedHistoricalAuditAsync(NpgsqlConnection owner,
        Guid tenant, DateTimeOffset time)
    {
        await using var tx = await owner.BeginTransactionAsync();
        await using var set = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant, true)", owner, tx);
        set.Parameters.AddWithValue("tenant", tenant.ToString());
        await set.ExecuteNonQueryAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO audit_events (id, tenant_id, actor_id, service_id,
                actor_type, action, object_id, correlation_id, trace_id, occurred_at)
            VALUES (@id, @tenant, 'fixture', 'fixture', 'SYSTEM',
                'fixture.historical', @object_id, 'fixture', 'fixture', @at)
            """, owner, tx);
        insert.Parameters.AddWithValue("id", Guid.NewGuid());
        insert.Parameters.AddWithValue("tenant", tenant);
        insert.Parameters.AddWithValue("object_id", Guid.NewGuid());
        insert.Parameters.AddWithValue("at", time);
        await insert.ExecuteNonQueryAsync();
        await tx.CommitAsync();
    }

    private static async Task SeedEventBatchAsync(NpgsqlConnection owner,
        Guid tenant, string fixture, DateTimeOffset inside, DateTimeOffset outside)
    {
        await using var tx = await owner.BeginTransactionAsync();
        await using var set = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant, true)", owner, tx);
        set.Parameters.AddWithValue("tenant", tenant.ToString());
        await set.ExecuteNonQueryAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO security_events
                (id, tenant_id, source, source_event_id, category, source_at,
                 normalized_at, schema_version, provenance, confidence,
                 correlation_id, trace_id, actor_id, service_id, structured_sha256,
                 parser_version, sensor_identity, raw_event_reference)
            SELECT gen_random_uuid(), @tenant, 'bulk-test',
                   CASE WHEN g = 2049 THEN 'bulk-outside-' || @fixture
                        ELSE 'bulk-' || @fixture || '-' || g::text END,
                   'authentication', CASE WHEN g = 2049 THEN @outside ELSE @inside END,
                   now(), 1, '{}'::jsonb, 1.0, 'batch', 'batch',
                   'batch', 'batch', repeat('0', 64), '1', 'batch', 'external:batch'
            FROM generate_series(1, 2049) AS g
            """, owner, tx);
        insert.Parameters.AddWithValue("tenant", tenant);
        insert.Parameters.AddWithValue("fixture", fixture);
        insert.Parameters.AddWithValue("inside", inside);
        insert.Parameters.AddWithValue("outside", outside);
        Assert.Equal(2049, await insert.ExecuteNonQueryAsync());
        await tx.CommitAsync();
    }

    private static string Hash(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException(name + " is required.");
}
