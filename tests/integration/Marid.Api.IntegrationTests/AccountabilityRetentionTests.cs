using System.Net;
using System.Text;
using System.Text.Json;
using Marid.Api;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Marid.Api.IntegrationTests;

public sealed class AccountabilityRetentionTests
{
    [Fact]
    public async Task Operator_agent_incident_and_hold_records_export_and_retain_correctly()
    {
        var connection = new NpgsqlConnectionStringBuilder
        {
            Host = Environment.GetEnvironmentVariable("MARID_TEST_DB_HOST") ?? "127.0.0.1",
            Port = int.Parse(Required("MARID_TEST_DB_PORT")), Database = "marid",
            Username = "marid_owner", Password = Required("MARID_TEST_OWNER_PASSWORD"),
            Pooling = false
        };
        await using var owner = new NpgsqlConnection(connection.ConnectionString);
        await owner.OpenAsync();
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var tenantA = await TenantCreator.CreateAsync(owner, "account-a-" + suffix, "Account A");
        var tenantB = await TenantCreator.CreateAsync(owner, "account-b-" + suffix, "Account B");
        connection.Username = "marid_app";
        connection.Password = Required("MARID_TEST_APP_PASSWORD");
        await using var app = NpgsqlDataSource.Create(connection.ConnectionString);
        connection.Username = "marid_worker";
        connection.Password = Required("MARID_TEST_WORKER_PASSWORD");
        await using var workerDb = NpgsqlDataSource.Create(connection.ConnectionString);
        var root = Path.Combine(Path.GetTempPath(), "marid-account-" + Guid.NewGuid().ToString("N"));
        try
        {
            var objects = new FileObjectStore(root);
            var tenantDb = new TenantDb(app);
            var evidence = new EvidenceStore(tenantDb, objects);
            var retention = new RetentionStore(tenantDb);
            var sessions = new OperatorSessionStore(tenantDb);
            var eventStore = new TenantStore(app);
            var exports = new ExportStore(tenantDb, objects);
            var agent = new TenantContext(tenantA, "agent-a", "agent-service-a",
                PrincipalKind.Service, "MARID_AGENT");
            var engineer = new TenantContext(tenantA, "engineer-a", "portal-a",
                PrincipalKind.Human, "NOCTURNE_ENGINEER");
            var manager = new TenantContext(tenantA, "manager-a", "portal-a",
                PrincipalKind.Human);
            var other = new TenantContext(tenantB, "other-b", "portal-b",
                PrincipalKind.Human);
            var upload = new EvidenceUpload("syslog", "account-" + suffix,
                DateTimeOffset.UtcNow, "sensor-a", "text/plain", "1", "RAW");
            var a = await evidence.UploadAsync(agent, upload,
                new MemoryStream(Encoding.UTF8.GetBytes("A-only raw")),
                "corr", "trace", default);
            var b = await evidence.UploadAsync(new TenantContext(tenantB,
                    "sensor-b", "service-b", PrincipalKind.Service),
                upload with { SensorIdentity = "sensor-b" },
                new MemoryStream(Encoding.UTF8.GetBytes("B-only raw")),
                "corr", "trace", default);
            Assert.Null(await retention.HoldAsync(manager, b.Summary.Id,
                "wrong tenant", "corr", "trace", default));
            var hold = await retention.HoldAsync(manager, a.Summary.Id,
                "Customer legal investigation", "corr", "trace", default);
            Assert.NotNull(hold);
            Assert.True((await evidence.GetAsync(manager, a.Summary.Id, default))?.LegalHold);

            var session = await sessions.StartAsync(engineer,
                new OperatorSessionInput("RESPONDER", "Investigate alert",
                    "INC-1234", true), IPAddress.Loopback,
                "corr", "trace", default);
            Assert.Null(await sessions.ActiveAsync(other, session.Id, default));
            Assert.True(await sessions.RecordActionAsync(engineer, session.Id,
                new OperatorActionInput("host.inspected", "host-a", "SUCCEEDED", null),
                "corr", "trace", default));
            Assert.True(await sessions.EndAsync(engineer, session.Id,
                "corr", "trace", default));
            Assert.Null(await sessions.ActiveAsync(engineer, session.Id, default));

            using var provenance = JsonDocument.Parse("{}");
            var input = new SecurityEventInput("syslog", "account-" + suffix,
                "endpoint", DateTimeOffset.UtcNow, "sensor-a", "1",
                "evidence:" + a.Summary.Id, [], provenance.RootElement,
                0.9m, null, null);
            var eventId = (await eventStore.IngestEventAsync(agent, input,
                "trace", "corr", default)).EventId;
            var incident = await eventStore.CreateIncidentAsync(manager,
                "Host A suspicious activity", IncidentSeverity.High,
                "corr", "trace", default);
            Assert.True(await eventStore.LinkIncidentEventAsync(manager,
                incident.Id, eventId, "corr", "trace", default));
            var activity = await eventStore.AddIncidentActivityAsync(manager,
                incident.Id, "STATUS", "INVESTIGATING", "Analyst review started",
                "corr", "trace", default);
            Assert.NotNull(activity);

            await ConfigureCapabilityAsync(owner, tenantA, suffix);
            using var parameters = JsonDocument.Parse("{\"host\":\"host-a\"}");
            var decisionStore = new DecisionStore(app, new PolicyEngine());
            var proposal = await decisionStore.ProposeAsync(agent,
                new ResponseProposalInput("host.inspect", "host-a",
                    parameters.RootElement, [eventId]), "corr", "trace", default);
            Assert.NotNull(proposal.ProposalId);
            var approval = await decisionStore.DecideAsync(manager,
                proposal.ProposalId.Value, ApprovalChoice.Approve,
                "corr", "trace", default);
            Assert.Equal(ApprovalWriteStatus.Created, approval.Status);
            var executions = new ActionExecutionStore(tenantDb);
            var recorded = await executions.RecordAsync(agent, proposal.ProposalId.Value,
                new ActionExecutionInput(approval.Value!.Id, "SUCCEEDED",
                    "Verified host state", null, "evidence:" + a.Summary.Id),
                "corr", "trace", default);
            Assert.NotNull(recorded.Value);
            var wrongEvidence = await executions.RecordAsync(agent, proposal.ProposalId.Value,
                new ActionExecutionInput(approval.Value.Id, "SUCCEEDED",
                    null, null, "evidence:" + b.Summary.Id),
                "corr", "trace", default);
            Assert.Null(wrongEvidence.Value);
            Assert.Null((await executions.RecordAsync(agent, Guid.NewGuid(),
                new ActionExecutionInput(null, "BLOCKED", null, null, null),
                "corr", "trace", default)).Value);

            var start = DateTimeOffset.UtcNow.AddHours(-1);
            var end = DateTimeOffset.UtcNow;
            var job = await exports.CreateAsync(manager,
                new ExportRequest(start, end, "account-" + suffix),
                "corr", "trace", default);
            var exportWorker = new ExportWorker(workerDb, objects,
                NullLogger<ExportWorker>.Instance);
            Assert.True(await exportWorker.RunOnceAsync(default));
            var artifacts = await exports.ArtifactsAsync(manager, job.Job.Id, default);
            Assert.NotNull(artifacts);
            foreach (var expected in new[] { "operator-sessions-", "executions-",
                         "incident-activity-", "incident-event-links-",
                         "event-evidence-links-", "proposals-", "approvals-" })
                Assert.Contains(artifacts, item => item.Name.StartsWith(expected));
            var executionArtifact = artifacts.Single(x => x.Name.StartsWith("executions-"));
            var opened = await exports.OpenArtifactAsync(manager, job.Job.Id,
                executionArtifact.Id, "corr", "trace", default);
            Assert.NotNull(opened);
            await using (var content = opened.Value.Content)
            using (var reader = new StreamReader(content))
                Assert.Contains(proposal.ProposalId.Value.ToString(),
                    await reader.ReadToEndAsync());
            Assert.Null(await exports.GetAsync(other, job.Job.Id, default));

            await retention.SetPolicyAsync(manager, "RAW", 30,
                "corr", "trace", default);
            await BackdateEvidenceAsync(owner, tenantA, a.Summary.Id);
            await BackdateEvidenceAsync(owner, tenantB, b.Summary.Id);
            var retentionWorker = new RetentionWorker(workerDb, objects,
                NullLogger<RetentionWorker>.Instance);
            await retentionWorker.RunTenantAsync(tenantA, default);
            await retentionWorker.RunTenantAsync(tenantB, default);
            Assert.NotNull(await evidence.GetAsync(manager, a.Summary.Id, default));
            Assert.NotNull(await evidence.GetAsync(other, b.Summary.Id, default));
            // Tenant B still has its default 365-day policy; shorten it before deletion.
            await retention.SetPolicyAsync(other, "RAW", 30,
                "corr", "trace", default);
            await retentionWorker.RunTenantAsync(tenantB, default);
            Assert.Null(await evidence.GetAsync(other, b.Summary.Id, default));
            Assert.True(await retention.ReleaseAsync(manager, a.Summary.Id,
                hold.Id, "corr", "trace", default));
            await retentionWorker.RunTenantAsync(tenantA, default);
            Assert.Null(await evidence.GetAsync(manager, a.Summary.Id, default));
            await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            {
                await using var content = await objects.OpenVerifiedAsync(
                    $"evidence/{tenantA:N}/{a.Summary.Id:N}.bin",
                    a.Summary.Sha256, default);
            });
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task ConfigureCapabilityAsync(NpgsqlConnection owner,
        Guid tenantId, string suffix)
    {
        await using var tx = await owner.BeginTransactionAsync();
        await using var set = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant, true)", owner, tx);
        set.Parameters.AddWithValue("tenant", tenantId.ToString());
        await set.ExecuteNonQueryAsync();
        await using var command = new NpgsqlCommand("""
            UPDATE tenant_controls SET autonomy = 'RECOMMEND', kill_mode = 'NORMAL'
            WHERE tenant_id = @tenant;
            INSERT INTO capabilities
                (id, tenant_id, capability_key, provider_identity, risk,
                 enabled, healthy, approval_required)
            VALUES (@id, @tenant, 'host.inspect', 'fixture', 'HIGH', true, true, true);
            INSERT INTO engagement_scopes
                (id, tenant_id, capability_key, resource_id, authorized_by,
                 valid_from, expires_at)
            VALUES (@scope, @tenant, 'host.inspect', 'host-a', 'fixture',
                    now() - interval '1 hour', now() + interval '1 hour');
            """, owner, tx);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("id", Guid.NewGuid());
        command.Parameters.AddWithValue("scope", Guid.NewGuid());
        await command.ExecuteNonQueryAsync();
        await tx.CommitAsync();
    }

    private static async Task BackdateEvidenceAsync(NpgsqlConnection owner,
        Guid tenant, Guid evidenceId)
    {
        await using var tx = await owner.BeginTransactionAsync();
        await using var set = new NpgsqlCommand(
            "SELECT set_config('app.tenant_id', @tenant, true)", owner, tx);
        set.Parameters.AddWithValue("tenant", tenant.ToString());
        await set.ExecuteNonQueryAsync();
        await using var command = new NpgsqlCommand("""
            UPDATE evidence_objects SET ingested_at = now() - interval '31 days'
            WHERE id = @id
            """, owner, tx);
        command.Parameters.AddWithValue("id", evidenceId);
        await command.ExecuteNonQueryAsync();
        await tx.CommitAsync();
    }

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException(name + " is required.");
}
