using System.Text.Json;
using Marid.Api;
using Npgsql;

namespace Marid.Api.IntegrationTests;

public sealed class StoreTests
{
    [Fact]
    public async Task Tenant_roles_and_event_idempotence_hold_in_postgres()
    {
        var ownerPassword = Environment.GetEnvironmentVariable("MARID_TEST_OWNER_PASSWORD")
            ?? throw new InvalidOperationException("Disposable database owner password is required.");
        var appPassword = Environment.GetEnvironmentVariable("MARID_TEST_APP_PASSWORD")
            ?? throw new InvalidOperationException("Disposable database app password is required.");
        var port = int.Parse(Environment.GetEnvironmentVariable("MARID_TEST_DB_PORT")
            ?? throw new InvalidOperationException("Disposable database port is required."));
        var connection = new NpgsqlConnectionStringBuilder
        {
            Host = Environment.GetEnvironmentVariable("MARID_TEST_DB_HOST") ?? "127.0.0.1",
            Port = port, Database = "marid",
            Username = "marid_owner", Password = ownerPassword, Pooling = false
        };
        var ownerConnectionString = connection.ConnectionString;
        await using var owner = new NpgsqlConnection(connection.ConnectionString);
        await owner.OpenAsync();
        var fixture = Guid.NewGuid().ToString("N")[..12];
        var tenantA = await TenantCreator.CreateAsync(owner, $"integration-a-{fixture}", "Integration A");
        var tenantB = await TenantCreator.CreateAsync(owner, $"integration-b-{fixture}", "Integration B");
        const string actor = "integration-sensor";
        const string service = "integration-ingest-client";
        await TenantRoleGrantor.GrantAsync(owner, tenantA, actor, service, "SERVICE",
            "EVENT_INGESTOR", DateTimeOffset.UtcNow.AddHours(1));

        connection.Username = "marid_app";
        connection.Password = appPassword;
        await using var app = NpgsqlDataSource.Create(connection.ConnectionString);
        await using var ownerDataSource = NpgsqlDataSource.Create(ownerConnectionString);
        Assert.True(await DatabaseAuthorityValidator.IsValidAsync(app, default));
        Assert.False(await DatabaseAuthorityValidator.IsValidAsync(ownerDataSource, default));
        var authorization = new TenantAuthorization(app);
        var contextA = new TenantContext(tenantA, actor, service, PrincipalKind.Service);
        var contextB = new TenantContext(tenantB, actor, service, PrincipalKind.Service);
        Assert.True(await authorization.IsAllowedAsync(contextA, "events.ingest", default));
        Assert.False(await authorization.IsAllowedAsync(contextB, "events.ingest", default));
        Assert.False(await authorization.IsAllowedAsync(contextA, "response.approve", default));

        using var provenance = JsonDocument.Parse("{}");
        var input = new SecurityEventInput("integration", $"event-{fixture}", "endpoint",
            DateTimeOffset.UtcNow, "fixture-sensor", "1", $"raw://{fixture}",
            [], provenance.RootElement, 0.9m, null, null);
        var store = new TenantStore(app);
        var first = await store.IngestEventAsync(contextA, input, "trace-1", "correlation-1", default);
        var exactDuplicate = await store.IngestEventAsync(contextA, input,
            "trace-2", "correlation-2", default);
        var alteredDuplicate = await store.IngestEventAsync(contextA,
            input with { Category = "network" }, "trace-3", "correlation-3", default);
        Assert.True(first.Created);
        Assert.False(exactDuplicate.Created);
        Assert.False(exactDuplicate.ConflictingDuplicate);
        Assert.Equal(first.EventId, exactDuplicate.EventId);
        Assert.True(alteredDuplicate.ConflictingDuplicate);
        Assert.Equal(first.EventId, alteredDuplicate.EventId);

        await using var audit = new NpgsqlCommand("""
            SELECT count(*) FROM audit_events
            WHERE tenant_id = @tenant_id AND object_id = @event_id
              AND action = 'security_event.duplicate_conflict'
            """, owner);
        audit.Parameters.AddWithValue("tenant_id", tenantA);
        audit.Parameters.AddWithValue("event_id", first.EventId);
        Assert.Equal(1L, (long)(await audit.ExecuteScalarAsync() ?? 0L));

        await TenantRoleGrantor.GrantAsync(owner, tenantA, actor, service, "SERVICE",
            "RESPONDER", DateTimeOffset.UtcNow.AddHours(1));
        const string reviewer = "integration-reviewer";
        const string reviewerClient = "operator-ui";
        await TenantRoleGrantor.GrantAsync(owner, tenantA, reviewer, reviewerClient,
            "HUMAN", "APPROVER", DateTimeOffset.UtcNow.AddHours(1));
        var reviewerContext = new TenantContext(tenantA, reviewer, reviewerClient, PrincipalKind.Human);
        Assert.True(await authorization.IsAllowedAsync(contextA, "response.propose", default));
        Assert.True(await authorization.IsAllowedAsync(reviewerContext, "response.approve", default));
        Assert.False(await authorization.IsAllowedAsync(contextA, "response.approve", default));

        const string capability = "endpoint.host.isolate";
        const string resource = "host-a";
        await using (var configure = new NpgsqlCommand("""
            UPDATE tenant_controls SET autonomy = 'RECOMMEND', kill_mode = 'NORMAL'
            WHERE tenant_id = @tenant_id;
            INSERT INTO capabilities
              (id, tenant_id, capability_key, provider_identity, risk,
               enabled, healthy, approval_required)
            VALUES (@capability_id, @tenant_id, @capability, 'test-provider',
                    'HIGH', true, true, true);
            INSERT INTO engagement_scopes
              (id, tenant_id, capability_key, resource_id, authorized_by,
               valid_from, expires_at)
            VALUES (@scope_id, @tenant_id, @capability, @resource,
                    'integration-owner', now() - interval '1 minute',
                    now() + interval '1 hour')
            """, owner))
        {
            configure.Parameters.AddWithValue("tenant_id", tenantA);
            configure.Parameters.AddWithValue("capability_id", Guid.NewGuid());
            configure.Parameters.AddWithValue("scope_id", Guid.NewGuid());
            configure.Parameters.AddWithValue("capability", capability);
            configure.Parameters.AddWithValue("resource", resource);
            await configure.ExecuteNonQueryAsync();
        }

        using var parameters = JsonDocument.Parse("{\"host\":\"host-a\"}");
        var proposalInput = new ResponseProposalInput(capability, resource,
            parameters.RootElement, [first.EventId]);
        var decisions = new DecisionStore(app, new PolicyEngine());
        var proposal = await decisions.ProposeAsync(contextA, proposalInput,
            "correlation-4", "trace-4", default);
        Assert.Equal(PolicyOutcome.RequireApproval, proposal.Outcome);
        Assert.NotNull(proposal.ProposalId);
        Assert.NotNull(proposal.ActionSha256);
        var selfReview = await decisions.DecideAsync(contextA, proposal.ProposalId.Value,
            ApprovalChoice.Approve, "correlation-5", "trace-5", default);
        Assert.Equal(ApprovalWriteStatus.Conflict, selfReview.Status);
        var reviewed = await decisions.DecideAsync(reviewerContext, proposal.ProposalId.Value,
            ApprovalChoice.Approve, "correlation-6", "trace-6", default);
        Assert.Equal(ApprovalWriteStatus.Created, reviewed.Status);
        Assert.Equal(proposal.ActionSha256, reviewed.Value?.ActionSha256);
        var secondReview = await decisions.DecideAsync(reviewerContext, proposal.ProposalId.Value,
            ApprovalChoice.Reject, "correlation-7", "trace-7", default);
        Assert.Equal(ApprovalWriteStatus.Conflict, secondReview.Status);

        var tampered = await decisions.ProposeAsync(contextA, proposalInput,
            "correlation-8", "trace-8", default);
        Assert.NotNull(tampered.ProposalId);
        await using (var change = new NpgsqlCommand("""
            UPDATE response_proposals SET parameters_json = '{"host":"other"}'
            WHERE id = @id
            """, owner))
        {
            change.Parameters.AddWithValue("id", tampered.ProposalId.Value);
            Assert.Equal(1, await change.ExecuteNonQueryAsync());
        }
        var alteredReview = await decisions.DecideAsync(reviewerContext, tampered.ProposalId.Value,
            ApprovalChoice.Approve, "correlation-9", "trace-9", default);
        Assert.Equal(ApprovalWriteStatus.Conflict, alteredReview.Status);

        var paused = await decisions.ProposeAsync(contextA, proposalInput,
            "correlation-10", "trace-10", default);
        Assert.NotNull(paused.ProposalId);
        await using (var kill = new NpgsqlCommand(
            "UPDATE tenant_controls SET kill_mode = 'PAUSED' WHERE tenant_id = @tenant_id", owner))
        {
            kill.Parameters.AddWithValue("tenant_id", tenantA);
            Assert.Equal(1, await kill.ExecuteNonQueryAsync());
        }
        var blocked = await decisions.DecideAsync(reviewerContext, paused.ProposalId.Value,
            ApprovalChoice.Approve, "correlation-11", "trace-11", default);
        Assert.Equal(ApprovalWriteStatus.Conflict, blocked.Status);

        var revokedGrant = await TenantRoleGrantor.RevokeAsync(owner, tenantA,
            actor, service, "RESPONDER");
        Assert.False(await authorization.IsAllowedAsync(contextA, "response.propose", default));
        await using var revocationAudit = new NpgsqlCommand("""
            SELECT count(*) FROM audit_events
            WHERE tenant_id = @tenant_id AND object_id = @grant_id
              AND action = 'role.revoked'
            """, owner);
        revocationAudit.Parameters.AddWithValue("tenant_id", tenantA);
        revocationAudit.Parameters.AddWithValue("grant_id", revokedGrant);
        Assert.Equal(1L, (long)(await revocationAudit.ExecuteScalarAsync() ?? 0L));
    }
}
