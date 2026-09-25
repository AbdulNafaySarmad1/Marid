using System.Security.Claims;
using System.Text.Json;
using Marid.Api;

namespace Marid.Api.Tests;

public class FoundationTests
{
    private static readonly PolicyEngine Engine = new();

    [Theory]
    [InlineData(ActionRisk.Read, AutonomyLevel.Observe, PolicyOutcome.Allow)]
    [InlineData(ActionRisk.Low, AutonomyLevel.Observe, PolicyOutcome.Deny)]
    [InlineData(ActionRisk.Low, AutonomyLevel.Recommend, PolicyOutcome.RequireApproval)]
    [InlineData(ActionRisk.Low, AutonomyLevel.LowRiskAutomatic, PolicyOutcome.Allow)]
    [InlineData(ActionRisk.Medium, AutonomyLevel.LowRiskAutomatic, PolicyOutcome.RequireApproval)]
    [InlineData(ActionRisk.Critical, AutonomyLevel.LowRiskAutomatic, PolicyOutcome.RequireApproval)]
    public void Policy_respects_autonomy_and_risk(ActionRisk risk, AutonomyLevel autonomy,
        PolicyOutcome expected)
    {
        var request = new PolicyRequest("endpoint.host.isolate", risk, autonomy,
            true, KillMode.Normal, true, true, true, false);
        Assert.Equal(expected, Engine.Evaluate(request).Outcome);
    }

    [Fact]
    public void Kill_switch_overrides_read_only_access()
    {
        var request = new PolicyRequest("events.read", ActionRisk.Read, AutonomyLevel.LowRiskAutomatic,
            true, KillMode.Paused, true, true, true, false);
        Assert.Equal(PolicyOutcome.Deny, Engine.Evaluate(request).Outcome);
    }

    [Fact]
    public void Missing_evidence_requests_more_evidence()
    {
        var request = new PolicyRequest("endpoint.host.isolate", ActionRisk.High,
            AutonomyLevel.LowRiskAutomatic, true, KillMode.Normal, false, true, true, false);
        Assert.Equal(PolicyOutcome.RequestMoreEvidence, Engine.Evaluate(request).Outcome);
    }

    [Fact]
    public void Read_only_kill_mode_blocks_response_even_when_autonomy_allows_it()
    {
        var request = new PolicyRequest("endpoint.host.isolate", ActionRisk.Low,
            AutonomyLevel.LowRiskAutomatic, true, KillMode.ReadOnly, true, true, true, false);
        Assert.Equal(PolicyOutcome.Deny, Engine.Evaluate(request).Outcome);
    }

    [Fact]
    public void Provider_can_require_approval_for_low_risk_action()
    {
        var request = new PolicyRequest("endpoint.file.inspect", ActionRisk.Low,
            AutonomyLevel.LowRiskAutomatic, true, KillMode.Normal, true, true, true, true);
        Assert.Equal(PolicyOutcome.RequireApproval, Engine.Evaluate(request).Outcome);
    }

    [Fact]
    public void Tenant_context_requires_signed_identity_claims()
    {
        var tenant = Guid.NewGuid();
        var identity = new ClaimsIdentity([
            new Claim("sub", "operator-1"), new Claim("tenant_id", tenant.ToString()),
            new Claim("azp", "operator-ui"),
            new Claim("actor_type", "human"),
            new Claim("scope", "incidents.read events.ingest")
        ], "test");
        var principal = new ClaimsPrincipal(identity);
        Assert.True(TenantContext.TryFrom(principal, out var context));
        Assert.Equal(tenant, context.TenantId);
        Assert.True(ScopeAuthorizer.HasScope(principal, "events.ingest"));
        Assert.False(ScopeAuthorizer.HasScope(principal, "incidents.write"));
        Assert.False(TenantContext.TryFrom(new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "operator-1")
        ], "test")), out _));
    }

    [Fact]
    public void Event_contract_rejects_future_time_and_invalid_confidence()
    {
        using var provenance = JsonDocument.Parse("{}");
        var input = new SecurityEventInput("sensor", "event-1", "network",
            DateTimeOffset.UtcNow.AddHours(1), "sensor-1", "1.0", "raw://event-1",
            [], provenance.RootElement, 1.5m, null, null);
        var errors = EventValidator.Validate(input);
        Assert.Contains("sourceTimestamp", errors.Keys);
        Assert.Contains("confidence", errors.Keys);
    }

    [Fact]
    public void Event_contract_rejects_ambiguous_provenance()
    {
        using var provenance = JsonDocument.Parse("{\"sensor\":\"a\",\"sensor\":\"b\"}");
        var input = new SecurityEventInput("sensor", "event-1", "network",
            DateTimeOffset.UtcNow, "sensor-1", "1.0", "raw://event-1",
            [], provenance.RootElement, 0.9m, null, null);
        Assert.Contains("provenance", EventValidator.Validate(input).Keys);
    }

    [Theory]
    [InlineData("tenant-one", true)]
    [InlineData("ab", false)]
    [InlineData("Tenant-One", false)]
    [InlineData("tenant_one", false)]
    public void Tenant_bootstrap_rejects_invalid_slugs(string slug, bool expected)
    {
        Assert.Equal(expected, TenantNameValidator.IsValidSlug(slug));
    }

    [Fact]
    public void Proposal_hash_is_bound_to_exact_parameter_json()
    {
        const string original = "{\"host\":\"alpha\",\"duration\":10}";
        var hash = ProposalValidator.Sha256(original);
        Assert.True(ProposalValidator.MatchesSha256(original, hash));
        Assert.False(ProposalValidator.MatchesSha256("{\"host\":\"beta\",\"duration\":10}", hash));
        Assert.False(ProposalValidator.MatchesSha256(original, new string('0', 64)));
    }

    [Fact]
    public void Action_hash_changes_when_resource_or_evidence_changes()
    {
        var tenant = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var hash = ProposalValidator.ActionSha256(tenant, "endpoint.host.isolate",
            "host-a", ActionRisk.High, "{}", [eventId]);
        Assert.True(ProposalValidator.HashesEqual(hash, ProposalValidator.ActionSha256(
            tenant, "endpoint.host.isolate", "host-a", ActionRisk.High, "{}", [eventId])));
        Assert.False(ProposalValidator.HashesEqual(hash, ProposalValidator.ActionSha256(
            tenant, "endpoint.host.isolate", "host-b", ActionRisk.High, "{}", [eventId])));
        Assert.False(ProposalValidator.HashesEqual(hash, ProposalValidator.ActionSha256(
            tenant, "endpoint.host.isolate", "host-a", ActionRisk.High, "{}", [Guid.NewGuid()])));
    }

    [Fact]
    public void Proposal_rejects_ambiguous_parameters_and_duplicate_evidence_ids()
    {
        using var parameters = JsonDocument.Parse("{\"host\":\"a\",\"host\":\"b\"}");
        var eventId = Guid.NewGuid();
        var input = new ResponseProposalInput("endpoint.host.isolate", "host-1",
            parameters.RootElement, [eventId, eventId]);
        var errors = ProposalValidator.Validate(input);
        Assert.Contains("parameters", errors.Keys);
        Assert.Contains("eventIds", errors.Keys);
    }

    [Fact]
    public void Tenant_role_grant_is_required_for_application_permission()
    {
        Assert.True(PermissionMap.Allows("response.approve", "APPROVER"));
        Assert.False(PermissionMap.Allows("response.approve", "RESPONDER"));
        Assert.False(PermissionMap.Allows("response.propose", "APPROVER"));
        Assert.False(PermissionMap.Allows("unknown.permission", "APPROVER"));
    }

    [Fact]
    public void Admin_role_grant_accepts_only_declared_roles()
    {
        Assert.True(TenantRoleGrantor.IsValidRole("APPROVER"));
        Assert.False(TenantRoleGrantor.IsValidRole("ADMIN"));
        Assert.False(TenantRoleGrantor.IsValidIdentity("operator\nroot"));
    }

    [Fact]
    public void Migration_discovery_rejects_sequence_gaps()
    {
        var directory = Directory.CreateTempSubdirectory("marid-migration-test-");
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "001_first.sql"), "SELECT 1;");
            File.WriteAllText(Path.Combine(directory.FullName, "003_third.sql"), "SELECT 3;");
            Assert.Throws<InvalidOperationException>(() => MigrationRunner.Discover(directory.FullName));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void Migration_discovery_rejects_unnumbered_sql()
    {
        var directory = Directory.CreateTempSubdirectory("marid-migration-test-");
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "001_first.sql"), "SELECT 1;");
            File.WriteAllText(Path.Combine(directory.FullName, "surprise.sql"), "SELECT 2;");
            Assert.Throws<InvalidOperationException>(() => MigrationRunner.Discover(directory.FullName));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void Nondevelopment_configuration_requires_verified_transport_and_app_role()
    {
        const string secureDatabase = "Host=db.internal;Database=marid;Username=marid_app;SSL Mode=VerifyFull";
        Assert.Throws<InvalidOperationException>(() =>
            ProductionConfigurationValidator.Validate(false, "http://id.internal/realms/marid",
                secureDatabase));
        Assert.Throws<InvalidOperationException>(() =>
            ProductionConfigurationValidator.Validate(false, "https://id.internal/realms/marid",
                "Host=db.internal;Database=marid;Username=marid_app;SSL Mode=Require"));
        Assert.Throws<InvalidOperationException>(() =>
            ProductionConfigurationValidator.Validate(false, "https://id.internal/realms/marid",
                "Host=db.internal;Database=marid;Username=marid_owner;SSL Mode=VerifyFull"));
        ProductionConfigurationValidator.Validate(false, "https://id.internal/realms/marid",
            secureDatabase);
        ProductionConfigurationValidator.Validate(true, "http://localhost:8080/realms/marid",
            "Host=localhost;Database=marid;Username=marid_app");
    }
}
