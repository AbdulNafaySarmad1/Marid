using System.Text.Json;
using Npgsql;

namespace Marid.Api;

public sealed class DecisionStore(NpgsqlDataSource dataSource, PolicyEngine policyEngine)
{
    private async Task<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)> OpenTenantAsync(
        TenantContext context, CancellationToken ct)
    {
        var connection = await dataSource.OpenConnectionAsync(ct);
        try
        {
            var transaction = await connection.BeginTransactionAsync(ct);
            await using var setContext = new NpgsqlCommand("""
                SELECT set_config('app.tenant_id', @tenant_id, true),
                       set_config('app.actor_id', @actor_id, true),
                       set_config('app.service_id', @service_id, true)
                """, connection, transaction);
            setContext.Parameters.AddWithValue("tenant_id", context.TenantId.ToString());
            setContext.Parameters.AddWithValue("actor_id", context.ActorId);
            setContext.Parameters.AddWithValue("service_id", context.ServiceId);
            await setContext.ExecuteNonQueryAsync(ct);
            return (connection, transaction);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    public async Task<ResponseProposalResult> ProposeAsync(TenantContext context,
        ResponseProposalInput input, string correlationId, string traceId,
        CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        var uniqueEvents = input.EventIds.Distinct().ToArray();
        await using var evidence = new NpgsqlCommand(
            "SELECT count(*) FROM security_events WHERE id = ANY(@event_ids)",
            connection, transaction);
        evidence.Parameters.AddWithValue("event_ids", uniqueEvents);
        var foundEvents = (long)(await evidence.ExecuteScalarAsync(ct) ?? 0L);
        var policy = await EvaluateCurrentAsync(connection, transaction, context.TenantId,
            input.Capability, input.ResourceId, foundEvents == uniqueEvents.Length, ct);
        if (policy.Outcome is not (PolicyOutcome.Allow or PolicyOutcome.RequireApproval))
        {
            await transaction.CommitAsync(ct);
            return new(null, policy.Outcome, policy.Reason, null, null, null);
        }

        var id = Guid.NewGuid();
        var parametersJson = input.Parameters.GetRawText();
        var hash = ProposalValidator.Sha256(parametersJson);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);
        var risk = await GetCapabilityRiskAsync(connection, transaction, input.Capability, ct);
        var actionHash = ProposalValidator.ActionSha256(context.TenantId, input.Capability,
            input.ResourceId, risk, parametersJson, uniqueEvents);
        await using var insert = new NpgsqlCommand("""
            INSERT INTO response_proposals
                (id, tenant_id, capability_key, resource_id, parameters_json,
                 parameters_sha256, action_sha256, risk, proposer_actor_id, proposer_service_id,
                 policy_outcome, policy_reason, expires_at, correlation_id, trace_id)
            VALUES (@id, @tenant_id, @capability_key, @resource_id, @parameters_json,
                    @parameters_sha256, @action_sha256, @risk, @proposer_actor_id, @proposer_service_id,
                    @policy_outcome, @policy_reason, @expires_at, @correlation_id, @trace_id)
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("capability_key", input.Capability);
        insert.Parameters.AddWithValue("resource_id", input.ResourceId);
        insert.Parameters.AddWithValue("parameters_json", parametersJson);
        insert.Parameters.AddWithValue("parameters_sha256", hash);
        insert.Parameters.AddWithValue("action_sha256", actionHash);
        insert.Parameters.AddWithValue("risk", risk.ToString().ToUpperInvariant());
        insert.Parameters.AddWithValue("proposer_actor_id", context.ActorId);
        insert.Parameters.AddWithValue("proposer_service_id", context.ServiceId);
        insert.Parameters.AddWithValue("policy_outcome", policy.Outcome == PolicyOutcome.Allow
            ? "ALLOW" : "REQUIRE_APPROVAL");
        insert.Parameters.AddWithValue("policy_reason", policy.Reason);
        insert.Parameters.AddWithValue("expires_at", expiresAt);
        insert.Parameters.AddWithValue("correlation_id", correlationId);
        insert.Parameters.AddWithValue("trace_id", traceId);
        await insert.ExecuteNonQueryAsync(ct);

        foreach (var eventId in uniqueEvents)
        {
            await using var link = new NpgsqlCommand("""
                INSERT INTO response_proposal_events (tenant_id, proposal_id, event_id)
                VALUES (@tenant_id, @proposal_id, @event_id)
                """, connection, transaction);
            link.Parameters.AddWithValue("tenant_id", context.TenantId);
            link.Parameters.AddWithValue("proposal_id", id);
            link.Parameters.AddWithValue("event_id", eventId);
            await link.ExecuteNonQueryAsync(ct);
        }
        await WriteAuditAsync(connection, transaction, context, "response_proposal.created",
            id, correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        return new(id, policy.Outcome, policy.Reason, hash, actionHash, expiresAt);
    }

    public async Task<IReadOnlyList<ResponseProposalSummary>> ListAsync(TenantContext context,
        CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var command = new NpgsqlCommand("""
            SELECT p.id, p.capability_key, p.resource_id, p.parameters_json,
                   p.parameters_sha256, p.action_sha256, p.risk, p.policy_outcome, p.created_at,
                   p.expires_at, d.decision
            FROM response_proposals p
            LEFT JOIN approval_decisions d
              ON d.tenant_id = p.tenant_id AND d.proposal_id = p.id
            ORDER BY p.created_at DESC LIMIT 100
            """, connection, transaction);
        var proposals = new List<ResponseProposalSummary>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            using var document = JsonDocument.Parse(reader.GetString(3));
            proposals.Add(new ResponseProposalSummary(
                reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                document.RootElement.Clone(), reader.GetString(4).Trim(), reader.GetString(5).Trim(),
                Enum.Parse<ActionRisk>(reader.GetString(6), true),
                reader.GetString(7) == "ALLOW" ? PolicyOutcome.Allow : PolicyOutcome.RequireApproval,
                new DateTimeOffset(reader.GetDateTime(8), TimeSpan.Zero),
                new DateTimeOffset(reader.GetDateTime(9), TimeSpan.Zero),
                reader.IsDBNull(10) ? null : ParseDecision(reader.GetString(10))));
        }
        await reader.DisposeAsync();
        await transaction.CommitAsync(ct);
        return proposals;
    }

    public async Task<ApprovalWriteResult> DecideAsync(TenantContext context, Guid proposalId,
        ApprovalChoice decision, string correlationId, string traceId, CancellationToken ct)
    {
        var (connection, transaction) = await OpenTenantAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var fetch = new NpgsqlCommand("""
            SELECT capability_key, resource_id, parameters_json, parameters_sha256,
                   action_sha256, risk, proposer_actor_id, expires_at, policy_outcome
            FROM response_proposals WHERE id = @id
            """, connection, transaction);
        fetch.Parameters.AddWithValue("id", proposalId);
        await using var reader = await fetch.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return new(ApprovalWriteStatus.NotFound, null, null);
        var capability = reader.GetString(0);
        var resource = reader.GetString(1);
        var parametersJson = reader.GetString(2);
        var storedHash = reader.GetString(3).Trim();
        var storedActionHash = reader.GetString(4).Trim();
        var risk = Enum.Parse<ActionRisk>(reader.GetString(5), true);
        var proposer = reader.GetString(6);
        var expiresAt = new DateTimeOffset(reader.GetDateTime(7), TimeSpan.Zero);
        var priorOutcome = reader.GetString(8);
        await reader.DisposeAsync();

        if (proposer == context.ActorId)
            return new(ApprovalWriteStatus.Conflict, null, "Proposers cannot review their own action.");
        if (expiresAt <= DateTimeOffset.UtcNow)
            return new(ApprovalWriteStatus.Conflict, null, "Proposal has expired.");
        if (!ProposalValidator.MatchesSha256(parametersJson, storedHash))
            return new(ApprovalWriteStatus.Conflict, null, "Proposal parameters failed integrity validation.");
        var eventIds = new List<Guid>();
        await using (var events = new NpgsqlCommand(
            "SELECT event_id FROM response_proposal_events WHERE proposal_id = @proposal_id",
            connection, transaction))
        {
            events.Parameters.AddWithValue("proposal_id", proposalId);
            await using var eventReader = await events.ExecuteReaderAsync(ct);
            while (await eventReader.ReadAsync(ct)) eventIds.Add(eventReader.GetGuid(0));
        }
        if (eventIds.Count == 0 || !ProposalValidator.HashesEqual(
                ProposalValidator.ActionSha256(context.TenantId, capability, resource,
                    risk, parametersJson, eventIds), storedActionHash))
            return new(ApprovalWriteStatus.Conflict, null, "Proposal action failed integrity validation.");
        if (priorOutcome != "REQUIRE_APPROVAL")
            return new(ApprovalWriteStatus.Conflict, null, "Proposal did not require approval.");

        if (decision == ApprovalChoice.Approve)
        {
            var policy = await EvaluateCurrentAsync(connection, transaction, context.TenantId,
                capability, resource, eventIds.Count > 0, ct);
            if (policy.Outcome != PolicyOutcome.RequireApproval)
                return new(ApprovalWriteStatus.Conflict, null,
                    "Current policy no longer permits approval; create a new proposal.");
        }

        var id = Guid.NewGuid();
        var validUntil = expiresAt < DateTimeOffset.UtcNow.AddMinutes(15)
            ? expiresAt : DateTimeOffset.UtcNow.AddMinutes(15);
        await using var insert = new NpgsqlCommand("""
            INSERT INTO approval_decisions
                (id, tenant_id, proposal_id, decision, reviewer_actor_id,
                 reviewer_service_id, parameters_sha256, action_sha256, valid_until,
                 correlation_id, trace_id)
            VALUES (@id, @tenant_id, @proposal_id, @decision, @reviewer_actor_id,
                    @reviewer_service_id, @parameters_sha256, @action_sha256, @valid_until,
                    @correlation_id, @trace_id)
            ON CONFLICT (tenant_id, proposal_id) DO NOTHING
            RETURNING id
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("proposal_id", proposalId);
        insert.Parameters.AddWithValue("decision", decision switch
        {
            ApprovalChoice.Approve => "APPROVE",
            ApprovalChoice.Reject => "REJECT",
            _ => "REQUEST_MORE_EVIDENCE"
        });
        insert.Parameters.AddWithValue("reviewer_actor_id", context.ActorId);
        insert.Parameters.AddWithValue("reviewer_service_id", context.ServiceId);
        insert.Parameters.AddWithValue("parameters_sha256", storedHash);
        insert.Parameters.AddWithValue("action_sha256", storedActionHash);
        insert.Parameters.AddWithValue("valid_until", validUntil);
        insert.Parameters.AddWithValue("correlation_id", correlationId);
        insert.Parameters.AddWithValue("trace_id", traceId);
        var inserted = await insert.ExecuteScalarAsync(ct);
        if (inserted is not Guid)
            return new(ApprovalWriteStatus.Conflict, null, "Proposal was already reviewed.");
        await WriteAuditAsync(connection, transaction, context,
            decision == ApprovalChoice.Approve ? "approval.approved" : "approval.reviewed",
            id, correlationId, traceId, ct);
        await transaction.CommitAsync(ct);
        return new(ApprovalWriteStatus.Created,
            new ApprovalResult(id, proposalId, decision, storedHash, storedActionHash,
                validUntil), null);
    }

    private async Task<PolicyDecision> EvaluateCurrentAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, Guid tenantId, string capability, string resource,
        bool hasEvidence, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            SELECT c.risk, c.enabled, c.healthy, c.approval_required,
                   tc.autonomy, tc.kill_mode,
                   EXISTS (
                       SELECT 1 FROM engagement_scopes es
                       WHERE es.tenant_id = c.tenant_id
                         AND es.capability_key = c.capability_key
                         AND es.resource_id = @resource_id
                         AND es.valid_from <= now() AND es.expires_at > now()
                   )
            FROM capabilities c
            JOIN tenant_controls tc ON tc.tenant_id = c.tenant_id
            WHERE c.tenant_id = @tenant_id AND c.capability_key = @capability_key
            """, connection, transaction);
        command.Parameters.AddWithValue("resource_id", resource);
        command.Parameters.AddWithValue("tenant_id", tenantId);
        command.Parameters.AddWithValue("capability_key", capability);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return new(PolicyOutcome.Deny, "Capability or tenant control is not configured.");
        var risk = Enum.Parse<ActionRisk>(reader.GetString(0), true);
        var enabled = reader.GetBoolean(1);
        var healthy = reader.GetBoolean(2);
        var approvalRequired = reader.GetBoolean(3);
        var autonomy = reader.GetString(4) switch
        {
            "OBSERVE" => AutonomyLevel.Observe,
            "RECOMMEND" => AutonomyLevel.Recommend,
            "LOW_RISK_AUTOMATIC" => AutonomyLevel.LowRiskAutomatic,
            _ => throw new InvalidOperationException("Unknown stored autonomy level.")
        };
        var killMode = reader.GetString(5) switch
        {
            "NORMAL" => KillMode.Normal,
            "READ_ONLY" => KillMode.ReadOnly,
            "PAUSED" => KillMode.Paused,
            _ => throw new InvalidOperationException("Unknown stored kill mode.")
        };
        var inScope = reader.GetBoolean(6);
        await reader.DisposeAsync();
        if (risk == ActionRisk.Read)
            return new(PolicyOutcome.Deny, "Read capabilities cannot be proposed as response actions.");
        return policyEngine.Evaluate(new PolicyRequest(capability, risk, autonomy, enabled,
            killMode, hasEvidence, healthy, inScope, approvalRequired));
    }

    private static async Task<ActionRisk> GetCapabilityRiskAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, string capability, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "SELECT risk FROM capabilities WHERE capability_key = @capability_key",
            connection, transaction);
        command.Parameters.AddWithValue("capability_key", capability);
        var result = (string)(await command.ExecuteScalarAsync(ct)
            ?? throw new InvalidOperationException("Capability disappeared during proposal creation."));
        return Enum.Parse<ActionRisk>(result, true);
    }

    private static ApprovalChoice ParseDecision(string value) => value switch
    {
        "APPROVE" => ApprovalChoice.Approve,
        "REJECT" => ApprovalChoice.Reject,
        "REQUEST_MORE_EVIDENCE" => ApprovalChoice.RequestMoreEvidence,
        _ => throw new InvalidOperationException("Unknown stored approval decision.")
    };

    private static async Task WriteAuditAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, TenantContext context, string action,
        Guid objectId, string correlationId, string traceId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO audit_events
                (id, tenant_id, actor_id, service_id, action, object_id,
                 correlation_id, trace_id)
            VALUES (@id, @tenant_id, @actor_id, @service_id, @action, @object_id,
                    @correlation_id, @trace_id)
            """, connection, transaction);
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
