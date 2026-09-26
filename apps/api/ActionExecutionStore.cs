using System.Security.Claims;
using Npgsql;

namespace Marid.Api;

public sealed record ActionExecutionInput(Guid? ApprovalId, string Result,
    string? VerificationResult, string? RollbackResult, string? ResultReference);
public sealed record ActionExecutionSummary(Guid Id, Guid ProposalId,
    Guid? ApprovalId, string Result, DateTimeOffset ExecutedAt);

public sealed class ActionExecutionStore(TenantDb tenantDb)
{
    public async Task<(ActionExecutionSummary? Value, string? Error)> RecordAsync(
        TenantContext context, Guid proposalId, ActionExecutionInput input,
        string correlationId, string traceId, CancellationToken ct)
    {
        if (context.Kind != PrincipalKind.Service ||
            input.Result is not ("SUCCEEDED" or "FAILED" or "BLOCKED") ||
            !Safe(input.VerificationResult, 1000) ||
            !Safe(input.RollbackResult, 1000) ||
            !Safe(input.ResultReference, 500))
            return (null, "Invalid execution record.");
        var (connection, transaction) = await tenantDb.OpenAsync(context, ct);
        await using var ownedConnection = connection;
        await using var ownedTransaction = transaction;
        await using var proposal = new NpgsqlCommand("""
            SELECT policy_outcome FROM response_proposals WHERE id = @id
            """, connection, transaction);
        proposal.Parameters.AddWithValue("id", proposalId);
        var policy = await proposal.ExecuteScalarAsync(ct) as string;
        if (policy is null) return (null, null);
        if (input.ResultReference is not null)
        {
            if (!input.ResultReference.StartsWith("evidence:", StringComparison.Ordinal) ||
                !Guid.TryParse(input.ResultReference[9..], out var evidenceId))
                return (null, "Result reference must be a tenant evidence ID.");
            await using var evidence = new NpgsqlCommand(
                "SELECT 1 FROM evidence_objects WHERE id = @id AND deleted_at IS NULL",
                connection, transaction);
            evidence.Parameters.AddWithValue("id", evidenceId);
            if (await evidence.ExecuteScalarAsync(ct) is null)
                return (null, "Result evidence is not available in this tenant.");
        }
        if (input.Result != "BLOCKED" && policy == "REQUIRE_APPROVAL")
        {
            if (input.ApprovalId is not Guid approvalId)
                return (null, "Approved actions need a valid approval reference.");
            await using var approval = new NpgsqlCommand("""
                SELECT 1 FROM approval_decisions
                WHERE id = @id AND proposal_id = @proposal_id
                  AND decision = 'APPROVE' AND valid_until > now()
                """, connection, transaction);
            approval.Parameters.AddWithValue("id", approvalId);
            approval.Parameters.AddWithValue("proposal_id", proposalId);
            if (await approval.ExecuteScalarAsync(ct) is null)
                return (null, "Approval is missing, invalid, or expired.");
        }
        else if (input.ApprovalId is not null)
            return (null, "Approval reference is not valid for this result.");
        var id = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO action_execution_records
                (id, tenant_id, proposal_id, approval_id, execution_identity,
                 result, verification_result, rollback_result, result_reference,
                 correlation_id, trace_id)
            VALUES (@id, @tenant_id, @proposal_id, @approval_id, @execution_identity,
                    @result, @verification_result, @rollback_result,
                    @result_reference, @correlation_id, @trace_id)
            RETURNING executed_at
            """, connection, transaction);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("tenant_id", context.TenantId);
        insert.Parameters.AddWithValue("proposal_id", proposalId);
        insert.Parameters.AddWithValue("approval_id", (object?)input.ApprovalId ?? DBNull.Value);
        insert.Parameters.AddWithValue("execution_identity", context.ServiceId);
        insert.Parameters.AddWithValue("result", input.Result);
        insert.Parameters.AddWithValue("verification_result",
            (object?)input.VerificationResult ?? DBNull.Value);
        insert.Parameters.AddWithValue("rollback_result",
            (object?)input.RollbackResult ?? DBNull.Value);
        insert.Parameters.AddWithValue("result_reference",
            (object?)input.ResultReference ?? DBNull.Value);
        insert.Parameters.AddWithValue("correlation_id", correlationId);
        insert.Parameters.AddWithValue("trace_id", traceId);
        var at = (DateTime)(await insert.ExecuteScalarAsync(ct))!;
        await AuditLedger.WriteAsync(connection, transaction, context,
            "agent.execution_recorded", id, correlationId, traceId, ct,
            target: proposalId.ToString(), outcome: input.Result,
            highPriority: input.Result != "SUCCEEDED");
        await transaction.CommitAsync(ct);
        return (new(id, proposalId, input.ApprovalId, input.Result,
            new DateTimeOffset(at, TimeSpan.Zero)), null);
    }

    private static bool Safe(string? value, int max) => value is null ||
        AuditLedger.SafeText(value, 1, max);
}

public static class ActionExecutionEndpoints
{
    public static void Map(RouteGroupBuilder api) =>
        api.MapPost("/response/proposals/{proposalId:guid}/execution-records",
            Record).RequireAuthorization("response.record_execution");

    private static async Task<IResult> Record(Guid proposalId,
        ActionExecutionInput input, ClaimsPrincipal user, HttpContext http,
        ActionExecutionStore store, TenantAuthorization authorization,
        CancellationToken ct)
    {
        if (!TenantContext.TryFrom(user, out var context)) return Results.Forbid();
        if (context.Kind != PrincipalKind.Service ||
            !await authorization.IsAllowedAsync(context, "response.record_execution", ct))
            return Results.Forbid();
        var result = await store.RecordAsync(context, proposalId, input,
            (string)http.Items["CorrelationId"]!,
            System.Diagnostics.Activity.Current?.TraceId.ToString() ?? http.TraceIdentifier, ct);
        return result.Value is not null
            ? Results.Created($"/v1/response/proposals/{proposalId}/execution-records/{result.Value.Id}",
                result.Value)
            : result.Error is null ? Results.NotFound()
                : Results.Conflict(new { reason = result.Error });
    }
}
