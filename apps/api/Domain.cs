using System.Security.Claims;
using System.Text.Json;

namespace Marid.Api;

public enum PrincipalKind { Human, Service }

public sealed record TenantContext(Guid TenantId, string ActorId, string ServiceId,
    PrincipalKind Kind)
{
    public static bool TryFrom(ClaimsPrincipal principal, out TenantContext context)
    {
        context = null!;
        if (principal.Identity?.IsAuthenticated != true) return false;
        var tenantValue = principal.FindFirstValue("tenant_id");
        var actor = principal.FindFirstValue("sub");
        var service = principal.FindFirstValue("azp") ?? principal.FindFirstValue("client_id");
        var kind = principal.FindFirstValue("actor_type") switch
        {
            "human" => PrincipalKind.Human,
            "service" => PrincipalKind.Service,
            _ => (PrincipalKind?)null
        };
        if (!Guid.TryParse(tenantValue, out var tenantId) || tenantId == Guid.Empty ||
            string.IsNullOrWhiteSpace(actor) || string.IsNullOrWhiteSpace(service) ||
            kind is null) return false;
        context = new TenantContext(tenantId, actor, service, kind.Value);
        return true;
    }
}

public static class ScopeAuthorizer
{
    public static bool HasScope(ClaimsPrincipal user, string required) =>
        user.FindAll("scope").Any(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Contains(required, StringComparer.Ordinal));
}

public sealed record SecurityEventInput(
    string Source,
    string SourceEventId,
    string Category,
    DateTimeOffset SourceTimestamp,
    string SensorIdentity,
    string ParserVersion,
    string RawEventReference,
    string[] EntityReferences,
    JsonElement Provenance,
    decimal Confidence,
    string? CorrelationId,
    string? TraceId);

public static class EventValidator
{
    public static Dictionary<string, string[]> Validate(SecurityEventInput value)
    {
        var errors = new Dictionary<string, string[]>();
        Check(value.Source, "source", 120);
        Check(value.SourceEventId, "sourceEventId", 200);
        Check(value.Category, "category", 120);
        Check(value.SensorIdentity, "sensorIdentity", 200);
        Check(value.ParserVersion, "parserVersion", 80);
        Check(value.RawEventReference, "rawEventReference", 500);
        if (value.SourceTimestamp == default || value.SourceTimestamp > DateTimeOffset.UtcNow.AddMinutes(5))
            errors["sourceTimestamp"] = ["Timestamp is missing or more than five minutes in the future."];
        if (value.Confidence < 0 || value.Confidence > 1)
            errors["confidence"] = ["Confidence must be between 0 and 1."];
        if (value.EntityReferences is null || value.EntityReferences.Length > 100 ||
            value.EntityReferences.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 300 ||
                                             x.Any(char.IsControl)))
            errors["entityReferences"] = ["Provide up to 100 nonempty entity references of at most 300 characters."];
        if (value.Provenance.ValueKind != JsonValueKind.Object)
            errors["provenance"] = ["Provenance must be a JSON object."];
        else if (value.Provenance.GetRawText().Length > 65_536 ||
                 JsonStructureValidator.HasAmbiguousJson(value.Provenance))
            errors["provenance"] = ["Provenance must be under 64 KiB without duplicate keys or excessive nesting."];
        if (value.CorrelationId?.Length > 200 || value.TraceId?.Length > 200 ||
            value.CorrelationId?.Any(char.IsControl) == true ||
            value.TraceId?.Any(char.IsControl) == true)
            errors["trace"] = ["Correlation and trace IDs must be printable and under 200 characters."];
        return errors;

        void Check(string? text, string key, int max)
        {
            if (string.IsNullOrWhiteSpace(text) || text.Length > max ||
                text.Any(char.IsControl))
                errors[key] = [$"Must have 1 to {max} characters."];
        }
    }
}

public static class JsonStructureValidator
{
    public static bool HasAmbiguousJson(JsonElement value, int depth = 0)
    {
        if (depth > 16) return true;
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name) ||
                    HasAmbiguousJson(property.Value, depth + 1)) return true;
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
                if (HasAmbiguousJson(item, depth + 1)) return true;
        }
        return false;
    }
}

public sealed record EventIngestResult(Guid EventId, bool Created, bool ConflictingDuplicate = false);
public enum IncidentSeverity { Low, Medium, High, Critical }
public sealed record CreateIncidentInput(string Title, string Severity);
public sealed record IncidentSummary(Guid Id, string Title, IncidentSeverity Severity,
    string Status, DateTimeOffset CreatedAt);

public enum PolicyOutcome { Allow, Deny, RequireApproval, Defer, RequestMoreEvidence }
public enum ActionRisk { Read, Low, Medium, High, Critical }
public enum AutonomyLevel { Observe, Recommend, LowRiskAutomatic }
public enum KillMode { Normal, ReadOnly, Paused }
public sealed record PolicyRequest(string Capability, ActionRisk Risk, AutonomyLevel Autonomy,
    bool CapabilityEnabled, KillMode KillMode, bool HasRequiredEvidence,
    bool ProviderHealthy, bool WithinEngagementScope, bool ApprovalRequired);
public sealed record PolicyDecision(PolicyOutcome Outcome, string Reason);

public sealed class PolicyEngine
{
    public PolicyDecision Evaluate(PolicyRequest request)
    {
        if (!Enum.IsDefined(request.Risk) || !Enum.IsDefined(request.Autonomy) ||
            !Enum.IsDefined(request.KillMode))
            return new(PolicyOutcome.Deny, "Unknown risk, autonomy, or kill mode.");
        if (request.KillMode == KillMode.Paused ||
            (request.KillMode == KillMode.ReadOnly && request.Risk != ActionRisk.Read))
            return new(PolicyOutcome.Deny, "Tenant kill switch blocks this operation.");
        if (string.IsNullOrWhiteSpace(request.Capability) || !request.CapabilityEnabled ||
            !request.WithinEngagementScope)
            return new(PolicyOutcome.Deny, "Capability unavailable, disabled, or outside engagement scope.");
        if (!request.HasRequiredEvidence)
            return new(PolicyOutcome.RequestMoreEvidence, "Required evidence is missing.");
        if (!request.ProviderHealthy)
            return new(PolicyOutcome.Defer, "Capability provider is unavailable.");
        if (request.Risk == ActionRisk.Read)
            return new(PolicyOutcome.Allow, "Read-only capability is in scope.");
        if (request.Autonomy == AutonomyLevel.Observe)
            return new(PolicyOutcome.Deny, "Autonomy is observe-only.");
        if (request.ApprovalRequired || request.Risk is ActionRisk.High or ActionRisk.Critical ||
            request.Autonomy == AutonomyLevel.Recommend ||
            request.Risk == ActionRisk.Medium)
            return new(PolicyOutcome.RequireApproval, "Human approval is required.");
        return new(PolicyOutcome.Allow, "Low-risk action is allowed by autonomy policy.");
    }
}
