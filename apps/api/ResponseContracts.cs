using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Buffers.Binary;

namespace Marid.Api;

public sealed record ResponseProposalInput(
    string Capability,
    string ResourceId,
    JsonElement Parameters,
    Guid[] EventIds);

public sealed record ResponseProposalResult(
    Guid? ProposalId,
    PolicyOutcome Outcome,
    string Reason,
    string? ParametersSha256,
    string? ActionSha256,
    DateTimeOffset? ExpiresAt);

public enum ApprovalChoice { Approve, Reject, RequestMoreEvidence }
public sealed record ApprovalInput(string Decision);
public sealed record ApprovalResult(
    Guid Id,
    Guid ProposalId,
    ApprovalChoice Decision,
    string ParametersSha256,
    string ActionSha256,
    DateTimeOffset ValidUntil);

public enum ApprovalWriteStatus { Created, NotFound, Conflict }
public sealed record ApprovalWriteResult(ApprovalWriteStatus Status, ApprovalResult? Value,
    string? Reason);

public sealed record ResponseProposalSummary(
    Guid Id,
    string Capability,
    string ResourceId,
    JsonElement Parameters,
    string ParametersSha256,
    string ActionSha256,
    ActionRisk Risk,
    PolicyOutcome PolicyOutcome,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    ApprovalChoice? Decision);

public static class ProposalValidator
{
    public static Dictionary<string, string[]> Validate(ResponseProposalInput input)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(input.Capability) || input.Capability.Length is < 3 or > 160 ||
            input.Capability.Any(c => !(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '.' or '_')))
            errors["capability"] = ["Use a capability key of 3 to 160 lowercase letters, digits, dots, or underscores."];
        if (string.IsNullOrWhiteSpace(input.ResourceId) || input.ResourceId.Length > 300 ||
            input.ResourceId.Any(char.IsControl))
            errors["resourceId"] = ["Resource ID must have 1 to 300 printable characters."];
        if (input.Parameters.ValueKind != JsonValueKind.Object ||
            input.Parameters.GetRawText().Length > 65_536 ||
            JsonStructureValidator.HasAmbiguousJson(input.Parameters))
            errors["parameters"] = ["Parameters must be a JSON object under 64 KiB, without duplicate keys or excessive nesting."];
        if (input.EventIds is null || input.EventIds.Length is < 1 or > 20 ||
            input.EventIds.Contains(Guid.Empty) || input.EventIds.Distinct().Count() != input.EventIds.Length)
            errors["eventIds"] = ["Provide 1 to 20 distinct nonempty event IDs."];
        return errors;
    }

    public static string Sha256(string parameterJson) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(parameterJson)))
            .ToLowerInvariant();

    public static string ActionSha256(Guid tenantId, string capability, string resourceId,
        ActionRisk risk, string parameterJson, IEnumerable<Guid> eventIds)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(tenantId.ToString("N"));
        Append(capability);
        Append(resourceId);
        Append(risk.ToString().ToUpperInvariant());
        Append(parameterJson);
        foreach (var eventId in eventIds.Select(x => x.ToString("N"))
                     .OrderBy(x => x, StringComparer.Ordinal))
            Append(eventId);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();

        void Append(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
    }

    public static bool MatchesSha256(string parameterJson, string storedHash)
    {
        if (storedHash.Length != 64) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(Encoding.UTF8.GetBytes(parameterJson)),
                Convert.FromHexString(storedHash));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool HashesEqual(string computedHash, string storedHash)
    {
        if (computedHash.Length != 64 || storedHash.Length != 64) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(computedHash), Convert.FromHexString(storedHash));
        }
        catch (FormatException)
        {
            return false;
        }
    }

}
