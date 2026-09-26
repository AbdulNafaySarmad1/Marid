using System.Diagnostics.Metrics;

namespace Marid.Api;

public static class EvidenceMetrics
{
    private static readonly Meter Meter = new("Marid.Evidence", "0.3.0");
    public static readonly Counter<long> EvidenceIngested = Meter.CreateCounter<long>(
        "marid.evidence.ingested");
    public static readonly Counter<long> EvidenceBytes = Meter.CreateCounter<long>(
        "marid.evidence.bytes");
    public static readonly Counter<long> StorageFailures = Meter.CreateCounter<long>(
        "marid.evidence.storage_failures");
    public static readonly Counter<long> IntegrityFailures = Meter.CreateCounter<long>(
        "marid.evidence.integrity_failures");
    public static readonly Counter<long> ExportsQueued = Meter.CreateCounter<long>(
        "marid.exports.queued");
    public static readonly Counter<long> ExportsStarted = Meter.CreateCounter<long>(
        "marid.exports.started");
    public static readonly Counter<long> ExportsCompleted = Meter.CreateCounter<long>(
        "marid.exports.completed");
    public static readonly Counter<long> ExportsFailed = Meter.CreateCounter<long>(
        "marid.exports.failed");
    public static readonly Counter<long> ExportBytes = Meter.CreateCounter<long>(
        "marid.exports.bytes");
    public static readonly Counter<long> DeliverySucceeded = Meter.CreateCounter<long>(
        "marid.exports.delivery_succeeded");
    public static readonly Counter<long> DeliveryFailed = Meter.CreateCounter<long>(
        "marid.exports.delivery_failed");
    public static readonly Counter<long> RetentionDeleted = Meter.CreateCounter<long>(
        "marid.retention.deleted");
    public static readonly Counter<long> LegalHoldSkips = Meter.CreateCounter<long>(
        "marid.retention.legal_hold_skips");
    public static readonly Counter<long> AuthorizationFailures = Meter.CreateCounter<long>(
        "marid.authorization.failures");
}
