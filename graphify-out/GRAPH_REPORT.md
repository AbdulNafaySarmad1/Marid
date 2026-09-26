# Graph Report - MARID  (2026-09-26)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 894 nodes · 1874 edges · 81 communities (64 shown, 17 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 178 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- Community 5
- Community 6
- Community 7
- Community 8
- Community 9
- Community 10
- Community 11
- Community 12
- Community 13
- Community 14
- Community 15
- Community 16
- Community 17
- Community 18
- Community 19
- Community 20
- Community 21
- Community 22
- Community 23
- Community 24
- Community 25
- Community 26
- Community 27
- Community 28
- Community 29
- Community 30
- Community 31
- Community 32
- Community 33
- Community 34
- Community 35
- Community 36
- Community 37
- Community 38
- Community 39
- Community 40
- Community 41
- Community 42
- Community 43
- Community 44
- Community 45
- Community 46
- Community 47
- Community 48
- Community 49
- Community 51
- Community 52
- Community 53
- Community 54
- Community 55
- Community 56
- Community 57
- Community 58
- Community 59
- Community 60
- Community 61
- Community 62
- Community 63
- Community 64
- Community 65
- Community 66
- Community 67
- Community 68
- Community 69
- Community 70
- Community 71
- Community 72
- Community 73
- Community 74
- Community 75
- Community 76
- Community 77

## God Nodes (most connected - your core abstractions)
1. `TenantContext` - 57 edges
2. `Marid.Api` - 32 edges
3. `ExportWorker` - 25 edges
4. `TenantAuthorization` - 24 edges
5. `ExportStore` - 21 edges
6. `tenants` - 20 edges
7. `FoundationTests` - 19 edges
8. `IObjectStore` - 16 edges
9. `EvidenceStore` - 15 edges
10. `ActionRisk` - 14 edges

## Surprising Connections (you probably didn't know these)
- `FoundationTests` --references--> `PolicyEngine`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/FoundationTests.cs → apps/api/Domain.cs
- `Marid.Api.Tests` --references--> `Microsoft.NET.Sdk`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/Marid.Api.Tests.csproj → apps/admin/Marid.Admin.csproj
- `Marid.Api.Tests` --references--> `net10.0`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/Marid.Api.Tests.csproj → apps/api/Marid.Api.csproj
- `EvidenceStore` --references--> `IObjectStore`  [EXTRACTED]
  apps/api/EvidenceStore.cs → apps/api/FileObjectStore.cs
- `EvidenceStore` --references--> `TenantDb`  [EXTRACTED]
  apps/api/EvidenceStore.cs → apps/api/TenantDb.cs

## Import Cycles
- None detected.

## Communities (81 total, 17 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.07
Nodes (48): audit_events, incidents, security_events, tenants, approval_decisions, capabilities, engagement_scopes, ix_approval_decisions_tenant_decided (+40 more)

### Community 1 - "Community 1"
Cohesion: 0.08
Nodes (36): CancellationToken, ClaimsPrincipal, Guid, HttpContext, IResult, RouteGroupBuilder, Task, EvidenceEndpoints (+28 more)

### Community 2 - "Community 2"
Cohesion: 0.08
Nodes (35): CancellationToken, Connection, Guid, IReadOnlyList, NpgsqlConnection, NpgsqlDataSource, NpgsqlTransaction, Task (+27 more)

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (29): CancellationToken, ClaimsPrincipal, Guid, HttpContext, IConfiguration, IResult, RouteGroupBuilder, Task (+21 more)

### Community 4 - "Community 4"
Cohesion: 0.11
Nodes (31): CancellationToken, DateTimeOffset, Guid, ILogger, IReadOnlyList, NpgsqlDataSource, Task, Dataset (+23 more)

### Community 5 - "Community 5"
Cohesion: 0.07
Nodes (32): CancellationToken, Func, IConfiguration, ILogger, IPAddress, Task, TurnstileConfiguration, TurnstileOutcome (+24 more)

### Community 6 - "Community 6"
Cohesion: 0.13
Nodes (22): CancellationToken, ClaimsPrincipal, DateTimeOffset, Guid, HttpContext, IPAddress, IResult, RouteGroupBuilder (+14 more)

### Community 7 - "Community 7"
Cohesion: 0.13
Nodes (25): CancellationToken, Guid, NpgsqlConnection, NpgsqlTransaction, Task, IncidentSeverity, Critical, High (+17 more)

### Community 8 - "Community 8"
Cohesion: 0.15
Nodes (16): CancellationToken, Func, Stream, Task, FileObjectStore, IsAvailable, IObjectStore, IsAvailable (+8 more)

### Community 9 - "Community 9"
Cohesion: 0.20
Nodes (15): CancellationToken, ClaimsPrincipal, DateTimeOffset, Guid, HttpContext, IReadOnlyList, IResult, RouteGroupBuilder (+7 more)

### Community 10 - "Community 10"
Cohesion: 0.08
Nodes (24): additionalProperties, pattern, type, items, maxItems, minItems, type, uniqueItems (+16 more)

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (12): CancellationToken, DateTimeOffset, Guid, IEnumerable, NpgsqlConnection, NpgsqlTransaction, Task, DeploymentDomains (+4 more)

### Community 12 - "Community 12"
Cohesion: 0.15
Nodes (17): Marid.Admin, Npgsql (9.0.5), Microsoft.NET.Sdk, Marid.Api, net10.0, Npgsql (9.0.5), coverlet.collector (6.0.4), DnsClient (1.8.0) (+9 more)

### Community 13 - "Community 13"
Cohesion: 0.17
Nodes (14): CancellationToken, ClaimsPrincipal, DateTimeOffset, Guid, HttpContext, IResult, RouteGroupBuilder, Task (+6 more)

### Community 14 - "Community 14"
Cohesion: 0.21
Nodes (10): Marid.Api.IntegrationTests, dnsclient, microsoft_extensions_logging_abstractions, npgsql, npgsqltypes, system_security_cryptography, system_text, system_text_json (+2 more)

### Community 15 - "Community 15"
Cohesion: 0.17
Nodes (9): Marid.Api.Tests, Marid.Api, microsoft_aspnetcore_builder, microsoft_aspnetcore_http_features, microsoft_aspnetcore_httpoverrides, microsoft_extensions_configuration, system_globalization, system_net (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.23
Nodes (11): CancellationToken, ClaimsPrincipal, HttpContext, IResult, RouteGroupBuilder, Task, ExportScheduleEndpoints, ExportScheduleInput (+3 more)

### Community 17 - "Community 17"
Cohesion: 0.16
Nodes (15): DateTimeOffset, Guid, CreateIncidentInput, EventIngestResult, EventValidator, IncidentActivityInput, IncidentActivitySummary, IncidentSummary (+7 more)

### Community 18 - "Community 18"
Cohesion: 0.13
Nodes (15): ASPNETCORE_ENVIRONMENT, applicationUrl, commandName, dotnetRunMessages, environmentVariables, launchBrowser, applicationUrl, commandName (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.16
Nodes (13): argparse, hashlib, importlib_util, json, Path, pathlib, re, digest() (+5 more)

### Community 20 - "Community 20"
Cohesion: 0.18
Nodes (8): CancellationToken, IReadOnlyList, NpgsqlConnection, Task, MigrationFile, MigrationRunner, Regex, InvalidOperationException

### Community 21 - "Community 21"
Cohesion: 0.27
Nodes (7): CancellationToken, DateTimeOffset, Guid, NpgsqlConnection, Task, TenantRoleGrantor, HashSet

### Community 22 - "Community 22"
Cohesion: 0.21
Nodes (8): IEnumerable, IPAddress, EdgeSecurity, ApiContentSecurityPolicy, ForwardedHeadersOptions, Fact, InvalidOperationException, EdgeSecurityTests

### Community 23 - "Community 23"
Cohesion: 0.42
Nodes (4): PolicyEngine, PolicyRequest, Fact, FoundationTests

### Community 24 - "Community 24"
Cohesion: 0.24
Nodes (6): CancellationToken, Guid, NpgsqlConnection, Task, TenantCreator, TenantNameValidator

### Community 25 - "Community 25"
Cohesion: 0.20
Nodes (8): NpgsqlDataSource, Program, WorkerDatabase, DataSource, IAsyncDisposable, microsoft_aspnetcore_authentication_jwtbearer, system_text_json_serialization, ValueTask

### Community 26 - "Community 26"
Cohesion: 0.28
Nodes (7): CancellationToken, DateTimeOffset, IReadOnlyList, NpgsqlDataSource, Task, DeploymentDomainStatus, DeploymentDomainStore

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (9): properties, provenance, sourceTimestamp, traceId, type, format, type, maxLength (+1 more)

### Community 28 - "Community 28"
Cohesion: 0.36
Nodes (4): Dictionary, JsonElement, JsonStructureValidator, SecurityEventInput

### Community 29 - "Community 29"
Cohesion: 0.29
Nodes (6): AutonomyLevel, LowRiskAutomatic, Observe, Recommend, InlineData, Theory

### Community 30 - "Community 30"
Cohesion: 0.29
Nodes (6): additionalProperties, $id, required, $schema, title, type

### Community 31 - "Community 31"
Cohesion: 0.29
Nodes (7): type, properties, correlationId, provenance, schemaVersion, type, const

### Community 32 - "Community 32"
Cohesion: 0.29
Nodes (7): items, type, type, items, type, entityReferences, normalizationWarnings

### Community 33 - "Community 33"
Cohesion: 0.29
Nodes (6): additionalProperties, $id, required, $schema, title, type

### Community 34 - "Community 34"
Cohesion: 0.29
Nodes (7): items, maxItems, type, maxLength, minLength, type, entityReferences

### Community 35 - "Community 35"
Cohesion: 0.60
Nodes (4): CancellationToken, NpgsqlDataSource, Task, DatabaseAuthorityValidator

### Community 36 - "Community 36"
Cohesion: 0.33
Nodes (4): CancellationToken, NpgsqlDataSource, Task, DomainIssuanceStore

### Community 37 - "Community 37"
Cohesion: 0.33
Nodes (5): marid_claim_export_job(), marid_enqueue_due_monthly_exports(), public.export_jobs, public.export_schedules, public.tenants

### Community 38 - "Community 38"
Cohesion: 0.40
Nodes (4): EvidenceMetrics, Counter, Meter, system_diagnostics_metrics

### Community 40 - "Community 40"
Cohesion: 0.50
Nodes (4): KillMode, Normal, Paused, ReadOnly

### Community 42 - "Community 42"
Cohesion: 0.50
Nodes (4): maximum, minimum, type, confidence

### Community 43 - "Community 43"
Cohesion: 0.50
Nodes (4): maxLength, minLength, type, category

### Community 44 - "Community 44"
Cohesion: 0.50
Nodes (4): maximum, minimum, type, confidence

### Community 45 - "Community 45"
Cohesion: 0.50
Nodes (4): maxLength, minLength, type, parserVersion

### Community 46 - "Community 46"
Cohesion: 0.50
Nodes (4): rawEventReference, maxLength, minLength, type

### Community 47 - "Community 47"
Cohesion: 0.50
Nodes (4): sensorIdentity, maxLength, minLength, type

### Community 48 - "Community 48"
Cohesion: 0.50
Nodes (4): source, maxLength, minLength, type

### Community 49 - "Community 49"
Cohesion: 0.50
Nodes (4): sourceEventId, maxLength, minLength, type

### Community 53 - "Community 53"
Cohesion: 0.67
Nodes (3): minLength, type, actorId

### Community 54 - "Community 54"
Cohesion: 0.67
Nodes (3): minLength, type, category

### Community 55 - "Community 55"
Cohesion: 0.67
Nodes (3): format, type, id

### Community 56 - "Community 56"
Cohesion: 0.67
Nodes (3): format, type, ingestedAt

### Community 57 - "Community 57"
Cohesion: 0.67
Nodes (3): format, type, normalizedAt

### Community 58 - "Community 58"
Cohesion: 0.67
Nodes (3): minLength, type, parserVersion

### Community 59 - "Community 59"
Cohesion: 0.67
Nodes (3): rawEventReference, minLength, type

### Community 60 - "Community 60"
Cohesion: 0.67
Nodes (3): sensorIdentity, minLength, type

### Community 61 - "Community 61"
Cohesion: 0.67
Nodes (3): serviceId, minLength, type

### Community 62 - "Community 62"
Cohesion: 0.67
Nodes (3): source, minLength, type

### Community 63 - "Community 63"
Cohesion: 0.67
Nodes (3): sourceEventId, minLength, type

### Community 64 - "Community 64"
Cohesion: 0.67
Nodes (3): sourceTimestamp, format, type

### Community 65 - "Community 65"
Cohesion: 0.67
Nodes (3): structuredSha256, pattern, type

### Community 66 - "Community 66"
Cohesion: 0.67
Nodes (3): tenantId, format, type

### Community 67 - "Community 67"
Cohesion: 0.67
Nodes (3): traceId, minLength, type

### Community 68 - "Community 68"
Cohesion: 0.67
Nodes (3): maxLength, type, correlationId

## Knowledge Gaps
- **169 isolated node(s):** `CreateIncidentInput`, `IncidentActivityInput`, `ApprovalInput`, `Program`, `Dataset` (+164 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 327 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Marid.Api` connect `Community 15` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 5`, `Community 6`, `Community 8`, `Community 9`, `Community 13`, `Community 14`, `Community 16`, `Community 17`, `Community 25`, `Community 26`, `Community 36`, `Community 38`, `Community 41`, `Community 51`, `Community 52`?**
  _High betweenness centrality (0.111) - this node is a cross-community bridge._
- **Why does `TenantContext` connect `Community 7` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 8`, `Community 9`, `Community 13`, `Community 16`, `Community 17`, `Community 26`?**
  _High betweenness centrality (0.095) - this node is a cross-community bridge._
- **Why does `DeploymentDomains` connect `Community 11` to `Community 14`?**
  _High betweenness centrality (0.029) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `TenantContext` (e.g. with `.RunTenantAsync()` and `.Operator_agent_incident_and_hold_records_export_and_retain_correctly()`) actually correct?**
  _`TenantContext` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `ExportWorker` (e.g. with `.Operator_agent_incident_and_hold_records_export_and_retain_correctly()` and `.Evidence_and_exports_remain_tenant_scoped_and_verifiable()`) actually correct?**
  _`ExportWorker` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `CreateIncidentInput`, `IncidentActivityInput`, `ApprovalInput` to the rest of the system?**
  _169 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.06531986531986532 - nodes in this community are weakly interconnected._
