# Graph Report - MARID  (2026-09-25)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 535 nodes · 832 edges · 54 communities (46 shown, 8 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 23 edges (avg confidence: 0.84)
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
- Community 50

## God Nodes (most connected - your core abstractions)
1. `FoundationTests` - 19 edges
2. `TenantContext` - 17 edges
3. `Marid.Api` - 16 edges
4. `ActionRisk` - 14 edges
5. `DecisionStore` - 12 edges
6. `TurnstileVerifier` - 12 edges
7. `PolicyRequest` - 11 edges
8. `PolicyOutcome` - 10 edges
9. `TurnstileOutcome` - 10 edges
10. `DeploymentDomains` - 10 edges

## Surprising Connections (you probably didn't know these)
- `FoundationTests` --references--> `PolicyEngine`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/FoundationTests.cs → apps/api/Domain.cs
- `Marid.Api.Tests` --references--> `Microsoft.NET.Sdk`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/Marid.Api.Tests.csproj → apps/admin/Marid.Admin.csproj
- `Marid.Api.Tests` --references--> `net10.0`  [EXTRACTED]
  tests/unit/Marid.Api.Tests/Marid.Api.Tests.csproj → apps/api/Marid.Api.csproj
- `DecisionStore` --references--> `PolicyEngine`  [EXTRACTED]
  apps/api/DecisionStore.cs → apps/api/Domain.cs
- `ResponseProposalSummary` --references--> `ActionRisk`  [EXTRACTED]
  apps/api/ResponseContracts.cs → apps/api/Domain.cs

## Import Cycles
- None detected.

## Communities (54 total, 8 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (39): CancellationToken, Connection, Guid, IReadOnlyList, NpgsqlConnection, NpgsqlDataSource, NpgsqlTransaction, Task (+31 more)

### Community 1 - "Community 1"
Cohesion: 0.07
Nodes (34): DateTimeOffset, Dictionary, JsonElement, AutonomyLevel, LowRiskAutomatic, Observe, Recommend, CreateIncidentInput (+26 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (29): CancellationToken, NpgsqlDataSource, Task, DatabaseAuthorityValidator, CancellationToken, NpgsqlDataSource, Task, DomainIssuanceStore (+21 more)

### Community 3 - "Community 3"
Cohesion: 0.07
Nodes (32): CancellationToken, IPAddress, Task, TurnstileConfiguration, TurnstileOutcome, Expired, HostnameMismatch, Invalid (+24 more)

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (24): additionalProperties, pattern, type, items, maxItems, minItems, type, uniqueItems (+16 more)

### Community 5 - "Community 5"
Cohesion: 0.20
Nodes (12): CancellationToken, DateTimeOffset, Guid, IEnumerable, NpgsqlConnection, NpgsqlTransaction, Task, DeploymentDomains (+4 more)

### Community 6 - "Community 6"
Cohesion: 0.15
Nodes (19): security_events, tenants, approval_decisions, capabilities, engagement_scopes, ix_approval_decisions_tenant_decided, ix_response_proposals_tenant_created, response_proposal_events (+11 more)

### Community 7 - "Community 7"
Cohesion: 0.14
Nodes (19): DateTimeOffset, Dictionary, Guid, JsonElement, ApprovalChoice, Approve, Reject, RequestMoreEvidence (+11 more)

### Community 8 - "Community 8"
Cohesion: 0.15
Nodes (17): Marid.Admin, Npgsql (9.0.5), Microsoft.NET.Sdk, Marid.Api, net10.0, Npgsql (9.0.5), coverlet.collector (6.0.4), DnsClient (1.8.0) (+9 more)

### Community 9 - "Community 9"
Cohesion: 0.13
Nodes (15): ASPNETCORE_ENVIRONMENT, applicationUrl, commandName, dotnetRunMessages, environmentVariables, launchBrowser, applicationUrl, commandName (+7 more)

### Community 10 - "Community 10"
Cohesion: 0.21
Nodes (8): IEnumerable, IPAddress, EdgeSecurity, ApiContentSecurityPolicy, ForwardedHeadersOptions, Fact, InvalidOperationException, EdgeSecurityTests

### Community 11 - "Community 11"
Cohesion: 0.30
Nodes (7): CancellationToken, DateTimeOffset, Guid, NpgsqlConnection, Task, TenantRoleGrantor, HashSet

### Community 12 - "Community 12"
Cohesion: 0.22
Nodes (7): CancellationToken, Guid, NpgsqlConnection, Task, TenantCreator, TenantNameValidator, system_text_regularexpressions

### Community 13 - "Community 13"
Cohesion: 0.25
Nodes (7): CancellationToken, IReadOnlyList, NpgsqlConnection, Task, MigrationFile, MigrationRunner, Regex

### Community 14 - "Community 14"
Cohesion: 0.28
Nodes (7): CancellationToken, DateTimeOffset, IReadOnlyList, NpgsqlDataSource, Task, DeploymentDomainStatus, DeploymentDomainStore

### Community 15 - "Community 15"
Cohesion: 0.25
Nodes (6): CancellationToken, Dictionary, NpgsqlDataSource, Task, PermissionMap, TenantAuthorization

### Community 16 - "Community 16"
Cohesion: 0.22
Nodes (9): properties, provenance, sourceTimestamp, traceId, type, format, type, maxLength (+1 more)

### Community 17 - "Community 17"
Cohesion: 0.29
Nodes (6): additionalProperties, $id, required, $schema, title, type

### Community 18 - "Community 18"
Cohesion: 0.29
Nodes (7): type, properties, correlationId, provenance, schemaVersion, type, const

### Community 19 - "Community 19"
Cohesion: 0.29
Nodes (7): items, type, type, items, type, entityReferences, normalizationWarnings

### Community 20 - "Community 20"
Cohesion: 0.29
Nodes (6): additionalProperties, $id, required, $schema, title, type

### Community 21 - "Community 21"
Cohesion: 0.29
Nodes (7): items, maxItems, type, maxLength, minLength, type, entityReferences

### Community 22 - "Community 22"
Cohesion: 0.50
Nodes (4): maximum, minimum, type, confidence

### Community 23 - "Community 23"
Cohesion: 0.50
Nodes (4): maxLength, minLength, type, category

### Community 24 - "Community 24"
Cohesion: 0.50
Nodes (4): maximum, minimum, type, confidence

### Community 25 - "Community 25"
Cohesion: 0.50
Nodes (4): maxLength, minLength, type, parserVersion

### Community 26 - "Community 26"
Cohesion: 0.50
Nodes (4): rawEventReference, maxLength, minLength, type

### Community 27 - "Community 27"
Cohesion: 0.50
Nodes (4): sensorIdentity, maxLength, minLength, type

### Community 28 - "Community 28"
Cohesion: 0.50
Nodes (4): source, maxLength, minLength, type

### Community 29 - "Community 29"
Cohesion: 0.50
Nodes (4): sourceEventId, maxLength, minLength, type

### Community 31 - "Community 31"
Cohesion: 0.67
Nodes (3): minLength, type, actorId

### Community 32 - "Community 32"
Cohesion: 0.67
Nodes (3): minLength, type, category

### Community 33 - "Community 33"
Cohesion: 0.67
Nodes (3): format, type, id

### Community 34 - "Community 34"
Cohesion: 0.67
Nodes (3): format, type, ingestedAt

### Community 35 - "Community 35"
Cohesion: 0.67
Nodes (3): format, type, normalizedAt

### Community 36 - "Community 36"
Cohesion: 0.67
Nodes (3): minLength, type, parserVersion

### Community 37 - "Community 37"
Cohesion: 0.67
Nodes (3): rawEventReference, minLength, type

### Community 38 - "Community 38"
Cohesion: 0.67
Nodes (3): sensorIdentity, minLength, type

### Community 39 - "Community 39"
Cohesion: 0.67
Nodes (3): serviceId, minLength, type

### Community 40 - "Community 40"
Cohesion: 0.67
Nodes (3): source, minLength, type

### Community 41 - "Community 41"
Cohesion: 0.67
Nodes (3): sourceEventId, minLength, type

### Community 42 - "Community 42"
Cohesion: 0.67
Nodes (3): sourceTimestamp, format, type

### Community 43 - "Community 43"
Cohesion: 0.67
Nodes (3): structuredSha256, pattern, type

### Community 44 - "Community 44"
Cohesion: 0.67
Nodes (3): tenantId, format, type

### Community 45 - "Community 45"
Cohesion: 0.67
Nodes (3): traceId, minLength, type

### Community 46 - "Community 46"
Cohesion: 0.67
Nodes (3): maxLength, type, correlationId

## Knowledge Gaps
- **165 isolated node(s):** `CreateIncidentInput`, `Program`, `ApprovalInput`, `Critical`, `High` (+160 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 243 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Marid.Api` connect `Community 2` to `Community 1`, `Community 3`, `Community 7`, `Community 14`, `Community 15`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **Why does `TenantContext` connect `Community 0` to `Community 1`, `Community 14`, `Community 15`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Why does `DeploymentDomains` connect `Community 5` to `Community 2`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **What connects `CreateIncidentInput`, `Program`, `ApprovalInput` to the rest of the system?**
  _165 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.0780399274047187 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.06568832983927324 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06037414965986394 - nodes in this community are weakly interconnected._
