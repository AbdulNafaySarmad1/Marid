# Production readiness gates

Status: **not production-ready**. This repository is a tested control-plane foundation, not a complete MARID deployment. A production release requires evidence for every required capability in the canonical specification.

| Gate | Current evidence | Status |
| --- | --- | --- |
| Tenant database isolation | Forced RLS, application privilege assertions, cross-tenant SQL and HTTP tests | Foundation verified |
| Authentication and authorization | Signed Keycloak service tokens, audience and scope checks, database role grants and revocation tested in disposable containers | Service path verified; human MFA and production provisioning open |
| Event intake | Normalized event contract, tenant deduplication, changed duplicate audit conflict | Foundation verified; sensor provenance and real connector ingestion open |
| Policy and approval | Deterministic evaluator, full action hash, distinct human review record, kill-switch recheck, live store tests | Foundation verified; governed administration and execution open |
| Backup and restoration | Disposable PostgreSQL dump restored and checked for schema and tenant records | Database smoke check only; encrypted offsite retention and full-platform recovery open |
| Secrets and cryptography | Test credentials generated in memory for disposable runs | Production secret provider, rotation, crypto service and key management open |
| Detection and investigation | No real Wazuh, Suricata, Zeek, OpenCTI, graph, R, ML, Jev, or agent integration | Open |
| Operator and customer workflows | Engineer session/API audit and basic structured export report | Operator cockpit, rich report rendering, SLA, notifications, and recovery orchestration open |
| Operations and deployment | Read-only host inventory script; nonroot API container built locally | RHEL deployment, monitoring, failure injection, and load tests open |
| Internet edge and domains | Tenant-unique DNS TXT claims, TLS issuance lookup, Caddy config validation, exact-IP proxy trust, server-side Turnstile verifier tests | No live domain, certificate synchronization, protected public workflow, admin UI, or edge acceptance run |
| Evidence and audit | File-backed raw objects with SHA-256, tenant-linked metadata, engineer sessions, agent execution records, incident activity, enriched append-only audit; disposable isolation/integrity tests | Production object store, sensor provenance, IdP engineer claim/MFA, external audit checkpoints open |
| Client exports | Durable PostgreSQL queue, monthly schedule, RLS-scoped streaming NDJSON, basic JSON/Markdown reports, SHA-256 manifest, authorized retrieval and delivery receipts | No KMS signature, customer destination adapter, independent receipt, production scale or restore evidence |
| Retention and holds | Category policies, legal holds, audited RAW-class tombstone/deletion tested in disposable storage | Other categories, client policy approval workflow, and production deletion rehearsal open |

## Repeatable checks

Run `dotnet test MARID.slnx -c Release -p:NuGetAudit=false -m:1`, `pwsh -File scripts/verify-db.ps1`, `pwsh -File scripts/verify-auth.ps1`, and `python -m unittest tests/unit/test_verify_export.py`. The database suite includes a 2,048-record in-period export and an excluded out-of-period record. The database and authentication scripts use disposable Docker Compose projects and remove their volumes when complete. The Keycloak test realm is deliberately fixed to test UUIDs and must not be used for customers.

Build the API container with `docker build -f apps/api/Dockerfile -t marid-api:local .`. It runs as the .NET image's nonroot application user. The image is a packaging artifact, not a complete production deployment. Pin base image digests and scan the final image in the release pipeline.

`scripts/verify-almalinux-vm.ps1` prepares a temporary, network-isolated AlmaLinux 9 virtual machine for the read-only host inventory. It verifies the cloud image's signed checksum and removes the guest disk after the run. On this Windows/Docker Desktop host, the verified guest reached system initialization but stalled in QEMU software emulation at a kernel clock check, so the inventory **did not pass**. AlmaLinux is a RHEL-compatible test guest; it does not establish validation on the intended RHEL release.

No production release or customer data onboarding should occur until the open gates have implementations, security review, and recorded validation results on the intended RHEL environment.
