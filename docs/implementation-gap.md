# Implementation gap — 2026-09-25

## Inspection

- The configured workspace did not exist and was created. It contained no source repository or prior implementation.
- Host is Windows; .NET SDK 10.0.401, Node 24.19.0, npm 11.17.0, Go 1.27.0, Python 3.14.7, and Rust/Cargo 1.98.1 are available.
- R, Podman, and host `psql` are absent. Docker Desktop became available for disposable PostgreSQL and Keycloak tests. No RHEL production host was inspected. Windows Hyper-V access was denied; a signed AlmaLinux 9 cloud image reached guest system initialization under QEMU software emulation but stalled at a clock check, so guest inventory was not validated.
- Active implementation profile: `dev-minimal`. No production deployment is configured.

## Implemented in this increment

- Repository, solution, API, development tenant bootstrap CLI and test projects.
- Canonical event envelope and intake JSON Schemas plus OpenAPI route contract.
- PostgreSQL tenant, event, incident, audit, tenant-control, capability, engagement-scope, proposal, and decision tables; forced RLS and narrow application grants.
- Transaction-local tenant and actor context in database access; parameterized writes; event deduplication by tenant/source/source event ID.
- JWT authority/audience configuration; tenant, actor, client identity, scope, enabled principal and database role enforcement on API routes. Disposable Keycloak service-account tokens have been tested through the HTTP layer, including wrong audience, no grant, revocation, and cross-tenant reads.
- Internal deterministic policy evaluator with deny, defer, more-evidence, and approval outcomes; immutable full-action-hash proposals and one human review decision per proposal. No privileged execution uses them yet.
- Event ID deduplication rejects changed content with an audited conflict.
- Numbered migration runner with hash verification and a session advisory lock.
- Local policy, identity-context and event-validation tests; live disposable PostgreSQL tests covering all migrations, migration idempotence, forced RLS, narrow application privileges, cross-tenant isolation, role checks, event deduplication conflicts, exact-action approval integrity, and approval blocking after a kill-switch change. A disposable database dump was restored and checked for schema and tenant records.
- API startup/readiness authority checks and nondevelopment configuration checks for HTTPS OIDC metadata and fully verified PostgreSQL TLS.
- Read-only RHEL inventory script, local PostgreSQL/Keycloak Compose definition, and a locally built nonroot API container image.
- Tenant-scoped deployment-domain registration and DNS TXT ownership checks, certificate-issuance eligibility, a private Caddy edge configuration, exact trusted-proxy handling, API security headers, and an isolated server-side Turnstile verifier. These controls have not been deployed on a public domain.
- A Graphify source and SQL knowledge graph with an interactive HTML view and machine-readable graph.

## Major incomplete phases

- Production Keycloak realm, human MFA flow, automated workload identity and token-claim provisioning; onboarding; governed role renewal and capability and tenant-control administration. The local CLI supports audited revocation, but has no two-person change workflow. The test realm is disposable only.
- Secure secrets through Infisical, durable jobs, connectors, sensor mTLS and actual Wazuh/Suricata/Zeek ingestion.
- Operational graph, raw evidence storage/manifests, OpenCTI, incident state, R, Python ML, Jev, model routing and agents.
- Configured capability providers, production change management for tenant controls and capability policy, response executor, action verification, and recovery. The schema and evaluator have kill-switch and capability fields, but there is no governed administration flow yet.
- Next.js operator cockpit, knowledge fabric, reporting, observability, backup/restore, archive, crypto service and RHEL Quadlet production deployment.
- Domain activation, certificate-status monitoring, an administrative UI, public Turnstile-protected workflow and rate limiting, optional Cloudflare controls, and live edge acceptance testing. No production domain or TLS certificate has been validated.
- Human Keycloak login/MFA, key rotation, connector integration, failure injection, full E2E, and full-platform restore testing. The live database and service-token tests cover only the foundation; production readiness is unproven.

## Next implementation sequence

1. Add reviewed production Keycloak realm/client provisioning with human MFA, service identity lifecycle, and key rotation checks.
2. Add governed tenant role revocation/renewal and capability controls under separate workload identities.
3. Add durable event jobs, real connector ingestion, immutable raw evidence references and sensor authentication.
4. Build response execution only after live approval-expiry, parameter-mutation, and policy-change tests pass.

## Boundaries and risks

The API currently accepts structured normalized events from authenticated clients; it does not prove sensor provenance, store the raw event, or perform enrichment. `structured_sha256` hashes a server serialization of the parsed request, not the original byte stream or raw source record. Audit events are append-only to the application role but are not yet cryptographically checkpointed. The policy evaluator is not exposed as an authorization endpoint because live capability configuration and approval verification are not built. Production must not reuse the development Compose topology or its environment-variable secret handling.
