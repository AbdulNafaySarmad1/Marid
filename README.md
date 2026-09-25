# MARID

MARID is being built in stages from the canonical enterprise specification. This repository currently contains an executable control-plane foundation: a .NET 10 API, PostgreSQL schema with forced row-level security, versioned contracts, deterministic policy evaluation, response proposals, exact-parameter approval records, and tests. It is **not production-ready**.

## Current boundaries

- JWTs must be validated against a configured OIDC authority. The API derives `tenant_id`, actor (`sub`), principal type (`actor_type`), and service/client identity (`azp` or `client_id`) from the signed token. Tenant IDs are not accepted from request bodies. A matching enabled principal and tenant role grant in PostgreSQL is also required for every protected route.
- Every tenant database operation starts a transaction, sets `app.tenant_id` locally, and uses PostgreSQL row-level security. The `marid_app` role has no table ownership or `BYPASSRLS` privilege.
- The policy evaluator is internal only. There is no response execution path or API that treats caller-supplied approval as authority.
- Proposals reference existing tenant events and exact engagement scopes. Decisions are append-only, tied to a hash of the tenant, capability, resource, risk, parameters, and event IDs, and require a distinct human reviewer before proposal expiry. Approval records do not execute actions.
- Reusing an event's source ID with changed content returns HTTP 409 and creates an audit record.
- At startup and on `/health/ready`, the API verifies that its database identity has no RLS bypass, tenant-table ownership, schema creation, or protected mutation privileges. Outside development, it requires an HTTPS OIDC authority and PostgreSQL `SSL Mode=VerifyFull`.
- Ingested event references point to externally preserved raw events. Raw evidence storage and cryptographic manifests remain to be implemented.
- Domain claims require a matching DNS TXT challenge. The TLS edge consults recent verification before requesting a certificate. Certificate activation, monitoring, and public deployment remain open.

## Develop

1. Provision PostgreSQL 16 and a Keycloak OIDC realm. The local Compose file starts development PostgreSQL and Keycloak containers; it must not be used as production infrastructure.
2. Supply `MARID_DB_OWNER_PASSWORD`, `MARID_DB_APP_PASSWORD`, and `MARID_KEYCLOAK_ADMIN_PASSWORD` to the Compose process from a local secret mechanism. Run `docker compose -f infrastructure/podman/dev-minimal.compose.yaml up -d` when a container engine is available. Database initialization creates the unprivileged application role but does not apply schema changes.
3. Run `dotnet run --project apps/admin -- migrate` from an interactive console. It prompts without terminal echo for the migration-owner password, applies numbered migrations under an advisory lock, and checks applied-file hashes. Then run `dotnet run --project apps/admin -- create-tenant example "Example Customer"` to create a tenant with observe-only, read-only controls. Configure Keycloak so signed access tokens carry its UUID and the required claims.
4. After verifying a Keycloak subject and client ID, grant a temporary application role with `dotnet run --project apps/admin -- grant-role <tenant-uuid> <subject-id> <service-id> HUMAN ANALYST <expiry-UTC-Z>`. Use `SERVICE EVENT_INGESTOR` for a narrow ingest client. The role expiry must be within 30 days. `dotnet run --project apps/admin -- revoke-role <tenant-uuid> <subject-id> <service-id> <ROLE>` expires an active grant immediately and audits it. Regranting an expired or revoked role requires a reviewed administrative migration; this development CLI does not silently renew it.
5. Configure the API process with `MARID_OIDC_AUTHORITY`, optional `MARID_OIDC_AUDIENCE` (default `marid-api`), and `ConnectionStrings__Marid`. The connection must use `marid_app`, never the migration owner.
6. Run `dotnet run --project apps/api` and `dotnet test MARID.slnx -c Release`.
7. With Docker Desktop available, run `pwsh -File scripts/verify-db.ps1` for migration, RLS, live store, backup, and restore checks. Run `pwsh -File scripts/verify-auth.ps1` for real Keycloak token and HTTP checks. Each script creates and removes an isolated Compose project and volume.
8. Build the nonroot API image with `docker build -f apps/api/Dockerfile -t marid-api:local .`. This validates packaging only; the production service layout and RHEL release gates remain open.

For a controlled CI process, `MARID_ADMIN_PASSWORD_STDIN=1` lets the admin CLI read one password line from redirected standard input. The password must come from a secret provider or an in-memory test value; do not place it in command arguments or tracked files.

The API requires `tenant_id`, `sub`, `actor_type`, `azp` or `client_id`, and an appropriate space-delimited `scope` claim in valid access tokens. Its current routes are described in [OpenAPI](packages/schemas/openapi.v1.yaml). A realm/client mapper and user provisioning flow are not yet supplied, so live login needs the next integration phase.

See [Keycloak development setup](docs/keycloak-dev.md) for the token contract and manual realm configuration checks.

See [production readiness gates](docs/production-readiness.md) for verified controls and release blockers. The disposable Keycloak realm in `tests/auth` exists only for automated verification.

See [Internet edge status](docs/edge.md) for the domain CLI, TLS edge topology, proxy trust, Turnstile configuration, and unfinished acceptance gates.

See the [Graphify repository map](docs/knowledge-graph.md) for an interactive code and SQL knowledge graph.

For a RHEL host, `sudo ./bootstrap.sh` performs **read-only** resource and security inventory. It never formats storage or modifies services.

The disposable AlmaLinux VM runner in `scripts/verify-almalinux-vm.ps1` verifies the image signature and checksum before running the same inventory in a network-isolated guest. It has not completed a boot on this host under QEMU software emulation; see the [readiness gates](docs/production-readiness.md).

See [implementation gaps](docs/implementation-gap.md) before treating any component as operational.
