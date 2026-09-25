# MARID Internet edge status

The edge is an **implementation in progress**. The repository has domain registration and DNS TXT verification, a tenant-isolated domain status API, a Caddy on-demand TLS configuration, exact-IP forwarded-header trust, API security headers, and a server-side Turnstile verifier. It does not yet have a public application UI, a Turnstile-protected public workflow, certificate-status synchronization, domain activation, or a deployed edge. No customer domain is live.

## Domain workflow available now

Run the administrative CLI through a private database connection:

```text
dotnet run --project apps/admin -- register-domain <tenant-uuid> soc.example.com
dotnet run --project apps/admin -- verify-domain <tenant-uuid> soc.example.com
dotnet run --project apps/admin -- list-domains <tenant-uuid>
dotnet run --project apps/admin -- remove-domain <tenant-uuid> soc.example.com
```

Registration prints a random TXT challenge at `_marid-verification.soc.example.com`. Verification compares a complete DNS TXT record with the stored challenge. The hostname is unique across tenants, and a failed recheck disables an active domain. Removal requires the domain to be inactive. Verified domain status can also be read at `GET /v1/deployment/domains` with the `deployment.domains.read` scope and an `AUDITOR` or `INCIDENT_MANAGER` tenant role; the token is excluded from that response.

The verified state is a certificate *eligibility* decision. The edge may request a certificate only when DNS ownership was verified in the last 24 hours. It does not make the domain active. Certificate status remains `PENDING` until a future certificate monitor records a validated certificate and an activation workflow is built.

## Edge topology

`infrastructure/edge/Caddyfile` configures Caddy to call `/internal/tls/allow?domain=...` before on-demand certificate issuance. It blocks `/internal/*` from public reverse proxy traffic and forwards application requests to `127.0.0.1:8080`. Caddy and the API must share a private network namespace; the API port, Caddy admin API, database, Keycloak administration, secret provider, and observability systems must stay off the public interface. Caddy's certificate data directory must persist across restarts. [Caddy documents on-demand TLS permission checks and automatic HTTPS redirects](https://caddyserver.com/docs/caddyfile/options).

Set `MARID_TRUSTED_PROXY_IPS` to the exact IP addresses that connect to the API. The application does not trust arbitrary forwarded headers. `MARID_HSTS_ENABLED=true` adds HSTS only after HTTPS and redirects have been validated on the deployed domain. The API currently sends a restrictive CSP for JSON routes; a future frontend must add only its required Turnstile script and frame origins. [Microsoft documents explicit trusted proxy configuration](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0), and [Cloudflare lists Turnstile's CSP requirements](https://developers.cloudflare.com/turnstile/reference/content-security-policy/).

## Turnstile

Set `TURNSTILE_ENABLED=true`, `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_REF`, and `TURNSTILE_EXPECTED_HOSTNAMES` when a public workflow is added. In production, the secret reference must be an absolute file under `/run/secrets/`; the secret value stays in the mounted file, never in configuration, source, a frontend bundle, or logs. The verifier posts the token to Cloudflare Siteverify, enforces success, hostname, action, and challenge age, and fails closed on timeout, invalid, malformed, or unavailable responses. It does not currently authorize any route, because MARID has no unauthenticated submission workflow. [Cloudflare requires server-side Siteverify validation and specifies single-use, five-minute tokens](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

## Release gates still open

- Deploy and validate the private/public network split and persistent Caddy certificate storage on the intended RHEL environment.
- Automate certificate health, expiry alerts, DNS rechecks, domain activation, primary-domain redirect, and safe deactivation/removal.
- Add the administrative web experience and a real public workflow with Turnstile plus rate limiting, then test invalid, expired, replayed, and provider-unavailable tokens through HTTP.
- Run domain DNS, HTTPS, redirect, certificate, security-header, authentication, origin isolation, internal-service exposure, and failure telemetry acceptance tests against a real deployment.
- Integrate optional Cloudflare WAF, bot controls, and origin restrictions through the production secret-management system without making Cloudflare a core dependency.
