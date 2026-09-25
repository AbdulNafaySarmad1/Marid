# Keycloak development identity contract

The local Compose service runs Keycloak in `start-dev` mode at `http://localhost:8080`. Create the `marid-dev` realm in its admin console. The API validates signatures and issuer metadata from `MARID_OIDC_AUTHORITY=http://localhost:8080/realms/marid-dev` and requires `aud=marid-api` by default.

Before invoking an API route, configure a client and verify its **access token** contains:

| Claim | Required value |
| --- | --- |
| `iss` | The configured realm URL |
| `aud` | `marid-api` |
| `tenant_id` | UUID returned by the tenant bootstrap CLI |
| `sub` | Human or service-account subject |
| `azp` or `client_id` | The client/workload identity |
| `scope` | Only the needed space-delimited API scopes: `events.ingest`, `incidents.read`, `incidents.write`, `response.read`, `response.propose`, `response.approve` |
| `actor_type` | `human` for people, `service` for workloads; do not put `human` on service-account tokens |

Use Keycloak's audience mapper to add the API audience to access tokens. For a single-tenant development client, a hardcoded claim mapper can add its tenant UUID. Give each tenant a distinct client or equivalent strongly separated mapping; never let callers select `tenant_id` in an API request. Grant only required client scopes and confirm the effective token claims using Keycloak's client-scope evaluation before testing the API. Service-account clients use the client-credentials grant and must have narrow roles/scopes. Keep `response.approve` and `actor_type=human` on human reviewer tokens only, with MFA enforced in Keycloak.

This is a manual development setup, not a production realm export. Production needs automated tenant/client provisioning, MFA and workload identity policy, secret storage, issuer/audience integration tests, key rotation validation, and a separate administrative review before activation.

For disposable verification, `pwsh -File scripts/verify-auth.ps1` imports the test-only realm in `tests/auth/marid-test-realm.json` into a fresh Keycloak container. It checks signed service tokens through the API, audience rejection, role grants and revocation, and cross-tenant reads. The generated client secret and database passwords exist only for that test run; the Compose project and volumes are removed afterward. This does not provision real users or prove MFA, key rotation, or production realm policy.

Official references: [Keycloak container setup](https://www.keycloak.org/server/containers), [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/).
