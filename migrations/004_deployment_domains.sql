-- A domain is never trusted until a fresh DNS ownership challenge succeeds.
CREATE TABLE deployment_domains (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    hostname text NOT NULL CHECK (
        length(hostname) BETWEEN 4 AND 253 AND
        hostname = lower(hostname) AND
        hostname ~ '^[a-z0-9.-]+$'),
    verification_method text NOT NULL DEFAULT 'DNS_TXT'
        CHECK (verification_method = 'DNS_TXT'),
    verification_token text NOT NULL,
    verification_status text NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'VERIFIED', 'FAILED')),
    first_verified_at timestamptz,
    last_verified_at timestamptz,
    last_checked_at timestamptz,
    active boolean NOT NULL DEFAULT false,
    is_primary boolean NOT NULL DEFAULT false,
    certificate_status text NOT NULL DEFAULT 'PENDING'
        CHECK (certificate_status IN ('PENDING', 'VALID', 'FAILED', 'EXPIRED')),
    certificate_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    CHECK (NOT is_primary OR active),
    CHECK (NOT active OR (
        removed_at IS NULL AND verification_status = 'VERIFIED' AND
        certificate_status = 'VALID' AND certificate_expires_at IS NOT NULL))
);
CREATE UNIQUE INDEX ux_deployment_domains_hostname
    ON deployment_domains(hostname) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX ux_deployment_domains_primary
    ON deployment_domains(tenant_id) WHERE is_primary AND removed_at IS NULL;
CREATE INDEX ix_deployment_domains_tenant ON deployment_domains(tenant_id, created_at DESC);

ALTER TABLE deployment_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_deployment_domains ON deployment_domains
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
-- The migration owner may perform the narrow cross-tenant issuance lookup below.
CREATE POLICY owner_deployment_domains ON deployment_domains TO marid_owner
    USING (true) WITH CHECK (true);
GRANT SELECT ON deployment_domains TO marid_app;

CREATE FUNCTION marid_domain_issuance_allowed(candidate text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.deployment_domains
        WHERE hostname = lower(candidate) AND removed_at IS NULL
          AND verification_status = 'VERIFIED'
          AND last_verified_at > now() - interval '24 hours'
    );
$$;
REVOKE ALL ON FUNCTION marid_domain_issuance_allowed(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_domain_issuance_allowed(text) TO marid_app;
