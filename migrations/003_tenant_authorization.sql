-- Keycloak authenticates identity. These grants are the application authority.
CREATE TABLE tenant_principals (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    subject_id text NOT NULL,
    service_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('HUMAN', 'SERVICE')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_id, service_id)
);

CREATE TABLE tenant_role_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    subject_id text NOT NULL,
    service_id text NOT NULL,
    role text NOT NULL CHECK (role IN (
        'EVENT_INGESTOR', 'ANALYST', 'INCIDENT_MANAGER',
        'RESPONDER', 'APPROVER', 'AUDITOR')),
    granted_by text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    UNIQUE (tenant_id, subject_id, service_id, role),
    FOREIGN KEY (tenant_id, subject_id, service_id)
        REFERENCES tenant_principals(tenant_id, subject_id, service_id)
);
CREATE INDEX ix_role_grants_lookup
    ON tenant_role_grants(tenant_id, subject_id, service_id, expires_at);

ALTER TABLE tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_role_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_role_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_principals_isolation ON tenant_principals
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_role_grants_isolation ON tenant_role_grants
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT ON tenant_principals, tenant_role_grants TO marid_app;
