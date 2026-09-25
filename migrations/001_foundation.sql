-- Run as a migration owner. The application role must not own these tables or bypass RLS.
CREATE TABLE IF NOT EXISTS tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    source text NOT NULL,
    source_event_id text NOT NULL,
    category text NOT NULL,
    source_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    normalized_at timestamptz NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version = 1),
    entity_references text[] NOT NULL DEFAULT '{}',
    provenance jsonb NOT NULL,
    confidence numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    actor_id text NOT NULL,
    service_id text NOT NULL,
    structured_sha256 char(64) NOT NULL,
    parser_version text NOT NULL,
    sensor_identity text NOT NULL,
    raw_event_reference text NOT NULL,
    normalization_warnings text[] NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, source, source_event_id)
);
CREATE INDEX IF NOT EXISTS ix_events_tenant_source_at ON security_events(tenant_id, source_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    severity text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status text NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_incidents_tenant_created ON incidents(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor_id text NOT NULL,
    service_id text NOT NULL,
    action text NOT NULL,
    object_id uuid NOT NULL,
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_tenant_occurred ON audit_events(tenant_id, occurred_at DESC);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_events ON security_events;
CREATE POLICY tenant_events ON security_events
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_incidents ON incidents;
CREATE POLICY tenant_incidents ON incidents
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_audit ON audit_events;
CREATE POLICY tenant_audit ON audit_events
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON security_events, incidents TO marid_app;
GRANT INSERT ON audit_events TO marid_app;
