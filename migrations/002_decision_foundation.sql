-- Authority data is owned by the migration/admin role. The API role can only
-- read configuration and append proposals/decisions; it cannot mutate them.
CREATE TABLE tenant_controls (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    autonomy text NOT NULL CHECK (autonomy IN ('OBSERVE', 'RECOMMEND', 'LOW_RISK_AUTOMATIC')),
    kill_mode text NOT NULL CHECK (kill_mode IN ('NORMAL', 'READ_ONLY', 'PAUSED')),
    revision bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE capabilities (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    capability_key text NOT NULL CHECK (length(capability_key) BETWEEN 3 AND 160),
    provider_identity text NOT NULL,
    risk text NOT NULL CHECK (risk IN ('READ', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    enabled boolean NOT NULL DEFAULT false,
    healthy boolean NOT NULL DEFAULT false,
    approval_required boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, capability_key)
);

CREATE TABLE engagement_scopes (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    capability_key text NOT NULL,
    resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 300),
    authorized_by text NOT NULL,
    valid_from timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > valid_from),
    FOREIGN KEY (tenant_id, capability_key) REFERENCES capabilities(tenant_id, capability_key)
);
CREATE INDEX ix_engagement_scope_lookup
    ON engagement_scopes(tenant_id, capability_key, resource_id, expires_at);

ALTER TABLE security_events
    ADD CONSTRAINT uq_security_events_tenant_id_id UNIQUE (tenant_id, id);

CREATE TABLE response_proposals (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    capability_key text NOT NULL,
    resource_id text NOT NULL,
    parameters_json text NOT NULL CHECK (length(parameters_json) BETWEEN 2 AND 65536),
    parameters_sha256 char(64) NOT NULL,
    action_sha256 char(64) NOT NULL,
    risk text NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    proposer_actor_id text NOT NULL,
    proposer_service_id text NOT NULL,
    policy_outcome text NOT NULL CHECK (policy_outcome IN ('REQUIRE_APPROVAL', 'ALLOW')),
    policy_reason text NOT NULL,
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, capability_key) REFERENCES capabilities(tenant_id, capability_key)
);
CREATE INDEX ix_response_proposals_tenant_created
    ON response_proposals(tenant_id, created_at DESC);

CREATE TABLE response_proposal_events (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    proposal_id uuid NOT NULL,
    event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, proposal_id, event_id),
    FOREIGN KEY (tenant_id, proposal_id) REFERENCES response_proposals(tenant_id, id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES security_events(tenant_id, id)
);

CREATE TABLE approval_decisions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    proposal_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('APPROVE', 'REJECT', 'REQUEST_MORE_EVIDENCE')),
    reviewer_actor_id text NOT NULL,
    reviewer_service_id text NOT NULL,
    parameters_sha256 char(64) NOT NULL,
    action_sha256 char(64) NOT NULL,
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    decided_at timestamptz NOT NULL DEFAULT now(),
    valid_until timestamptz NOT NULL,
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    UNIQUE (tenant_id, proposal_id),
    FOREIGN KEY (tenant_id, proposal_id) REFERENCES response_proposals(tenant_id, id)
);
CREATE INDEX ix_approval_decisions_tenant_decided
    ON approval_decisions(tenant_id, decided_at DESC);

ALTER TABLE tenant_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_controls FORCE ROW LEVEL SECURITY;
ALTER TABLE capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE capabilities FORCE ROW LEVEL SECURITY;
ALTER TABLE engagement_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagement_scopes FORCE ROW LEVEL SECURITY;
ALTER TABLE response_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_proposals FORCE ROW LEVEL SECURITY;
ALTER TABLE response_proposal_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_proposal_events FORCE ROW LEVEL SECURITY;
ALTER TABLE approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_decisions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_controls_isolation ON tenant_controls
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY capabilities_isolation ON capabilities
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY engagement_scopes_isolation ON engagement_scopes
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY response_proposals_isolation ON response_proposals
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY response_proposal_events_isolation ON response_proposal_events
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY approval_decisions_isolation ON approval_decisions
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT ON tenant_controls, capabilities, engagement_scopes TO marid_app;
GRANT SELECT, INSERT ON response_proposals, response_proposal_events, approval_decisions TO marid_app;
