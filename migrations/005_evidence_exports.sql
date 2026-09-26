-- All data access below is tenant-scoped. The migration owner keeps ownership;
-- marid_app may append records and advance job/session state only where granted.
CREATE TABLE evidence_objects (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    source text NOT NULL CHECK (length(source) BETWEEN 1 AND 120),
    source_event_id text,
    source_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    sensor_identity text NOT NULL,
    content_type text NOT NULL,
    byte_size bigint NOT NULL CHECK (byte_size > 0),
    object_key text NOT NULL UNIQUE,
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    parser_version text NOT NULL,
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    retention_class text NOT NULL DEFAULT 'RAW' CHECK (retention_class IN ('RAW', 'EXTENDED')),
    integrity_state text NOT NULL DEFAULT 'VERIFIED' CHECK (integrity_state IN ('VERIFIED', 'FAILED')),
    deleted_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source, source_event_id)
);
CREATE INDEX ix_evidence_tenant_source_at ON evidence_objects(tenant_id, source_at, id);

CREATE TABLE event_evidence_links (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    event_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, event_id, evidence_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES security_events(tenant_id, id),
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence_objects(tenant_id, id)
);

CREATE TABLE operator_sessions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor_id text NOT NULL,
    service_id text NOT NULL,
    role text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 1000),
    ticket_ref text NOT NULL CHECK (length(ticket_ref) BETWEEN 1 AND 200),
    break_glass boolean NOT NULL DEFAULT false,
    source_ip inet,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    UNIQUE (tenant_id, id),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);
CREATE INDEX ix_operator_sessions_tenant_started ON operator_sessions(tenant_id, started_at, id);

ALTER TABLE audit_events
    ADD COLUMN actor_type text NOT NULL DEFAULT 'SERVICE'
        CHECK (actor_type IN ('CLIENT_USER', 'NOCTURNE_ENGINEER', 'MARID_AGENT', 'SERVICE', 'SYSTEM')),
    ADD COLUMN role text,
    ADD COLUMN capability text,
    ADD COLUMN session_id uuid,
    ADD COLUMN reason text,
    ADD COLUMN ticket_ref text,
    ADD COLUMN target_resource text,
    ADD COLUMN parameters_sha256 char(64),
    ADD COLUMN outcome text,
    ADD COLUMN approval_id uuid,
    ADD COLUMN source_ip inet,
    ADD COLUMN severity text NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO', 'HIGH'));
ALTER TABLE audit_events ADD CONSTRAINT fk_audit_session
    FOREIGN KEY (tenant_id, session_id) REFERENCES operator_sessions(tenant_id, id);
CREATE INDEX ix_audit_tenant_range ON audit_events(tenant_id, occurred_at, id);
GRANT SELECT ON audit_events TO marid_app;

ALTER TABLE approval_decisions ADD CONSTRAINT uq_approval_tenant_id UNIQUE (tenant_id, id);
CREATE TABLE action_execution_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    proposal_id uuid NOT NULL,
    approval_id uuid,
    execution_identity text NOT NULL,
    result text NOT NULL,
    verification_result text,
    rollback_result text,
    result_reference text,
    executed_at timestamptz NOT NULL DEFAULT now(),
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    FOREIGN KEY (tenant_id, proposal_id) REFERENCES response_proposals(tenant_id, id),
    FOREIGN KEY (tenant_id, approval_id) REFERENCES approval_decisions(tenant_id, id)
);
CREATE INDEX ix_executions_tenant_time ON action_execution_records(tenant_id, executed_at, id);

CREATE TABLE retention_policies (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    category text NOT NULL CHECK (category IN
        ('TELEMETRY', 'RAW', 'AUDIT', 'INCIDENT', 'EXPORT')),
    retain_days integer NOT NULL CHECK (retain_days BETWEEN 30 AND 36500),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, category)
);
CREATE TABLE legal_holds (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    evidence_id uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 1000),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence_objects(tenant_id, id)
);
CREATE UNIQUE INDEX ux_active_evidence_hold ON legal_holds(tenant_id, evidence_id)
    WHERE released_at IS NULL;

CREATE TABLE export_schedules (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    enabled boolean NOT NULL DEFAULT true,
    day_of_month integer NOT NULL DEFAULT 1 CHECK (day_of_month BETWEEN 1 AND 28),
    last_enqueued_period date,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE export_jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED' CHECK
        (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    requested_by text NOT NULL,
    idempotency_key text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    lease_until timestamptz,
    completed_at timestamptz,
    manifest_key text,
    manifest_sha256 char(64),
    bytes_total bigint NOT NULL DEFAULT 0,
    error_code text,
    CHECK (period_end > period_start AND period_end <= period_start + interval '1 year'),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX ix_export_jobs_queue ON export_jobs(status, lease_until, requested_at);
CREATE INDEX ix_export_jobs_tenant_requested ON export_jobs(tenant_id, requested_at DESC);

CREATE TABLE export_artifacts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    name text NOT NULL,
    object_key text NOT NULL UNIQUE,
    byte_size bigint NOT NULL CHECK (byte_size >= 0),
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, job_id, name),
    FOREIGN KEY (tenant_id, job_id) REFERENCES export_jobs(tenant_id, id)
);
CREATE TABLE export_deliveries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    destination_type text NOT NULL CHECK (destination_type IN ('PORTAL', 'API', 'CLIENT_STORAGE')),
    destination_ref text,
    outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED', 'FAILED')),
    receipt text,
    attempted_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, job_id) REFERENCES export_jobs(tenant_id, id)
);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'evidence_objects', 'event_evidence_links', 'operator_sessions',
        'action_execution_records', 'retention_policies', 'legal_holds',
        'export_schedules', 'export_jobs', 'export_artifacts', 'export_deliveries'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END $$;

GRANT SELECT, INSERT ON evidence_objects, event_evidence_links, operator_sessions,
    action_execution_records, legal_holds, export_jobs, export_artifacts,
    export_deliveries TO marid_app;
GRANT SELECT ON retention_policies, export_schedules TO marid_app;
GRANT UPDATE (ended_at) ON operator_sessions TO marid_app;
GRANT UPDATE (status, attempts, lease_until, completed_at, manifest_key,
              manifest_sha256, bytes_total, error_code) ON export_jobs TO marid_app;

-- A narrow queue claim is the only cross-tenant operation. It returns job identity,
-- never evidence. The worker must set app.tenant_id before reading any data.
CREATE POLICY owner_export_jobs ON export_jobs TO marid_owner
    USING (true) WITH CHECK (true);
CREATE FUNCTION marid_claim_export_job() RETURNS TABLE(job_id uuid, job_tenant_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    UPDATE public.export_jobs j
    SET status = 'RUNNING', attempts = attempts + 1,
        lease_until = now() + interval '30 minutes', error_code = NULL
    WHERE j.id = (
        SELECT q.id FROM public.export_jobs q
        WHERE (q.status = 'QUEUED' OR
               (q.status = 'RUNNING' AND q.lease_until < now()))
          AND q.attempts < 5
        ORDER BY q.requested_at, q.id
        FOR UPDATE SKIP LOCKED LIMIT 1
    )
    RETURNING j.id, j.tenant_id;
$$;
REVOKE ALL ON FUNCTION marid_claim_export_job() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_claim_export_job() TO marid_worker;
GRANT SELECT ON security_events, incidents, audit_events, evidence_objects,
    event_evidence_links, operator_sessions, response_proposals,
    response_proposal_events, approval_decisions, action_execution_records,
    retention_policies, legal_holds, export_schedules, export_jobs,
    export_artifacts, export_deliveries TO marid_worker;
GRANT INSERT ON audit_events, export_artifacts, export_deliveries TO marid_worker;
GRANT UPDATE (status, attempts, lease_until, completed_at, manifest_key,
              manifest_sha256, bytes_total, error_code) ON export_jobs TO marid_worker;
