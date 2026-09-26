ALTER TABLE approval_decisions
    ADD CONSTRAINT uq_approval_tenant_proposal_id UNIQUE (tenant_id, proposal_id, id);
ALTER TABLE action_execution_records
    ADD CONSTRAINT fk_execution_approval_for_proposal
    FOREIGN KEY (tenant_id, proposal_id, approval_id)
    REFERENCES approval_decisions(tenant_id, proposal_id, id);

ALTER TABLE evidence_objects
    ADD COLUMN storage_deleted_at timestamptz,
    ADD CONSTRAINT evidence_storage_deletion_order
        CHECK (storage_deleted_at IS NULL OR deleted_at IS NOT NULL);
ALTER TABLE event_evidence_links
    ADD COLUMN linked_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX ix_event_evidence_links_time
    ON event_evidence_links(tenant_id, linked_at, evidence_id);
GRANT UPDATE (deleted_at, storage_deleted_at, integrity_state)
    ON evidence_objects TO marid_worker;
GRANT UPDATE (released_at) ON legal_holds TO marid_app;
GRANT INSERT ON retention_policies TO marid_app;
GRANT UPDATE (retain_days, updated_at) ON retention_policies TO marid_app;
GRANT UPDATE (enabled, day_of_month, updated_at) ON export_schedules TO marid_app;
GRANT INSERT ON export_schedules TO marid_app;
GRANT SELECT (id) ON tenants TO marid_worker;

-- The app cannot lock evidence rows directly because it has no UPDATE grant.
-- This function locks only a live object in the current RLS tenant until the
-- caller commits its legal-hold insert, excluding concurrent retention claims.
CREATE FUNCTION marid_lock_live_evidence(candidate uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.evidence_objects
        WHERE id = candidate AND deleted_at IS NULL
          AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        FOR UPDATE
    );
$$;
REVOKE ALL ON FUNCTION marid_lock_live_evidence(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_lock_live_evidence(uuid) TO marid_app;

CREATE FUNCTION marid_mark_evidence_integrity_failed(candidate uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    WITH changed AS (
        UPDATE public.evidence_objects
        SET integrity_state = 'FAILED'
        WHERE id = candidate AND deleted_at IS NULL
          AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        RETURNING id
    )
    SELECT EXISTS (SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION marid_mark_evidence_integrity_failed(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_mark_evidence_integrity_failed(uuid) TO marid_app;

DO $$
DECLARE item record;
BEGIN
    FOR item IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id', item.id::text, true);
        INSERT INTO retention_policies (tenant_id, category, retain_days)
        VALUES (item.id, 'TELEMETRY', 365), (item.id, 'RAW', 365),
               (item.id, 'AUDIT', 2555), (item.id, 'INCIDENT', 2555),
               (item.id, 'EXPORT', 365)
        ON CONFLICT DO NOTHING;
    END LOOP;
END $$;

ALTER TABLE incidents ADD CONSTRAINT uq_incident_tenant_id UNIQUE (tenant_id, id);
CREATE TABLE incident_activity (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    incident_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN
        ('CREATED', 'INVESTIGATION', 'REMEDIATION', 'STATUS', 'CLOSED')),
    status text NOT NULL CHECK (status IN
        ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    note text NOT NULL CHECK (length(note) BETWEEN 1 AND 4000),
    actor_id text NOT NULL,
    service_id text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    correlation_id text NOT NULL,
    trace_id text NOT NULL,
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id)
);
CREATE INDEX ix_incident_activity_tenant_time
    ON incident_activity(tenant_id, occurred_at, id);

CREATE TABLE incident_event_links (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    incident_id uuid NOT NULL,
    event_id uuid NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT now(),
    linked_by text NOT NULL,
    PRIMARY KEY (tenant_id, incident_id, event_id),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES security_events(tenant_id, id)
);
CREATE INDEX ix_incident_event_links_time
    ON incident_event_links(tenant_id, linked_at, event_id);

ALTER TABLE incident_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_activity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON incident_activity
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE incident_event_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_event_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON incident_event_links
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT ON incident_activity, incident_event_links TO marid_app;
GRANT SELECT ON incident_activity, incident_event_links TO marid_worker;
GRANT UPDATE (status, updated_at) ON incidents TO marid_app;

-- Backfill a transparent initial snapshot for incidents created before this migration.
DO $$
DECLARE item record;
BEGIN
    FOR item IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id', item.id::text, true);
        INSERT INTO incident_activity
            (id, tenant_id, incident_id, kind, status, note, actor_id,
             service_id, occurred_at, correlation_id, trace_id)
        SELECT gen_random_uuid(), tenant_id, id, 'CREATED', status,
               'Initial state at evidence migration', 'marid-migration',
               'marid-admin', created_at, id::text, id::text
        FROM incidents WHERE tenant_id = item.id;
    END LOOP;
END $$;
