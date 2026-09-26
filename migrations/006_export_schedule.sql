ALTER TABLE export_jobs ADD COLUMN generation_at timestamptz;
ALTER TABLE export_artifacts ADD COLUMN row_count bigint NOT NULL DEFAULT 0
    CHECK (row_count >= 0);

CREATE OR REPLACE FUNCTION marid_claim_export_job()
RETURNS TABLE(job_id uuid, job_tenant_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    UPDATE public.export_jobs j
    SET status = 'RUNNING', attempts = attempts + 1,
        generation_at = coalesce(generation_at, now()),
        lease_until = now() + interval '30 minutes', error_code = NULL
    WHERE j.id = (
        SELECT q.id FROM public.export_jobs q
        WHERE (q.status = 'QUEUED' OR
               (q.status IN ('RUNNING', 'FAILED') AND q.lease_until < now()))
          AND q.attempts < 5
        ORDER BY q.requested_at, q.id
        FOR UPDATE SKIP LOCKED LIMIT 1
    )
    RETURNING j.id, j.tenant_id;
$$;
REVOKE ALL ON FUNCTION marid_claim_export_job() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_claim_export_job() TO marid_worker;

CREATE POLICY owner_export_schedules ON export_schedules TO marid_owner
    USING (true) WITH CHECK (true);
INSERT INTO export_schedules (tenant_id)
SELECT id FROM tenants ON CONFLICT (tenant_id) DO NOTHING;

CREATE FUNCTION marid_enqueue_due_monthly_exports() RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    item record;
    month_end timestamptz := date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    month_start timestamptz := month_end - interval '1 month';
    enqueued integer := 0;
    new_id uuid;
BEGIN
    FOR item IN
        SELECT s.tenant_id FROM public.export_schedules s
        JOIN public.tenants t ON t.id = s.tenant_id
        WHERE t.created_at < month_end AND s.enabled
          AND s.day_of_month <= extract(day FROM now() AT TIME ZONE 'UTC')
          AND (s.last_enqueued_period IS NULL OR s.last_enqueued_period < month_start::date)
        ORDER BY s.tenant_id FOR UPDATE OF s SKIP LOCKED
    LOOP
        new_id := gen_random_uuid();
        INSERT INTO public.export_jobs
            (id, tenant_id, period_start, period_end, requested_by, idempotency_key)
        VALUES (new_id, item.tenant_id, month_start, month_end,
                'marid-scheduler', 'monthly-' || to_char(month_start AT TIME ZONE 'UTC', 'YYYY-MM'))
        ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;
        IF FOUND THEN
            enqueued := enqueued + 1;
            PERFORM set_config('app.tenant_id', item.tenant_id::text, true);
            INSERT INTO public.audit_events
                (id, tenant_id, actor_id, service_id, actor_type, action,
                 object_id, correlation_id, trace_id)
            VALUES (gen_random_uuid(), item.tenant_id, 'marid-scheduler',
                    'marid-worker', 'SYSTEM', 'export.queued', new_id,
                    new_id::text, new_id::text);
        END IF;
        UPDATE public.export_schedules SET last_enqueued_period = month_start::date
        WHERE tenant_id = item.tenant_id;
    END LOOP;
    RETURN enqueued;
END;
$$;
REVOKE ALL ON FUNCTION marid_enqueue_due_monthly_exports() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION marid_enqueue_due_monthly_exports() TO marid_worker;
