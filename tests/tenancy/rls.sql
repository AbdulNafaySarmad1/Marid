-- Run with psql -v ON_ERROR_STOP=1 as the migration owner against a disposable database.
-- All changes are rolled back after the tenant isolation assertions.
BEGIN;
DO $$
DECLARE
  protected_tables text[] := ARRAY[
    'security_events', 'incidents', 'audit_events', 'tenant_controls',
    'capabilities', 'engagement_scopes', 'response_proposals',
    'response_proposal_events', 'approval_decisions',
    'tenant_principals', 'tenant_role_grants', 'deployment_domains'
  ];
BEGIN
  IF (SELECT count(*) FROM pg_class
      WHERE relnamespace = 'public'::regnamespace
        AND relname = ANY(protected_tables)
        AND relrowsecurity AND relforcerowsecurity)
       <> array_length(protected_tables, 1) THEN
    RAISE EXCEPTION 'A tenant table is missing forced row-level security';
  END IF;
  IF (SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = 'marid_app') THEN
    RAISE EXCEPTION 'Application role can bypass row-level security';
  END IF;
  IF has_table_privilege('marid_app', 'public.security_events', 'UPDATE') OR
     has_table_privilege('marid_app', 'public.security_events', 'DELETE') OR
     has_table_privilege('marid_app', 'public.approval_decisions', 'UPDATE') OR
     has_table_privilege('marid_app', 'public.approval_decisions', 'DELETE') OR
     has_table_privilege('marid_app', 'public.tenant_role_grants', 'INSERT') OR
     has_table_privilege('marid_app', 'public.deployment_domains', 'INSERT') OR
     has_table_privilege('marid_app', 'public.deployment_domains', 'UPDATE') THEN
    RAISE EXCEPTION 'Application role has a forbidden mutation privilege';
  END IF;
END $$;
INSERT INTO tenants (id, slug, display_name) VALUES
  ('11111111-1111-4111-8111-111111111111', 'rls-test-a', 'RLS Test A'),
  ('22222222-2222-4222-8222-222222222222', 'rls-test-b', 'RLS Test B')
ON CONFLICT (id) DO NOTHING;
INSERT INTO tenant_controls (tenant_id, autonomy, kill_mode) VALUES
  ('11111111-1111-4111-8111-111111111111', 'OBSERVE', 'READ_ONLY'),
  ('22222222-2222-4222-8222-222222222222', 'OBSERVE', 'READ_ONLY');
INSERT INTO tenant_principals (tenant_id, subject_id, service_id, kind) VALUES
  ('11111111-1111-4111-8111-111111111111', 'analyst-a', 'operator-ui', 'HUMAN'),
  ('22222222-2222-4222-8222-222222222222', 'analyst-b', 'operator-ui', 'HUMAN');
INSERT INTO tenant_role_grants
  (id, tenant_id, subject_id, service_id, role, granted_by)
VALUES
  ('f1111111-1111-4111-8111-111111111111',
   '11111111-1111-4111-8111-111111111111', 'analyst-a', 'operator-ui', 'ANALYST', 'test-owner'),
  ('f2222222-2222-4222-8222-222222222222',
   '22222222-2222-4222-8222-222222222222', 'analyst-b', 'operator-ui', 'ANALYST', 'test-owner');
INSERT INTO capabilities
  (id, tenant_id, capability_key, provider_identity, risk, enabled, healthy, approval_required)
VALUES
  ('c1111111-1111-4111-8111-111111111111',
   '11111111-1111-4111-8111-111111111111', 'endpoint.host.isolate', 'test-fixture', 'HIGH', true, true, true),
  ('c2222222-2222-4222-8222-222222222222',
   '22222222-2222-4222-8222-222222222222', 'endpoint.host.isolate', 'test-fixture', 'HIGH', true, true, true);
INSERT INTO deployment_domains (id, tenant_id, hostname, verification_token)
VALUES ('e1111111-1111-4111-8111-111111111111',
        '11111111-1111-4111-8111-111111111111', 'soc.example.com', 'test-token');
UPDATE deployment_domains SET verification_status = 'VERIFIED', last_verified_at = now()
WHERE hostname = 'soc.example.com';
DO $$
BEGIN
  BEGIN
    INSERT INTO deployment_domains (id, tenant_id, hostname, verification_token)
    VALUES ('e2222222-2222-4222-8222-222222222222',
            '22222222-2222-4222-8222-222222222222', 'soc.example.com', 'other-token');
    RAISE EXCEPTION 'Another tenant claimed an existing hostname';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END $$;

SET ROLE marid_app;
DO $$
BEGIN
  IF NOT marid_domain_issuance_allowed('soc.example.com') OR
     marid_domain_issuance_allowed('other.example.com') THEN
    RAISE EXCEPTION 'TLS issuance did not follow verified domain ownership';
  END IF;
END $$;
SELECT set_config('app.tenant_id', '11111111-1111-4111-8111-111111111111', true);
INSERT INTO incidents (id, tenant_id, title, severity, status)
VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        '11111111-1111-4111-8111-111111111111', 'Tenant A incident', 'LOW', 'OPEN');
INSERT INTO security_events
  (id, tenant_id, source, source_event_id, category, source_at, normalized_at,
   schema_version, provenance, confidence, correlation_id, trace_id, actor_id,
   service_id, structured_sha256, parser_version, sensor_identity, raw_event_reference)
VALUES
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
   '11111111-1111-4111-8111-111111111111', 'fixture', 'event-a', 'endpoint', now(), now(),
   1, '{}'::jsonb, 1.0, 'correlation-a', 'trace-a', 'test-actor', 'test-service',
   repeat('a', 64), '1', 'fixture-sensor', 'raw://fixture-a');
INSERT INTO response_proposals
  (id, tenant_id, capability_key, resource_id, parameters_json, parameters_sha256, action_sha256,
   risk, proposer_actor_id, proposer_service_id, policy_outcome, policy_reason,
   expires_at, correlation_id, trace_id)
VALUES
  ('dddddddd-dddd-4ddd-8ddd-dddddddddddd',
   '11111111-1111-4111-8111-111111111111', 'endpoint.host.isolate', 'host-a', '{}',
   repeat('b', 64), repeat('c', 64), 'HIGH', 'test-actor', 'test-service', 'REQUIRE_APPROVAL',
   'Test fixture', now() + interval '30 minutes', 'correlation-a', 'trace-a');
INSERT INTO response_proposal_events (tenant_id, proposal_id, event_id)
VALUES ('11111111-1111-4111-8111-111111111111',
        'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
        'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');

SELECT set_config('app.tenant_id', '22222222-2222-4222-8222-222222222222', true);
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM incidents WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') THEN
    RAISE EXCEPTION 'Cross-tenant incident read was permitted';
  END IF;
  IF EXISTS (SELECT 1 FROM security_events WHERE id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee') THEN
    RAISE EXCEPTION 'Cross-tenant event read was permitted';
  END IF;
  IF EXISTS (SELECT 1 FROM response_proposals WHERE id = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd') THEN
    RAISE EXCEPTION 'Cross-tenant proposal read was permitted';
  END IF;
  IF EXISTS (SELECT 1 FROM tenant_role_grants WHERE subject_id = 'analyst-a') THEN
    RAISE EXCEPTION 'Cross-tenant role grant read was permitted';
  END IF;
  IF EXISTS (SELECT 1 FROM deployment_domains WHERE hostname = 'soc.example.com') THEN
    RAISE EXCEPTION 'Cross-tenant domain read was permitted';
  END IF;
  BEGIN
    INSERT INTO incidents (id, tenant_id, title, severity, status)
    VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            '11111111-1111-4111-8111-111111111111', 'Wrong tenant', 'LOW', 'OPEN');
    RAISE EXCEPTION 'Cross-tenant incident write was permitted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END $$;
RESET ROLE;
ROLLBACK;
