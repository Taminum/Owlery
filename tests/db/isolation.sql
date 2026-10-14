-- Schema-level isolation checks. Run against a migrated database; everything is rolled back.
--   psql -v ON_ERROR_STOP=1 -f tests/db/isolation.sql
BEGIN;

INSERT INTO panels (id, name, base_url) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', 'A', 'https://a.example.test'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'B', 'https://b.example.test');
INSERT INTO nodes (id, panel_id, remote_uuid, name) VALUES
  ('aaaaaaaa-1111-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001', 'r1', 'a-node'),
  ('bbbbbbbb-1111-4000-8000-000000000002', 'bbbbbbbb-0000-4000-8000-000000000002', 'r1', 'b-node');  -- same remote uuid, other panel: allowed
INSERT INTO users (id, panel_id, remote_uuid) VALUES
  ('aaaaaaaa-2222-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001', 'u1'),
  ('bbbbbbbb-2222-4000-8000-000000000002', 'bbbbbbbb-0000-4000-8000-000000000002', 'u1');
INSERT INTO agents (id, panel_id, node_id, token_hash) VALUES
  ('aaaaaaaa-3333-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-1111-4000-8000-000000000001', '\x00');

DO $$
DECLARE failed boolean;
BEGIN
  -- 1. an event for panel A may not point at panel B's node
  failed := false;
  BEGIN
    INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, protocol, raw_fingerprint)
    VALUES (gen_random_uuid(), 'aaaaaaaa-0000-4000-8000-000000000001', 'bbbbbbbb-1111-4000-8000-000000000002',
            'aaaaaaaa-3333-4000-8000-000000000001', now(), 'example.test', 'tcp', '\x00');
  EXCEPTION WHEN foreign_key_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'cross-panel node link was accepted'; END IF;

  -- 2. an event for panel A may not resolve to panel B's user
  failed := false;
  BEGIN
    INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, user_id, ts, destination_host, protocol, raw_fingerprint)
    VALUES (gen_random_uuid(), 'aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-1111-4000-8000-000000000001',
            'aaaaaaaa-3333-4000-8000-000000000001', 'bbbbbbbb-2222-4000-8000-000000000002', now(), 'example.test', 'tcp', '\x00');
  EXCEPTION WHEN foreign_key_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'cross-panel user link was accepted'; END IF;

  -- 3. an alias may not bind a node of panel A to a user of panel B
  failed := false;
  BEGIN
    INSERT INTO node_user_aliases (panel_id, node_id, xray_email, user_id, valid_from, source, confidence)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-1111-4000-8000-000000000001', '4',
            'bbbbbbbb-2222-4000-8000-000000000002', now(), 'test', 'configured');
  EXCEPTION WHEN foreign_key_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'cross-panel alias was accepted'; END IF;

  -- 4. an event needs a destination, and ports are bounded
  failed := false;
  BEGIN
    INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, protocol, raw_fingerprint)
    VALUES (gen_random_uuid(), 'aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-1111-4000-8000-000000000001',
            'aaaaaaaa-3333-4000-8000-000000000001', now(), 'tcp', '\x00');
  EXCEPTION WHEN check_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'event without destination was accepted'; END IF;

  -- 5. byte counters can never be negative
  failed := false;
  BEGIN
    INSERT INTO traffic_samples (panel_id, direction, bytes_total, observed_at, source)
    VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'down', -1, now(), 'test');
  EXCEPTION WHEN check_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'negative bytes were accepted'; END IF;

  -- 6. panel URLs must be https
  failed := false;
  BEGIN
    INSERT INTO panels (name, base_url) VALUES ('X', 'http://insecure.example.test');
  EXCEPTION WHEN check_violation THEN failed := true; END;
  IF NOT failed THEN RAISE EXCEPTION 'http panel url was accepted'; END IF;
END $$;

ROLLBACK;
\echo isolation checks passed
