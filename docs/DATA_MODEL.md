# Data model (PostgreSQL)

## Tables (conceptual)
- `panels(id uuid pk, name text, base_url text, status, capabilities jsonb, sync_interval_seconds int, retention_days int, created_at, updated_at)`
- `panel_credentials(panel_id uuid pk fk, ciphertext bytea, nonce bytea, key_version int, updated_at)` (strict DB permissions)
- `nodes(id uuid pk, panel_id uuid fk, remote_uuid text, name text, last_sync_at, UNIQUE(panel_id,remote_uuid))`
- `users(id uuid pk, panel_id uuid fk, remote_uuid text, display_name text, last_sync_at, UNIQUE(panel_id,remote_uuid))`
- `node_user_aliases(id uuid pk, panel_id, node_id, xray_email, user_id nullable, valid_from, valid_to, source, confidence)`; no cross-panel alias.
- `agents(id uuid pk, panel_id, node_id, token_hash, status, last_seen, last_ack_seq)`
- `connection_events(event_id uuid pk, panel_id, node_id, agent_id, ts timestamptz, client_ip inet nullable, destination_host text nullable, destination_ip inet nullable, destination_port int, protocol text, inbound_tag text, outbound_tag text, xray_email text nullable, user_id uuid nullable, raw_fingerprint bytea, received_at timestamptz)`
- `traffic_samples(id uuid pk, panel_id, node_id nullable, user_id nullable, direction, bytes_total bigint, observed_at, source text, UNIQUE(panel_id,node_id,user_id,direction,observed_at,source))`
- `sync_runs(id uuid pk, panel_id, operation, status, started_at, finished_at, error_code)`
- `audit_log(id uuid pk, actor_id, panel_id nullable, action, object_type, object_id, ts, metadata jsonb)`
- `service_rules(id, rule_version, pattern, service, confidence, enabled)`

## Indexes
- Events `(panel_id, ts DESC)`, `(panel_id, node_id, ts DESC)`, `(panel_id, user_id, ts DESC)`, `(panel_id, destination_host, ts DESC)`.
- Consider daily partitioning for events once volume justifies; retention via partition drop with explicit cutoff.
- Counter samples `(panel_id, observed_at DESC)` and node/user composites.

## Semantics
- All event and sample queries require allowed panel scope.
- Connection event counts reflect accepted log lines, not bytes or unique sessions.
- Byte deltas computed only from comparable monotonic counters for same scope/source; detect resets and missing intervals; do not report negative deltas.
- All timestamp storage UTC, display in selected timezone.
- Duplicate event prevention by stable `event_id` generated from agent ID + log file identity + record offset or monotonic agent sequence; avoid dropping legitimate identical-looking connections.
- If remote UUID absent, do not invent an identity link.

## As built in M1 (migration `0002_auth_sync.sql`)
- New: `accounts` (Argon2id hash, `is_owner`, lockout fields), `memberships(account_id, panel_id, role)`, `sessions`
  (token SHA-256, expiry, ip, user agent), `schema_migrations`.
- `panels` gained `demo`, `deleted_at` (archive), `use_custom_ca`, `sync_options`, `api_version`, `last_probe(_at)`,
  `next_sync_at`, `last_sync_at/status`, `consecutive_failures`, `circuit_open_until`; name is unique among live panels.
- `nodes`/`users` gained status columns, `first_seen_at` and `removed_at`; `(panel_id, remote_uuid)` stays unique.
- `sync_runs` gained `trigger`, `stats`, `detail`; `audit_log` gained `actor_name`, `ip`, `request_id`.
- Migrations are embedded in the API and applied under an advisory lock; a database created by M0 is baselined.
