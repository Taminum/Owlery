-- Owlery 0001: multi-panel from the very first migration.
-- Isolation is enforced in the schema too: every child row carries panel_id and
-- references its parent through a composite (panel_id, id) key, so a node, user
-- or agent from one panel can never be linked to another panel's rows.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE panels (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text        NOT NULL,
    base_url              text        NOT NULL CHECK (base_url LIKE 'https://%'),
    status                text        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','active','disabled','error')),
    capabilities          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    sync_interval_seconds integer     NOT NULL DEFAULT 300 CHECK (sync_interval_seconds >= 30),
    retention_days        integer     NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- Stored separately so it can get stricter DB permissions than panels.
CREATE TABLE panel_credentials (
    panel_id    uuid PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,
    ciphertext  bytea       NOT NULL,
    nonce       bytea       NOT NULL CHECK (octet_length(nonce) = 12),
    key_version integer     NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id     uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    remote_uuid  text        NOT NULL,
    name         text        NOT NULL,
    last_sync_at timestamptz,
    UNIQUE (panel_id, remote_uuid),
    UNIQUE (panel_id, id)
);

CREATE TABLE users (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id     uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    remote_uuid  text        NOT NULL,
    display_name text,
    last_sync_at timestamptz,
    UNIQUE (panel_id, remote_uuid),
    UNIQUE (panel_id, id)
);

-- Raw Xray "email" is only a hint, valid per node and time range; never global.
CREATE TABLE node_user_aliases (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id   uuid        NOT NULL,
    node_id    uuid        NOT NULL,
    xray_email text        NOT NULL,
    user_id    uuid,
    valid_from timestamptz NOT NULL,
    valid_to   timestamptz,
    source     text        NOT NULL,
    confidence text        NOT NULL CHECK (confidence IN ('verified','configured','unverified')),
    FOREIGN KEY (panel_id, node_id) REFERENCES nodes(panel_id, id) ON DELETE CASCADE,
    FOREIGN KEY (panel_id, user_id) REFERENCES users(panel_id, id) ON DELETE SET NULL (user_id)
);
CREATE INDEX node_user_aliases_lookup ON node_user_aliases (panel_id, node_id, xray_email, valid_from DESC);

CREATE TABLE agents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id     uuid        NOT NULL,
    node_id      uuid        NOT NULL,
    token_hash   bytea       NOT NULL,
    status       text        NOT NULL DEFAULT 'enrolling'
                     CHECK (status IN ('enrolling','active','revoked')),
    last_seen    timestamptz,
    last_ack_seq bigint      NOT NULL DEFAULT 0,
    UNIQUE (panel_id, id),
    FOREIGN KEY (panel_id, node_id) REFERENCES nodes(panel_id, id) ON DELETE CASCADE
);

CREATE TABLE connection_events (
    event_id         uuid        PRIMARY KEY,
    panel_id         uuid        NOT NULL,
    node_id          uuid        NOT NULL,
    agent_id         uuid        NOT NULL,
    ts               timestamptz NOT NULL,
    client_ip        inet,
    destination_host text,
    destination_ip   inet,
    destination_port integer     CHECK (destination_port BETWEEN 0 AND 65535),
    protocol         text        NOT NULL CHECK (protocol IN ('tcp','udp')),
    inbound_tag      text,
    outbound_tag     text,
    xray_email       text,
    user_id          uuid,
    raw_fingerprint  bytea       NOT NULL,
    received_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_id, node_id)  REFERENCES nodes(panel_id, id)  ON DELETE CASCADE,
    FOREIGN KEY (panel_id, agent_id) REFERENCES agents(panel_id, id) ON DELETE CASCADE,
    FOREIGN KEY (panel_id, user_id)  REFERENCES users(panel_id, id)  ON DELETE SET NULL (user_id),
    CHECK (destination_host IS NOT NULL OR destination_ip IS NOT NULL)
);
CREATE INDEX connection_events_panel_ts  ON connection_events (panel_id, ts DESC);
CREATE INDEX connection_events_node_ts   ON connection_events (panel_id, node_id, ts DESC);
CREATE INDEX connection_events_user_ts   ON connection_events (panel_id, user_id, ts DESC);
CREATE INDEX connection_events_host_ts   ON connection_events (panel_id, destination_host, ts DESC);

-- Authoritative panel API counters only. Never derived from log line counts.
CREATE TABLE traffic_samples (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id    uuid        NOT NULL,
    node_id     uuid,
    user_id     uuid,
    direction   text        NOT NULL CHECK (direction IN ('up','down')),
    bytes_total bigint      NOT NULL CHECK (bytes_total >= 0),
    observed_at timestamptz NOT NULL,
    source      text        NOT NULL,
    FOREIGN KEY (panel_id, node_id) REFERENCES nodes(panel_id, id) ON DELETE CASCADE,
    FOREIGN KEY (panel_id, user_id) REFERENCES users(panel_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX traffic_samples_unique ON traffic_samples
    (panel_id, COALESCE(node_id, '00000000-0000-0000-0000-000000000000'),
     COALESCE(user_id, '00000000-0000-0000-0000-000000000000'), direction, observed_at, source);
CREATE INDEX traffic_samples_panel_time ON traffic_samples (panel_id, observed_at DESC);

CREATE TABLE sync_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id    uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    operation   text        NOT NULL,
    status      text        NOT NULL CHECK (status IN ('running','ok','partial','failed')),
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    error_code  text
);
CREATE INDEX sync_runs_panel_started ON sync_runs (panel_id, started_at DESC);

-- No FK on panel_id: audit history must outlive a deleted panel. Never store secrets in metadata.
CREATE TABLE audit_log (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    uuid,
    panel_id    uuid,
    action      text        NOT NULL,
    object_type text        NOT NULL,
    object_id   text,
    ts          timestamptz NOT NULL DEFAULT now(),
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_ts ON audit_log (ts DESC);
CREATE INDEX audit_log_panel_ts ON audit_log (panel_id, ts DESC);

CREATE TABLE service_rules (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_version integer NOT NULL,
    pattern      text    NOT NULL,
    service      text    NOT NULL,
    confidence   text    NOT NULL CHECK (confidence IN ('high','medium','low')),
    enabled      boolean NOT NULL DEFAULT true
);
