-- Owlery 0022: security agents, snapshots and the security journal.
--
-- A security agent belongs to one VPS and has its own credential, separate from the Xray/router/AWG
-- agents. It only reports; nothing is sent to it. Snapshots are state, so a missed one costs a gap in
-- freshness, not lost data: the next one carries the whole picture.

CREATE TABLE security_agents (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id        uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    token_hash    bytea       NOT NULL,
    status        text        NOT NULL DEFAULT 'enrolling' CHECK (status IN ('enrolling', 'active', 'revoked')),
    epoch         text,
    agent_version text,
    hostname      text,
    capabilities  text[]      NOT NULL DEFAULT '{}',
    last_ack_seq  bigint      NOT NULL DEFAULT 0,
    last_seen     timestamptz,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);
-- One live agent per VPS; revoked ones stay as history.
CREATE UNIQUE INDEX security_agents_one_live ON security_agents (vps_id) WHERE status <> 'revoked';

-- The latest word on each category, with its freshness.
CREATE TABLE security_snapshot_state (
    vps_id        uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    category      text        NOT NULL CHECK (category IN ('fail2ban', 'sockets', 'firewall')),
    status        text        NOT NULL,
    source_hash   text        NOT NULL,
    observed_at   timestamptz NOT NULL,
    received_at   timestamptz NOT NULL,
    clock_skew_ms bigint      NOT NULL DEFAULT 0,
    agent_id      uuid,
    data          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (vps_id, category)
);

-- History is written only when something changed, so it stays small.
CREATE TABLE security_snapshots (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id      uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    category    text        NOT NULL,
    status      text        NOT NULL,
    source_hash text        NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    data        jsonb       NOT NULL
);
CREATE INDEX security_snapshots_by_vps ON security_snapshots (vps_id, category, observed_at DESC);

CREATE TABLE security_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id      uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    category    text        NOT NULL,
    type        text        NOT NULL,
    severity    text        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    source      text        NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    dedupe_key  text        NOT NULL,
    agent_id    uuid,
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (vps_id, dedupe_key)
);
CREATE INDEX security_events_by_vps ON security_events (vps_id, observed_at DESC, id);
CREATE INDEX security_events_by_category ON security_events (category, observed_at);
