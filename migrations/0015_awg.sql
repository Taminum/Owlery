-- RemnaScope 0015: AmneziaWG, read-only inventory and counters (stage 1).
--
-- Nothing here holds a secret: no private keys, no preshared keys, no client endpoints. A peer is its
-- public key, a name, a tunnel address, and counters read from the running interface.

ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_kind_check;
ALTER TABLE agents ADD CONSTRAINT agents_kind_check CHECK (kind IN ('node', 'router', 'awg'));

CREATE TABLE awg_instances (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    uuid        NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    panel_id    uuid        NOT NULL REFERENCES panels (id) ON DELETE CASCADE,
    container   text        NOT NULL,
    interface   text        NOT NULL,
    listen_port integer,
    variant     text        NOT NULL DEFAULT '',        -- derived from the names of the parameters in the config
    mode        text        NOT NULL DEFAULT 'read_only' CHECK (mode IN ('discovered', 'read_only', 'managed', 'offline')),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_report timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, container, interface)
);

CREATE TABLE awg_peers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id   uuid        NOT NULL REFERENCES awg_instances (id) ON DELETE CASCADE,
    public_key    text        NOT NULL,
    label         text        NOT NULL DEFAULT '',
    tunnel_ip     text        NOT NULL DEFAULT '',
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),  -- last snapshot that listed the peer
    gone_at       timestamptz,                         -- set when a snapshot no longer lists it
    UNIQUE (instance_id, public_key)
);

-- Absolute counters as read from the interface (rx = received from the peer, tx = sent to it).
-- A counter that goes down means the interface restarted: the delta logic treats it as a reset.
CREATE TABLE awg_samples (
    peer_id   uuid        NOT NULL REFERENCES awg_peers (id) ON DELETE CASCADE,
    ts        timestamptz NOT NULL,
    rx_bytes  bigint      NOT NULL,
    tx_bytes  bigint      NOT NULL,
    handshake timestamptz,                             -- NULL = never
    PRIMARY KEY (peer_id, ts)
);
CREATE INDEX awg_samples_ts ON awg_samples (ts);
