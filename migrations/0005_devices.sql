-- RemnaScope 0005: devices behind a router.
--
-- A router agent reads the sing-box Clash API on the router and reports connections per LAN
-- device, with the domain sing-box sniffed and the bytes it counted. Those records describe the
-- same traffic the exit nodes see under one shared user, so they live in their own table and are
-- never added to connection_events counts (no double counting).

ALTER TABLE agents ADD COLUMN kind text NOT NULL DEFAULT 'node' CHECK (kind IN ('node', 'router'));

-- A node still has at most one live node agent; router agents are attached to a node of the
-- panel only to stay inside the panel's scope, and do not compete for that slot.
DROP INDEX agents_one_live_per_node;
CREATE UNIQUE INDEX agents_one_live_per_node ON agents (panel_id, node_id) WHERE status <> 'revoked' AND kind = 'node';

CREATE TABLE device_connections (
    panel_id         uuid        NOT NULL,
    agent_id         uuid        NOT NULL,
    conn_key         text        NOT NULL,            -- id sing-box gave the connection
    started_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    device_ip        inet        NOT NULL,
    device_name      text,
    destination_host text,
    destination_ip   inet,
    destination_port integer,
    protocol         text        NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    up_bytes         bigint      NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes       bigint      NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    outbound         text,
    PRIMARY KEY (agent_id, conn_key, started_at),
    FOREIGN KEY (panel_id, agent_id) REFERENCES agents (panel_id, id) ON DELETE CASCADE,
    CHECK (destination_host IS NOT NULL OR destination_ip IS NOT NULL),
    CHECK (destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535))
);
CREATE INDEX device_connections_panel_time ON device_connections (panel_id, started_at DESC);
CREATE INDEX device_connections_device ON device_connections (panel_id, device_ip, started_at DESC);
