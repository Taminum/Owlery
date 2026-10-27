-- Owlery 0003: agents and event ingestion bookkeeping.

ALTER TABLE agents
    ADD COLUMN name           text,
    ADD COLUMN epoch          text,
    ADD COLUMN agent_version  text,
    ADD COLUMN source_id      text,
    ADD COLUMN last_hello_at  timestamptz,
    ADD COLUMN last_batch_at  timestamptz,
    ADD COLUMN last_event_at  timestamptz,
    ADD COLUMN spool_bytes    bigint      NOT NULL DEFAULT 0,
    ADD COLUMN dropped_total  bigint      NOT NULL DEFAULT 0,
    ADD COLUMN parse_errors   bigint      NOT NULL DEFAULT 0,
    ADD COLUMN events_total   bigint      NOT NULL DEFAULT 0,
    ADD COLUMN created_at     timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN revoked_at     timestamptz;
-- One live agent per node; revoked ones stay for history.
CREATE UNIQUE INDEX agents_one_live_per_node ON agents (panel_id, node_id) WHERE status <> 'revoked';

ALTER TABLE connection_events
    ADD COLUMN parser_version integer NOT NULL DEFAULT 1,
    ADD COLUMN arrow          text,
    ADD COLUMN internal       boolean NOT NULL DEFAULT false;

-- Periods the agent says it could not deliver (restart of the source, full spool, ...).
CREATE TABLE agent_gaps (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id   uuid        NOT NULL,
    agent_id   uuid        NOT NULL,
    node_id    uuid        NOT NULL,
    reported_at timestamptz NOT NULL DEFAULT now(),
    from_ts    timestamptz,
    to_ts      timestamptz,
    lines      bigint,
    reason     text        NOT NULL,
    FOREIGN KEY (panel_id, agent_id) REFERENCES agents(panel_id, id) ON DELETE CASCADE
);
CREATE INDEX agent_gaps_panel_time ON agent_gaps (panel_id, reported_at DESC);
