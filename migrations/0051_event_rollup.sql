-- Half-hour sums of connection events, so the overview reads a few thousand rows for a day instead of every event of
-- it, seven times. kind: 1 protocol, 2 host, 3 address, 4 port, 5 user ('s' the node itself, 'u:<user id>', 'r:<id as
-- logged>'). The sums are a copy: any half-hour can be recounted from the events (see internal/store/rollup.go).
CREATE TABLE event_rollup (
    panel_id uuid        NOT NULL,
    node_id  uuid        NOT NULL,
    bucket   timestamptz NOT NULL,
    kind     smallint    NOT NULL CHECK (kind BETWEEN 1 AND 5),
    key      text        NOT NULL,
    n        bigint      NOT NULL CHECK (n > 0),
    PRIMARY KEY (panel_id, bucket, kind, node_id, key),
    FOREIGN KEY (panel_id, node_id) REFERENCES nodes (panel_id, id) ON DELETE CASCADE
);
CREATE INDEX event_rollup_bucket ON event_rollup (bucket);

-- How far the sums reach: every half-hour from filled_from up to (not including) fresh_to is counted.
CREATE TABLE event_rollup_state (
    one         boolean     PRIMARY KEY DEFAULT true CHECK (one),
    filled_from timestamptz NOT NULL,
    fresh_to    timestamptz NOT NULL
);

-- Half-hours that received events after they were counted (an agent sending what it had kept while it was cut off).
CREATE TABLE event_rollup_dirty (
    bucket timestamptz PRIMARY KEY
);
