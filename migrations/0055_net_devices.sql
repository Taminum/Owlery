-- Network devices that have no agent of ours (MikroTik routers): a script on the device posts what it knows once a minute with a
-- token of its own. Only the latest reading is kept, with the byte counters of the one before it so that speeds can be worked out.
CREATE TABLE net_devices (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    kind        text        NOT NULL DEFAULT 'mikrotik',
    token_hash  bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    last_seen   timestamptz,
    last        jsonb       NOT NULL DEFAULT '{}',
    counters    jsonb       NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX net_devices_name ON net_devices (lower(name)) WHERE archived_at IS NULL;
