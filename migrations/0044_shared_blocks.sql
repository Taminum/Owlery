-- Addresses blocked on one machine, passed on to the others that take part in the shared list. One row per address:
-- the machine that blocked it first, and when the block ends (NULL: it does not).
CREATE TABLE security_shared_blocks (
    ip         text PRIMARY KEY CHECK (length(ip) BETWEEN 2 AND 45),
    source_vps uuid NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    since      timestamptz NOT NULL,
    until      timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
