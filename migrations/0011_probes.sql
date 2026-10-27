-- Owlery 0011: channel probes.
--
-- The server connects to a target from the outside (TCP, optionally a TLS handshake) every minute
-- and records how long it took and whether it worked. It sends no data and logs in nowhere: it
-- only measures the way in, which is what a client's first packets also have to cross.
CREATE TABLE probe_targets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id   uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    host       text        NOT NULL,
    port       integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    mode       text        NOT NULL CHECK (mode IN ('tcp', 'tls')),
    sni        text,
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (panel_id, name)
);

CREATE TABLE probe_results (
    target_id  uuid        NOT NULL REFERENCES probe_targets(id) ON DELETE CASCADE,
    ts         timestamptz NOT NULL,
    ok         boolean     NOT NULL,
    connect_ms integer,
    tls_ms     integer,
    error      text,
    PRIMARY KEY (target_id, ts)
);
