-- RemnaScope 0023: external checks of a VPS's public TCP ports and TLS certificates.
--
-- The checker runs on the RemnaScope server (vantage "api_server"), which is not independent of the
-- servers it checks when the API lives on one of them. Every result carries that vantage, and the UI says so.
-- A target must be an address or domain registered on the VPS: there is no "check any host".

CREATE TABLE security_port_endpoints (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id          uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    host            text        NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    port            integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    expected        boolean     NOT NULL DEFAULT false,
    source          text        NOT NULL CHECK (source IN ('manual', 'local_listener')),
    enabled         boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_checked_at timestamptz,
    next_due_at     timestamptz,
    last_result     text CHECK (last_result IN ('reachable', 'refused', 'timeout', 'filtered_or_unknown', 'error')),
    last_error      text,
    last_ip         text,
    last_rtt_ms     integer,
    changed_at      timestamptz,
    UNIQUE (vps_id, host, port)
);
CREATE INDEX security_port_endpoints_due ON security_port_endpoints (next_due_at NULLS FIRST) WHERE enabled;

CREATE TABLE security_tls_endpoints (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id          uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    host            text        NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    port            integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    sni             text        NOT NULL DEFAULT '' CHECK (length(sni) <= 253),
    profile         text        NOT NULL DEFAULT 'tls' CHECK (profile IN ('tls')),
    enabled         boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_checked_at timestamptz,
    next_due_at     timestamptz,
    last_state      text,
    last_ip         text,
    last_fingerprint text,
    last_not_after  timestamptz,
    last_band       integer     NOT NULL DEFAULT 0,
    last_obs        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (vps_id, host, port, sni)
);
CREATE INDEX security_tls_endpoints_due ON security_tls_endpoints (next_due_at NULLS FIRST) WHERE enabled;

-- Written only when the certificate or the verdict changed, so renewals can be told apart from repeats.
CREATE TABLE security_tls_observations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id uuid        NOT NULL REFERENCES security_tls_endpoints(id) ON DELETE CASCADE,
    observed_at timestamptz NOT NULL,
    state       text        NOT NULL,
    fingerprint text,
    data        jsonb       NOT NULL
);
CREATE INDEX security_tls_observations_by_endpoint ON security_tls_observations (endpoint_id, observed_at DESC);
