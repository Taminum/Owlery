-- How loaded the monitored servers are. Reported by the security agent with every full tick.
-- host_info keeps what the machine is and the latest reading; host_samples keeps one reading a minute for a week.
CREATE TABLE host_info (
    vps_id     uuid PRIMARY KEY REFERENCES security_vps(id) ON DELETE CASCADE,
    updated_at timestamptz NOT NULL,
    os         text   NOT NULL DEFAULT '',
    kernel     text   NOT NULL DEFAULT '',
    arch       text   NOT NULL DEFAULT '',
    cpu_model  text   NOT NULL DEFAULT '',
    cpus       integer NOT NULL DEFAULT 0,
    mem_total  bigint NOT NULL DEFAULT 0,
    swap_total bigint NOT NULL DEFAULT 0,
    last       jsonb  NOT NULL DEFAULT '{}'::jsonb -- the latest reading as the agent sent it
);

CREATE TABLE host_samples (
    vps_id     uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL,
    cpu        real,        -- percent; NULL when the agent had nothing to compare yet
    load1      real        NOT NULL,
    mem_used   bigint      NOT NULL,
    mem_total  bigint      NOT NULL,
    disk_used  bigint      NOT NULL DEFAULT 0,  -- the root file system, or the first one
    disk_total bigint      NOT NULL DEFAULT 0,
    net_rx     bigint      NOT NULL DEFAULT 0,
    net_tx     bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (vps_id, at)
);
