-- Wake-on-LAN: a machine somebody turned it on for. The network cards were named by the machine's own agent when it was turned on
-- (and are renewed whenever the agent is asked again); mac is the one to wake it by. A machine that is turned off here keeps no row,
-- so no hardware address is kept for it.
CREATE TABLE wol_targets (
    vps_id     uuid        PRIMARY KEY REFERENCES security_vps(id) ON DELETE CASCADE,
    mac        text        NOT NULL CHECK (mac ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'),
    nics       jsonb       NOT NULL DEFAULT '[]',
    updated_at timestamptz NOT NULL DEFAULT now()
);
