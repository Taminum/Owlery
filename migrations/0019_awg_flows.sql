-- Owlery 0019: where the devices of an AmneziaWG server connect to, summed per hour.
--
-- The sensor on the host sees packet headers and reports, per minute, one line per flow: the device's address in
-- the tunnel, the destination address and port, bytes each way, and a name when the packets said one in the
-- open (TLS server name, HTTP Host, DNS answer). Only those sums are stored here: no packets, no payloads, no
-- paths. They are a separate source: they are not added to what the nodes and the router report.
CREATE TABLE awg_flow_hourly (
    instance_id uuid        NOT NULL REFERENCES awg_instances (id) ON DELETE CASCADE,
    peer_id     uuid        REFERENCES awg_peers (id) ON DELETE CASCADE,   -- NULL when the address matches no known device
    client_ip   inet        NOT NULL,
    hour        timestamptz NOT NULL,
    proto       smallint    NOT NULL,
    remote_ip   inet        NOT NULL,
    remote_port integer     NOT NULL,
    name        text        NOT NULL DEFAULT '',
    name_src    text        NOT NULL DEFAULT '' CHECK (name_src IN ('', 'sni', 'host', 'dns')),
    up_bytes    bigint      NOT NULL DEFAULT 0,
    down_bytes  bigint      NOT NULL DEFAULT 0,
    last_seen   timestamptz NOT NULL,
    PRIMARY KEY (instance_id, client_ip, hour, proto, remote_ip, remote_port, name)
);
CREATE INDEX awg_flow_hourly_hour ON awg_flow_hourly (hour);
CREATE INDEX awg_flow_hourly_peer ON awg_flow_hourly (peer_id, hour);
