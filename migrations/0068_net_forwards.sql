-- Ports a router opens to the outside (destination-NAT rules: forwards and UPnP), so that a new one can be told from the ones
-- the owner already knows. The rules a router lists when this lands are taken as known; later ones wait for the owner.
CREATE TABLE net_forwards (
    device_id  uuid        NOT NULL REFERENCES net_devices (id) ON DELETE CASCADE,
    key        text        NOT NULL,
    rule       jsonb       NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    confirmed  boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, key)
);
ALTER TABLE net_devices ADD COLUMN fw_baseline_at timestamptz;

INSERT INTO net_forwards (device_id, key, rule, confirmed)
SELECT d.id, concat_ws('|', r->>'chain', r->>'action', coalesce(r->>'dst_port',''), coalesce(r->>'to_addr',''), coalesce(r->>'to_ports','')), r, true
FROM net_devices d, jsonb_array_elements(coalesce(d.last->'nat', '[]'::jsonb)) r
WHERE r->>'chain' = 'dstnat'
ON CONFLICT DO NOTHING;
UPDATE net_devices SET fw_baseline_at = coalesce(last_seen, now()) WHERE last_seen IS NOT NULL;
