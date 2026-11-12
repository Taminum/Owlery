-- Every device a router has ever listed as a client, kept by MAC address: what it was called, where it was last seen and when,
-- and whether the owner has looked at it ("confirmed"). A device that is new and unconfirmed raises an alert.
CREATE TABLE lan_devices (
    mac        text PRIMARY KEY,
    ip         text        NOT NULL,
    host       text        NOT NULL DEFAULT '',
    name       text        NOT NULL DEFAULT '',
    source_id  uuid,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    confirmed  boolean     NOT NULL DEFAULT false
);

-- What the routers list today is the baseline: it is known, so only devices that appear after this are "new".
INSERT INTO lan_devices (mac, ip, host, source_id, confirmed)
SELECT upper(c->>'mac'), c->>'ip', coalesce(c->>'host', ''), n.id, true
FROM net_devices n, jsonb_array_elements(coalesce(n.last->'clients', '[]'::jsonb)) c
WHERE n.archived_at IS NULL AND c->>'mac' IS NOT NULL AND c->>'ip' IS NOT NULL
ON CONFLICT (mac) DO NOTHING;
