-- What the panel's torrent blocker reported, and how many devices (HWID) each subscription has. Both are read-only
-- data and both stay empty while the panel has the plugin or the HWID limit switched off.
CREATE TABLE torrent_reports (
    panel_id    uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    remote_id   bigint      NOT NULL,
    remote_user text        NOT NULL, -- the panel's user id, as users.remote_uuid holds it
    node        text        NOT NULL DEFAULT '',
    reported_at timestamptz NOT NULL,
    PRIMARY KEY (panel_id, remote_id)
);
CREATE INDEX torrent_reports_at ON torrent_reports (reported_at);
CREATE INDEX torrent_reports_user ON torrent_reports (panel_id, remote_user, reported_at DESC);

-- The last look at the devices of a panel: replaced as a whole on every pass.
CREATE TABLE subscription_devices (
    panel_id    uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    remote_user text        NOT NULL,
    devices     integer     NOT NULL,
    seen_at     timestamptz NOT NULL,
    PRIMARY KEY (panel_id, remote_user)
);
