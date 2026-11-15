-- Things the owner asks a router to do (MikroTik, OpenWrt): the router cannot be reached from outside, so it asks for them
-- itself once a minute, with the same token it reports with, and is handed one at a time. The kinds are fixed in the code.
CREATE TABLE net_commands (
    id         bigserial   PRIMARY KEY,
    device_id  uuid        NOT NULL REFERENCES net_devices (id) ON DELETE CASCADE,
    kind       text        NOT NULL,
    a1         text        NOT NULL DEFAULT '',
    a2         text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz,
    tries      int         NOT NULL DEFAULT 0,
    done_at    timestamptz,
    ok         boolean,
    note       text        NOT NULL DEFAULT ''
);
CREATE INDEX net_commands_device ON net_commands (device_id, id);
