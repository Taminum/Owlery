-- A maintenance window: while it lasts the machine's alerts are not reported (nothing is sent, nothing shows as open). When it
-- ends and a cause is still there, a new alert opens and is announced again. One window per machine.
CREATE TABLE maintenance_windows (
    vps_id     uuid        PRIMARY KEY REFERENCES security_vps(id) ON DELETE CASCADE,
    until      timestamptz NOT NULL,
    note       text        NOT NULL DEFAULT '' CHECK (length(note) <= 200),
    created_at timestamptz NOT NULL DEFAULT now()
);
