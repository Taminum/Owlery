-- What the "Здоровье панели" page needs that the server cannot work out by itself at the moment it is asked:
-- the nightly dump says how it went (backup.sh writes a row after it), and the size of the database is sampled
-- once a day so its growth can be drawn.
CREATE TABLE panel_backups (
    id       bigserial PRIMARY KEY,
    taken_at timestamptz NOT NULL DEFAULT now(),
    bytes    bigint      NOT NULL,
    ok       boolean     NOT NULL
);
CREATE INDEX panel_backups_time ON panel_backups (taken_at DESC);

CREATE TABLE panel_db_samples (
    day      date   PRIMARY KEY,
    db_bytes bigint NOT NULL
);
