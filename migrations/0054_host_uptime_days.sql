-- How many minutes of each day a machine's agent reported. The minute samples are kept for a week; this is the
-- little that is kept for a month and more, so that the card can show "answered 99.8% of the last 30 days".
CREATE TABLE host_uptime_days (
    vps_id  uuid NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    day     date NOT NULL,
    minutes int  NOT NULL CHECK (minutes >= 0 AND minutes <= 1440),
    PRIMARY KEY (vps_id, day)
);
