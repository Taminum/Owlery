-- Thresholds and on/off switches for one machine's resource alerts, and alerts put off for a while.
-- A machine with no row follows the defaults. A rule is 'disk:<mount>', 'forecast' (days), 'cpu' or 'mem' (percent).
CREATE TABLE alert_rules (
    vps_id    uuid    NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    rule      text    NOT NULL CHECK (rule ~ '^(disk:.{1,64}|forecast|cpu|mem)$'),
    enabled   boolean NOT NULL DEFAULT true,
    threshold integer CHECK (threshold BETWEEN 1 AND 100000),   -- NULL: the default
    PRIMARY KEY (vps_id, rule)
);

-- An alert put off: while it lasts the condition is not reported, so nothing is sent and nothing shows as open. When it
-- ends and the cause is still there, a new alert opens and is announced again.
CREATE TABLE alert_snoozes (
    kind       text        NOT NULL,
    subject    text        NOT NULL,
    until      timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, subject)
);
