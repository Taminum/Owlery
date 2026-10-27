-- Owlery 0009: alerts, and custom classification rules.

-- An alert is open while its condition holds and is closed by the evaluator when it stops holding.
-- There is at most one open alert per (kind, subject).
CREATE TABLE alerts (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    panel_id     uuid REFERENCES panels(id) ON DELETE CASCADE,
    kind         text        NOT NULL,
    subject      text        NOT NULL,
    label        text        NOT NULL,
    detail       text        NOT NULL DEFAULT '',
    opened_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz
);
CREATE UNIQUE INDEX alerts_one_open ON alerts (kind, subject) WHERE resolved_at IS NULL;
CREATE INDEX alerts_panel_time ON alerts (panel_id, opened_at DESC);

-- Rules added by a person live next to the built-in ones. They get a higher rule_version, which
-- wins a tie on pattern length, so a custom rule overrides a built-in one and deleting it restores it.
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'builtin' CHECK (source IN ('builtin', 'custom'));
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS created_at timestamptz;
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS created_by uuid;
