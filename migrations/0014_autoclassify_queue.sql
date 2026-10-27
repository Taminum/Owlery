-- Owlery 0014: automatic classification, stage B (queue, worker, auto rules, budget).
--
-- An automatic result is an ordinary row of service_rules with source 'auto' and rule_version 0, the
-- lowest version there is: a built-in rule (1) or a custom rule (1000) for the same pattern always wins
-- the tie in ruleMatch, and the rows of the raw events are never touched. Deleting an auto rule just
-- brings the domain back to "not classified".

ALTER TABLE service_rules DROP CONSTRAINT IF EXISTS service_rules_source_check;
ALTER TABLE service_rules ADD CONSTRAINT service_rules_source_check CHECK (source IN ('builtin', 'custom', 'auto'));
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS score         real;         -- model confidence 0..1, auto rules only
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS model         text;
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS reason        text;
ALTER TABLE service_rules ADD COLUMN IF NOT EXISTS classified_at timestamptz;
CREATE INDEX IF NOT EXISTS service_rules_auto_age ON service_rules (classified_at) WHERE source = 'auto';

ALTER TABLE autoclassify_settings ADD COLUMN IF NOT EXISTS last_success_at   timestamptz;
ALTER TABLE autoclassify_settings ADD COLUMN IF NOT EXISTS last_error_code   text;
ALTER TABLE autoclassify_settings ADD COLUMN IF NOT EXISTS last_error_at     timestamptz;
ALTER TABLE autoclassify_settings ADD COLUMN IF NOT EXISTS backfill_state    text NOT NULL DEFAULT 'idle' CHECK (backfill_state IN ('idle', 'running', 'done'));
ALTER TABLE autoclassify_settings ADD COLUMN IF NOT EXISTS backfill_started_at timestamptz;

-- One job per canonical domain. Rules are global in Owlery, so the queue is too.
CREATE TABLE classify_jobs (
    domain          text PRIMARY KEY,
    state           text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'retry', 'done', 'undetermined', 'failed', 'skipped')),
    origin          text        NOT NULL DEFAULT 'live' CHECK (origin IN ('live', 'backfill', 'review')),
    priority        integer     NOT NULL DEFAULT 0,      -- connections seen when it was queued: busiest first
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_at       timestamptz,
    last_error_code text,
    enqueued_at     timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz
);
CREATE INDEX classify_jobs_ready ON classify_jobs (priority DESC, enqueued_at) WHERE state IN ('pending', 'retry');
CREATE INDEX classify_jobs_state ON classify_jobs (state, next_attempt_at);

-- What was spent per day, for the daily budget.
CREATE TABLE classify_budget (
    day       date PRIMARY KEY,
    domains   integer NOT NULL DEFAULT 0,
    requests  integer NOT NULL DEFAULT 0,
    tokens_in integer NOT NULL DEFAULT 0,
    tokens_out integer NOT NULL DEFAULT 0
);
