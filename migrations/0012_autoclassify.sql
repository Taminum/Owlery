-- Owlery 0012: automatic classification of unknown sites (stage A: settings and dry runs).
--
-- A dry run sends a sample of unknown registrable domains (names only) to the model and keeps the
-- answers HERE, apart from the real rules, so the quality can be judged before anything is applied.

CREATE TABLE autoclassify_settings (
    id          boolean PRIMARY KEY DEFAULT true CHECK (id),  -- exactly one row
    enabled     boolean     NOT NULL DEFAULT false,
    model       text        NOT NULL DEFAULT '',
    batch_size  integer     NOT NULL DEFAULT 15 CHECK (batch_size BETWEEN 5 AND 30),
    daily_limit integer     NOT NULL DEFAULT 300 CHECK (daily_limit BETWEEN 0 AND 20000),  -- domains per day
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid
);
INSERT INTO autoclassify_settings (id) VALUES (true);

CREATE TABLE classify_dryrun_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    model       text        NOT NULL,
    state       text        NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'done', 'failed')),
    requested   integer     NOT NULL DEFAULT 0,
    requests    integer     NOT NULL DEFAULT 0,
    tokens_in   integer     NOT NULL DEFAULT 0,
    tokens_out  integer     NOT NULL DEFAULT 0,
    error_code  text,
    started_by  uuid
);

CREATE TABLE classify_dryrun_items (
    run_id       uuid    NOT NULL REFERENCES classify_dryrun_runs(id) ON DELETE CASCADE,
    site         text    NOT NULL,
    connections  integer NOT NULL DEFAULT 0,
    picked_by    text    NOT NULL DEFAULT 'top',   -- top | random
    valid        boolean NOT NULL,
    undetermined boolean NOT NULL DEFAULT false,
    category     text,
    service      text,
    confidence   real,
    reason       text,
    issue        text,
    PRIMARY KEY (run_id, site)
);
