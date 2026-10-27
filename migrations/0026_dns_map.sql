-- Owlery 0026: DNS Map, the publicly observable DNS records of a domain and how they change.
--
-- A map holds what was observed for a domain and the names that were looked at; it is never the whole zone.
-- A record set keeps the last complete and settled observation of it (values, result) next to the last
-- observation of any kind (last_result), so a timeout or a server failure can never replace what was known.
-- History is the list of changes, each explained by two resolvers agreeing on the new state.

CREATE TABLE dns_maps (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain           text        NOT NULL CHECK (length(domain) BETWEEN 3 AND 253),
    display          text        NOT NULL,
    created_by       uuid,
    -- The owner confirmed the scope when creating the map: this domain, public resolvers, names it knows.
    scope_confirmed_at timestamptz NOT NULL,
    enabled          boolean     NOT NULL DEFAULT true,
    interval_hours   integer     NOT NULL DEFAULT 24 CHECK (interval_hours BETWEEN 1 AND 168),
    extra_names      text[]      NOT NULL DEFAULT '{}',
    use_ct           boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    archived_at      timestamptz,
    last_run_at      timestamptz,
    next_run_at      timestamptz,
    last_status      text CHECK (last_status IN ('ok', 'partial', 'failed')),
    baseline_done    boolean     NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX dns_maps_live_domain ON dns_maps (domain) WHERE archived_at IS NULL;
CREATE INDEX dns_maps_due ON dns_maps (next_run_at NULLS FIRST) WHERE enabled AND archived_at IS NULL;

CREATE TABLE dns_map_names (
    map_id     uuid        NOT NULL REFERENCES dns_maps(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    provenance text        NOT NULL CHECK (provenance IN ('apex', 'www', 'manual_name', 'existing_intel', 'cname_target')),
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (map_id, name)
);

CREATE TABLE dns_records (
    map_id            uuid        NOT NULL REFERENCES dns_maps(id) ON DELETE CASCADE,
    name              text        NOT NULL,
    type              text        NOT NULL,
    result            text,                       -- last settled state: answer | nodata | nxdomain; NULL until one exists
    values            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    ttl               integer     NOT NULL DEFAULT 0,
    confirmed         boolean     NOT NULL DEFAULT false, -- the last observation was agreed on by two resolvers
    last_result       text        NOT NULL,       -- the last observation of any kind, failures included
    views             jsonb       NOT NULL DEFAULT '[]'::jsonb,
    first_seen        timestamptz NOT NULL,
    last_seen         timestamptz,                -- last time the record was observed present
    last_checked      timestamptz NOT NULL,
    last_changed      timestamptz,
    no_longer_observed boolean    NOT NULL DEFAULT false,
    PRIMARY KEY (map_id, name, type)
);
CREATE INDEX dns_records_by_map ON dns_records (map_id, name, type);

CREATE TABLE dns_check_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    map_id      uuid        NOT NULL REFERENCES dns_maps(id) ON DELETE CASCADE,
    trigger     text        NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    started_at  timestamptz NOT NULL,
    finished_at timestamptz,
    status      text        NOT NULL CHECK (status IN ('running', 'ok', 'partial', 'failed')),
    coverage    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    auth        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    mismatch    text[]      NOT NULL DEFAULT '{}',
    error       text
);
CREATE INDEX dns_check_runs_by_map ON dns_check_runs (map_id, started_at DESC);

CREATE TABLE dns_changes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    map_id      uuid        NOT NULL REFERENCES dns_maps(id) ON DELETE CASCADE,
    run_id      uuid,
    name        text        NOT NULL,
    type        text        NOT NULL,
    kind        text        NOT NULL,
    before      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    after       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    observed_at timestamptz NOT NULL,
    volatile    boolean     NOT NULL DEFAULT false,  -- this record set has changed back and forth lately: CDN, round-robin or propagation
    dedupe_key  text        NOT NULL,
    UNIQUE (map_id, dedupe_key)
);
CREATE INDEX dns_changes_by_map ON dns_changes (map_id, observed_at DESC, id);
