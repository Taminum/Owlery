-- How each machine's address blocker is set up. A machine with no row works by the defaults (watch, 5 failures in 10 minutes,
-- blocks last a day, nothing whitelisted); a row appears when somebody changes a setting.
CREATE TABLE security_block_settings (
    vps_id       uuid PRIMARY KEY REFERENCES security_vps(id) ON DELETE CASCADE,
    mode         text NOT NULL DEFAULT 'watch' CHECK (mode IN ('off', 'watch', 'block')),
    threshold    integer NOT NULL DEFAULT 5 CHECK (threshold BETWEEN 2 AND 1000),
    window_min   integer NOT NULL DEFAULT 10 CHECK (window_min BETWEEN 1 AND 1440),
    ttl_hours    integer NOT NULL DEFAULT 24 CHECK (ttl_hours BETWEEN 0 AND 8760),
    whitelist    text[] NOT NULL DEFAULT '{}',
    share        boolean NOT NULL DEFAULT true,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
