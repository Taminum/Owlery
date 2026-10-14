-- RemnaScope 0002: accounts, RBAC, sessions, panel connection state, sync bookkeeping.

CREATE TABLE accounts (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username            text        NOT NULL CHECK (length(username) BETWEEN 3 AND 64),
    password_hash       text        NOT NULL,
    is_owner            boolean     NOT NULL DEFAULT false,
    disabled            boolean     NOT NULL DEFAULT false,
    failed_logins       integer     NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX accounts_username_lower ON accounts (lower(username));

-- Per-panel role. Owners (accounts.is_owner) see every panel and need no row here.
CREATE TABLE memberships (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    panel_id   uuid NOT NULL REFERENCES panels(id)   ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin','operator','viewer')),
    PRIMARY KEY (account_id, panel_id)
);
CREATE INDEX memberships_panel ON memberships (panel_id);

-- Only the SHA-256 of the session token is stored; the token itself lives in an HttpOnly cookie.
CREATE TABLE sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea       NOT NULL UNIQUE,
    account_id   uuid        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    ip           inet,
    user_agent   text
);
CREATE INDEX sessions_account ON sessions (account_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

ALTER TABLE panels
    ADD COLUMN demo                 boolean     NOT NULL DEFAULT false,
    ADD COLUMN deleted_at           timestamptz,
    ADD COLUMN use_custom_ca        boolean     NOT NULL DEFAULT false,
    ADD COLUMN sync_options         jsonb       NOT NULL DEFAULT '{"nodes":true,"users":true,"stats":false}'::jsonb,
    ADD COLUMN api_version          text,
    ADD COLUMN last_probe_at        timestamptz,
    ADD COLUMN last_probe           jsonb,
    ADD COLUMN next_sync_at         timestamptz,
    ADD COLUMN last_sync_at         timestamptz,
    ADD COLUMN last_sync_status     text,
    ADD COLUMN consecutive_failures integer     NOT NULL DEFAULT 0,
    ADD COLUMN circuit_open_until   timestamptz;
CREATE UNIQUE INDEX panels_name_active ON panels (lower(name)) WHERE deleted_at IS NULL;

ALTER TABLE nodes
    ADD COLUMN is_connected       boolean,
    ADD COLUMN is_disabled        boolean,
    ADD COLUMN country_code       text,
    ADD COLUMN users_online       integer,
    ADD COLUMN xray_version       text,
    ADD COLUMN last_status_change timestamptz,
    ADD COLUMN first_seen_at      timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN removed_at         timestamptz;

ALTER TABLE users
    ADD COLUMN status        text,
    ADD COLUMN first_seen_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN removed_at    timestamptz;

ALTER TABLE sync_runs
    ADD COLUMN trigger text  NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule','manual')),
    ADD COLUMN stats   jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN detail  text;

ALTER TABLE audit_log
    ADD COLUMN actor_name text,
    ADD COLUMN ip         inet,
    ADD COLUMN request_id text;
