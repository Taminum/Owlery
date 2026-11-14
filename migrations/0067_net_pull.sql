-- Routers that Owlery asks itself (Keenetic, through its KeenDNS name) instead of waiting for a script to post: where to ask, the
-- login, and the password sealed with the same keys as the panel tokens. A device that posts has none of these.
ALTER TABLE net_devices
    ADD COLUMN pull_url         text,
    ADD COLUMN pull_login       text,
    ADD COLUMN pull_secret      bytea,
    ADD COLUMN pull_nonce       bytea,
    ADD COLUMN pull_key_version integer,
    ADD COLUMN pull_error       text,
    ADD COLUMN pull_error_at    timestamptz;
