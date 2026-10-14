-- RemnaScope 0008: two-factor sign-in (TOTP) with one-time recovery codes.
--
-- The TOTP secret is stored encrypted with the same keyring as panel tokens (AES-256-GCM, the
-- account id bound in as associated data). totp_enabled_at stays NULL while a secret is only
-- pending (set up but not yet confirmed with a code).
ALTER TABLE accounts
    ADD COLUMN totp_ciphertext  bytea,
    ADD COLUMN totp_nonce       bytea,
    ADD COLUMN totp_key_version integer,
    ADD COLUMN totp_enabled_at  timestamptz,
    ADD COLUMN totp_last_step   bigint NOT NULL DEFAULT 0;

-- Recovery codes are random and long, so a plain SHA-256 is enough; each works once.
CREATE TABLE recovery_codes (
    account_id uuid        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash  bytea       NOT NULL,
    used_at    timestamptz,
    PRIMARY KEY (account_id, code_hash)
);

-- Between a correct password and a correct code. The token is opaque and stored hashed.
CREATE TABLE mfa_challenges (
    token_hash bytea PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    attempts   integer     NOT NULL DEFAULT 0
);
CREATE INDEX mfa_challenges_expiry ON mfa_challenges (expires_at);
