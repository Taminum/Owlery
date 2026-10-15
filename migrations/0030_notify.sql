-- RemnaScope 0030: notifications outside the page (Telegram).
--
-- A channel keeps its secret (the bot token and chat id) sealed with the master key like a panel's API token.
-- The page never gets it back: only a short hint of the chat id and the last result of sending.
CREATE TABLE notify_channels (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               text        NOT NULL CHECK (kind IN ('telegram')),
    name               text        NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    secret_ct          bytea       NOT NULL,
    secret_nonce       bytea       NOT NULL,
    secret_key_version integer     NOT NULL,
    chat_hint          text        NOT NULL DEFAULT '',
    enabled            boolean     NOT NULL DEFAULT true,
    on_alerts          boolean     NOT NULL DEFAULT true,
    digest_hour        integer     CHECK (digest_hour BETWEEN 0 AND 23),  -- NULL: no daily digest
    digest_tz          text        NOT NULL DEFAULT 'UTC' CHECK (length(digest_tz) <= 64),
    digest_sent_on     date,
    last_ok_at         timestamptz,
    last_error         text,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Which alerts have been announced. What was already there is history and is not announced.
ALTER TABLE alerts ADD COLUMN notified_open_at timestamptz, ADD COLUMN notified_close_at timestamptz;
UPDATE alerts SET notified_open_at = now(), notified_close_at = CASE WHEN resolved_at IS NOT NULL THEN now() END;
