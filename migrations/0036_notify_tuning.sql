-- Fine tuning of the Telegram channel and the bot's commands.
--   prefs        which alert groups are off, whether closings are announced, quiet hours, reminders (JSON)
--   commands     the bot answers commands written in the channel's own chat
--   muted_until  everything but critical alerts is held until then (the /mute command)
--   bot_offset   the last update of the bot that was handled
ALTER TABLE notify_channels
    ADD COLUMN prefs       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN commands    boolean     NOT NULL DEFAULT true,
    ADD COLUMN muted_until timestamptz,
    ADD COLUMN bot_offset  bigint      NOT NULL DEFAULT 0;
-- When an open alert was last repeated as a reminder.
ALTER TABLE alerts ADD COLUMN reminded_at timestamptz;
