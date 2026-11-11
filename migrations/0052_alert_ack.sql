-- A person can accept an alert from Telegram: it stays open (the cause is still there) but stops being repeated
-- and shows as accepted in the list. A new alert of the same thing starts again unaccepted.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acked_at timestamptz;
