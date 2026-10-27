-- Owlery 0017: when a device was created, as the old management table recorded it. Used as the
-- start of its running total.
ALTER TABLE awg_peers ADD COLUMN IF NOT EXISTS created_hint timestamptz;
