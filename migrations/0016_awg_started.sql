-- RemnaScope 0016: AmneziaWG, when the container started and what the Amnezia panel had recorded.
--
-- The server's own counters run from about the container start and restart from zero with it, so the
-- page says from when they run. The Amnezia management panel kept its own totals and last handshakes
-- in a table of its own; they are imported once as a labelled snapshot (legacy_*), never mixed into
-- RemnaScope's counters.
ALTER TABLE awg_instances ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE awg_instances ADD COLUMN IF NOT EXISTS legacy_at timestamptz;
ALTER TABLE awg_peers ADD COLUMN IF NOT EXISTS legacy_down bigint;
ALTER TABLE awg_peers ADD COLUMN IF NOT EXISTS legacy_up bigint;
ALTER TABLE awg_peers ADD COLUMN IF NOT EXISTS legacy_hs timestamptz;
