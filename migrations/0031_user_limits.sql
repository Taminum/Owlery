-- What the panel says about each user's allowance: when the subscription ends, the traffic limit
-- (NULL or 0 = no limit) and what has been used in the current period. Read-only copies, refreshed
-- by every users sync; they feed the "ends soon" and "close to the limit" alerts.
ALTER TABLE users
    ADD COLUMN expire_at           timestamptz,
    ADD COLUMN traffic_limit_bytes bigint,
    ADD COLUMN traffic_used_bytes  bigint;
