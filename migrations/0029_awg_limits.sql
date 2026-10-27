-- Owlery 0029: an expiry date and a traffic limit for an AmneziaWG device.
--
-- Owlery enforces them by revoking the device on the host when its time or its allowance is over; a
-- revoked device cannot be switched back on (its keys are gone with it), so it has to be created again. The
-- traffic is counted from limit_from (the moment the limit was set) with the same reset-aware arithmetic the
-- rest of the AmneziaWG screens use.
ALTER TABLE awg_peers
    ADD COLUMN expires_at          timestamptz,
    ADD COLUMN traffic_limit_bytes bigint CHECK (traffic_limit_bytes IS NULL OR traffic_limit_bytes > 0),
    ADD COLUMN limit_from          timestamptz,
    ADD COLUMN auto_revoked_reason text CHECK (auto_revoked_reason IN ('expired', 'traffic_limit'));
