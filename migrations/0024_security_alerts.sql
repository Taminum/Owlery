-- Owlery 0024: what the security alerts need to tell a surprise from a baseline.
--
-- unexpected_since is set when a public port that was not answering starts to answer (after the first
-- observation, which is a baseline) and cleared when it stops. A port the operator marks expected is
-- never an alert for answering.
ALTER TABLE security_port_endpoints ADD COLUMN unexpected_since timestamptz;
