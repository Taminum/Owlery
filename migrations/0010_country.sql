-- Owlery 0010: country of the destination address.
--
-- Set by the application from the destination IP with the embedded DB-IP table. NULL means the
-- connection has no IP in the log (a domain-only line) or the address is private/unknown. "ZZ"
-- marks an address the table does not know, so a backfill does not look at it again.
ALTER TABLE connection_events ADD COLUMN IF NOT EXISTS country char(2);
ALTER TABLE device_connections ADD COLUMN IF NOT EXISTS country char(2);
