-- RemnaScope 0006: which panel user a router agent stands for.
--
-- Everything behind a router reaches the exit nodes as one panel user (for example id 4). The
-- router agent sees the same connections with the domain and the device. When it is set, the
-- destination views use the router's records for that user instead of the nodes' (bare-IP)
-- lines, so the same traffic is never counted twice.
ALTER TABLE agents ADD COLUMN covers_user text;
