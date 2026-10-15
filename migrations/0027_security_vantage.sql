-- Where a port check was made from, kept with its result: the RemnaScope server, or a security agent that
-- its host set up as a checker. "Independent" is true only when the checker is not the checked server.
ALTER TABLE security_port_endpoints
    ADD COLUMN last_vantage      text,
    ADD COLUMN last_vantage_name text,
    ADD COLUMN last_independent  boolean;
