-- RemnaScope 0028: finding endpoints nobody listed.
--
--  * A TLS endpoint can come from the checker itself (source 'auto'): a registered domain on 443, or a known
--    listener on a well-known TLS port, where a TLS handshake presented a certificate. It is never a port
--    scan: only addresses the server already has and ports it is known to listen on are tried.
--  * A server can opt in to a bounded scan (security_vps.discovery_scan, off by default) of a fixed list of
--    common service ports on its registered IP addresses, at most once a day. What answers is added as a
--    port endpoint (source 'discovered', not expected), so it is announced as unexpected until marked.
ALTER TABLE security_vps
    ADD COLUMN discovery_scan    boolean NOT NULL DEFAULT false,
    ADD COLUMN discovery_scan_at timestamptz;

ALTER TABLE security_port_endpoints DROP CONSTRAINT security_port_endpoints_source_check;
ALTER TABLE security_port_endpoints ADD CONSTRAINT security_port_endpoints_source_check
    CHECK (source IN ('manual', 'local_listener', 'discovered'));
ALTER TABLE security_port_endpoints ADD COLUMN tls_probed_at timestamptz;

ALTER TABLE security_vps_addresses ADD COLUMN tls_probed_at timestamptz;

ALTER TABLE security_tls_endpoints
    ADD COLUMN source text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'auto'));
