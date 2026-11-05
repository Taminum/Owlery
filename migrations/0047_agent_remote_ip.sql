-- The address a security agent connected from, as the server saw it: the machine's own address, or the office's when the
-- machine sits behind a router. It is shown in the list of servers and updated at every connection.
ALTER TABLE security_agents ADD COLUMN remote_ip text NOT NULL DEFAULT '' CHECK (length(remote_ip) <= 45);
