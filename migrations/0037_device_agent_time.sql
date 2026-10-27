-- The analytics queries ask for the first record of every router agent (to drop the nodes' copy of what the router saw).
-- Without this index that is a pass over all router records; with it, one lookup per agent.
CREATE INDEX IF NOT EXISTS device_connections_agent_time ON device_connections (agent_id, started_at);
