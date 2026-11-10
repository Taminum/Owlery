-- The (panel, node, time) index on connection_events was never used once since the database was created: every
-- query that narrows to nodes goes through (panel, time) and filters. It is the largest index of the table (780 MB
-- at 7 million rows) and is written on every event, on a server whose memory holds a fifth of the data.
DROP INDEX IF EXISTS connection_events_node_ts;
