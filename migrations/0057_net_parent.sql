-- Which router a router stands behind (a second router on the first one's network); NULL for the one at the edge.
ALTER TABLE net_devices ADD COLUMN parent_id uuid REFERENCES net_devices(id) ON DELETE SET NULL;
