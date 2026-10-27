-- Owlery 0020: what the AmneziaWG hourly sums need to take part in the Sites and Domains views.
-- site    : the registrable domain of the name (when a name is known), as for every other source
-- country : the country of the destination address
-- flows   : how many connections began in the hour, as the sensor saw them (a connection that began earlier counts 0)
ALTER TABLE awg_flow_hourly ADD COLUMN IF NOT EXISTS site    text;
ALTER TABLE awg_flow_hourly ADD COLUMN IF NOT EXISTS country text;
ALTER TABLE awg_flow_hourly ADD COLUMN IF NOT EXISTS flows   integer NOT NULL DEFAULT 0;
