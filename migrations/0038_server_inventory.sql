-- A server is the centre of the fleet view: what it is, where it lives and what it is for. Everything here is
-- entered by a person; what the agent measures stays in host_info.
--   roles         entry, exit, panel, service, workstation, home, hypervisor, router (any number of them)
--   os            what the owner calls the system, for servers without an agent too ("Windows Server 2022")
--   provider      the hosting company, the shop or "дома"
--   country, city where the machine is
--   grp           one group per server, for the fleet page ("Офис", "VPN")
--   tags          free labels
--   purchased_on  when it was bought or rented first
ALTER TABLE security_vps
    ADD COLUMN roles        text[] NOT NULL DEFAULT '{}'
        CHECK (roles <@ ARRAY['entry','exit','panel','service','workstation','home','hypervisor','router']::text[]),
    ADD COLUMN os           text   NOT NULL DEFAULT '' CHECK (length(os) <= 80),
    ADD COLUMN provider     text   NOT NULL DEFAULT '' CHECK (length(provider) <= 80),
    ADD COLUMN country      text   NOT NULL DEFAULT '' CHECK (length(country) <= 60),
    ADD COLUMN city         text   NOT NULL DEFAULT '' CHECK (length(city) <= 60),
    ADD COLUMN grp          text   NOT NULL DEFAULT '' CHECK (length(grp) <= 60),
    ADD COLUMN tags         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    ADD COLUMN purchased_on date;
