-- What a flood of packets or connections shows: packet counters, connection counts and the kernel's own signs of an
-- overflowing queue, kept with every minute sample.
ALTER TABLE host_samples
    ADD COLUMN rx_pkts      bigint  NOT NULL DEFAULT 0,
    ADD COLUMN tx_pkts      bigint  NOT NULL DEFAULT 0,
    ADD COLUMN estab        integer NOT NULL DEFAULT 0,
    ADD COLUMN syn_recv     integer NOT NULL DEFAULT 0,
    ADD COLUMN cookies      bigint  NOT NULL DEFAULT 0,
    ADD COLUMN listen_drops bigint  NOT NULL DEFAULT 0;
