-- The agent now also reports what the machine is made of.
ALTER TABLE security_snapshot_state DROP CONSTRAINT security_snapshot_state_category_check;
ALTER TABLE security_snapshot_state ADD CONSTRAINT security_snapshot_state_category_check
    CHECK (category IN ('fail2ban', 'sockets', 'firewall', 'winsec', 'hardware'));
