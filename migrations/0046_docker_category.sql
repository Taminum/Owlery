-- The "docker" category: the containers of a Linux machine.
ALTER TABLE security_snapshot_state DROP CONSTRAINT security_snapshot_state_category_check;
ALTER TABLE security_snapshot_state ADD CONSTRAINT security_snapshot_state_category_check
    CHECK (category IN ('fail2ban', 'sockets', 'firewall', 'winsec', 'hardware', 'docker'));
