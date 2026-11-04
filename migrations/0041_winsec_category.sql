-- The Windows agent now reports a fourth kind of snapshot: sign-ins from other machines and Defender.
ALTER TABLE security_snapshot_state DROP CONSTRAINT security_snapshot_state_category_check;
ALTER TABLE security_snapshot_state ADD CONSTRAINT security_snapshot_state_category_check
    CHECK (category IN ('fail2ban', 'sockets', 'firewall', 'winsec'));
