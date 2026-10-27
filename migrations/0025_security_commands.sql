-- Owlery 0025: manual Fail2ban ban and unban, as commands with a recorded outcome.
--
-- A command is sent to the server's agent over its live connection or not at all; nothing waits in a queue
-- for the agent to come back. 'pending' means sent and not yet answered. A command that is not answered in
-- time becomes 'unknown', never 'executed', and a later read of Fail2ban's state may settle it
-- ('confirmed_by_state') or show that nothing changed ('failed').

CREATE TABLE security_commands (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id          uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    agent_id        uuid        NOT NULL,
    action          text        NOT NULL CHECK (action IN ('ban', 'unban')),
    jail            text        NOT NULL CHECK (length(jail) BETWEEN 1 AND 64),
    ip              text        NOT NULL CHECK (length(ip) BETWEEN 2 AND 45),
    state           text        NOT NULL DEFAULT 'pending' CHECK (state IN
                    ('pending', 'executed', 'already_done', 'rejected', 'failed', 'expired', 'duplicate', 'unknown', 'confirmed_by_state')),
    actor_id        uuid,
    request_id      text,
    idempotency_key text        NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 64),
    requested_at    timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    deadline        timestamptz NOT NULL,
    finished_at     timestamptz,
    result_code     text,
    verified        boolean     NOT NULL DEFAULT false,
    UNIQUE (vps_id, idempotency_key)
);
CREATE INDEX security_commands_by_vps ON security_commands (vps_id, requested_at DESC);
CREATE INDEX security_commands_open ON security_commands (state, deadline) WHERE state IN ('pending', 'unknown');
