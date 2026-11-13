-- Who asked a panel for a subscription, from where and with what client (the panel's subscription request history).
-- It is read-only data: a subscription taken from many different addresses is a sign that it has been passed on.
CREATE TABLE subscription_requests (
    panel_id     uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    remote_id    bigint      NOT NULL,
    remote_user  text        NOT NULL, -- the panel's user id, as users.remote_uuid holds it
    requested_at timestamptz NOT NULL,
    ip           text        NOT NULL DEFAULT '',
    user_agent   text        NOT NULL DEFAULT '',
    PRIMARY KEY (panel_id, remote_id)
);
CREATE INDEX subscription_requests_user ON subscription_requests (panel_id, remote_user, requested_at DESC);
CREATE INDEX subscription_requests_at ON subscription_requests (requested_at);
