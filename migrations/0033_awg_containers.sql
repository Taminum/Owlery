-- What each running AmneziaWG container says about itself: the version of the awg tools inside it, the version
-- of the amneziawg kernel module on the host, and whether the container has no interface (so nothing connects).
-- One row per container, refreshed by every snapshot; it feeds two alerts.
CREATE TABLE awg_containers (
    agent_id  uuid        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    container text        NOT NULL,
    tools     text        NOT NULL DEFAULT '',
    module    text        NOT NULL DEFAULT '',
    down      boolean     NOT NULL DEFAULT false,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (agent_id, container)
);
