-- Web services published from a machine: an admin panel bound to 127.0.0.1 on it, opened in the browser at
-- https://<slug>.<services domain> through the machine's agent. The slug is the whole subdomain, unique for good:
-- an old link must never lead to another machine's panel.
CREATE TABLE web_services (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id      uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    slug        text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'),
    title       text        NOT NULL CHECK (length(title) BETWEEN 1 AND 80),
    port        integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz
);
CREATE INDEX web_services_vps ON web_services (vps_id) WHERE archived_at IS NULL;
