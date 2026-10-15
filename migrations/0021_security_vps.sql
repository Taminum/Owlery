-- RemnaScope 0021: the VPS as the unit of security.
--
-- A VPS is not a panel and not a node: one server can hold a panel, several nodes, AmneziaWG and
-- anything else. It exists on its own (created by hand) and may be linked to panels or nodes the
-- operator confirmed belong to it. An address in common is never proof of that, so a link is only
-- ever created by a person.

CREATE TABLE security_vps (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    origin      text        NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual')),
    enabled     boolean     NOT NULL DEFAULT true,
    note        text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz
);
-- Names are unique among live servers, so an archived one does not block its name.
CREATE UNIQUE INDEX security_vps_live_name ON security_vps (lower(name)) WHERE archived_at IS NULL;

CREATE TABLE security_vps_addresses (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id     uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    address    text        NOT NULL CHECK (length(address) BETWEEN 1 AND 253),
    kind       text        NOT NULL CHECK (kind IN ('ipv4', 'ipv6', 'domain')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (vps_id, address)
);

-- A confirmed association with a panel (node_id NULL) or with one node of it.
CREATE TABLE security_vps_links (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vps_id     uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    panel_id   uuid        NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    node_id    uuid,
    provenance text        NOT NULL DEFAULT 'operator_confirmed' CHECK (provenance IN ('operator_confirmed')),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (panel_id, node_id) REFERENCES nodes(panel_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX security_vps_links_panel ON security_vps_links (vps_id, panel_id) WHERE node_id IS NULL;
CREATE UNIQUE INDEX security_vps_links_node  ON security_vps_links (vps_id, panel_id, node_id) WHERE node_id IS NOT NULL;
CREATE INDEX security_vps_links_by_panel ON security_vps_links (panel_id);
