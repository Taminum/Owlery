-- What a Proxmox host says about itself, as reported by the security agent that runs on it (the module is optional and
-- off until the owner turns it on). pve_hosts keeps the latest reading; pve_guest_samples one reading an hour of each guest,
-- enough to say when a disk will be full.
CREATE TABLE pve_hosts (
    vps_id     uuid PRIMARY KEY REFERENCES security_vps(id) ON DELETE CASCADE,
    updated_at timestamptz NOT NULL,
    last       jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE pve_guest_samples (
    vps_id    uuid        NOT NULL REFERENCES security_vps(id) ON DELETE CASCADE,
    guest_id  integer     NOT NULL,
    at        timestamptz NOT NULL,
    running   boolean     NOT NULL,
    disk_used bigint      NOT NULL DEFAULT 0,
    disk_max  bigint      NOT NULL DEFAULT 0,
    mem_used  bigint      NOT NULL DEFAULT 0,
    mem_max   bigint      NOT NULL DEFAULT 0,
    PRIMARY KEY (vps_id, guest_id, at)
);
CREATE INDEX pve_guest_samples_at ON pve_guest_samples (at);

-- Proxmox is a module of its own, off until the owner turns it on.
ALTER TABLE app_modules DROP CONSTRAINT app_modules_id_check;
ALTER TABLE app_modules ADD CONSTRAINT app_modules_id_check CHECK (id IN ('remnawave', 'awg', 'security', 'intel', 'billing', 'proxmox'));
