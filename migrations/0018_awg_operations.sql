-- Owlery 0018: a record of every change Owlery asked an AmneziaWG host to make. It holds who asked,
-- what, and how it ended. Never a key other than the device's PUBLIC key, never a configuration.
CREATE TABLE awg_operations (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id  uuid        REFERENCES awg_instances (id) ON DELETE SET NULL,
    kind         text        NOT NULL CHECK (kind IN ('add', 'revoke')),
    public_key   text,
    label        text,
    status       text        NOT NULL CHECK (status IN ('ok', 'error')),
    error_code   text,
    requested_by uuid,
    requested_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX awg_operations_when ON awg_operations (requested_at DESC);
