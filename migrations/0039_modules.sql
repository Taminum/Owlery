-- Optional parts of the program. A module that is off is not in the menu; everything about it stays where it was,
-- so turning it back on brings it back as it was. A module without a row is on.
CREATE TABLE app_modules (
    id         text PRIMARY KEY CHECK (id IN ('remnawave', 'awg', 'security', 'intel', 'billing')),
    enabled    boolean     NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid
);
