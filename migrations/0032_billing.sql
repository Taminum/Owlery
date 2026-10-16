-- The owner's own list of what is paid for and when: servers, domains, anything with a due date.
-- It is not read from Remnawave; it belongs to the owner and to no panel.
CREATE TABLE bills (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text          NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    provider      text          NOT NULL DEFAULT '' CHECK (length(provider) <= 80),
    amount        numeric(12,2) NOT NULL CHECK (amount >= 0),
    currency      text          NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    period_months integer       NOT NULL CHECK (period_months BETWEEN 1 AND 60),
    next_due      date          NOT NULL,
    note          text          NOT NULL DEFAULT '' CHECK (length(note) <= 300),
    archived_at   timestamptz,
    created_at    timestamptz   NOT NULL DEFAULT now()
);

-- One row for every time a bill was marked as paid; next_due moves on by one period each time.
CREATE TABLE bill_payments (
    id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    bill_id  uuid          NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
    paid_on  date          NOT NULL,
    due_was  date          NOT NULL,
    amount   numeric(12,2) NOT NULL,
    currency text          NOT NULL
);
CREATE INDEX bill_payments_bill ON bill_payments (bill_id, paid_on DESC);
