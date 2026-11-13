-- The month a channel last got the monthly report for (the first day of it). New channels start at the previous month, so the first
-- report a channel gets is the one for the month that is under way when it is made.
ALTER TABLE notify_channels ADD COLUMN report_month date NOT NULL DEFAULT (date_trunc('month', now() - interval '1 month'))::date;
