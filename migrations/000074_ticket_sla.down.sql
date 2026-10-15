-- Reverse 000074.
--
-- Dropping the columns DOES destroy data: who picked up each ticket and when, which is the whole
-- scorecard history. The tickets themselves survive; their response times do not.

DROP TABLE IF EXISTS ticket_automation;

DROP INDEX IF EXISTS idx_tickets_created;
DROP INDEX IF EXISTS idx_tickets_dedupe_open;

ALTER TABLE tickets DROP COLUMN IF EXISTS recurrences;
ALTER TABLE tickets DROP COLUMN IF EXISTS auto_created;
ALTER TABLE tickets DROP COLUMN IF EXISTS dedupe_key;
ALTER TABLE tickets DROP COLUMN IF EXISTS acked_by;
ALTER TABLE tickets DROP COLUMN IF EXISTS acked_at;
