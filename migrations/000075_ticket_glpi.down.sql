-- Reverse 000075.
--
-- This DOES destroy data: the link between each DeusWatch ticket and its GLPI counterpart. The
-- tickets survive on both sides, but re-applying the migration will push duplicates into GLPI for
-- every ticket that is still unresolved, because nothing remembers they were already sent.

DROP INDEX IF EXISTS idx_tickets_glpi_live;
DROP INDEX IF EXISTS idx_tickets_glpi_unpushed;

ALTER TABLE tickets DROP COLUMN IF EXISTS glpi_synced_at;
ALTER TABLE tickets DROP COLUMN IF EXISTS glpi_id;
