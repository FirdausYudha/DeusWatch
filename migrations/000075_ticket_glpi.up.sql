-- Migration 000075: mirror DeusWatch tickets into GLPI.
--
-- The hospital IT team works in GLPI under an ITIL frame. A security tool with its own separate
-- ticket queue asks them to work in two places, and the field discussion was explicit about which
-- place loses: people answer chat and skip the queue they are supposed to fill. So the tickets go
-- to where the work already happens.
--
-- The sync is one-way for content and read-only for status: DeusWatch owns what a ticket says,
-- GLPI owns how far along it is. These two columns are the whole of the link.

-- The GLPI ticket this one was pushed as. NULL means not pushed yet (or pushing is off).
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS glpi_id int;

-- When the link was last reconciled. Separate from updated_at so a sync that changes nothing is
-- still recorded as having happened — otherwise a silently broken sync looks identical to a quiet
-- one, which is the failure mode worth designing against.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS glpi_synced_at timestamptz;

-- The push queue: LIVE tickets that still need to reach GLPI. Live only, matching the query:
-- switching the integration on at a site with a long history must not push every ticket it ever
-- had into GLPI. Partial, so a ticket leaves this index for good once it is linked or finished.
CREATE INDEX IF NOT EXISTS idx_tickets_glpi_unpushed
    ON tickets (created_at)
    WHERE glpi_id IS NULL AND status IN ('open', 'in_progress');

-- The pull set: linked tickets still live enough for their GLPI status to matter. A closed ticket
-- is not polled again.
CREATE INDEX IF NOT EXISTS idx_tickets_glpi_live
    ON tickets (glpi_id)
    WHERE glpi_id IS NOT NULL AND status IN ('open', 'in_progress', 'resolved');
