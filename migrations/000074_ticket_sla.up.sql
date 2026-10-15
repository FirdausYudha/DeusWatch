-- Migration 000074: ticket SLA measurement and alert-to-ticket automation.
--
-- From the hospital field discussion (docs/insight-lapangan-rs.md, gap 4). Two problems, one
-- table:
--
--   1. Nobody fills in tickets. "User itu kalau ada troubleshoot paling malas isi ticketing...
--      jadi kita kadang dobel: WhatsApp ya kita terima, tiket ya kita isi sendiri." A ticket that
--      a human has to remember to open is a ticket that does not exist, so alerts above a
--      threshold open one themselves.
--
--   2. Tickets are how IT performance is judged there: "jamnya awalnya ini masuk, nanti
--      penyelesaiannya kayak gimana. Nanti bisa jadi rapot." created_at and resolved_at already
--      gave time-to-resolve; what was missing is when somebody first PICKED IT UP, which is the
--      half of a scorecard that says whether the team is responsive as opposed to merely eventually
--      finished.

-- acked_at: the first time a human did anything with the ticket (took it, moved it off open, or
-- wrote a note). Separate from updated_at, which every later edit overwrites, and from resolved_at,
-- which answers a different question. Nullable forever on a ticket nobody ever touched: that is a
-- fact the scorecard needs to show, not a gap to fill in with a default.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS acked_at timestamptz;

-- acked_by: who picked it up. A scorecard that cannot attribute response time is a scorecard about
-- nobody.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS acked_by text;

-- dedupe_key: set only on tickets opened by automation. A brute-force rule firing every few seconds
-- must land on ONE ticket, not four hundred; without this the automation would bury the queue it is
-- supposed to fill, and the team would turn it off within the hour.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS dedupe_key text;

-- recurrences: how many further alerts collapsed onto this ticket after it was opened. Without it
-- deduplication silently discards the evidence of scale, and "this fired four hundred times since
-- you took it" is exactly what the person holding the ticket needs to know.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS recurrences int NOT NULL DEFAULT 0;

-- auto_created: distinguishes a machine-opened ticket from one a person wrote. The scorecard reports
-- them separately, because response time on an alert the system raised at 3am is a different
-- measurement from response time on a request a colleague typed.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS auto_created boolean NOT NULL DEFAULT false;

-- The lookup automation does on every qualifying alert: is there already a live ticket for this
-- rule+source? Partial, because a resolved ticket must NOT absorb a fresh recurrence — the attack
-- coming back is news.
CREATE INDEX IF NOT EXISTS idx_tickets_dedupe_open
    ON tickets (dedupe_key)
    WHERE dedupe_key IS NOT NULL AND status IN ('open', 'in_progress');

-- The scorecard scans by age, and by assignee within a window.
CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets (created_at DESC);

-- Deployment-wide settings, a singleton row like notify_config (000019). Not per-tenant: this is an
-- operator decision about how the installation behaves, the same shape as the notification config it
-- sits beside.
CREATE TABLE IF NOT EXISTS ticket_automation (
    id                  int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    -- Off by default. Switching on a thing that creates records on its own is the operator's call,
    -- never an upgrade's.
    enabled             boolean  NOT NULL DEFAULT false,
    -- 0..4 (info..critical). 3 = high: low enough to catch what matters, high enough that the queue
    -- stays readable.
    min_severity        smallint NOT NULL DEFAULT 3,
    -- How long one dedupe_key keeps collapsing onto the same open ticket.
    dedupe_window_mins  int      NOT NULL DEFAULT 60,
    -- Who machine-opened tickets land on. Empty means unassigned.
    default_assignee    text     NOT NULL DEFAULT '',
    -- Telegram/email on ticket events, through the existing notification channels. The point of the
    -- field work: people answer chat, not a ticket queue, so the queue has to reach the chat.
    notify_on_create    boolean  NOT NULL DEFAULT true,
    notify_on_resolve   boolean  NOT NULL DEFAULT false,
    updated_at          timestamptz NOT NULL DEFAULT now()
);
INSERT INTO ticket_automation (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
