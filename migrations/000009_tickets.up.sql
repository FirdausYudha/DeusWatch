-- Migration 000009 — Tier-2 DFIR ticketing / case management (TheHive/IRIS-style).
--
-- An alert (or any finding) becomes a ticket that a Tier-2 analyst owns: open →
-- in_progress → resolved → closed, with an assignee, case notes, and timestamps so
-- time-to-resolve is measurable.

CREATE TABLE IF NOT EXISTS tickets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title       text     NOT NULL,
    description text     NOT NULL DEFAULT '',
    severity    smallint NOT NULL DEFAULT 2,      -- 0..4 (info..critical)
    status      text     NOT NULL DEFAULT 'open', -- open | in_progress | resolved | closed
    assignee    text,                             -- username of the owning analyst
    created_by  text     NOT NULL,
    source_ip   inet,                             -- originating alert context (optional)
    rule_id     text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,                       -- set when first resolved/closed
    closed_at   timestamptz
);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets (status, created_at DESC);

-- Append-style case notes / activity for a ticket (DFIR working log).
CREATE TABLE IF NOT EXISTS ticket_comments (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ticket_id  uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author     text NOT NULL,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments (ticket_id, created_at);
