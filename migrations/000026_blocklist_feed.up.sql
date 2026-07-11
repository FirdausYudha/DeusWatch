-- Migration 000026 - UI-managed token for the external-firewall blocklist feed
-- (GET /api/blocklist?token=...). Single-row config; seeded from BLOCKLIST_FEED_TOKEN on first
-- start if set, then regenerated from the Response page. Empty token = feed disabled.
CREATE TABLE IF NOT EXISTS blocklist_feed (
    id         int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    token      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
