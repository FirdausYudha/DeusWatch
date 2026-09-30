-- Migration 000064: soft-delete tombstone for agents.
--
-- Deleting a *valid* (non-revoked) agent must keep its row alive briefly: the gateway only tells an
-- agent to self-uninstall via HTTP 410, which needs the row to still exist and be revoked. A deleted
-- row would instead return 409 ("unknown agent") and the agent would keep running. So a valid-agent
-- delete sets revoked=true + deleted_at=now() (hidden from the list, still 410'd) and its telemetry
-- is purged immediately; a background reaper hard-deletes the tombstone once the agent is gone.
-- Already-revoked agents are hard-deleted directly (no tombstone needed).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

-- The list/enrollment/gateway lookups all want live rows; index the common "not deleted" filter.
CREATE INDEX IF NOT EXISTS idx_agents_not_deleted ON agents (enrolled_at DESC) WHERE deleted_at IS NULL;
