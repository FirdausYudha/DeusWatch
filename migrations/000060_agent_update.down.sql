ALTER TABLE agents
    DROP COLUMN IF EXISTS agent_version,
    DROP COLUMN IF EXISTS update_requested_at;
