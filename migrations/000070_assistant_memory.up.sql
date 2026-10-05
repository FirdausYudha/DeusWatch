-- Migration 000070: durable per-user facts the assistant should keep.
--
-- Separate from assistant_messages on purpose. That table is a transcript: capped, pruned oldest
-- first, and only its last few turns ever reach the model. A nickname mentioned thirteen turns ago
-- is already invisible there, which is not what anyone means by "remember".
--
-- These rows are small, few, and injected into EVERY prompt regardless of how long ago they were
-- said. They are written only when the operator asks for them, never inferred, and they are listed
-- in the UI so a fact cannot be remembered without being visible.
CREATE TABLE IF NOT EXISTS assistant_memories (
    id         bigserial PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fact       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- The same fact asked for twice is one fact, not two lines of prompt.
    UNIQUE (user_id, fact)
);

CREATE INDEX IF NOT EXISTS idx_assistant_memories_user ON assistant_memories (user_id, created_at);
