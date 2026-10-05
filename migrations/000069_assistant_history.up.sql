-- Migration 000069: per-user assistant conversation history.
--
-- Until now a conversation lived only in the browser tab and was lost on close, which made the
-- assistant useless for anything spanning a shift: an operator could not come back to what they
-- were told an hour ago.
--
-- Keyed on the user, cascading on delete: removing an account removes its conversation with it.
-- These rows hold security data and whatever the operator typed, so they inherit the account's
-- lifetime rather than outliving it.
CREATE TABLE IF NOT EXISTS assistant_messages (
    id         bigserial PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('user', 'assistant')),
    -- What the operator sees.
    content    text        NOT NULL,
    -- What is replayed to the model. Usually identical to content; for a turn that ran a database
    -- query it also carries the result table, so reopening the panel does not lose the rows the
    -- next question was going to be about.
    context    text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every read is "this user's most recent messages", so the index matches it exactly.
CREATE INDEX IF NOT EXISTS idx_assistant_messages_user_time
    ON assistant_messages (user_id, created_at DESC);
