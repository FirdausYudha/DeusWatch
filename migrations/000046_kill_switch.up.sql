-- Migration 000046 - ransomware kill-switch (feature 3).
--
-- Reuses the existing agent_file_actions queue rather than adding a parallel pipeline: the
-- manager->agent delivery, one-shot semantics, result reporting and gateway handlers are already
-- proven there. A kill is just another action the agent polls for, with 'kill_process' naming the
-- process instead of a file.
--
-- The identity columns are what make the kill safe. The agent refuses to kill on a bare PID,
-- because between detection here and execution there the target can exit and the OS can recycle
-- its PID onto an innocent process. proc_start (Linux starttime / Windows creation time) is the
-- signal a recycled PID cannot reproduce; proc_name and the exe path (carried in `path`) are
-- corroborating.
ALTER TABLE agent_file_actions ADD COLUMN IF NOT EXISTS pid        integer;
ALTER TABLE agent_file_actions ADD COLUMN IF NOT EXISTS proc_name  text;
ALTER TABLE agent_file_actions ADD COLUMN IF NOT EXISTS proc_start text;

-- Why the killer feature needs an extra status: killing a process is the most destructive action
-- DeusWatch can take, so detections land as 'recommended' and stay inert until a human approves
-- them (which moves the row to 'requested'). PendingFileActions only ever delivers 'requested',
-- so a recommendation can never reach an agent on its own. Auto-kill exists, but it is an
-- explicit opt-in (KILL_SWITCH_AUTO=1) that writes 'requested' directly.
--   recommended -> requested -> delivered -> done | failed
-- 'done' carries the honest outcome in `result` (killed / skipped_protected / skipped_gone /
-- skipped_mismatch / skipped_no_identity) - "done" means we finished deciding, not that a
-- process died.
COMMENT ON COLUMN agent_file_actions.pid IS 'kill_process: target pid, verified against proc_start before the kill';

-- The Response page lists pending kill recommendations across ALL agents, newest first.
CREATE INDEX IF NOT EXISTS idx_agent_file_actions_kill
    ON agent_file_actions (action, status, created_at DESC)
    WHERE action = 'kill_process';
