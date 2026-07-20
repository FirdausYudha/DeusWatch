-- Revert 000046 - ransomware kill-switch.
DROP INDEX IF EXISTS idx_agent_file_actions_kill;
DELETE FROM agent_file_actions WHERE action = 'kill_process';
ALTER TABLE agent_file_actions DROP COLUMN IF EXISTS proc_start;
ALTER TABLE agent_file_actions DROP COLUMN IF EXISTS proc_name;
ALTER TABLE agent_file_actions DROP COLUMN IF EXISTS pid;
