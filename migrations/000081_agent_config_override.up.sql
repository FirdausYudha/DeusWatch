-- Migration 000081 - tell an operator's choice apart from a seeded default.
--
-- Enrollment seeds every agent with the OS-appropriate default sources (000xxx / v2.0.1), on
-- purpose: a new host watches its logs out of the box and those sources are visible and editable
-- in the UI, rather than hiding inside the agent binary where an admin adding a FIM watch would
-- replace them without realising.
--
-- Agent groups then read "this row has a config" as "an operator chose a policy for this agent",
-- which is wrong for a seeded default and breaks the feature completely: every agent looks like
-- it has an override, so a group would never apply to anything. Found by the group tests, which
-- is the only reason it is not shipping that way.
--
-- A separate migration rather than an edit to 000080 for the same reason 000079 was separate from
-- 000078: editing a migration that HAS run leaves the column missing with no sign of it until the
-- feature fails at runtime, and "almost certainly nobody applied it yet" is not good enough.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS config_is_override boolean NOT NULL DEFAULT false;

-- Existing agents that carry a config are treated as overrides. We cannot tell retroactively
-- whether a config was seeded or customised, and this is the conservative direction: an upgrade
-- must never silently change what an endpoint collects. An operator who wants such an agent to
-- follow a group clears its config, which is one click and says what it does.
UPDATE agents SET config_is_override = true WHERE config IS NOT NULL;
