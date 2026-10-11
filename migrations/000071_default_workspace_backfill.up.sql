-- Put every user who belongs to no workspace into the Default one.
--
-- Migration 000049 did this once, for the users that existed when it ran. Nothing assigned a
-- workspace to anyone created afterwards, and access flows user -> workspace -> tenant with
-- ResolveUserScope failing closed, so every account added through the UI since then logged in to an
-- empty product: no agents, no events, no blocklist. CreateUser now assigns Default at creation;
-- this repairs the accounts that predate that.
--
-- It stayed invisible because admins carry manage_tenants, which takes the RLS bypass and does not
-- consult membership at all. Only the analyst and viewer accounts, the ones created for other
-- people, saw the empty deployment. On a fresh install the seeded admin is in the same position:
-- 000049's backfill runs against an empty users table, and seedAdmin inserts afterwards.
--
-- Only users with NO membership anywhere are touched. Someone deliberately moved to another tenant
-- has a membership already and is left exactly where they were put.

INSERT INTO workspace_members (workspace_id, user_id)
SELECT '00000000-0000-0000-0000-000000000002', u.id
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM workspace_members m WHERE m.user_id = u.id)
  AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = '00000000-0000-0000-0000-000000000002')
ON CONFLICT DO NOTHING;
