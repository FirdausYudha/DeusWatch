-- Migration 000007 — per-user granular RBAC permission overrides.
--
-- NULL permissions = inherit the role's default permission set; a non-NULL array
-- = an explicit custom permission set for that user (the checklist in the UI).
-- This lets an admin tailor access per user beyond the three built-in roles.

ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions text[];
