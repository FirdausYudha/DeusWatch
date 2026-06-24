-- Auto-approve flag: when true the response engine executes the progressive
-- ban automatically (no manual approval step).
ALTER TABLE ban_policy ADD COLUMN IF NOT EXISTS auto_approve boolean NOT NULL DEFAULT false;
