-- 000055_whitelist_kind: classify whitelist entries as `internal` or `external`.
--
-- Both kinds are still "never banned" (that's what whitelist means). The distinction is used by the
-- direction classifier (INBOUND / OUTBOUND / LATERAL) on the dashboard:
--   * internal — our own network. Counts as "our side" when deciding the direction of an event.
--   * external — a trusted third party (a partner, a security scanner, a CDN we use). Never banned,
--                but NOT our side, so it doesn't flip a source into LATERAL.
-- Existing rows default to `internal` because that matches the historical intent of "our IPs".
ALTER TABLE ip_whitelist
	ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'internal'
		CHECK (kind IN ('internal','external'));
