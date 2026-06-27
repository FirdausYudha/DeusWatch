-- Migration 000016 — FIM file-hash reputation verdict on events.
-- The enrichment worker looks a file event's SHA-256 up against reputation sources
-- (CIRCL/VirusTotal) and stores the verdict here (deuswatch.file_hash.*).
ALTER TABLE events ADD COLUMN IF NOT EXISTS dw_filehash_verdict text; -- known_good | known_bad | unknown
ALTER TABLE events ADD COLUMN IF NOT EXISTS dw_filehash_detail  text;
