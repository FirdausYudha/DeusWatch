-- Migration 000029 - superior FIM: store the line diff of a modified text file so the
-- dashboard can show WHICH lines changed (e.g. the code injected during a defacement).
ALTER TABLE events ADD COLUMN IF NOT EXISTS file_diff text;
