-- Rollback migrasi 000002.

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
