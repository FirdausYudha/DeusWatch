-- Reversing this drops the reading history, which for an accreditation period is the evidence
-- itself and cannot be regenerated: nobody can re-measure last quarter's room temperature.
DROP TABLE IF EXISTS env_readings;
DROP TABLE IF EXISTS env_sensors;
