-- Reverse 000073: drop the service-check tables.
--
-- This DOES destroy data: the configured checks and their probe history. There is no other copy,
-- so rolling this back means re-entering the endpoints. The retention policy and the hypertable
-- go with the table.

DROP TABLE IF EXISTS service_check_results;
DROP TABLE IF EXISTS service_checks;
