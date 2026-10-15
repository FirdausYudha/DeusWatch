-- Reverse 000076: drop the SNMP tables.
--
-- This DOES destroy data: the configured devices and their sensor definitions, plus all polled
-- history. Rolling back means re-entering every device, its credentials, and the vendor OIDs the
-- operator looked up for CPU and temperature. The hypertables and their retention policies go too.

DROP TABLE IF EXISTS snmp_iface_samples;
DROP TABLE IF EXISTS snmp_readings;
DROP TABLE IF EXISTS snmp_sensors;
DROP TABLE IF EXISTS snmp_devices;
