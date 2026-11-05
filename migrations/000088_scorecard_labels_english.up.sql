-- Migration 000088 - translate the scorecard indicator labels and units to English.
--
-- The scorecard (migration 000086) seeded Indonesian labels for the capstone. The product UI is
-- English throughout, so the stored labels and units are translated here. The CSF function names
-- were already English. Idempotent UPDATEs keyed by indicator_key, so this runs cleanly whether
-- the row still holds the original seed or was already touched.
UPDATE scorecard_thresholds SET label = 'Active data-source coverage',   unit = '%'    WHERE indicator_key = 'source_coverage';
UPDATE scorecard_thresholds SET label = 'Scenario detection rate',       unit = '%'    WHERE indicator_key = 'detection_rate';
UPDATE scorecard_thresholds SET label = 'MTTD (median time to detect)',  unit = 'min'  WHERE indicator_key = 'mttd';
UPDATE scorecard_thresholds SET label = 'MTTR (median time to respond)', unit = 'min'  WHERE indicator_key = 'mttr';
UPDATE scorecard_thresholds SET label = 'CIS benchmark score',           unit = '%'    WHERE indicator_key = 'benchmark_score';
UPDATE scorecard_thresholds SET label = 'False-positive ratio',          unit = '%'    WHERE indicator_key = 'false_positive_ratio';
UPDATE scorecard_thresholds SET label = 'Bridging-failure detection (S11)', unit = '%' WHERE indicator_key = 'bridging_detection';
UPDATE scorecard_thresholds SET label = 'Report preparation time',       unit = 'days' WHERE indicator_key = 'report_prep_time';
