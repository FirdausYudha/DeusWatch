-- Restore the original Indonesian labels/units seeded by migration 000086.
UPDATE scorecard_thresholds SET label = 'Cakupan sumber data aktif',        unit = '%'    WHERE indicator_key = 'source_coverage';
UPDATE scorecard_thresholds SET label = 'Tingkat deteksi skenario',         unit = '%'    WHERE indicator_key = 'detection_rate';
UPDATE scorecard_thresholds SET label = 'MTTD (median deteksi)',            unit = 'menit' WHERE indicator_key = 'mttd';
UPDATE scorecard_thresholds SET label = 'MTTR (median respons)',            unit = 'menit' WHERE indicator_key = 'mttr';
UPDATE scorecard_thresholds SET label = 'Skor benchmark CIS',               unit = '%'    WHERE indicator_key = 'benchmark_score';
UPDATE scorecard_thresholds SET label = 'Rasio positif palsu',              unit = '%'    WHERE indicator_key = 'false_positive_ratio';
UPDATE scorecard_thresholds SET label = 'Deteksi gangguan bridging (S11)',  unit = '%'    WHERE indicator_key = 'bridging_detection';
UPDATE scorecard_thresholds SET label = 'Waktu penyiapan laporan',          unit = 'hari' WHERE indicator_key = 'report_prep_time';
