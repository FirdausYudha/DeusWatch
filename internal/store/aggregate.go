package store

import (
	"context"
	"fmt"

	"deuswatch/internal/detect"
)

// QueryAgg menjalankan query agregasi yang sudah di-compile oleh sigma.AggRule.
// Memenuhi detect.AggExecutor. Query selalu mengembalikan kolom (grp, n, last_seen);
// argumen sudah ber-parameter (tak ada interpolasi nilai literal di compiler).
func (s *Store) QueryAgg(ctx context.Context, query string, args []any) ([]detect.AggGroup, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query agregasi: %w", err)
	}
	defer rows.Close()

	var out []detect.AggGroup
	for rows.Next() {
		var g detect.AggGroup
		if err := rows.Scan(&g.Group, &g.Count, &g.LastSeen); err != nil {
			return nil, fmt.Errorf("store: scan agregasi: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
