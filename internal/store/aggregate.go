package store

import (
	"context"
	"fmt"

	"deuswatch/internal/detect"
)

// QueryAgg runs an aggregation query already compiled by sigma.AggRule. It satisfies
// detect.AggExecutor. The query always returns columns (grp, n, last_seen); the
// arguments are already parameterized (the compiler never interpolates literals).
func (s *Store) QueryAgg(ctx context.Context, query string, args []any) ([]detect.AggGroup, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: aggregation query: %w", err)
	}
	defer rows.Close()

	var out []detect.AggGroup
	for rows.Next() {
		var g detect.AggGroup
		if err := rows.Scan(&g.Group, &g.Count, &g.LastSeen, &g.Agent, &g.Host); err != nil {
			return nil, fmt.Errorf("store: scan aggregation: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
