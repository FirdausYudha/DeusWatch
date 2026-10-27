package store

import (
	"testing"
	"time"
)

const testDSN = "postgres://u:p@localhost:5432/db?sslmode=disable"

// TestPoolConfigAppliesToEveryPath is the regression guard for the starvation bug.
//
// Connect (the API) used to call pgxpool.New with NO configuration, so it ran on pgx's default
// MaxConns of max(4, NumCPU) while ConnectSuperadmin (worker, gateway) had 30 and honoured
// DB_MAX_CONNS. On a four-core host the API had four connections, and because every protected
// request holds a transaction for its whole duration, clicking between a few menus exhausted the
// pool: data endpoints returned 500 and the session lookup, needing a connection of its own,
// failed too. Both roles now go through poolConfig, and this fails if one is given settings the
// other does not get.
func TestPoolConfigAppliesToEveryPath(t *testing.T) {
	t.Setenv("DB_MAX_CONNS", "")
	cfg, err := poolConfig(testDSN)
	if err != nil {
		t.Fatalf("poolConfig: %v", err)
	}
	if cfg.MaxConns != 30 {
		t.Errorf("MaxConns = %d, want the explicit default of 30 rather than pgx's max(4, NumCPU)",
			cfg.MaxConns)
	}
	// The eviction settings matter as much as the size: without them a silently-broken connection
	// stays cached and only a container restart recovers.
	if cfg.HealthCheckPeriod != 30*time.Second {
		t.Errorf("HealthCheckPeriod = %v", cfg.HealthCheckPeriod)
	}
	if cfg.MaxConnIdleTime != 5*time.Minute {
		t.Errorf("MaxConnIdleTime = %v", cfg.MaxConnIdleTime)
	}
	if cfg.MaxConnLifetime != 30*time.Minute {
		t.Errorf("MaxConnLifetime = %v", cfg.MaxConnLifetime)
	}
}

func TestPoolConfigHonoursDBMaxConns(t *testing.T) {
	t.Setenv("DB_MAX_CONNS", "12")
	cfg, err := poolConfig(testDSN)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 12 {
		t.Errorf("MaxConns = %d, want 12", cfg.MaxConns)
	}
}

// TestPoolConfigRejectsNonsense: a bad value must fall back to the default rather than produce a
// pool that refuses every connection, with a typo as the cause and nothing saying so.
func TestPoolConfigRejectsNonsense(t *testing.T) {
	for _, v := range []string{
		"0", "-1", "abc", "30 ", "2147483648", // one past int32, which used to wrap negative
		"1e3", "",
	} {
		t.Setenv("DB_MAX_CONNS", v)
		cfg, err := poolConfig(testDSN)
		if err != nil {
			t.Fatalf("DB_MAX_CONNS=%q: %v", v, err)
		}
		if cfg.MaxConns != 30 {
			t.Errorf("DB_MAX_CONNS=%q gave MaxConns=%d, want the default 30", v, cfg.MaxConns)
		}
	}
}

func TestPoolConfigRejectsBadDSN(t *testing.T) {
	if _, err := poolConfig("not a dsn at all ::::"); err == nil {
		t.Fatal("a malformed DSN was accepted")
	}
}
