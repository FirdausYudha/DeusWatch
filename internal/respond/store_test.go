package respond

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestStoreLifecycle memverifikasi SQL response_actions terhadap Postgres nyata
// (di-skip bila DB tak tersedia).
func TestStoreLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}

	ip := fmt.Sprintf("198.51.%d.%d", time.Now().UnixNano()%256, (time.Now().UnixNano()/256)%256)
	defer pool.Exec(ctx, `DELETE FROM response_actions WHERE source_ip=$1::inet`, ip)

	s := NewStore(pool)

	// Insert recommended.
	a := &Action{SourceIP: ip, ActionType: "block", Reason: "SSH Brute Force", RuleID: "r1",
		BanSeconds: 600, OffenseCount: 1, Source: "playbook", Status: StatusRecommended}
	id, err := s.Insert(ctx, a)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Offenses awal 0 (belum ada executed).
	if n, _ := s.Offenses(ctx, ip); n != 0 {
		t.Fatalf("offenses awal %d, mau 0", n)
	}

	// Get.
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SourceIP != ip || got.BanSeconds != 600 || got.Status != StatusRecommended {
		t.Fatalf("get tak sesuai: %+v", got)
	}

	// Approve (set status) + executed.
	if err := s.SetStatus(ctx, id, StatusApproved, "alice"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := s.SetExecuted(ctx, id, "nftables", nil); err != nil {
		t.Fatalf("SetExecuted: %v", err)
	}
	got, _ = s.Get(ctx, id)
	if got.Status != StatusExecuted || got.Responder != "nftables" || got.DecidedBy != "alice" {
		t.Fatalf("setelah eksekusi: %+v", got)
	}
	if got.ExecutedAt == nil {
		t.Fatal("executed_at harus terisi")
	}

	// Sekarang offenses = 1 (satu executed).
	if n, _ := s.Offenses(ctx, ip); n != 1 {
		t.Fatalf("offenses setelah executed %d, mau 1", n)
	}

	// List by status.
	list, err := s.List(ctx, string(StatusExecuted), 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, x := range list {
		if x.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("aksi executed tak muncul di List(executed)")
	}
}
