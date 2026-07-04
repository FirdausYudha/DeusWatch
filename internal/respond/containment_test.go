package respond

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

// fakeContainStore is an in-memory ContainmentStore for testing the evaluator without a DB.
// It enforces the same anti-double-containment guard as the real partial unique index.
type fakeContainStore struct {
	mu    sync.Mutex
	items map[string]*Containment
	seq   int
}

func newFakeContainStore() *fakeContainStore {
	return &fakeContainStore{items: map[string]*Containment{}}
}

func (f *fakeContainStore) InsertContainment(_ context.Context, c *Containment) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.items {
		if e.AgentID == c.AgentID && (e.Status == ContainRecommended || e.Status == ContainContained) {
			return "", false, nil // active record exists — dedup
		}
	}
	f.seq++
	id := fmt.Sprintf("c%d", f.seq)
	cp := *c
	cp.ID, cp.CreatedAt = id, time.Now()
	f.items[id] = &cp
	return id, true, nil
}

func (f *fakeContainStore) GetContainment(_ context.Context, id string) (*Containment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.items[id]; ok {
		cp := *e
		return &cp, nil
	}
	return nil, fmt.Errorf("not found")
}

func (f *fakeContainStore) MarkContained(_ context.Context, id string, exp *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.items[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	now := time.Now()
	e.Status, e.ExpiresAt, e.ContainedAt = ContainContained, exp, &now
	return nil
}

func (f *fakeContainStore) SetContainmentStatus(_ context.Context, id string, status ContainmentStatus, by string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.items[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	e.Status, e.DecidedBy = status, by
	return nil
}

func (f *fakeContainStore) SetContainmentError(_ context.Context, id, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.items[id]; ok {
		e.Error = msg
	}
	return nil
}

func (f *fakeContainStore) ActiveContainmentByAgent(_ context.Context, name string) (*Containment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.items {
		if e.AgentID == name && e.Status == ContainContained {
			cp := *e
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeContainStore) ExpiredContained(_ context.Context, now time.Time) ([]*Containment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*Containment
	for _, e := range f.items {
		if e.Status == ContainContained && e.ExpiresAt != nil && e.ExpiresAt.Before(now) {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

// fakeEdge records the Block/Unblock calls (the best-effort edge half of "both").
type fakeEdge struct {
	mu               sync.Mutex
	blocked, unblock []string
}

func (r *fakeEdge) Name() string { return "fake" }
func (r *fakeEdge) Block(_ context.Context, ip string, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked = append(r.blocked, ip)
	return nil
}
func (r *fakeEdge) Unblock(_ context.Context, ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unblock = append(r.unblock, ip)
	return nil
}

func contAlert(agentID, hostIP string, sev, threshold ingest.Severity, timeout int) *ingest.Event {
	ev := &ingest.Event{
		Event: ingest.EventFields{Severity: sev},
		Host:  &ingest.Host{Name: "victim-pc", IP: hostIP},
		Rule:  &ingest.Rule{ID: "r-ransomware", Name: "Ransomware behaviour"},
		DeusWatch: ingest.DeusWatch{Containment: &ingest.Containment{
			ActionType: "network_containment", TimeoutSeconds: timeout, Threshold: threshold,
		}},
	}
	if agentID != "" {
		ev.Agent = &ingest.Agent{ID: agentID}
	}
	return ev
}

func TestContainmentEvaluate(t *testing.T) {
	ctx := context.Background()

	t.Run("no containment intent → skip", func(t *testing.T) {
		e := NewContainmentEngine(newFakeContainStore(), nil, true)
		ev := &ingest.Event{Agent: &ingest.Agent{ID: "a1"}, Event: ingest.EventFields{Severity: ingest.SeverityCritical}}
		if c, err := e.Evaluate(ctx, ev); err != nil || c != nil {
			t.Fatalf("expected nil,nil for an alert without a mitigation_action; got %v,%v", c, err)
		}
	})

	t.Run("no agent id → cannot isolate", func(t *testing.T) {
		e := NewContainmentEngine(newFakeContainStore(), nil, true)
		ev := contAlert("", "10.0.0.5", ingest.SeverityCritical, ingest.SeverityHigh, 0)
		if c, err := e.Evaluate(ctx, ev); err != nil || c != nil {
			t.Fatalf("expected nil without an agent id; got %v,%v", c, err)
		}
	})

	t.Run("auto off → recommend only, no edge block", func(t *testing.T) {
		edge := &fakeEdge{}
		e := NewContainmentEngine(newFakeContainStore(), edge, false)
		c, err := e.Evaluate(ctx, contAlert("a1", "10.0.0.5", ingest.SeverityCritical, ingest.SeverityHigh, 0))
		if err != nil || c == nil {
			t.Fatalf("expected a recommendation; got %v,%v", c, err)
		}
		if c.Status != ContainRecommended {
			t.Fatalf("want recommended, got %s", c.Status)
		}
		if len(edge.blocked) != 0 {
			t.Fatalf("edge must not block when auto is off: %v", edge.blocked)
		}
	})

	t.Run("auto on + severity ≥ threshold → contained + edge block + extraction", func(t *testing.T) {
		edge := &fakeEdge{}
		store := newFakeContainStore()
		e := NewContainmentEngine(store, edge, true)
		c, err := e.Evaluate(ctx, contAlert("agent-42", "10.0.0.9", ingest.SeverityCritical, ingest.SeverityHigh, 1800))
		if err != nil || c == nil {
			t.Fatalf("expected containment; got %v,%v", c, err)
		}
		if c.Status != ContainContained {
			t.Fatalf("want contained, got %s", c.Status)
		}
		if c.AgentID != "agent-42" || c.IP != "10.0.0.9" {
			t.Fatalf("bad extraction: agent=%q ip=%q", c.AgentID, c.IP)
		}
		if c.ExpiresAt == nil {
			t.Fatal("timeout 1800 should set an expiry")
		}
		if len(edge.blocked) != 1 || edge.blocked[0] != "10.0.0.9" {
			t.Fatalf("edge should have blocked the host IP: %v", edge.blocked)
		}
	})

	t.Run("double containment is prevented", func(t *testing.T) {
		store := newFakeContainStore()
		e := NewContainmentEngine(store, &fakeEdge{}, true)
		if _, err := e.Evaluate(ctx, contAlert("dup", "10.0.0.1", ingest.SeverityCritical, ingest.SeverityHigh, 0)); err != nil {
			t.Fatal(err)
		}
		c, err := e.Evaluate(ctx, contAlert("dup", "10.0.0.1", ingest.SeverityCritical, ingest.SeverityHigh, 0))
		if err != nil {
			t.Fatal(err)
		}
		if c != nil {
			t.Fatalf("second alert for a contained host must be skipped, got %+v", c)
		}
	})

	t.Run("severity below threshold → recommend, not auto-contain", func(t *testing.T) {
		edge := &fakeEdge{}
		e := NewContainmentEngine(newFakeContainStore(), edge, true)
		c, err := e.Evaluate(ctx, contAlert("low", "10.0.0.7", ingest.SeverityMedium, ingest.SeverityHigh, 0))
		if err != nil || c == nil {
			t.Fatalf("expected a recommendation; got %v,%v", c, err)
		}
		if c.Status != ContainRecommended {
			t.Fatalf("below-threshold alert must not auto-contain, got %s", c.Status)
		}
		if len(edge.blocked) != 0 {
			t.Fatalf("no edge block expected: %v", edge.blocked)
		}
	})

	t.Run("manager host is never contained", func(t *testing.T) {
		e := NewContainmentEngine(newFakeContainStore(), &fakeEdge{}, true)
		_, mgr, _ := net.ParseCIDR("10.0.0.0/24")
		e.SetManagerNets([]*net.IPNet{mgr})
		c, err := e.Evaluate(ctx, contAlert("mgr", "10.0.0.9", ingest.SeverityCritical, ingest.SeverityHigh, 0))
		if err != nil || c != nil {
			t.Fatalf("a manager-range host must never be contained; got %v,%v", c, err)
		}
	})
}

func TestContainmentReleaseAndSweep(t *testing.T) {
	ctx := context.Background()
	edge := &fakeEdge{}
	store := newFakeContainStore()
	e := NewContainmentEngine(store, edge, true)

	// Contain with a 1s timeout, then it should be auto-released by the sweep.
	c, err := e.Evaluate(ctx, contAlert("sweep-me", "10.0.0.50", ingest.SeverityCritical, ingest.SeverityHigh, 1))
	if err != nil || c == nil || c.Status != ContainContained {
		t.Fatalf("expected contained; got %v,%v", c, err)
	}
	// Force expiry in the store.
	past := time.Now().Add(-time.Minute)
	store.items[c.ID].ExpiresAt = &past

	n, err := e.SweepExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected 1 auto-release, got %d (%v)", n, err)
	}
	got, _ := store.GetContainment(ctx, c.ID)
	if got.Status != ContainReleased {
		t.Fatalf("want released after sweep, got %s", got.Status)
	}
	if len(edge.unblock) != 1 || edge.unblock[0] != "10.0.0.50" {
		t.Fatalf("release must unblock the edge: %v", edge.unblock)
	}
}
