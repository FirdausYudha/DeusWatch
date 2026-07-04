package respond

// Network Containment (host isolation) — the DeusWatch response to a *compromised host*
// (a user opened malware / clicked phishing / ransomware behaviour on an endpoint). Unlike
// the perimeter IP-ban engine (engine.go), which blocks an external attacker's source IP,
// containment isolates one of OUR OWN agent hosts from the LAN — everything except the
// manager — to stop lateral spread to servers, storage and other users.
//
// Two enforcement points ("both"), applied together and best-effort:
//   1. Host self-isolation: the agent applies its own firewall (nftables/netsh) to drop all
//      traffic except the manager + an allow-list. Delivered as a per-agent directive the
//      agent polls (derived from the active containment row — see Store.ActiveContainmentByAgent
//      and the gateway ContainmentHandler). This is the PRIMARY control: it always works and
//      needs no network gear.
//   2. Edge block: the host's IP is also blocked at the network edge via the existing
//      Responder (nftables/MikroTik/CrowdSec) when the IP is known. Best-effort.
//
// The evaluator is driven by a rule's `mitigation_action: network_containment` block, carried
// onto the alert as ev.DeusWatch.Containment. Auto-containment fires only when the global
// auto switch is on AND the alert severity meets the rule's criticality_threshold; otherwise
// a "recommended" containment awaits analyst approval.

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// ContainmentStatus is a containment's lifecycle status.
type ContainmentStatus string

const (
	ContainRecommended ContainmentStatus = "recommended" // qualified, awaiting approval
	ContainContained   ContainmentStatus = "contained"   // host is isolated
	ContainReleased    ContainmentStatus = "released"    // isolation lifted
	ContainDismissed   ContainmentStatus = "dismissed"   // recommendation rejected
	ContainFailed      ContainmentStatus = "failed"
)

// Containment is one host-isolation record.
type Containment struct {
	ID             string            `json:"id"`
	CreatedAt      time.Time         `json:"created_at"`
	AgentID        string            `json:"agent_id"`   // agent CN / name — key into `agents`
	HostName       string            `json:"host_name"`  // reported hostname (context)
	IP             string            `json:"ip_address"` // host IP for the edge block (may be empty)
	Reason         string            `json:"reason"`
	RuleID         string            `json:"rule_id"`
	TimeoutSeconds int               `json:"timeout_seconds"` // 0 = until manual release
	Status         ContainmentStatus `json:"status"`
	Auto           bool              `json:"auto"`
	DecidedBy      string            `json:"decided_by"`
	ContainedAt    *time.Time        `json:"contained_at"`
	ExpiresAt      *time.Time        `json:"expires_at"`
	ReleasedAt     *time.Time        `json:"released_at"`
	Error          string            `json:"error"`
}

// BanDuration returns the edge-block duration (0 = permanent / until manual release).
func (c Containment) BanDuration() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// ContainmentStore is the persistence the containment engine needs (satisfied by *Store).
type ContainmentStore interface {
	// InsertContainment inserts a recommended containment for an agent, but only if that
	// agent has no active (recommended/contained) one — the anti-double-containment guard.
	// created=false means a duplicate was skipped (no error).
	InsertContainment(ctx context.Context, c *Containment) (id string, created bool, err error)
	GetContainment(ctx context.Context, id string) (*Containment, error)
	MarkContained(ctx context.Context, id string, expiresAt *time.Time) error
	SetContainmentStatus(ctx context.Context, id string, status ContainmentStatus, by string) error
	SetContainmentError(ctx context.Context, id, msg string) error
	// ActiveContainmentByAgent returns the currently-contained record for an agent name, or nil.
	ActiveContainmentByAgent(ctx context.Context, agentName string) (*Containment, error)
	// ExpiredContained returns contained rows whose expiry has passed (for the sweeper).
	ExpiredContained(ctx context.Context, now time.Time) ([]*Containment, error)
}

// ContainmentEngine turns compromised-host alerts into host-isolation actions and applies
// them. Safe for concurrent use: the config (auto/allow/manager nets) is guarded by a mutex
// and the anti-double-containment guard is enforced atomically in the store.
type ContainmentEngine struct {
	store ContainmentStore
	edge  Responder // edge firewall/router for the IP block half of "both"; may be nil

	mu         sync.RWMutex
	auto       bool         // global auto-contain switch (else recommend-only)
	allowIPs   []string     // IPs an isolated agent must keep reachable (manager/gateway/DNS)
	managerNet []*net.IPNet // hosts that must NEVER be contained (the manager itself)
}

// NewContainmentEngine builds a containment engine. edge may be nil (host self-isolation
// still works — it's the primary control). auto=false means every qualifying alert becomes
// a recommendation awaiting approval.
func NewContainmentEngine(store ContainmentStore, edge Responder, auto bool) *ContainmentEngine {
	return &ContainmentEngine{store: store, edge: edge, auto: auto}
}

// SetAllowIPs sets the IPs an isolated host keeps reachable (live reload).
func (e *ContainmentEngine) SetAllowIPs(ips []string) {
	e.mu.Lock()
	e.allowIPs = ips
	e.mu.Unlock()
}

// SetManagerNets sets the never-contain networks (the manager's own hosts).
func (e *ContainmentEngine) SetManagerNets(nets []*net.IPNet) {
	e.mu.Lock()
	e.managerNet = nets
	e.mu.Unlock()
}

// AllowIPs returns a copy of the current allow-list (used by the gateway directive path).
func (e *ContainmentEngine) AllowIPs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.allowIPs...)
}

// Evaluate is the real-time evaluator: given a freshly-fired alert it decides whether the
// alert's host qualifies for containment and, if auto is enabled and the severity meets the
// rule's threshold, isolates it immediately. Returns nil for alerts that don't qualify.
//
// It performs the three checks the design calls for: (1) the rule authorized containment and
// the severity threshold is met; (2) the agent isn't already contained (no double-containment
// / loop); (3) it extracts the agent_id and ip_address from the alert.
func (e *ContainmentEngine) Evaluate(ctx context.Context, ev *ingest.Event) (*Containment, error) {
	if ev == nil || ev.DeusWatch.Containment == nil {
		return nil, nil // rule did not authorize containment
	}
	intent := ev.DeusWatch.Containment
	if intent.ActionType != "network_containment" {
		return nil, nil
	}

	// (3) Extract the target host identity. Without an agent id we cannot isolate a host.
	agentID := ""
	if ev.Agent != nil {
		agentID = ev.Agent.ID
	}
	if agentID == "" {
		return nil, nil
	}
	hostName := ""
	if ev.Host != nil {
		hostName = ev.Host.Name
	}
	ip := hostIP(ev)

	e.mu.RLock()
	auto, mgr := e.auto, e.managerNet
	e.mu.RUnlock()

	// Never isolate the manager's own host (would cut the SOC off from itself).
	if ip != "" && ipInNets(ip, mgr) {
		return nil, nil
	}

	// (1) Auto only when globally enabled AND the alert is at/above the rule's threshold.
	qualifiesAuto := auto && ev.Event.Severity >= intent.Threshold

	rec := &Containment{
		AgentID:        agentID,
		HostName:       hostName,
		IP:             ip,
		Reason:         reasonFor(ev),
		TimeoutSeconds: intent.TimeoutSeconds,
		Status:         ContainRecommended,
		Auto:           qualifiesAuto,
	}
	if ev.Rule != nil {
		rec.RuleID = ev.Rule.ID
	}

	// (2) Anti-double-containment: the store inserts only if the agent has no active record.
	id, created, err := e.store.InsertContainment(ctx, rec)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, nil // already contained / pending — collapse to the existing action
	}
	rec.ID = id

	if qualifiesAuto {
		if err := e.contain(ctx, rec, "auto"); err != nil {
			log.Printf("respond: auto-contain %s (%s) failed: %v", rec.AgentID, rec.IP, err)
		}
	}
	return rec, nil
}

// Approve executes a recommended containment after analyst approval.
func (e *ContainmentEngine) Approve(ctx context.Context, id, by string) error {
	c, err := e.store.GetContainment(ctx, id)
	if err != nil {
		return err
	}
	if c.Status != ContainRecommended {
		return containStatusErr(c.Status)
	}
	return e.contain(ctx, c, by)
}

// Dismiss rejects a recommended containment (no isolation applied).
func (e *ContainmentEngine) Dismiss(ctx context.Context, id, by string) error {
	c, err := e.store.GetContainment(ctx, id)
	if err != nil {
		return err
	}
	if c.Status != ContainRecommended {
		return containStatusErr(c.Status)
	}
	return e.store.SetContainmentStatus(ctx, id, ContainDismissed, by)
}

// Release lifts an active containment: unblocks the edge and marks it released. The agent
// stops isolating on its next poll (no active record for it anymore).
func (e *ContainmentEngine) Release(ctx context.Context, id, by string) error {
	c, err := e.store.GetContainment(ctx, id)
	if err != nil {
		return err
	}
	if c.Status != ContainContained {
		return containStatusErr(c.Status)
	}
	if c.IP != "" && e.edge != nil {
		if err := e.edge.Unblock(ctx, c.IP); err != nil {
			log.Printf("respond: edge unblock %s failed: %v", c.IP, err)
		}
	}
	return e.store.SetContainmentStatus(ctx, id, ContainReleased, by)
}

// SweepExpired releases every contained host whose timeout has passed. Returns the count.
func (e *ContainmentEngine) SweepExpired(ctx context.Context) (int, error) {
	rows, err := e.store.ExpiredContained(ctx, time.Now())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range rows {
		if err := e.Release(ctx, c.ID, "auto-expire"); err != nil {
			log.Printf("respond: auto-release %s failed: %v", c.ID, err)
			continue
		}
		n++
	}
	return n, nil
}

// contain marks the record contained (which is what the agent's directive is derived from)
// and applies the best-effort edge block. Host self-isolation needs no push — the agent
// polls its directive and sees the now-active containment.
func (e *ContainmentEngine) contain(ctx context.Context, c *Containment, by string) error {
	var expiresAt *time.Time
	if c.TimeoutSeconds > 0 {
		t := time.Now().Add(time.Duration(c.TimeoutSeconds) * time.Second)
		expiresAt = &t
	}
	if err := e.store.MarkContained(ctx, c.ID, expiresAt); err != nil {
		return err
	}
	c.Status, c.ExpiresAt, c.DecidedBy = ContainContained, expiresAt, by

	if c.IP != "" && e.edge != nil {
		if berr := e.edge.Block(ctx, c.IP, c.BanDuration()); berr != nil {
			// Edge is best-effort; host self-isolation is the primary control. Record and go on.
			_ = e.store.SetContainmentError(ctx, c.ID, "edge block: "+berr.Error())
			log.Printf("respond: edge block %s failed (host still self-isolated): %v", c.IP, berr)
		}
	}
	log.Printf("respond: CONTAINED agent=%s host=%s ip=%s by=%s timeout=%s",
		c.AgentID, c.HostName, c.IP, by, durLabel(c.BanDuration()))
	return nil
}

// hostIP picks the host's own IP for the edge block: the host IP first, then the event's
// source IP (some endpoint alerts carry the local address there), else empty.
func hostIP(ev *ingest.Event) string {
	if ev.Host != nil && ev.Host.IP != "" {
		return ev.Host.IP
	}
	if ev.Source != nil && ev.Source.IP != "" {
		return ev.Source.IP
	}
	return ""
}

func containStatusErr(s ContainmentStatus) error {
	return simpleError("respond: containment is already " + string(s))
}
