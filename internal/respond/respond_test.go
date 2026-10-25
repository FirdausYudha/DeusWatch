package respond

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

// ── BanPolicy ─────────────────────────────────────────────

func TestBanPolicyProgressive(t *testing.T) {
	p := DefaultBanPolicy()
	cases := []struct {
		offense int
		want    time.Duration
	}{
		{1, 10 * time.Minute},
		{2, time.Hour},
		{3, 24 * time.Hour},
		{4, 0}, // permanent
		{99, 0},
	}
	for _, c := range cases {
		if got := p.Duration(c.offense); got != c.want {
			t.Errorf("offense %d: duration %v, want %v", c.offense, got, c.want)
		}
	}
}

func TestBanPolicyCapNoPermanent(t *testing.T) {
	p := BanPolicy{Durations: []time.Duration{time.Minute, time.Hour}, Permanent: false}
	if got := p.Duration(5); got != time.Hour {
		t.Fatalf("without permanent it should cap at the longest duration, got %v", got)
	}
}

// ── fake store & responder ────────────────────────────────

type fakeStore struct {
	offenses  int
	open      bool // HasOpenAction result (dedup)
	actions   map[string]*Action
	nextID    int
	lastIns   *Action
	statusLog []string
	execLog   []string
}

func newFakeStore(offenses int) *fakeStore {
	return &fakeStore{offenses: offenses, actions: map[string]*Action{}}
}

func (f *fakeStore) Insert(_ context.Context, a *Action) (string, error) {
	f.nextID++
	id := "act-" + string(rune('0'+f.nextID))
	cp := *a
	cp.ID = id
	f.actions[id] = &cp
	f.lastIns = &cp
	return id, nil
}
func (f *fakeStore) Offenses(_ context.Context, _ string, _ time.Time) (int, error) {
	return f.offenses, nil
}
func (f *fakeStore) HasOpenAction(_ context.Context, _ string) (bool, error) {
	return f.open, nil
}
func (f *fakeStore) AppendReason(_ context.Context, _, _ string) error {
	return nil
}
func (f *fakeStore) Get(_ context.Context, id string) (*Action, error) {
	a, ok := f.actions[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *a
	return &cp, nil
}
func (f *fakeStore) SetStatus(_ context.Context, id string, status Status, by string) error {
	f.statusLog = append(f.statusLog, string(status)+":"+by)
	if a, ok := f.actions[id]; ok {
		a.Status = status
	}
	return nil
}

// UnbanIP mirrors the real store: it lifts EVERY active block for the IP, so a test can prove
// the engine clears all of them rather than only the row it was handed.
func (f *fakeStore) UnbanIP(_ context.Context, ip, by string) (int64, error) {
	var n int64
	for _, a := range f.actions {
		if a.ActionType != "block" || a.SourceIP != ip {
			continue
		}
		if a.Status != StatusApproved && a.Status != StatusExecuted {
			continue
		}
		a.Status = StatusUnbanned
		f.statusLog = append(f.statusLog, string(StatusUnbanned)+":"+by)
		n++
	}
	return n, nil
}

func (f *fakeStore) SetExecuted(_ context.Context, id, responder string, execErr error) error {
	s := "executed"
	if execErr != nil {
		s = "failed:" + execErr.Error()
	}
	f.execLog = append(f.execLog, s)
	if a, ok := f.actions[id]; ok {
		if execErr != nil {
			a.Status = StatusFailed
		} else {
			a.Status = StatusExecuted
		}
	}
	return nil
}

type fakeResponder struct {
	blocked []string
	// unblocked records each Unblock so a test can prove the responder is called ONCE per IP and
	// not once per lifted row: a router asked to delete the same address-list entry three times
	// logs two failures that look like a broken integration.
	unblocked []string
	dur       time.Duration
	err       error
}

func (f *fakeResponder) Name() string { return "fake" }
func (f *fakeResponder) Block(_ context.Context, ip string, d time.Duration) error {
	f.blocked = append(f.blocked, ip)
	f.dur = d
	return f.err
}
func (f *fakeResponder) Unblock(_ context.Context, ip string) error {
	f.unblocked = append(f.unblocked, ip)
	return nil
}

func alertEvent(ip string) *ingest.Event {
	return &ingest.Event{
		Event:  ingest.EventFields{Category: "intrusion_detection", Severity: ingest.SeverityHigh},
		Source: &ingest.Endpoint{IP: ip},
		Rule:   &ingest.Rule{ID: "deuswatch-ssh-bruteforce", Name: "SSH Brute Force"},
	}
}

// ── Engine ────────────────────────────────────────────────

func TestEngineRecommendNoAutoApprove(t *testing.T) {
	store := newFakeStore(0)
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), false)

	a, err := e.Recommend(context.Background(), alertEvent("203.0.113.7"))
	if err != nil {
		t.Fatalf("Recommend: %v", err)
	}
	if a == nil || a.Status != StatusRecommended {
		t.Fatalf("should be recommended: %+v", a)
	}
	if a.OffenseCount != 1 || a.BanSeconds != int((10*time.Minute).Seconds()) {
		t.Fatalf("wrong progressive ban: offense=%d sec=%d", a.OffenseCount, a.BanSeconds)
	}
	if len(resp.blocked) != 0 {
		t.Fatal("without auto-approve there must be no block")
	}
}

func TestEngineRecommendAutoApprove(t *testing.T) {
	store := newFakeStore(2) // already blocked 2x -> 3rd offense = 24h
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), true)

	a, err := e.Recommend(context.Background(), alertEvent("45.155.205.99"))
	if err != nil {
		t.Fatalf("Recommend: %v", err)
	}
	if a.OffenseCount != 3 || a.BanSeconds != int((24*time.Hour).Seconds()) {
		t.Fatalf("wrong progression: offense=%d sec=%d", a.OffenseCount, a.BanSeconds)
	}
	if len(resp.blocked) != 1 || resp.blocked[0] != "45.155.205.99" {
		t.Fatalf("auto-approve should block: %+v", resp.blocked)
	}
	if resp.dur != 24*time.Hour {
		t.Fatalf("wrong block duration: %v", resp.dur)
	}
	if len(store.execLog) != 1 || store.execLog[0] != "executed" {
		t.Fatalf("execution not recorded as executed: %+v", store.execLog)
	}
}

func TestEngineRecommendDedupsOpenAction(t *testing.T) {
	store := newFakeStore(1)
	store.open = true // already has a pending recommendation or active block
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), true)

	a, err := e.Recommend(context.Background(), alertEvent("198.51.100.7"))
	if err != nil || a != nil {
		t.Fatalf("an IP with an open action must be skipped: a=%+v err=%v", a, err)
	}
	if store.lastIns != nil || len(resp.blocked) != 0 {
		t.Fatalf("dedup must not insert or block: ins=%+v blocked=%v", store.lastIns, resp.blocked)
	}

	// Once the open action clears, a new event is handled again (escalated).
	store.open = false
	if a, err := e.Recommend(context.Background(), alertEvent("198.51.100.7")); err != nil || a == nil {
		t.Fatalf("after the open action clears it must recommend again: a=%+v err=%v", a, err)
	}
}

func TestEngineRecommendSkipsWhitelisted(t *testing.T) {
	store := newFakeStore(0)
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), true)
	_, ipnet, _ := net.ParseCIDR("192.168.81.0/24")
	e.SetWhitelist([]*net.IPNet{ipnet})

	a, err := e.Recommend(context.Background(), alertEvent("192.168.81.135"))
	if err != nil || a != nil {
		t.Fatalf("a whitelisted IP must be skipped: a=%+v err=%v", a, err)
	}
	if len(resp.blocked) != 0 || store.lastIns != nil {
		t.Fatalf("whitelisted IP must produce no block and no row: blocked=%v ins=%+v", resp.blocked, store.lastIns)
	}

	// A non-whitelisted IP still gets recommended/blocked.
	if a, err := e.Recommend(context.Background(), alertEvent("203.0.113.9")); err != nil || a == nil {
		t.Fatalf("non-whitelisted IP must still be handled: a=%+v err=%v", a, err)
	}
}

func TestEngineRecommendSkipsNoIP(t *testing.T) {
	e := NewEngine(newFakeStore(0), &fakeResponder{}, DefaultBanPolicy(), true)
	a, err := e.Recommend(context.Background(), &ingest.Event{Event: ingest.EventFields{Category: "intrusion_detection"}})
	if err != nil || a != nil {
		t.Fatalf("an event without an IP must be skipped: a=%+v err=%v", a, err)
	}
}

func TestEngineApproveExecutes(t *testing.T) {
	store := newFakeStore(0)
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), false)

	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	if err := e.Approve(context.Background(), a.ID, "alice"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(resp.blocked) != 1 {
		t.Fatal("approve should execute the block")
	}
	if len(store.statusLog) == 0 || !strings.HasPrefix(store.statusLog[0], "approved:alice") {
		t.Fatalf("approved status not recorded: %+v", store.statusLog)
	}
}

func TestEngineApproveRejectsNonRecommended(t *testing.T) {
	store := newFakeStore(0)
	e := NewEngine(store, &fakeResponder{}, DefaultBanPolicy(), false)
	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	_ = e.Dismiss(context.Background(), a.ID, "bob")
	if err := e.Approve(context.Background(), a.ID, "alice"); err == nil {
		t.Fatal("approving an already-dismissed action must error")
	}
}

func TestEngineExecuteFailureRecorded(t *testing.T) {
	store := newFakeStore(0)
	resp := &fakeResponder{err: errors.New("nft down")}
	e := NewEngine(store, resp, DefaultBanPolicy(), false)

	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	err := e.Approve(context.Background(), a.ID, "alice")
	if err == nil {
		t.Fatal("a responder failure must be propagated")
	}
	if len(store.execLog) != 1 || !strings.HasPrefix(store.execLog[0], "failed:") {
		t.Fatalf("the failure must be recorded: %+v", store.execLog)
	}
}

// ── Responders ────────────────────────────────────────────

func TestNftablesResponderArgs(t *testing.T) {
	var got []string
	r := &NftablesResponder{table: "deuswatch", set: "banlist", run: func(_ context.Context, name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}}
	if err := r.Block(context.Background(), "1.2.3.4", 10*time.Minute); err != nil {
		t.Fatalf("Block: %v", err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "nft add element inet deuswatch banlist") || !strings.Contains(joined, "timeout 600s") {
		t.Fatalf("wrong nft command: %q", joined)
	}
}

func TestNftablesPermanentNoTimeout(t *testing.T) {
	var joined string
	r := &NftablesResponder{table: "t", set: "s", run: func(_ context.Context, name string, args ...string) error {
		joined = name + " " + strings.Join(args, " ")
		return nil
	}}
	_ = r.Block(context.Background(), "9.9.9.9", 0)
	if strings.Contains(joined, "timeout") {
		t.Fatalf("a permanent ban must have no timeout: %q", joined)
	}
}

func TestCrowdSecResponderArgs(t *testing.T) {
	var got []string
	r := &CrowdSecResponder{run: func(_ context.Context, name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}}
	_ = r.Block(context.Background(), "1.2.3.4", time.Hour)
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "cscli decisions add --ip 1.2.3.4 --duration 1h0m0s --type ban") {
		t.Fatalf("wrong cscli command: %q", joined)
	}
}

func TestMikrotikResponderHTTP(t *testing.T) {
	var gotPath, gotBody, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := NewMikrotikResponder(srv.URL, "admin", "pw", "deuswatch_ban", false)
	r.hc = srv.Client()
	if err := r.Block(context.Background(), "5.6.7.8", 24*time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if gotPath != "/rest/ip/firewall/address-list" {
		t.Fatalf("wrong path: %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("basic auth not sent")
	}
	if !strings.Contains(gotBody, `"address":"5.6.7.8"`) || !strings.Contains(gotBody, `"timeout":"1d"`) {
		t.Fatalf("wrong body: %q", gotBody)
	}
}

func TestDryRunResponderNoop(t *testing.T) {
	r := NewDryRunResponder("nftables")
	if r.Name() != "dryrun(nftables)" {
		t.Fatalf("wrong name: %q", r.Name())
	}
	if err := r.Block(context.Background(), "1.2.3.4", time.Minute); err != nil {
		t.Fatalf("dry-run Block must not error: %v", err)
	}
	// A dry-run probe has nothing to reach, so it must never report a failure the operator would
	// chase: liveness (RESPONSE_LIVE) is the signal that something is actually being pushed.
	if err := r.Verify(context.Background()); err != nil {
		t.Fatalf("dry-run Verify must not error: %v", err)
	}
}

// ── Verify (reachability probes) ──────────────────────────

func TestNftablesVerifyMissingBinary(t *testing.T) {
	r := &NftablesResponder{table: "t", set: "s",
		run:      func(context.Context, string, ...string) error { return nil },
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
	}
	err := r.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nft binary is not installed") {
		t.Fatalf("expected a binary-not-installed error, got: %v", err)
	}
}

func TestNftablesVerifySetMissing(t *testing.T) {
	var ran string
	r := &NftablesResponder{table: "deuswatch", set: "banlist",
		lookPath: func(string) (string, error) { return "/usr/sbin/nft", nil },
		run: func(_ context.Context, name string, args ...string) error {
			ran = name + " " + strings.Join(args, " ")
			return errors.New("No such file or directory")
		},
	}
	err := r.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not usable") {
		t.Fatalf("expected an unusable-set error, got: %v", err)
	}
	// It must list the set, not add anything: a probe never changes state.
	if !strings.Contains(ran, "nft list set inet deuswatch banlist") {
		t.Fatalf("Verify ran the wrong (or a mutating) command: %q", ran)
	}
}

func TestNftablesVerifyOK(t *testing.T) {
	r := &NftablesResponder{table: "t", set: "s",
		lookPath: func(string) (string, error) { return "/usr/sbin/nft", nil },
		run:      func(context.Context, string, ...string) error { return nil },
	}
	if err := r.Verify(context.Background()); err != nil {
		t.Fatalf("a reachable nftables set must verify clean: %v", err)
	}
}

func TestCrowdSecVerify(t *testing.T) {
	missing := &CrowdSecResponder{
		run:      func(context.Context, string, ...string) error { return nil },
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
	}
	if err := missing.Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "cscli binary is not installed") {
		t.Fatalf("expected a cscli-not-installed error, got: %v", err)
	}

	var ran string
	down := &CrowdSecResponder{
		lookPath: func(string) (string, error) { return "/usr/bin/cscli", nil },
		run: func(_ context.Context, name string, args ...string) error {
			ran = name + " " + strings.Join(args, " ")
			return errors.New("connection refused")
		},
	}
	if err := down.Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "LAPI did not answer") {
		t.Fatalf("expected a LAPI-unreachable error, got: %v", err)
	}
	if !strings.Contains(ran, "cscli lapi status") {
		t.Fatalf("Verify ran the wrong command: %q", ran)
	}
}

// MultiResponder.Verify must surface a failing member rather than let a healthy one mask it.
func TestMultiResponderVerify(t *testing.T) {
	ok := &NftablesResponder{table: "t", set: "s",
		lookPath: func(string) (string, error) { return "/x", nil },
		run:      func(context.Context, string, ...string) error { return nil },
	}
	bad := &NftablesResponder{table: "t", set: "s",
		lookPath: func(string) (string, error) { return "/x", nil },
		run:      func(context.Context, string, ...string) error { return errors.New("boom") },
	}
	if err := NewMultiResponder([]Responder{ok, bad}).Verify(context.Background()); err == nil {
		t.Fatal("a failing member must make the multi probe fail")
	}
	if err := NewMultiResponder([]Responder{ok, ok}).Verify(context.Background()); err != nil {
		t.Fatalf("all-healthy members must verify clean: %v", err)
	}
}

// TestUnbanLiftsEveryBlockForTheIP is the regression guard for the lockout bug.
//
// Enforcement is per IP: ActiveBlocks, which the agent firewall and the edge sync are built from,
// returns DISTINCT source_ip over every approved or executed block. Unban used to lift one ROW.
// So an IP with several active blocks stayed in the nftables set after the operator unbanned the
// entry they could see: the row flipped to unbanned, the UI said success, and the host stayed
// locked out with nothing saying why. With auto-approve on, several rows per IP is the normal
// case, which is how somebody loses SSH to their own server.
func TestUnbanLiftsEveryBlockForTheIP(t *testing.T) {
	const ip = "203.0.113.50"
	store := newFakeStore(0)
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), true)

	// Three separate detections for the same IP, all auto-approved and executed, which is what a
	// repeatedly-offending address produces.
	var ids []string
	for i := 0; i < 3; i++ {
		store.open = false
		a, err := e.Recommend(context.Background(), alertEvent(ip))
		if err != nil || a == nil {
			t.Fatalf("Recommend %d: a=%+v err=%v", i, a, err)
		}
		ids = append(ids, a.ID)
	}
	for _, id := range ids {
		if got := store.actions[id].Status; got != StatusExecuted {
			t.Fatalf("action %s is %q, want executed before the unban", id, got)
		}
	}

	// Unban the one the operator happens to be looking at.
	n, err := e.Unban(context.Background(), ids[0], "firdaus")
	if err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if n != 3 {
		t.Errorf("lifted %d blocks, want all 3; the caller is told what it cleared", n)
	}

	// Every row for that IP must be lifted, or the IP stays in ActiveBlocks and the host stays
	// blocked no matter what the screen says.
	for _, id := range ids {
		if got := store.actions[id].Status; got != StatusUnbanned {
			t.Errorf("action %s is still %q: the IP remains blocked after an unban", id, got)
		}
	}

	// The responder is told once, not once per row: a router would otherwise be asked to delete
	// the same address-list entry three times.
	if len(resp.unblocked) != 1 || resp.unblocked[0] != ip {
		t.Errorf("responder unblocks = %v, want exactly one for %s", resp.unblocked, ip)
	}
}

// TestUnbanLeavesOtherIPsAlone: lifting per IP must not become lifting everything.
func TestUnbanLeavesOtherIPsAlone(t *testing.T) {
	store := newFakeStore(0)
	e := NewEngine(store, &fakeResponder{}, DefaultBanPolicy(), true)

	mine, err := e.Recommend(context.Background(), alertEvent("203.0.113.50"))
	if err != nil {
		t.Fatal(err)
	}
	store.open = false
	other, err := e.Recommend(context.Background(), alertEvent("198.51.100.9"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.Unban(context.Background(), mine.ID, "firdaus"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if got := store.actions[other.ID].Status; got != StatusExecuted {
		t.Errorf("an unrelated IP was unbanned too: %s is %q", other.ID, got)
	}
}

// TestUnbanRejectsAlreadyLifted keeps the guard that stopped an unban being reported for an
// action that was never active.
func TestUnbanRejectsAlreadyLifted(t *testing.T) {
	store := newFakeStore(0)
	e := NewEngine(store, &fakeResponder{}, DefaultBanPolicy(), false)

	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	if _, err := e.Unban(context.Background(), a.ID, "alice"); err == nil {
		t.Fatal("unbanning a merely recommended action must error")
	}
}
