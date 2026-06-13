package respond

import (
	"context"
	"errors"
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
		{4, 0}, // permanen
		{99, 0},
	}
	for _, c := range cases {
		if got := p.Duration(c.offense); got != c.want {
			t.Errorf("offense %d: durasi %v, mau %v", c.offense, got, c.want)
		}
	}
}

func TestBanPolicyCapNoPermanent(t *testing.T) {
	p := BanPolicy{Durations: []time.Duration{time.Minute, time.Hour}, Permanent: false}
	if got := p.Duration(5); got != time.Hour {
		t.Fatalf("tanpa permanent harus mentok di durasi terpanjang, dapat %v", got)
	}
}

// ── fake store & responder ────────────────────────────────

type fakeStore struct {
	offenses  int
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
func (f *fakeStore) Offenses(_ context.Context, _ string) (int, error) { return f.offenses, nil }
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
	dur     time.Duration
	err     error
}

func (f *fakeResponder) Name() string { return "fake" }
func (f *fakeResponder) Block(_ context.Context, ip string, d time.Duration) error {
	f.blocked = append(f.blocked, ip)
	f.dur = d
	return f.err
}
func (f *fakeResponder) Unblock(_ context.Context, _ string) error { return nil }

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
		t.Fatalf("harus recommended: %+v", a)
	}
	if a.OffenseCount != 1 || a.BanSeconds != int((10 * time.Minute).Seconds()) {
		t.Fatalf("ban progresif salah: offense=%d sec=%d", a.OffenseCount, a.BanSeconds)
	}
	if len(resp.blocked) != 0 {
		t.Fatal("tanpa auto-approve tak boleh ada blokir")
	}
}

func TestEngineRecommendAutoApprove(t *testing.T) {
	store := newFakeStore(2) // sudah 2x diblok -> pelanggaran ke-3 = 24h
	resp := &fakeResponder{}
	e := NewEngine(store, resp, DefaultBanPolicy(), true)

	a, err := e.Recommend(context.Background(), alertEvent("45.155.205.99"))
	if err != nil {
		t.Fatalf("Recommend: %v", err)
	}
	if a.OffenseCount != 3 || a.BanSeconds != int((24 * time.Hour).Seconds()) {
		t.Fatalf("progresif salah: offense=%d sec=%d", a.OffenseCount, a.BanSeconds)
	}
	if len(resp.blocked) != 1 || resp.blocked[0] != "45.155.205.99" {
		t.Fatalf("auto-approve harus memblokir: %+v", resp.blocked)
	}
	if resp.dur != 24*time.Hour {
		t.Fatalf("durasi blokir salah: %v", resp.dur)
	}
	if len(store.execLog) != 1 || store.execLog[0] != "executed" {
		t.Fatalf("eksekusi tak tercatat executed: %+v", store.execLog)
	}
}

func TestEngineRecommendSkipsNoIP(t *testing.T) {
	e := NewEngine(newFakeStore(0), &fakeResponder{}, DefaultBanPolicy(), true)
	a, err := e.Recommend(context.Background(), &ingest.Event{Event: ingest.EventFields{Category: "intrusion_detection"}})
	if err != nil || a != nil {
		t.Fatalf("event tanpa IP harus dilewati: a=%+v err=%v", a, err)
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
		t.Fatal("approve harus mengeksekusi blokir")
	}
	if len(store.statusLog) == 0 || !strings.HasPrefix(store.statusLog[0], "approved:alice") {
		t.Fatalf("status approved tak tercatat: %+v", store.statusLog)
	}
}

func TestEngineApproveRejectsNonRecommended(t *testing.T) {
	store := newFakeStore(0)
	e := NewEngine(store, &fakeResponder{}, DefaultBanPolicy(), false)
	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	_ = e.Dismiss(context.Background(), a.ID, "bob")
	if err := e.Approve(context.Background(), a.ID, "alice"); err == nil {
		t.Fatal("approve aksi yang sudah dismissed harus error")
	}
}

func TestEngineExecuteFailureRecorded(t *testing.T) {
	store := newFakeStore(0)
	resp := &fakeResponder{err: errors.New("nft down")}
	e := NewEngine(store, resp, DefaultBanPolicy(), false)

	a, _ := e.Recommend(context.Background(), alertEvent("1.2.3.4"))
	err := e.Approve(context.Background(), a.ID, "alice")
	if err == nil {
		t.Fatal("kegagalan responder harus diteruskan")
	}
	if len(store.execLog) != 1 || !strings.HasPrefix(store.execLog[0], "failed:") {
		t.Fatalf("kegagalan harus tercatat: %+v", store.execLog)
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
		t.Fatalf("perintah nft salah: %q", joined)
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
		t.Fatalf("ban permanen tak boleh ada timeout: %q", joined)
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
		t.Fatalf("perintah cscli salah: %q", joined)
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

	r := NewMikrotikResponder(srv.URL, "admin", "pw", "deuswatch_ban")
	r.hc = srv.Client()
	if err := r.Block(context.Background(), "5.6.7.8", 24*time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if gotPath != "/rest/ip/firewall/address-list" {
		t.Fatalf("path salah: %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("basic auth tak terkirim")
	}
	if !strings.Contains(gotBody, `"address":"5.6.7.8"`) || !strings.Contains(gotBody, `"timeout":"1d"`) {
		t.Fatalf("body salah: %q", gotBody)
	}
}

func TestDryRunResponderNoop(t *testing.T) {
	r := NewDryRunResponder("nftables")
	if r.Name() != "dryrun(nftables)" {
		t.Fatalf("nama salah: %q", r.Name())
	}
	if err := r.Block(context.Background(), "1.2.3.4", time.Minute); err != nil {
		t.Fatalf("dry-run Block tak boleh error: %v", err)
	}
}
