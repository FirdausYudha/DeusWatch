package respond

import (
	"context"
	"log"

	"deuswatch/internal/ingest"
)

// ActionStore adalah persistensi yang dibutuhkan Engine (dipenuhi *Store; di-stub di test).
type ActionStore interface {
	Insert(ctx context.Context, a *Action) (string, error)
	Offenses(ctx context.Context, ip string) (int, error)
	Get(ctx context.Context, id string) (*Action, error)
	SetStatus(ctx context.Context, id string, status Status, decidedBy string) error
	SetExecuted(ctx context.Context, id, responder string, execErr error) error
}

// Engine mengubah alert menjadi rekomendasi blokir & mengeksekusinya setelah approval.
type Engine struct {
	store       ActionStore
	responder   Responder // boleh nil (eksekusi dinonaktifkan)
	policy      BanPolicy
	autoApprove bool
}

// NewEngine membuat engine. autoApprove=true langsung mengeksekusi tanpa approval manual.
func NewEngine(store ActionStore, responder Responder, policy BanPolicy, autoApprove bool) *Engine {
	if len(policy.Durations) == 0 {
		policy = DefaultBanPolicy()
	}
	return &Engine{store: store, responder: responder, policy: policy, autoApprove: autoApprove}
}

// Recommend membuat rekomendasi blokir dari sebuah alert (butuh source IP). Durasi
// ban dihitung progresif dari riwayat IP. Bila autoApprove aktif & ada responder,
// langsung dieksekusi. Mengembalikan nil,nil bila event tak relevan (tanpa IP).
func (e *Engine) Recommend(ctx context.Context, ev *ingest.Event) (*Action, error) {
	if ev == nil || ev.Source == nil || ev.Source.IP == "" {
		return nil, nil
	}
	prior, err := e.store.Offenses(ctx, ev.Source.IP)
	if err != nil {
		return nil, err
	}
	offense := prior + 1
	dur := e.policy.Duration(offense)

	a := &Action{
		SourceIP:     ev.Source.IP,
		ActionType:   "block",
		Reason:       reasonFor(ev),
		BanSeconds:   int(dur.Seconds()),
		OffenseCount: offense,
		Source:       string(ingest.RemediationPlaybook),
		Status:       StatusRecommended,
	}
	if ev.Rule != nil {
		a.RuleID = ev.Rule.ID
	}
	id, err := e.store.Insert(ctx, a)
	if err != nil {
		return nil, err
	}
	a.ID = id

	if e.autoApprove && e.responder != nil {
		if err := e.execute(ctx, a, "auto"); err != nil {
			log.Printf("respond: auto-eksekusi %s gagal: %v", a.SourceIP, err)
		}
	}
	return a, nil
}

// Approve menyetujui aksi lalu mengeksekusinya.
func (e *Engine) Approve(ctx context.Context, id, by string) error {
	a, err := e.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if a.Status != StatusRecommended {
		return errStatus(a.Status)
	}
	if err := e.store.SetStatus(ctx, id, StatusApproved, by); err != nil {
		return err
	}
	return e.execute(ctx, a, by)
}

// Dismiss menolak rekomendasi (tak dieksekusi).
func (e *Engine) Dismiss(ctx context.Context, id, by string) error {
	a, err := e.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if a.Status != StatusRecommended {
		return errStatus(a.Status)
	}
	return e.store.SetStatus(ctx, id, StatusDismissed, by)
}

// execute menjalankan blokir via responder & mencatat hasilnya.
func (e *Engine) execute(ctx context.Context, a *Action, _ string) error {
	if e.responder == nil {
		return e.store.SetExecuted(ctx, a.ID, "", errNoResponder)
	}
	blockErr := e.responder.Block(ctx, a.SourceIP, a.BanDuration())
	if serr := e.store.SetExecuted(ctx, a.ID, e.responder.Name(), blockErr); serr != nil {
		return serr
	}
	return blockErr
}

func reasonFor(ev *ingest.Event) string {
	if ev.Rule != nil && ev.Rule.Name != "" {
		return ev.Rule.Name
	}
	if ev.DeusWatch.Label != "" {
		return ev.DeusWatch.Label
	}
	return "alert"
}

type statusError struct{ s Status }

func (e statusError) Error() string { return "respond: aksi sudah " + string(e.s) + " (bukan recommended)" }
func errStatus(s Status) error      { return statusError{s} }

type simpleError string

func (e simpleError) Error() string { return string(e) }

const errNoResponder = simpleError("respond: tidak ada responder dikonfigurasi (RESPONDER=none)")
