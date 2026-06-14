package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

type fakeNotifier struct {
	mu    sync.Mutex
	name  string
	got   []Notification
	err   error
}

func (f *fakeNotifier) Name() string { return f.name }
func (f *fakeNotifier) Notify(_ context.Context, n Notification) error {
	f.mu.Lock()
	f.got = append(f.got, n)
	f.mu.Unlock()
	return f.err
}
func (f *fakeNotifier) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.got) }

func highAlert(ip string) Notification {
	return Notification{Title: "SSH Brute Force", Severity: ingest.SeverityHigh, SourceIP: ip, Rule: "SSH Brute Force"}
}

func TestFromEvent(t *testing.T) {
	ev := &ingest.Event{
		Event:  ingest.EventFields{Severity: ingest.SeverityHigh},
		Source: &ingest.Endpoint{IP: "1.2.3.4"},
		Rule:   &ingest.Rule{ID: "r1", Name: "SSH Brute Force"},
		Threat: &ingest.Threat{Technique: ingest.Technique{ID: "T1110"}, TacticName: "Credential Access"},
	}
	n := FromEvent(ev)
	if n.SourceIP != "1.2.3.4" || n.Rule != "SSH Brute Force" || n.Technique != "T1110" {
		t.Fatalf("wrong mapping: %+v", n)
	}
	if !strings.Contains(n.Text(), "T1110") || !strings.Contains(n.Text(), "HIGH") {
		t.Fatalf("incomplete text: %q", n.Text())
	}
}

func TestDispatcherSeverityThreshold(t *testing.T) {
	f := &fakeNotifier{name: "fake"}
	d := NewDispatcher(ingest.SeverityHigh, 0, f)

	_ = d.Dispatch(context.Background(), Notification{Severity: ingest.SeverityMedium, Rule: "x"})
	if f.count() != 0 {
		t.Fatal("severity below the threshold must not be sent")
	}
	_ = d.Dispatch(context.Background(), highAlert("1.1.1.1"))
	if f.count() != 1 {
		t.Fatal("severity >= threshold must be sent")
	}
}

func TestDispatcherThrottle(t *testing.T) {
	f := &fakeNotifier{name: "fake"}
	d := NewDispatcher(ingest.SeverityLow, 10*time.Minute, f)
	now := time.Now()
	d.now = func() time.Time { return now }

	_ = d.Dispatch(context.Background(), highAlert("9.9.9.9"))
	_ = d.Dispatch(context.Background(), highAlert("9.9.9.9")) // duplicate within the window
	if f.count() != 1 {
		t.Fatalf("the duplicate must be suppressed, sent %d", f.count())
	}
	// A different IP still passes.
	_ = d.Dispatch(context.Background(), highAlert("8.8.8.8"))
	if f.count() != 2 {
		t.Fatalf("a different IP must pass, sent %d", f.count())
	}
	// After the window passes.
	now = now.Add(11 * time.Minute)
	_ = d.Dispatch(context.Background(), highAlert("9.9.9.9"))
	if f.count() != 3 {
		t.Fatalf("after throttle it must pass again, sent %d", f.count())
	}
}

func TestDispatcherFanOutAggregatesErrors(t *testing.T) {
	ok := &fakeNotifier{name: "ok"}
	bad := &fakeNotifier{name: "bad", err: errors.New("boom")}
	d := NewDispatcher(ingest.SeverityLow, 0, ok, bad)

	err := d.Dispatch(context.Background(), highAlert("1.1.1.1"))
	if err == nil || !strings.Contains(err.Error(), "bad: boom") {
		t.Fatalf("sink errors must be collected: %v", err)
	}
	if ok.count() != 1 {
		t.Fatal("the other sink must still receive even if one fails")
	}
}

func TestDispatcherDisabled(t *testing.T) {
	var d *Dispatcher
	if d.Enabled() {
		t.Fatal("a nil dispatcher must not be enabled")
	}
	if err := d.Dispatch(context.Background(), highAlert("1.1.1.1")); err != nil {
		t.Fatalf("dispatch to nil must not error: %v", err)
	}
}

func TestTelegramNotifier(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tn := NewTelegramNotifier("TOKEN", "CHAT")
	tn.base = srv.URL
	tn.hc = srv.Client()
	if err := tn.Notify(context.Background(), highAlert("1.2.3.4")); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotPath != "/botTOKEN/sendMessage" {
		t.Fatalf("wrong path: %q", gotPath)
	}
	if !strings.Contains(gotBody, "chat_id=CHAT") {
		t.Fatalf("body missing chat_id: %q", gotBody)
	}
}

func TestWebhookNotifier(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wn := NewWebhookNotifier(srv.URL)
	wn.hc = srv.Client()
	if err := wn.Notify(context.Background(), highAlert("5.6.7.8")); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if !strings.Contains(gotBody, `"source_ip":"5.6.7.8"`) || !strings.Contains(gotBody, `"severity":"high"`) {
		t.Fatalf("wrong webhook payload: %q", gotBody)
	}
}

func TestEmailNotifierMessage(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte
	var gotAuth smtp.Auth
	e := NewEmailNotifier("smtp.example", "587", "user", "pass", "soc@example.com", []string{"a@x.com", "b@x.com"})
	e.send = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		gotAddr, gotAuth, gotFrom, gotTo, gotMsg = addr, a, from, to, msg
		return nil
	}
	if err := e.Notify(context.Background(), highAlert("1.2.3.4")); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if gotAddr != "smtp.example:587" {
		t.Fatalf("wrong addr: %q", gotAddr)
	}
	if gotAuth == nil {
		t.Fatal("auth must be set when a user is present")
	}
	if gotFrom != "soc@example.com" || len(gotTo) != 2 {
		t.Fatalf("wrong from/to: %q %v", gotFrom, gotTo)
	}
	msg := string(gotMsg)
	if !strings.Contains(msg, "Subject: [DeusWatch][HIGH] SSH Brute Force") || !strings.Contains(msg, "To: a@x.com, b@x.com") {
		t.Fatalf("wrong email header:\n%s", msg)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a@x.com , b@x.com ,, ")
	if len(got) != 2 || got[0] != "a@x.com" || got[1] != "b@x.com" {
		t.Fatalf("wrong split: %+v", got)
	}
}
