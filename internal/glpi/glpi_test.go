package glpi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGLPI mimics the documented GLPI REST shape: a session token from initSession, then
// App-Token + Session-Token on everything after it.
func fakeGLPI(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/apirest.php") {
			t.Errorf("request did not go to the API root: %s", r.URL.Path)
		}
		if r.Header.Get("App-Token") != "app-123" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`["ERROR_APP_TOKEN","missing App-Token"]`))
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/apirest.php") {
		case "/initSession":
			if r.Header.Get("Authorization") != "user_token user-456" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"session_token":"sess-789"}`))
		default:
			if r.Header.Get("Session-Token") != "sess-789" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`["ERROR_SESSION_TOKEN_INVALID",""]`))
				return
			}
			h(w, r)
		}
	}))
}

func open(t *testing.T, url string) *Session {
	t.Helper()
	s, err := New(url, "app-123", "user-456", false).Open(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return s
}

func TestCreateAndReadTicket(t *testing.T) {
	var got map[string]any
	srv := fakeGLPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/Ticket"):
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				Input map[string]any `json:"input"`
			}
			_ = json.Unmarshal(body, &payload)
			got = payload.Input
			_, _ = w.Write([]byte(`{"id":4242,"message":""}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Ticket/4242"):
			_, _ = w.Write([]byte(`{"id":4242,"status":5}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	defer srv.Close()

	s := open(t, srv.URL)
	id, err := s.CreateTicket(context.Background(), NewTicket{
		Title: "Brute force on SIMRS", Content: "detail", Urgency: 4,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id != 4242 {
		t.Fatalf("expected the id GLPI returned, got %d", id)
	}
	if got["name"] != "Brute force on SIMRS" || got["content"] != "detail" {
		t.Errorf("ticket fields were not sent as GLPI expects: %+v", got)
	}
	// Unset optional ids must be ABSENT, not zero: a 0 points GLPI at a record that does not exist.
	if _, ok := got["itilcategories_id"]; ok {
		t.Errorf("an unset category must not be sent at all: %+v", got)
	}

	st, err := s.TicketStatus(context.Background(), 4242)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st != StatusSolved {
		t.Fatalf("expected the status GLPI reported, got %d", st)
	}
}

// GLPI has returned the created object inside a single-element array in some versions. Discovering
// that in production would mean every push silently failing.
func TestCreateAcceptsArrayResponse(t *testing.T) {
	id, err := parseCreatedID([]byte(`[{"id":77,"message":""}]`))
	if err != nil || id != 77 {
		t.Fatalf("array response should yield the id, got %d (%v)", id, err)
	}
	if _, err := parseCreatedID([]byte(`{"message":"no id here"}`)); err == nil {
		t.Fatal("a response without an id must be an error, not a silent zero")
	}
}

// An error must name what GLPI said, so the operator knows whether to fix the token or the URL.
func TestErrorCarriesGLPIMessage(t *testing.T) {
	srv := fakeGLPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`["ERROR_GLPI_ADD","mandatory field is missing"]`))
	})
	defer srv.Close()

	_, err := open(t, srv.URL).CreateTicket(context.Background(), NewTicket{Title: "x"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "mandatory field is missing") {
		t.Fatalf("error should quote GLPI, got %v", err)
	}
}

func TestBadTokenIsReported(t *testing.T) {
	srv := fakeGLPI(t, func(http.ResponseWriter, *http.Request) {})
	defer srv.Close()

	_, err := New(srv.URL, "app-123", "wrong-user-token", false).Open(context.Background())
	if err == nil {
		t.Fatal("a rejected user token must fail Open, not yield an empty session")
	}
}

// Operators paste what is in their address bar; both forms have to work.
func TestBaseURLAcceptsInstanceRoot(t *testing.T) {
	for _, in := range []string{"https://glpi.test", "https://glpi.test/", "https://glpi.test/apirest.php"} {
		if got := New(in, "a", "b", false).base; got != "https://glpi.test/apirest.php" {
			t.Errorf("New(%q) built base %q", in, got)
		}
	}
}

func TestUrgencyFromSeverity(t *testing.T) {
	cases := map[int]int{0: 1, 2: 3, 4: 5, -3: 1, 99: 5}
	for sev, want := range cases {
		if got := UrgencyFromSeverity(sev); got != want {
			t.Errorf("severity %d → urgency %d, want %d", sev, got, want)
		}
	}
}

// The mapping where the two vocabularies do not line up. Pending must stay live: calling it
// resolved would stop the SLA clock on work that has not finished.
func TestStatusMapping(t *testing.T) {
	cases := []struct {
		glpi int
		want string
		ok   bool
	}{
		{StatusNew, "open", true},
		{StatusAssigned, "in_progress", true},
		{StatusPlanned, "in_progress", true},
		{StatusPending, "in_progress", true},
		{StatusSolved, "resolved", true},
		{StatusClosed, "closed", true},
		{99, "", false},
		{0, "", false},
	}
	for _, c := range cases {
		got, ok := StatusToDeusWatch(c.glpi)
		if got != c.want || ok != c.ok {
			t.Errorf("GLPI status %d → (%q,%v), want (%q,%v)", c.glpi, got, ok, c.want, c.ok)
		}
	}
}
