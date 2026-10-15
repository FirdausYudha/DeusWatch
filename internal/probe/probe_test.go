package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"metaData":{"code":"200"}}`))
	}))
	defer srv.Close()

	got := Run(context.Background(), Check{
		Kind: KindHTTP, Target: srv.URL, Headers: map[string]string{"X-Token": "secret"},
		ExpectBody: `"code":"200"`, Timeout: 5 * time.Second,
	}, srv.Client())
	if !got.OK || got.Status != 200 || got.Error != "" {
		t.Fatalf("expected a healthy result, got %+v", got)
	}
}

// The failure this whole feature exists for: the endpoint answers HTTP 200 while the payload says
// the operation failed. A status-code-only check calls that healthy and the counter stays stuck.
func TestHTTPTwoHundredWithFailureInBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metaData":{"code":"500","message":"Service sedang gangguan"}}`))
	}))
	defer srv.Close()

	got := Run(context.Background(), Check{
		Kind: KindHTTP, Target: srv.URL, ExpectBody: `"code":"200"`, Timeout: 5 * time.Second,
	}, srv.Client())
	if got.OK {
		t.Fatal("a 200 whose body reports failure must not pass")
	}
	if got.Status != 200 || !strings.Contains(got.Error, "did not contain") {
		t.Fatalf("error should name the body mismatch, got %+v", got)
	}
}

func TestHTTPStatusRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusUnauthorized) // healthy for this endpoint, see below
	}))
	defer srv.Close()

	// Default rule: anything >= 400 is a failure.
	if got := Run(context.Background(), Check{Kind: KindHTTP, Target: srv.URL + "/gone", Timeout: time.Second},
		srv.Client()); got.OK || !strings.Contains(got.Error, "HTTP 500") {
		t.Fatalf("500 should fail with its code named, got %+v", got)
	}
	// An explicit expectation lets an endpoint that always answers 401 count as healthy.
	if got := Run(context.Background(),
		Check{Kind: KindHTTP, Target: srv.URL + "/auth", ExpectStatus: 401, Timeout: time.Second},
		srv.Client()); !got.OK {
		t.Fatalf("401 should pass when it is the expected status, got %+v", got)
	}
	// ...and the same endpoint fails when it stops answering what was expected.
	if got := Run(context.Background(),
		Check{Kind: KindHTTP, Target: srv.URL + "/auth", ExpectStatus: 200, Timeout: time.Second},
		srv.Client()); got.OK || !strings.Contains(got.Error, "expected 200") {
		t.Fatalf("unexpected status should fail and say what was expected, got %+v", got)
	}
}

// Up on paper, down at the counter: a slow service has to register as a failure or the rule buys
// nothing.
func TestHTTPLatencyBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	got := Run(context.Background(), Check{
		Kind: KindHTTP, Target: srv.URL, Timeout: 5 * time.Second, LatencyWarn: 20 * time.Millisecond,
	}, srv.Client())
	if got.OK || !strings.Contains(got.Error, "over the 20ms budget") {
		t.Fatalf("a slow response should fail the latency rule, got %+v", got)
	}
	if got.Status != 200 {
		t.Errorf("the real status must still be recorded, got %d", got.Status)
	}
}

func TestHTTPUnreachableIsAResultNotAnError(t *testing.T) {
	// Port 1 on loopback refuses immediately; the point is that Run reports rather than panics.
	got := Run(context.Background(),
		Check{Kind: KindHTTP, Target: "http://127.0.0.1:1/", Timeout: time.Second}, http.DefaultClient)
	if got.OK || got.Error == "" {
		t.Fatalf("an unreachable target must come back as a failed result with a reason, got %+v", got)
	}
}

func TestTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	if got := Run(context.Background(),
		Check{Kind: KindTCP, Target: ln.Addr().String(), Timeout: 2 * time.Second},
		nil); !got.OK {
		t.Fatalf("an open port should pass, got %+v", got)
	}
	if got := Run(context.Background(),
		Check{Kind: KindTCP, Target: "127.0.0.1:1", Timeout: time.Second},
		nil); got.OK || !strings.Contains(got.Error, "cannot connect") {
		t.Fatalf("a closed port should fail with a reason, got %+v", got)
	}
}
