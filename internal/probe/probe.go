// Package probe runs one service/API health check and reports what happened.
//
// It exists because "is the host up" and "is the service working" are different questions, and a
// hospital integration fails at the second one while the first stays green. The onsite engineer
// put it plainly: ping is fine, GET works, but edit and the fingerprint service do not, and the
// infra dashboard shows nothing while the registration desk is stuck. So a probe here asserts what
// one ENDPOINT is supposed to do, not whether a machine answers.
//
// The package is deliberately pure: it takes a Check, performs it, and returns a Result. No
// database, no scheduling, no alerting. That keeps every rule below testable against an httptest
// server, which matters because these rules decide whether somebody gets paged at 3am.
package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Kinds of check. HTTP covers the web services an integration actually uses; TCP covers the
// databases and plain sockets where there is no HTTP to speak.
const (
	KindHTTP = "http"
	KindTCP  = "tcp"
)

// MaxBodyRead bounds how much of a response body is read for the ExpectBody match. A health probe
// that pulls a multi-megabyte error page every 60 seconds is its own outage.
const MaxBodyRead = 64 << 10

// Check is one endpoint to probe.
type Check struct {
	Kind   string // KindHTTP | KindTCP
	Target string // URL for http, host:port for tcp
	Method string // defaults to GET
	// Headers carries request headers, including credentials. The BPJS web services want a
	// username and a token on every call; the caller decrypts them before handing them over.
	Headers map[string]string
	// ExpectStatus is the exact status that means healthy. 0 means "any non-error response",
	// i.e. below 400. A specific code is for endpoints that answer 401 or 404 when they are fine.
	ExpectStatus int
	// ExpectBody, when set, must appear in the response body. This is the rule that catches the
	// endpoints answering HTTP 200 with a failure inside the payload, which a status check misses.
	ExpectBody string
	Timeout    time.Duration
	// LatencyWarn, when non-zero, fails the check if the response took longer. A registration API
	// that answers in nine seconds is up on paper and down at the counter.
	LatencyWarn time.Duration
}

// Result is what one probe observed.
type Result struct {
	OK      bool
	Status  int           // HTTP status; 0 for TCP or when no response arrived
	Latency time.Duration // time to first response (HTTP) or to connect (TCP)
	// Error is operator-facing and says what to go and look at. Empty when OK.
	Error string
}

// Run performs the check. It never returns an error: a failed probe is a Result with OK=false and
// a reason, because "the check could not be made" and "the service is down" land on the same
// screen and the operator needs the reason either way.
func Run(ctx context.Context, c Check, hc *http.Client) Result {
	if c.Kind == KindTCP {
		return runTCP(ctx, c)
	}
	return runHTTP(ctx, c, hc)
}

func runTCP(ctx context.Context, c Check) Result {
	start := time.Now()
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", c.Target)
	lat := time.Since(start)
	if err != nil {
		return Result{Latency: lat, Error: fmt.Sprintf("cannot connect to %s: %v", c.Target, err)}
	}
	_ = conn.Close()
	if over := latencyBreach(lat, c.LatencyWarn); over != "" {
		return Result{Latency: lat, Error: over}
	}
	return Result{OK: true, Latency: lat}
}

func runHTTP(ctx context.Context, c Check, hc *http.Client) Result {
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	rctx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(rctx, method, c.Target, nil)
	if err != nil {
		return Result{Error: fmt.Sprintf("bad request for %s: %v", c.Target, err)}
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := hc.Do(req)
	lat := time.Since(start)
	if err != nil {
		// Reachability, TLS and timeout all land here. The raw error names which one, and that is
		// the difference between "fix the network" and "fix the certificate".
		return Result{Latency: lat, Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	var body string
	if c.ExpectBody != "" {
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, MaxBodyRead))
		if rerr != nil {
			return Result{Status: resp.StatusCode, Latency: lat,
				Error: fmt.Sprintf("HTTP %d but the body could not be read: %v", resp.StatusCode, rerr)}
		}
		body = string(b)
	} else {
		// Drain a little so the connection can be reused rather than torn down each interval.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBodyRead))
	}

	if msg := statusBreach(resp.StatusCode, c.ExpectStatus); msg != "" {
		return Result{Status: resp.StatusCode, Latency: lat, Error: msg}
	}
	if c.ExpectBody != "" && !strings.Contains(body, c.ExpectBody) {
		// The failure mode this rule exists for: a 200 whose payload says the operation failed.
		return Result{Status: resp.StatusCode, Latency: lat,
			Error: fmt.Sprintf("HTTP %d but the response did not contain %q", resp.StatusCode, c.ExpectBody)}
	}
	if over := latencyBreach(lat, c.LatencyWarn); over != "" {
		return Result{Status: resp.StatusCode, Latency: lat, Error: over}
	}
	return Result{OK: true, Status: resp.StatusCode, Latency: lat}
}

// statusBreach reports why a status code fails the check, or "" when it passes.
func statusBreach(got, expect int) string {
	if expect > 0 {
		if got != expect {
			return fmt.Sprintf("HTTP %d, expected %d", got, expect)
		}
		return ""
	}
	if got >= 400 {
		return fmt.Sprintf("HTTP %d", got)
	}
	return ""
}

// latencyBreach reports a latency rule violation, or "" when within budget (or no budget set).
func latencyBreach(got, budget time.Duration) string {
	if budget <= 0 || got <= budget {
		return ""
	}
	return fmt.Sprintf("responded in %dms, over the %dms budget", got.Milliseconds(), budget.Milliseconds())
}
