package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginLimiterLocksAfterThreshold(t *testing.T) {
	l := NewLoginLimiter(3, time.Minute, time.Minute)
	keys := []string{"ip:1.2.3.4", "user:admin"}

	if w := l.RetryAfter(keys...); w != 0 {
		t.Fatalf("fresh limiter should allow, got wait %v", w)
	}
	if l.Fail(keys...) || l.Fail(keys...) {
		t.Fatal("must not lock before the threshold")
	}
	if !l.Fail(keys...) {
		t.Fatal("3rd failure must report the lock transition")
	}
	if w := l.RetryAfter(keys...); w <= 0 {
		t.Fatal("locked key must return a positive wait")
	}
	// The lock applies via EITHER key: same IP, different username.
	if w := l.RetryAfter("ip:1.2.3.4", "user:other"); w <= 0 {
		t.Fatal("IP key must stay locked for other usernames")
	}
	// A different IP + different user is unaffected.
	if w := l.RetryAfter("ip:5.6.7.8", "user:other"); w != 0 {
		t.Fatalf("unrelated keys must be allowed, got wait %v", w)
	}
}

func TestLoginLimiterResetAndDisable(t *testing.T) {
	l := NewLoginLimiter(2, time.Minute, time.Minute)
	l.Fail("user:bob")
	l.Reset("user:bob")
	if l.Fail("user:bob") {
		t.Fatal("reset must clear the failure count")
	}

	off := NewLoginLimiter(0, time.Minute, time.Minute) // 0 = disabled
	for i := 0; i < 10; i++ {
		off.Fail("user:bob")
	}
	if w := off.RetryAfter("user:bob"); w != 0 {
		t.Fatal("disabled limiter must never lock")
	}
}

func TestLoginLimiterWindowExpiry(t *testing.T) {
	l := NewLoginLimiter(3, 10*time.Millisecond, time.Minute)
	l.Fail("k")
	l.Fail("k")
	time.Sleep(20 * time.Millisecond)
	// The window elapsed: the count restarts, so this must not lock.
	if l.Fail("k") {
		t.Fatal("failures outside the window must not accumulate")
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		user, pw string
		ok       bool
	}{
		{"alice", "correct horse battery staple", true},
		{"alice", "short7!", false},              // under min length
		{"alice", "password123", false},          // common list
		{"alice", "ALICE", false},                // too short AND username; rejected
		{"christopher", "Christopher", false},    // equals username (case-insensitive)
		{"alice", "aaaaaaaaaa", false},           // one repeated character
		{"alice", "thewatcher", false},           // shipped default must not be reused
		{"alice", "N0t-common-at-all", true},
	}
	for _, c := range cases {
		err := ValidatePassword(c.user, c.pw)
		if c.ok && err != nil {
			t.Errorf("ValidatePassword(%q,%q) unexpectedly rejected: %v", c.user, c.pw, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidatePassword(%q,%q) unexpectedly accepted", c.user, c.pw)
		}
	}
}

func TestSetMinPasswordLenClampsFloor(t *testing.T) {
	defer SetMinPasswordLen(8)
	SetMinPasswordLen(4) // must clamp back up to 8
	if err := ValidatePassword("u", "sevench"); err == nil {
		t.Fatal("7-char password must stay rejected even after a lower override")
	}
	SetMinPasswordLen(12)
	if err := ValidatePassword("u", "elevenchars"); err == nil {
		t.Fatal("11-char password must be rejected at min 12")
	}
	if err := ValidatePassword("u", "twelve chars"); err != nil {
		t.Fatalf("12-char password must pass at min 12: %v", err)
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	defer func() { trustedProxies = nil }()

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.RemoteAddr = "172.18.0.5:41000" // e.g. the nginx container
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	// No trust configured: the header is ignored.
	if got := ClientIP(req); got != "172.18.0.5" {
		t.Fatalf("without trust config want peer IP, got %s", got)
	}

	if err := SetTrustedProxies("172.16.0.0/12"); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("trusted proxy: want forwarded client IP, got %s", got)
	}

	// A client-forged extra hop on the left must NOT win: rightmost untrusted wins.
	req.Header.Set("X-Forwarded-For", "10.9.9.9, 203.0.113.9")
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("forged left hop must be ignored, got %s", got)
	}

	// Direct (untrusted) peer with a spoofed header: header ignored.
	req.RemoteAddr = "198.51.100.7:5555"
	if got := ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("untrusted peer must not pick its own IP, got %s", got)
	}

	// Malformed header from a trusted peer falls back to the peer address.
	req.RemoteAddr = "172.18.0.5:41000"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := ClientIP(req); got != "172.18.0.5" {
		t.Fatalf("malformed XFF must fall back to peer, got %s", got)
	}
}

func TestSetTrustedProxiesParsing(t *testing.T) {
	defer func() { trustedProxies = nil }()
	if err := SetTrustedProxies("172.16.0.0/12, 10.0.0.1, ::1"); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	if len(trustedProxies) != 3 {
		t.Fatalf("want 3 parsed networks, got %d", len(trustedProxies))
	}
	if err := SetTrustedProxies("garbage"); err == nil {
		t.Fatal("invalid entry must return an error")
	}
}
