package auth

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// LoginLimiter is an in-memory brute-force guard for the login endpoint. Failed
// attempts are counted per key (client IP and username); when a key exceeds
// maxFailures within window, it is locked out for lockout. State is per-process
// (resets on restart) - the goal is slowing online guessing, not durable bans;
// persistent attackers are the response engine's job.
type LoginLimiter struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	entries     map[string]*limiterEntry
	lastPrune   time.Time
}

type limiterEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// Login limiter defaults; override via LOGIN_MAX_FAILURES / LOGIN_LOCKOUT.
const (
	defaultMaxFailures = 5
	defaultLockout     = 15 * time.Minute
)

// NewLoginLimiter builds a limiter. maxFailures <= 0 disables limiting entirely
// (RetryAfter always 0, Fail never locks).
func NewLoginLimiter(maxFailures int, window, lockout time.Duration) *LoginLimiter {
	return &LoginLimiter{
		maxFailures: maxFailures,
		window:      window,
		lockout:     lockout,
		entries:     map[string]*limiterEntry{},
	}
}

// newLoginLimiterFromEnv reads LOGIN_MAX_FAILURES (0 disables) and LOGIN_LOCKOUT
// (Go duration, doubles as the failure-counting window) with hardened defaults.
func newLoginLimiterFromEnv() *LoginLimiter {
	maxFailures := defaultMaxFailures
	if v := os.Getenv("LOGIN_MAX_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxFailures = n
		}
	}
	lockout := defaultLockout
	if v := os.Getenv("LOGIN_LOCKOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			lockout = d
		}
	}
	return NewLoginLimiter(maxFailures, lockout, lockout)
}

// RetryAfter returns how long the caller must wait because one of the keys is
// locked out (0 = allowed).
func (l *LoginLimiter) RetryAfter(keys ...string) time.Duration {
	if l == nil || l.maxFailures <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		if e := l.entries[k]; e != nil && e.lockedUntil.After(now) {
			if d := e.lockedUntil.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait
}

// Fail records a failed attempt on every key and reports whether any key just
// crossed the threshold into a lockout (callers audit-log that transition once).
func (l *LoginLimiter) Fail(keys ...string) bool {
	if l == nil || l.maxFailures <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.prune(now)
	locked := false
	for _, k := range keys {
		e := l.entries[k]
		if e == nil || now.Sub(e.windowStart) > l.window {
			e = &limiterEntry{windowStart: now}
			l.entries[k] = e
		}
		e.failures++
		if e.failures == l.maxFailures {
			e.lockedUntil = now.Add(l.lockout)
			locked = true
		}
	}
	return locked
}

// Reset clears the keys after a successful login.
func (l *LoginLimiter) Reset(keys ...string) {
	if l == nil || l.maxFailures <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}

// prune drops expired entries (called under mu, at most once a minute) so the
// map does not grow unboundedly under a spray of spoofed usernames.
func (l *LoginLimiter) prune(now time.Time) {
	if now.Sub(l.lastPrune) < time.Minute && len(l.entries) < 100_000 {
		return
	}
	l.lastPrune = now
	for k, e := range l.entries {
		if now.Sub(e.windowStart) > l.window && !e.lockedUntil.After(now) {
			delete(l.entries, k)
		}
	}
}
