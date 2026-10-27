package auth

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
)

type ctxKey int

const userCtxKey ctxKey = iota

func withUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}

// UserFrom retrieves the authenticated user from the context (if present).
func UserFrom(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userCtxKey).(*User)
	return u, ok
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

// trustedProxies are CIDRs of reverse proxies (the bundled web/nginx container)
// whose X-Forwarded-For header is honored. Empty (the default outside compose)
// means the header is ignored and the TCP peer address is used - a client must
// never be able to pick its own IP for rate limiting or the audit log.
var trustedProxies []*net.IPNet

// SetTrustedProxies configures the proxy allowlist from comma-separated CIDRs
// or bare IPs (TRUSTED_PROXIES). Invalid entries are reported, valid ones kept.
func SetTrustedProxies(list string) error {
	var nets []*net.IPNet
	var bad []string
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") { // bare IP → host route
			if strings.Contains(part, ":") {
				part += "/128"
			} else {
				part += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
		} else {
			bad = append(bad, part)
		}
	}
	trustedProxies = nets
	if len(bad) > 0 {
		return errors.New("auth: invalid TRUSTED_PROXIES entries: " + strings.Join(bad, ", "))
	}
	return nil
}

func isTrustedProxy(ip net.IP) bool {
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the caller's IP address (without port). When the direct peer
// is a trusted proxy, X-Forwarded-For is walked right-to-left and the first hop
// not belonging to a trusted proxy wins (the address the untrusted client cannot
// forge). Anything a client could have written further left is ignored.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !isTrustedProxy(peer) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		ip := net.ParseIP(hop)
		if ip == nil {
			break // malformed header → fall back to the peer address
		}
		if !isTrustedProxy(ip) {
			return hop
		}
	}
	return host
}

// Middleware requires a valid session token and puts the user into the context (401 on failure).
func (s *Store) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := s.SessionUser(r.Context(), bearerToken(r))
		if err != nil {
			// Only a genuine authentication failure is 401. SessionUser returns ErrAuth for a
			// missing, unknown, expired or disabled session, and the underlying error for
			// anything else, which in practice means the database could not answer.
			//
			// Reporting that as 401 was actively misleading. A starved connection pool made every
			// data endpoint return 500 and every authenticated request return 401 at the same
			// time, so the UI looked like it had logged the operator out while the real cause was
			// nowhere on screen. 503 says "the server could not check", which is what happened,
			// and it keeps the session rather than inviting a pointless re-login.
			if !errors.Is(err, ErrAuth) {
				log.Printf("auth: could not resolve the session, answering 503: %v", err)
				http.Error(w, "the server could not verify your session; it is not reachable right now",
					http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
	})
}

// RequirePermission denies (403) if the user in the context lacks permission p.
func RequirePermission(p Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFrom(r.Context())
		if !ok || !u.Can(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
