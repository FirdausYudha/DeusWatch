// Package glpi is a minimal client for the GLPI REST API, used to mirror DeusWatch tickets into
// the GLPI instance a team already works in.
//
// Why this exists: the hospital IT team runs GLPI under an ITIL frame and lives in two of its
// modules, assets and incidents. A security tool that keeps its own separate ticket queue asks
// them to work in two places, and the field discussion was explicit that the second place loses —
// people answer chat and skip the queue they are supposed to fill. So DeusWatch pushes its tickets
// to where the work already happens.
//
// The sync is deliberately ONE-WAY for content and read-only for status: DeusWatch owns what a
// ticket says, GLPI owns how far along it is. Nothing here can overwrite a field GLPI considers
// its own, which is what makes two-way conflict resolution unnecessary rather than merely deferred.
//
// The client is a plain HTTP client with no storage and no scheduling, so every request shape and
// every status mapping below is testable against an httptest server.
package glpi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GLPI ticket statuses, as the API numbers them.
const (
	StatusNew      = 1
	StatusAssigned = 2 // "Processing (assigned)"
	StatusPlanned  = 3 // "Processing (planned)"
	StatusPending  = 4
	StatusSolved   = 5
	StatusClosed   = 6
)

// maxBodyRead bounds error-path reads. A GLPI returning an HTML error page must not be slurped
// whole into a log line.
const maxBodyRead = 16 << 10

// Client talks to one GLPI instance.
type Client struct {
	base      string // e.g. https://glpi.rs.local/apirest.php
	appToken  string
	userToken string
	hc        *http.Client
}

// New builds a client. insecure skips TLS verification, for the self-signed certificate on an
// internal GLPI reached over a trusted network — the same escape hatch the MikroTik connector has.
func New(base, appToken, userToken string, insecure bool) *Client {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	// Accept the instance root as well as the API root: an operator reads "GLPI URL" and pastes
	// what is in their address bar, and failing on that is a support ticket, not a safety feature.
	if !strings.HasSuffix(base, "apirest.php") {
		base += "/apirest.php"
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	if insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // operator opt-in, documented
	}
	return &Client{base: base, appToken: appToken, userToken: userToken, hc: hc}
}

// Session is an authenticated GLPI session. GLPI issues a session token that must be released;
// leaking them exhausts the instance's session table, which is a way to take GLPI down by
// accident.
type Session struct {
	c     *Client
	token string
}

type initSessionResp struct {
	SessionToken string `json:"session_token"`
}

// Open authenticates and returns a session. Always pair with Close.
func (c *Client) Open(ctx context.Context) (*Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/initSession", nil)
	if err != nil {
		return nil, fmt.Errorf("glpi: build initSession: %w", err)
	}
	req.Header.Set("App-Token", c.appToken)
	req.Header.Set("Authorization", "user_token "+c.userToken)

	var out initSessionResp
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	if out.SessionToken == "" {
		return nil, fmt.Errorf("glpi: initSession returned no session token (check the App-Token and user token)")
	}
	return &Session{c: c, token: out.SessionToken}, nil
}

// Close releases the session. Errors are returned for logging but a failure here is not worth
// failing the caller's work over: the session expires on its own.
func (s *Session) Close(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.c.base+"/killSession", nil)
	if err != nil {
		return err
	}
	s.headers(req)
	return s.c.do(req, nil)
}

func (s *Session) headers(req *http.Request) {
	req.Header.Set("App-Token", s.c.appToken)
	req.Header.Set("Session-Token", s.token)
	req.Header.Set("Content-Type", "application/json")
}

// NewTicket is a DeusWatch ticket on its way into GLPI.
type NewTicket struct {
	Title   string
	Content string
	// Urgency on GLPI's 1..5 scale. Use UrgencyFromSeverity.
	Urgency int
	// Category and Requester are optional GLPI ids; 0 leaves them unset so GLPI applies its own
	// defaults rather than pointing at a record that may not exist.
	Category  int
	Requester int
}

// createResp covers both shapes GLPI has returned for a create: a bare object, and a single-element
// array. Accepting both is cheaper than discovering the difference in production.
type createResp struct {
	ID int `json:"id"`
}

// CreateTicket opens a ticket in GLPI and returns its id.
func (s *Session) CreateTicket(ctx context.Context, t NewTicket) (int, error) {
	input := map[string]any{
		"name":    t.Title,
		"content": t.Content,
	}
	if t.Urgency > 0 {
		input["urgency"] = t.Urgency
	}
	if t.Category > 0 {
		input["itilcategories_id"] = t.Category
	}
	if t.Requester > 0 {
		input["_users_id_requester"] = t.Requester
	}
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return 0, fmt.Errorf("glpi: encode ticket: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.c.base+"/Ticket", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("glpi: build create: %w", err)
	}
	s.headers(req)

	raw, err := s.c.doRaw(req)
	if err != nil {
		return 0, err
	}
	id, err := parseCreatedID(raw)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// parseCreatedID reads the new ticket's id out of either response shape.
func parseCreatedID(raw []byte) (int, error) {
	var one createResp
	if err := json.Unmarshal(raw, &one); err == nil && one.ID > 0 {
		return one.ID, nil
	}
	var many []createResp
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 && many[0].ID > 0 {
		return many[0].ID, nil
	}
	return 0, fmt.Errorf("glpi: create returned no ticket id: %s", clip(string(raw), 200))
}

type ticketResp struct {
	ID     int `json:"id"`
	Status int `json:"status"`
}

// TicketStatus reads one ticket's current GLPI status.
func (s *Session) TicketStatus(ctx context.Context, id int) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/Ticket/%d", s.c.base, id), nil)
	if err != nil {
		return 0, fmt.Errorf("glpi: build get: %w", err)
	}
	s.headers(req)

	var out ticketResp
	if err := s.c.do(req, &out); err != nil {
		return 0, err
	}
	if out.Status == 0 {
		return 0, fmt.Errorf("glpi: ticket %d returned no status", id)
	}
	return out.Status, nil
}

// do performs a request and decodes JSON into out (nil to discard).
func (c *Client) do(req *http.Request, out any) error {
	raw, err := c.doRaw(req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("glpi: unexpected response from %s: %s", req.URL.Path, clip(string(raw), 200))
	}
	return nil
}

// doRaw performs a request and returns the body, turning a non-2xx into an error that names what
// GLPI actually said — the difference between "fix the token" and "fix the URL".
func (c *Client) doRaw(req *http.Request) ([]byte, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("glpi: %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("glpi: %s: HTTP %d: %s", req.URL.Path, resp.StatusCode, clip(string(raw), 200))
	}
	if rerr != nil {
		return nil, fmt.Errorf("glpi: %s: read body: %w", req.URL.Path, rerr)
	}
	return raw, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// UrgencyFromSeverity maps DeusWatch's 0..4 severity onto GLPI's 1..5 urgency. Both run low to
// high, so this is an offset rather than a judgement.
func UrgencyFromSeverity(sev int) int {
	u := sev + 1
	if u < 1 {
		return 1
	}
	if u > 5 {
		return 5
	}
	return u
}

// StatusToDeusWatch maps a GLPI status onto a DeusWatch one, and reports whether the mapping is
// defined at all.
//
// The vocabularies are not the same size and this is where that shows. GLPI's "Pending" — waiting
// on a third party — has no DeusWatch equivalent. It maps to in_progress, deliberately: the ticket
// is still live and still owned, and the alternative (calling it resolved) would stop the SLA clock
// on work that has not finished and quietly flatter the scorecard. An unknown status returns
// ok=false so the caller leaves the ticket alone instead of guessing.
func StatusToDeusWatch(glpiStatus int) (status string, ok bool) {
	switch glpiStatus {
	case StatusNew:
		return "open", true
	case StatusAssigned, StatusPlanned, StatusPending:
		return "in_progress", true
	case StatusSolved:
		return "resolved", true
	case StatusClosed:
		return "closed", true
	default:
		return "", false
	}
}
