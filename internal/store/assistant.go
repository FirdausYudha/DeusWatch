package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxPersonaLen caps the stored persona. It is prepended to every assistant turn, so an essay here
// is paid for on every message, and it still has to stay far short of crowding out the reference
// data beneath it.
//
// The floor is not taste: the built-in default must fit with room to extend it, because the UI
// offers "Load the default to edit" and the editor truncates at this length. A cap below the
// default would silently cut the tail off whatever the operator loaded, and the tail is where the
// prompt-injection boundary lives. Raise this before growing assistant.DefaultPersona, never after.
const MaxPersonaLen = 8000

// AssistantConfig is the operator-editable part of the assistant (ADR 0003, phase 4).
type AssistantConfig struct {
	// Persona replaces the built-in system persona wholesale. Empty = use the built-in one.
	Persona string `json:"persona"`
}

// LoadAssistantConfig reads the single config row. A missing row is not an error: it means the
// deployment has never saved one, which is the same thing as "use the default".
func (s *Store) LoadAssistantConfig(ctx context.Context) (AssistantConfig, error) {
	var c AssistantConfig
	err := s.q(ctx).QueryRow(ctx,
		`SELECT COALESCE(persona,'') FROM assistant_config WHERE id = 1`).Scan(&c.Persona)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("store: load assistant config: %w", err)
	}
	return c, nil
}

// SaveAssistantConfig upserts the single row. The persona is trimmed and truncated rather than
// rejected: an operator who pasted something slightly too long wants it saved, not a form error.
func (s *Store) SaveAssistantConfig(ctx context.Context, c AssistantConfig) error {
	p := strings.TrimSpace(c.Persona)
	if len(p) > MaxPersonaLen {
		p = p[:MaxPersonaLen]
	}
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO assistant_config (id, persona) VALUES (1, $1)
		 ON CONFLICT (id) DO UPDATE SET persona = EXCLUDED.persona`, p)
	if err != nil {
		return fmt.Errorf("store: save assistant config: %w", err)
	}
	return nil
}

// AgentRow is one endpoint as the assistant needs to describe it.
type AgentRow struct {
	Name    string
	OS      string
	Status  string // unknown | online | degraded | disconnected | stale
	Version string
	Revoked bool
	Detail  string
}

// AgentRoster lists the enrolled endpoints for the assistant's context.
//
// It reads the table directly rather than going through enroll.Store, which needs the CA loaded
// and therefore would make the assistant's answers depend on whether enrollment happens to be
// enabled. Nothing here is a secret: it is the same list the Agents page shows.
//
// This exists because its absence was a real failure, not a gap in polish. Asked which agents were
// online, the model had nothing in context, and a model with nothing in context invents: it named
// two hosts that do not exist and recommended an upgrade for one of them.
func (s *Store) AgentRoster(ctx context.Context) ([]AgentRow, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT name, COALESCE(os,''), COALESCE(status,'unknown'), COALESCE(agent_version,''),
		        revoked, COALESCE(health_detail,'')
		 FROM agents WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: agent roster: %w", err)
	}
	defer rows.Close()
	out := make([]AgentRow, 0, 16)
	for rows.Next() {
		var a AgentRow
		if err := rows.Scan(&a.Name, &a.OS, &a.Status, &a.Version, &a.Revoked, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RuleDigest summarises the loaded detection rules.
//
// Deliberately an aggregate, not a list. There are hundreds of built-in rules and enumerating them
// would crowd out everything else in the prompt; it would also be the wrong answer, since nobody
// asking "what rules are running" wants 800 names read back. The custom rules are listed because
// those are the ones an operator wrote and remembers.
type RuleDigest struct {
	Total, Enabled, Builtin, Custom, Aggregation int
	ByCategory                                   map[string]int
	CustomNames                                  []string
}

// MaxCustomRuleNames caps the named list for the same reason the roster is capped.
const MaxCustomRuleNames = 30

// RulesDigest counts the rule table instead of loading it. rules.Store.List pulls every rule's full
// YAML, which is hundreds of kilobytes and would be read on every single chat message.
func (s *Store) RulesDigest(ctx context.Context) (RuleDigest, error) {
	d := RuleDigest{ByCategory: map[string]int{}}
	rows, err := s.q(ctx).Query(ctx,
		`SELECT COALESCE(category,'general'), kind, enabled, builtin, count(*)
		   FROM rules GROUP BY 1,2,3,4`)
	if err != nil {
		return d, fmt.Errorf("store: rules digest: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cat, kind   string
			enabled, bi bool
			n           int
		)
		if err := rows.Scan(&cat, &kind, &enabled, &bi, &n); err != nil {
			return d, err
		}
		d.Total += n
		if enabled {
			d.Enabled += n
			// Only enabled rules are counted per category: a disabled rule is not "running", and
			// reporting it as coverage is the kind of quiet overstatement this assistant must avoid.
			d.ByCategory[cat] += n
		}
		if bi {
			d.Builtin += n
		} else {
			d.Custom += n
		}
		if kind == "aggregation" {
			d.Aggregation += n
		}
	}
	if err := rows.Err(); err != nil {
		return d, err
	}

	nameRows, err := s.q(ctx).Query(ctx,
		`SELECT name, enabled FROM rules WHERE NOT builtin ORDER BY name LIMIT $1`, MaxCustomRuleNames)
	if err != nil {
		return d, nil // the counts are still worth having
	}
	defer nameRows.Close()
	for nameRows.Next() {
		var (
			name string
			on   bool
		)
		if err := nameRows.Scan(&name, &on); err != nil {
			return d, nil
		}
		if !on {
			name += " (disabled)"
		}
		d.CustomNames = append(d.CustomNames, name)
	}
	return d, nil
}

// OpsDigest is the ticket queue, recent file-integrity activity and vulnerability posture.
//
// Three more vacuums the assistant used to fill with invention. Each is an aggregate for the same
// reason the rule digest is: nobody asking "any open tickets?" wants every ticket read back, and
// loading them would cost more than the answer is worth on every message.
type OpsDigest struct {
	TicketsByStatus map[string]int
	TicketsOpenHigh int // open or in_progress at severity >= 3 (high/critical), the ones that matter

	FileChanges  int      // file-integrity events in the window
	TopFilePaths []string // "path (n)", most changed first
	// FIMRead separates "no file changed" from "the query failed". Collapsing the two would have
	// the assistant reporting a quiet night on a broken read, which is the precise failure this
	// whole platform exists to prevent.
	FIMRead bool

	VulnAgents                      int // agents with a completed scan
	VulnCritical, VulnHigh, VulnTot int
}

// OpsDigestFor gathers the three in one place. Every part is best-effort: a section that cannot be
// read is left zero and the renderer says it has no data, which is the honest outcome. Partial
// knowledge beats refusing to answer the other two questions.
func (s *Store) OpsDigestFor(ctx context.Context, since, until time.Time) OpsDigest {
	d := OpsDigest{TicketsByStatus: map[string]int{}}

	if rows, err := s.q(ctx).Query(ctx,
		`SELECT status, count(*), count(*) FILTER (WHERE severity >= 3) FROM tickets GROUP BY status`); err == nil {
		for rows.Next() {
			var (
				st       string
				n, nHigh int
			)
			if rows.Scan(&st, &n, &nHigh) == nil {
				d.TicketsByStatus[st] = n
				if st == "open" || st == "in_progress" {
					d.TicketsOpenHigh += nHigh
				}
			}
		}
		rows.Close()
	}

	// File-integrity activity is ordinary events tagged with the file category, the same rows the
	// File Integrity page lists.
	if err := s.q(ctx).QueryRow(ctx,
		`SELECT count(*) FROM events WHERE time >= $1 AND time < $2 AND event_category = 'file'`,
		since, until).Scan(&d.FileChanges); err == nil {
		d.FIMRead = true
	}
	if rows, err := s.q(ctx).Query(ctx,
		`SELECT file_path, count(*) AS n FROM events
		  WHERE time >= $1 AND time < $2 AND event_category = 'file' AND file_path IS NOT NULL AND file_path <> ''
		  GROUP BY file_path ORDER BY n DESC LIMIT 8`, since, until); err == nil {
		for rows.Next() {
			var (
				p string
				n int
			)
			if rows.Scan(&p, &n) == nil {
				d.TopFilePaths = append(d.TopFilePaths, fmt.Sprintf("%s (%d)", p, n))
			}
		}
		rows.Close()
	}

	if sums, err := s.ListVulnSummaries(ctx); err == nil {
		d.VulnAgents = len(sums)
		for _, v := range sums {
			d.VulnCritical += v.Critical
			d.VulnHigh += v.High
			d.VulnTot += v.Total
		}
	}
	return d
}

// EnforcementDigest is the response engine's state: what is banned, what is waiting for approval,
// and which addresses keep coming back.
//
// The fifth vacuum of the same kind. Asked whether an IP was already blocked, the model had no ban
// data at all and said no, while the Response page behind the chat panel showed that address banned
// four times, the last one still running. Wrong in the most expensive direction: an operator told
// an address is unhandled acts on it, or worse, stops looking.
type EnforcementDigest struct {
	ActiveBlocks []string // currently in force, capped
	ActiveCount  int
	Pending      int      // recommendations waiting for a human
	Offenders    []string // "ip (n bans)", repeat customers first
}

// MaxEnforcementLines caps each list for the same reason the roster is capped.
const MaxEnforcementLines = 15

// EnforcementDigestFor reads the response queue. Best-effort per section: a ban list that cannot be
// read must not look like an empty one, so the renderer is told which it is.
func (s *Store) EnforcementDigestFor(ctx context.Context) (EnforcementDigest, bool) {
	var d EnforcementDigest
	rows, err := s.q(ctx).Query(ctx, `
		SELECT DISTINCT host(source_ip) FROM response_actions
		 WHERE action = 'block' AND status IN ('approved','executed')
		   AND (ban_seconds = 0
		        OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now())`)
	if err != nil {
		return d, false
	}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			d.ActiveCount++
			if len(d.ActiveBlocks) < MaxEnforcementLines {
				d.ActiveBlocks = append(d.ActiveBlocks, ip)
			}
		}
	}
	rows.Close()

	_ = s.q(ctx).QueryRow(ctx,
		`SELECT count(*) FROM response_actions WHERE status = 'recommended'`).Scan(&d.Pending)

	// Offence history is what answers "have we seen this one before", which is a different question
	// from "is it banned right now" and the one an operator usually means.
	if orows, oerr := s.q(ctx).Query(ctx, `
		SELECT host(source_ip), count(*) AS n FROM response_actions
		 WHERE action = 'block' AND status = 'executed'
		 GROUP BY 1 ORDER BY n DESC, 1 LIMIT $1`, MaxEnforcementLines); oerr == nil {
		for orows.Next() {
			var (
				ip string
				n  int
			)
			if orows.Scan(&ip, &n) == nil {
				d.Offenders = append(d.Offenders, fmt.Sprintf("%s (%d ban%s)", ip, n, plural(n)))
			}
		}
		orows.Close()
	}
	return d, true
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// IPDossier is everything known about one address the operator named.
//
// A top-N offender list cannot answer "is 72.167.227.34 dangerous?". A busy deployment has dozens
// of addresses tied on the same offence count, so the one being asked about is usually outside any
// slice short enough to put in a prompt, and the assistant answers "I have no information" about a
// row sitting on the operator's screen. Looking up the address that was actually named costs one
// indexed query and scales to any fleet.
type IPDossier struct {
	IP string
	// Found is false when the address appears nowhere in the response history, which is a real
	// answer ("never seen") and must not be confused with "I could not look".
	Found                    bool
	Offenses, Total, Pending int
	LastStatus, LastReason   string
	LastAgent                string
	Blocked                  bool
	BlockedUntil             *time.Time
	LastSeen                 *time.Time
	Events24h                int
	Whitelisted              bool
}

// IPDossierFor gathers one address's history. The shape mirrors the Offenders view the Response
// page shows, so the assistant and the screen agree.
func (s *Store) IPDossierFor(ctx context.Context, ip string) (IPDossier, error) {
	d := IPDossier{IP: ip}
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'executed'),
		       count(*),
		       count(*) FILTER (WHERE status = 'recommended'),
		       COALESCE((array_agg(status ORDER BY created_at DESC))[1], ''),
		       COALESCE((array_agg(COALESCE(reason,'') ORDER BY created_at DESC))[1], ''),
		       COALESCE((array_agg(COALESCE(agent_id,'') ORDER BY created_at DESC))[1], ''),
		       max(created_at),
		       max(COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds))
		           FILTER (WHERE status IN ('approved','executed') AND ban_seconds > 0),
		       COALESCE(bool_or(status IN ('approved','executed')
		               AND (ban_seconds = 0
		                    OR COALESCE(executed_at, decided_at, created_at) + make_interval(secs => ban_seconds) > now())), false)
		  FROM response_actions WHERE source_ip = $1::inet`, ip).
		Scan(&d.Offenses, &d.Total, &d.Pending, &d.LastStatus, &d.LastReason, &d.LastAgent,
			&d.LastSeen, &d.BlockedUntil, &d.Blocked)
	if err != nil {
		return d, err
	}
	d.Found = d.Total > 0

	// Activity in the last day, so "never banned" can still be answered with "but it is hitting you
	// right now", which is the case an offender list cannot show at all.
	_ = s.q(ctx).QueryRow(ctx,
		`SELECT count(*) FROM events WHERE source_ip = $1::inet AND time >= now() - interval '24 hours'`,
		ip).Scan(&d.Events24h)
	if d.Events24h > 0 {
		d.Found = true
	}

	_ = s.q(ctx).QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM ip_whitelist WHERE $1::inet <<= cidr)`, ip).Scan(&d.Whitelisted)
	return d, nil
}
