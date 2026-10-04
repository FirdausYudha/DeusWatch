package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
