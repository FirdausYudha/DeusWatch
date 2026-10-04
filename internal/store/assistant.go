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
