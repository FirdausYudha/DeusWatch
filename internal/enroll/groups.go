package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"deuswatch/internal/agent"
)

// Group is a named collection policy shared by many agents.
type Group struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Sources     []agent.Source `json:"sources"`
	Members     int            `json:"members"`
}

// ErrGroupNameTaken is returned when a tenant already has a group under that name.
var ErrGroupNameTaken = errors.New("enroll: a group with that name already exists")

// Groups lists the tenant's groups with their member counts.
func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT g.id::text, g.name, g.description, g.config,
		       (SELECT count(*) FROM agents a WHERE a.group_id = g.id AND NOT a.revoked)
		  FROM agent_groups g
		 ORDER BY lower(g.name)`)
	if err != nil {
		return nil, fmt.Errorf("enroll: list groups: %w", err)
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var raw *string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &raw, &g.Members); err != nil {
			return nil, fmt.Errorf("enroll: scan group: %w", err)
		}
		g.Sources = sourcesFromConfig(raw)
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateGroup adds a group. Sources may be empty; a group with no sources is a label with no
// policy, which is a legitimate thing to set up before deciding what it collects.
func (s *Store) CreateGroup(ctx context.Context, name, description string, sources []agent.Source) (string, error) {
	cfg, err := json.Marshal(agent.Config{Sources: sources})
	if err != nil {
		return "", err
	}
	var id string
	err = s.q(ctx).QueryRow(ctx,
		`INSERT INTO agent_groups (name, description, config) VALUES ($1, $2, $3) RETURNING id::text`,
		name, description, cfg).Scan(&id)
	if isUniqueViolation(err) {
		return "", ErrGroupNameTaken
	}
	if err != nil {
		return "", fmt.Errorf("enroll: create group: %w", err)
	}
	return id, nil
}

// SetGroupConfig replaces a group's sources and bumps every member's config_rev, which is what
// makes one edit reach every agent in the group.
//
// Both statements run in one transaction. Writing the config without bumping the members would
// leave a group whose stored policy is not the one its agents are running, with nothing on any
// screen to say so, and no later edit would fix it: the agents would already be at the version
// the next bump produced.
func (s *Store) SetGroupConfig(ctx context.Context, id string, sources []agent.Source) (int64, error) {
	cfg, err := json.Marshal(agent.Config{Sources: sources})
	if err != nil {
		return 0, err
	}
	var affected int64
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE agent_groups SET config = $1, updated_at = now() WHERE id = $2`, cfg, id)
		if err != nil {
			return fmt.Errorf("enroll: store group config: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("enroll: group not found")
		}
		mt, err := tx.Exec(ctx,
			`UPDATE agents SET config_rev = config_rev + 1 WHERE group_id = $1 AND NOT revoked`, id)
		if err != nil {
			return fmt.Errorf("enroll: bump group members: %w", err)
		}
		affected = mt.RowsAffected()
		return nil
	})
	return affected, err
}

// DeleteGroup removes a group. Its members keep whatever they are running until something else
// changes their config: the ON DELETE SET NULL clears the assignment, and the config_rev bump
// tells them their effective config has changed, which for an agent with no own config means
// collecting its built-in defaults again.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE agents SET config_rev = config_rev + 1 WHERE group_id = $1`, id); err != nil {
			return fmt.Errorf("enroll: bump former members: %w", err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM agent_groups WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("enroll: delete group: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("enroll: group not found")
		}
		return nil
	})
}

// SetAgentGroup assigns an agent to a group, or clears the assignment when groupID is empty.
func (s *Store) SetAgentGroup(ctx context.Context, agentID, groupID string) error {
	var gid any
	if groupID != "" {
		gid = groupID
	}
	tag, err := s.q(ctx).Exec(ctx,
		`UPDATE agents SET group_id = $1, config_rev = config_rev + 1 WHERE id = $2`, gid, agentID)
	if err != nil {
		return fmt.Errorf("enroll: assign group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("enroll: agent not found")
	}
	return nil
}

// sourcesFromConfig pulls the sources out of a stored agent.Config, treating unreadable JSON as
// "no sources" rather than failing the whole listing.
func sourcesFromConfig(raw *string) []agent.Source {
	if raw == nil {
		return nil
	}
	var cfg agent.Config
	if err := json.Unmarshal([]byte(*raw), &cfg); err != nil {
		return nil
	}
	return cfg.Sources
}

// inTx runs fn in a transaction, rolling back on error. Local to this file because the two group
// writes are the only places here that need more than one statement to be atomic.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isUniqueViolation reports whether err is Postgres SQLSTATE 23505.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// effectiveConfig picks the config an agent is actually served.
//
// Precedence: an operator's per-agent override, then the agent's group, then whatever the row
// already carried. That last case is the enrollment seed, the OS default sources written so a new
// host watches its logs out of the box, and it has to rank BELOW the group. Treating it as an
// override is what broke this feature before it shipped: every agent carries a seed, so every
// agent would look like it had been customised and a group would never apply to anything.
func effectiveConfig(own *string, override bool, group *string) *string {
	if override && own != nil {
		return own
	}
	if group != nil {
		return group
	}
	return own
}
