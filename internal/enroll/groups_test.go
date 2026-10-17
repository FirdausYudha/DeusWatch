package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/agent"
	"deuswatch/internal/mtls"
)

// groupTestStore enrolls one agent and returns the store, its pool, the agent id and its name.
func groupTestStore(t *testing.T, ctx context.Context) (*Store, *pgxpool.Pool, string, string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)

	dir := t.TempDir()
	if _, err := mtls.GenerateBundle(mtls.Options{Dir: dir, ValidFor: time.Hour}); err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	ca, err := mtls.LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	s := NewStore(pool, ca)

	name := fmt.Sprintf("grouptest-agent-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM agents WHERE name LIKE 'grouptest-agent-%'`)
		_, _ = pool.Exec(bg, `DELETE FROM agent_groups WHERE name ILIKE 'grouptest-%'`)
		_, _ = pool.Exec(bg, `DELETE FROM agent_enroll_tokens WHERE created_by='grouptest'`)
	})

	raw, _, err := s.CreateToken(ctx, "grouptest", "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := s.Enroll(ctx, raw, name, "linux"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM agents WHERE name=$1`, name).Scan(&id); err != nil {
		t.Fatalf("read agent id: %v", err)
	}
	return s, pool, id, name
}

// served returns the config the agent would actually be handed, and whether it gets one at all.
func served(t *testing.T, s *Store, ctx context.Context, name string) (agent.Config, bool) {
	t.Helper()
	b, err := s.GetConfigByName(ctx, name)
	if err != nil {
		t.Fatalf("GetConfigByName: %v", err)
	}
	if b == nil {
		return agent.Config{}, false
	}
	var cfg agent.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("served config is not readable: %v", err)
	}
	return cfg, true
}

func src(dataset string) agent.Source {
	return agent.Source{Dataset: dataset, Type: "file"}
}

// TestGroupConfigResolution covers the precedence an operator has to be able to predict: the
// per-agent config wins, clearing it falls back to the group, and with neither there is nothing
// to serve.
func TestGroupConfigResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, _, id, name := groupTestStore(t, ctx)

	if _, ok := served(t, s, ctx, name); ok {
		t.Fatal("a fresh agent with no config and no group was served one")
	}

	gid, err := s.CreateGroup(ctx, "grouptest-servers", "web servers", []agent.Source{src("group.policy")})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.SetAgentGroup(ctx, id, gid); err != nil {
		t.Fatalf("SetAgentGroup: %v", err)
	}
	cfg, ok := served(t, s, ctx, name)
	if !ok || len(cfg.Sources) != 1 || cfg.Sources[0].Dataset != "group.policy" {
		t.Fatalf("group config not served: %+v (found=%v)", cfg.Sources, ok)
	}

	// A per-agent config overrides; it does not merge.
	if _, err := s.SetConfig(ctx, id, []agent.Source{src("own.policy")}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	cfg, _ = served(t, s, ctx, name)
	if len(cfg.Sources) != 1 || cfg.Sources[0].Dataset != "own.policy" {
		t.Fatalf("the per-agent config did not override the group: %+v", cfg.Sources)
	}

	if err := s.ClearConfig(ctx, id); err != nil {
		t.Fatalf("ClearConfig: %v", err)
	}
	cfg, _ = served(t, s, ctx, name)
	if len(cfg.Sources) != 1 || cfg.Sources[0].Dataset != "group.policy" {
		t.Fatalf("clearing the per-agent config did not fall back to the group: %+v", cfg.Sources)
	}
}

// TestConfigRevNeverGoesBackwards is the whole reason config_rev exists. The agent re-applies
// only when the version it is handed is strictly GREATER than the one it runs, so any operator
// action that lowers the number makes a real change invisible, permanently and silently. This
// walks the sequence most likely to do it: a long-edited per-agent config replaced by a freshly
// created group, whose own stored version is 0.
func TestConfigRevNeverGoesBackwards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, _, id, name := groupTestStore(t, ctx)

	for i := 0; i < 6; i++ {
		if _, err := s.SetConfig(ctx, id, []agent.Source{src(fmt.Sprintf("own.%d", i))}); err != nil {
			t.Fatalf("SetConfig %d: %v", i, err)
		}
	}
	cfg, _ := served(t, s, ctx, name)
	high := cfg.Version
	if high < 6 {
		t.Fatalf("version after 6 edits is %d, expected at least 6", high)
	}

	gid, err := s.CreateGroup(ctx, "grouptest-fresh", "", []agent.Source{src("group.fresh")})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.SetAgentGroup(ctx, id, gid); err != nil {
		t.Fatalf("SetAgentGroup: %v", err)
	}
	if err := s.ClearConfig(ctx, id); err != nil {
		t.Fatalf("ClearConfig: %v", err)
	}
	cfg, _ = served(t, s, ctx, name)
	if cfg.Version <= high {
		t.Fatalf("version went from %d to %d; the agent would ignore this change forever", high, cfg.Version)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Dataset != "group.fresh" {
		t.Fatalf("served the wrong config after the switch: %+v", cfg.Sources)
	}
}

// TestSetGroupConfigReachesMembers is the feature in one assertion: one edit, every member's
// version bumped, so every member re-applies.
func TestSetGroupConfigReachesMembers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, _, id, name := groupTestStore(t, ctx)

	gid, err := s.CreateGroup(ctx, "grouptest-bulk", "", []agent.Source{src("v1")})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.SetAgentGroup(ctx, id, gid); err != nil {
		t.Fatalf("SetAgentGroup: %v", err)
	}
	before, _ := served(t, s, ctx, name)

	members, err := s.SetGroupConfig(ctx, gid, []agent.Source{src("v2"), src("v2b")})
	if err != nil {
		t.Fatalf("SetGroupConfig: %v", err)
	}
	if members != 1 {
		t.Errorf("reported %d members bumped, want 1", members)
	}
	after, _ := served(t, s, ctx, name)
	if after.Version <= before.Version {
		t.Fatalf("member version did not advance past %d (got %d); the edit would never be applied",
			before.Version, after.Version)
	}
	if len(after.Sources) != 2 {
		t.Fatalf("member is serving %d sources, want 2", len(after.Sources))
	}
}

// TestGroupNameTaken: a duplicate is operator error, and the handler can only answer 409 if the
// store distinguishes it. Case-insensitive, because a tenant holding both "Servers" and
// "servers" is a trap rather than a feature.
func TestGroupNameTaken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, _, _, _ := groupTestStore(t, ctx)

	if _, err := s.CreateGroup(ctx, "grouptest-dup", "", nil); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := s.CreateGroup(ctx, "GROUPTEST-DUP", "", nil); !errors.Is(err, ErrGroupNameTaken) {
		t.Fatalf("second create returned %v, want ErrGroupNameTaken", err)
	}
}

// TestDeleteGroupReleasesMembers: a deleted group must not leave members pinned to a policy
// nobody can edit any more, and they still have to learn that something changed.
func TestDeleteGroupReleasesMembers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, pool, id, name := groupTestStore(t, ctx)

	gid, err := s.CreateGroup(ctx, "grouptest-doomed", "", []agent.Source{src("doomed")})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.SetAgentGroup(ctx, id, gid); err != nil {
		t.Fatalf("SetAgentGroup: %v", err)
	}
	before, _ := served(t, s, ctx, name)

	if err := s.DeleteGroup(ctx, gid); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, ok := served(t, s, ctx, name); ok {
		t.Fatal("the agent is still being served the config of a group that was deleted")
	}
	var rev int
	if err := pool.QueryRow(ctx, `SELECT config_rev FROM agents WHERE id=$1`, id).Scan(&rev); err != nil {
		t.Fatalf("read config_rev: %v", err)
	}
	if rev <= before.Version {
		t.Fatalf("config_rev %d did not advance past %d after the group was deleted", rev, before.Version)
	}
}

// TestListAgentsReportsEffectivePolicy: the list must describe the machine, not the database. An
// agent showing a stored-but-overridden config, or not saying whose config it is showing, is the
// single most confusing thing about per-agent overrides.
func TestListAgentsReportsEffectivePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, _, id, name := groupTestStore(t, ctx)

	gid, err := s.CreateGroup(ctx, "grouptest-listed", "", []agent.Source{src("from.group")})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.SetAgentGroup(ctx, id, gid); err != nil {
		t.Fatalf("SetAgentGroup: %v", err)
	}

	find := func() AgentInfo {
		t.Helper()
		list, err := s.ListAgents(ctx)
		if err != nil {
			t.Fatalf("ListAgents: %v", err)
		}
		for _, a := range list {
			if a.Name == name {
				return a
			}
		}
		t.Fatalf("agent %q is not in the listing", name)
		return AgentInfo{}
	}

	a := find()
	if a.OwnConfig {
		t.Error("an agent with no config of its own is reported as having one")
	}
	if a.GroupName != "grouptest-listed" {
		t.Errorf("group name = %q, want grouptest-listed", a.GroupName)
	}
	if len(a.Sources) != 1 || a.Sources[0].Dataset != "from.group" {
		t.Errorf("listing shows %+v, want the policy of the group", a.Sources)
	}

	if _, err := s.SetConfig(ctx, id, []agent.Source{src("from.agent")}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	a = find()
	if !a.OwnConfig {
		t.Error("an agent with a config of its own is not reported as having one")
	}
	if len(a.Sources) != 1 || a.Sources[0].Dataset != "from.agent" {
		t.Errorf("listing shows %+v, want the per-agent policy", a.Sources)
	}
}
