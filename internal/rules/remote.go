package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"deuswatch/internal/detect/sigma"
)

// Remote rule-pack feed — the "online" half of the marketplace.
//
// Bundled packs (the packs package) install with no network at all. A remote feed adds packs
// that can appear or be refreshed WITHOUT upgrading DeusWatch: a small catalog.json lists each
// pack and its rule files, which are fetched over HTTPS and imported through exactly the same
// validated path as a bundled install (sigma.Classify → insert → enable).
//
// Trust: the default feed is the DeusWatch repo itself, so the operator controls the content.
// Set PACKS_FEED_URL to point somewhere else, or to "" / "off" to disable all egress. Only
// Sigma YAML is ever fetched, and every file must classify before it is stored — a rule that
// doesn't parse is rejected rather than imported.

// defaultFeedURL is the curated feed shipped with DeusWatch (the project's own repo).
const defaultFeedURL = "https://raw.githubusercontent.com/FirdausYudha/DeusWatch/main/packs"

// feedTimeout bounds a whole catalog/rule fetch so a hung feed can't wedge the API.
const feedTimeout = 20 * time.Second

// maxRuleBytes caps a single fetched rule file (a Sigma rule is a few KB).
const maxRuleBytes = 512 << 10

// RemotePack is one entry in the feed's catalog.json.
type RemotePack struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Desc  string   `json:"desc"`
	Files []string `json:"files"`
}

type remoteCatalog struct {
	Version int          `json:"version"`
	Packs   []RemotePack `json:"packs"`
}

// FeedURL returns the configured feed base URL, or "" when the feed is disabled.
func FeedURL() string {
	v, set := os.LookupEnv("PACKS_FEED_URL")
	if !set {
		return defaultFeedURL
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "off") {
		return "" // explicitly disabled: no outbound requests
	}
	return strings.TrimRight(v, "/")
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rules: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rules: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// RemoteCatalog fetches the feed's pack list. Returns nil (no error) when the feed is disabled,
// so callers can treat "offline" as simply having no remote packs.
func RemoteCatalog(ctx context.Context) ([]RemotePack, error) {
	base := FeedURL()
	if base == "" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, feedTimeout)
	defer cancel()
	body, err := fetch(ctx, base+"/catalog.json", 256<<10)
	if err != nil {
		return nil, err
	}
	var cat remoteCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("rules: feed catalog: %w", err)
	}
	return cat.Packs, nil
}

// InstallRemotePack fetches a feed pack's rules and imports them (category = pack id), skipping
// rules already present so a re-run acts as an UPDATE: only genuinely new rules are added.
// Returns how many were added.
func (s *Store) InstallRemotePack(ctx context.Context, id string) (int, error) {
	base := FeedURL()
	if base == "" {
		return 0, fmt.Errorf("rules: the rule-pack feed is disabled (PACKS_FEED_URL)")
	}
	cat, err := RemoteCatalog(ctx)
	if err != nil {
		return 0, err
	}
	var want *RemotePack
	for i := range cat {
		if cat[i].ID == id {
			want = &cat[i]
			break
		}
	}
	if want == nil {
		return 0, fmt.Errorf("rules: %q is not in the feed", id)
	}
	ctx, cancel := context.WithTimeout(ctx, feedTimeout)
	defer cancel()

	added := 0
	for _, f := range want.Files {
		// Only ever fetch a plain .yml file name from inside the pack's own directory.
		name := path.Base(strings.TrimSpace(f))
		if name == "" || name == "." || path.Ext(name) != ".yml" {
			continue
		}
		data, ferr := fetch(ctx, base+"/"+id+"/"+name, maxRuleBytes)
		if ferr != nil {
			return added, ferr
		}
		kind, cerr := sigma.Classify(data)
		if cerr != nil {
			return added, fmt.Errorf("rules: feed pack %q: %s: %w", id, name, cerr)
		}
		title := titleOf(string(data), name)
		var exists bool
		if qerr := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rules WHERE name=$1)`, title).Scan(&exists); qerr != nil {
			return added, qerr
		}
		if exists {
			continue // already have it — this is what makes re-install an update
		}
		if _, ierr := s.pool.Exec(ctx,
			`INSERT INTO rules (name, kind, category, yaml, enabled, builtin) VALUES ($1,$2,$3,$4,true,true)`,
			title, kind, id, string(data)); ierr == nil {
			added++
		}
	}
	return added, nil
}
