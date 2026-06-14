package agent

// Config is the manager-managed desired collection state (config push, design doc
// section 12). Version is bumped on each change so the agent knows when to re-apply.
type Config struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
}
