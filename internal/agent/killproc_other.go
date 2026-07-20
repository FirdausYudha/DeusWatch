//go:build !linux && !windows

package agent

// NewProcSource returns nil on platforms where DeusWatch has no verified process introspection.
// KillSwitch turns a nil source into an explicit "not supported on this platform" failure rather
// than a silent skip, so the UI can never imply a containment that did not happen.
func NewProcSource() ProcSource { return nil }
