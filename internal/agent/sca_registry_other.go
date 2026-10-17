//go:build !windows

package agent

// RegistryValue has no meaning off Windows and always reports absent.
//
// Absent rather than empty-but-present on purpose. A stub that answered "present" would make
// every Windows CIS registry check pass on a Linux host, and a benchmark that reports a hardened
// score for checks it never ran is worse than one that reports nothing. A Windows policy's
// requirements block keeps it from being evaluated here at all, and this is the backstop for a
// policy written without one.
func (h hostSystem) RegistryValue(_, _ string) (string, bool) { return "", false }
