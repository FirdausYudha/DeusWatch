//go:build windows

package agent

import "golang.org/x/sys/windows/registry"

// RegistryValue reads a registry value for an `r:` rule. The empty value name asks only whether
// the key exists, which is how CIS writes "this policy key is present at all".
func (h hostSystem) RegistryValue(keyPath, value string) (string, bool) {
	hive, sub, err := parseRegistryPath(keyPath)
	if err != nil {
		return "", false
	}
	k, err := registry.OpenKey(hive, sub, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	if value == "" {
		return "", true // the key exists, which is the whole question
	}
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return "", false
	}
	for _, n := range names {
		if n == value {
			return readRegistryValue(k, n), true
		}
	}
	return "", false
}
