//go:build windows

package agent

// Windows registry integrity monitoring.
//
// A source of type "registry" watches registry keys the way a "fim" source watches files, and
// deliberately emits the SAME FIMChange payload. The registry is where Windows persistence
// actually lives, Run keys, services, Winlogon, image-file-execution hijacks, so a file-only
// integrity monitor misses the half of the attack that survives a reboot.
//
// Reusing FIMChange rather than inventing a RegistryChange is the whole trick: the gateway's
// normalizer, the detection rules, the dashboard, the ticketing and the diff view all already
// understand it. A registry value is a path and a hash, which is what that struct holds. The
// manager needs no changes at all.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// registryScanInterval is the default interval between registry scans. Slower than the FIM
// default: there is no change notification being used here, the keys worth watching are small,
// and a persistence key written by an attacker is not a thing that un-writes itself, so a minute
// either way costs nothing while a tight loop on a domain controller does.
const registryScanInterval = 120 * time.Second

// registryMaxValues caps the values one source will track. A source pointed at a hive root by
// mistake (HKLM alone is millions of values) would otherwise grow the agent's memory until the
// host notices, which is a worse outcome than refusing to scan.
const registryMaxValues = 20000

// hiveNames maps the prefix an operator writes to its handle. Both the long and short spellings
// are accepted because every piece of Windows documentation mixes them freely.
var hiveNames = map[string]registry.Key{
	"HKEY_LOCAL_MACHINE":  registry.LOCAL_MACHINE,
	"HKLM":                registry.LOCAL_MACHINE,
	"HKEY_CURRENT_USER":   registry.CURRENT_USER,
	"HKCU":                registry.CURRENT_USER,
	"HKEY_USERS":          registry.USERS,
	"HKU":                 registry.USERS,
	"HKEY_CLASSES_ROOT":   registry.CLASSES_ROOT,
	"HKCR":                registry.CLASSES_ROOT,
	"HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG,
	"HKCC":                registry.CURRENT_CONFIG,
}

// parseRegistryPath splits "HKLM\Software\Foo" into its hive and subkey.
func parseRegistryPath(p string) (registry.Key, string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "/", `\`))
	p = strings.Trim(p, `\`)
	if p == "" {
		return 0, "", fmt.Errorf("empty registry path")
	}
	hiveName, sub, _ := strings.Cut(p, `\`)
	hive, ok := hiveNames[strings.ToUpper(hiveName)]
	if !ok {
		return 0, "", fmt.Errorf("unknown registry hive %q", hiveName)
	}
	return hive, sub, nil
}

// RegistryScanner holds the baseline of every watched value and reports what moved between two
// scans. Mirrors FIMScanner so the two collectors read alike.
type RegistryScanner struct {
	roots    []string
	baseline map[string]registryValue
	// truncated records that the last scan hit registryMaxValues, so the warning is logged once
	// per occurrence rather than once per value.
	truncated bool
}

// NewRegistryScanner builds a scanner over the given key paths.
func NewRegistryScanner(roots ...string) *RegistryScanner {
	return &RegistryScanner{roots: roots, baseline: map[string]registryValue{}}
}

// Scan walks the watched keys and returns the changes since the previous Scan. The first call
// establishes the baseline and reports nothing, which is the same contract FIMScanner has: an
// agent starting up must not announce the entire registry as newly created.
func (r *RegistryScanner) Scan() ([]FIMChange, error) {
	current := map[string]registryValue{}
	r.truncated = false
	var firstErr error
	for _, root := range r.roots {
		if err := r.walk(root, current); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// A walk that failed outright must not be read as "every value was deleted". Denied access to
	// one key, or a hive that is briefly unavailable, would otherwise produce a deletion alert for
	// everything under it, which is both wrong and the loudest possible way to be wrong.
	if firstErr != nil && len(current) == 0 {
		return nil, firstErr
	}
	changes := diffRegistry(r.baseline, current)
	r.baseline = current
	if r.truncated {
		log.Printf("agent: registry scan hit the %d value limit; narrow the watched keys, some values are NOT being monitored",
			registryMaxValues)
	}
	return changes, firstErr
}

// walk reads every value under root and its subkeys into out.
func (r *RegistryScanner) walk(root string, out map[string]registryValue) error {
	hive, sub, err := parseRegistryPath(root)
	if err != nil {
		return fmt.Errorf("registry path %q: %w", root, err)
	}
	return r.walkKey(hive, sub, normalizeRegPath(root), out)
}

func (r *RegistryScanner) walkKey(hive registry.Key, sub, display string, out map[string]registryValue) error {
	k, err := registry.OpenKey(hive, sub, registry.READ|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		// One unreadable key is normal (permissions, a key that vanished mid-walk) and must not
		// abort the whole source: the rest of the watched tree is still worth monitoring.
		return fmt.Errorf("open %s: %w", display, err)
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err == nil {
		for _, name := range names {
			if len(out) >= registryMaxValues {
				r.truncated = true
				return nil
			}
			text := readRegistryValue(k, name)
			shown := name
			if shown == "" {
				shown = "(Default)" // the unnamed value, as regedit labels it
			}
			path := display + `\` + shown
			out[path] = registryValue{hash: hashBytes([]byte(text)), text: text}
		}
	}

	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil // values were still collected; an unreadable subkey list is not fatal
	}
	for _, name := range subs {
		if len(out) >= registryMaxValues {
			r.truncated = true
			return nil
		}
		child := name
		if sub != "" {
			child = sub + `\` + name
		}
		if err := r.walkKey(hive, child, display+`\`+name, out); err != nil {
			continue // logged nowhere on purpose: a deep tree would produce pages of noise
		}
	}
	return nil
}

// readRegistryValue renders any value type as text so one comparison covers all of them.
//
// Rendering rather than comparing raw bytes is what lets an alert say what the value BECAME. A
// Run key whose data changed is only actionable if an operator can read the new command line
// without going to the machine.
func readRegistryValue(k registry.Key, name string) string {
	if s, _, err := k.GetStringValue(name); err == nil {
		return s
	}
	if ss, _, err := k.GetStringsValue(name); err == nil {
		return strings.Join(ss, "\n")
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return strconv.FormatUint(n, 10)
	}
	if b, _, err := k.GetBinaryValue(name); err == nil {
		// Binary blobs are hashed, not rendered: a certificate or a serialised struct printed as
		// hex is not something anybody reads, and the hash is enough to detect the change.
		return "binary:" + hashBytes(b)
	}
	// A value that exists but cannot be read any of these ways is still worth tracking by its
	// presence, so it gets a stable placeholder rather than being dropped.
	return "unreadable"
}

// collectRegistry is the "registry" source collector.
func collectRegistry(ctx context.Context, s Source, out chan<- Line) error {
	roots := splitFIMPaths(s.Path)
	if len(roots) == 0 {
		return fmt.Errorf("registry source %q: empty Path", s.Dataset)
	}
	for _, root := range roots {
		if _, _, err := parseRegistryPath(root); err != nil {
			return fmt.Errorf("registry source %q: %w", s.Dataset, err)
		}
	}
	scanner := NewRegistryScanner(roots...)
	if _, err := scanner.Scan(); err != nil { // baseline
		log.Printf("agent: registry %q: baseline scan: %v", s.Dataset, err)
	}

	tick := time.NewTicker(s.scanInterval(registryScanInterval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		changes, err := scanner.Scan()
		if err != nil {
			log.Printf("agent: registry %q: scan: %v", s.Dataset, err)
		}
		for _, c := range changes {
			body, err := json.Marshal(c)
			if err != nil {
				continue
			}
			select {
			case out <- Line{Dataset: s.Dataset, Message: string(body)}:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
