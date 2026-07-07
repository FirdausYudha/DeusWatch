// Command wazuh2sigma reverse-engineers Wazuh XML rules into DeusWatch Sigma keyword rules.
//
// It converts the SAFELY-translatable slice: single-event rules that carry a literal <match>
// text pattern, on a log source DeusWatch normalizes (auth / web / network), mapping the Wazuh
// level to a Sigma level and <mitre><id> to attack tags. The keywords match event.original (the
// raw log line) - the same thing Wazuh's <match> does - and every rule is scoped by logsource
// category so it only runs on its real source (no cross-dataset false positives).
//
// What it deliberately does NOT convert: decoder-chaining parents (if_sid, no pattern),
// frequency/correlation rules (if_matched_sid + frequency), <regex> (OSSEC regex != Sigma
// regex), and sources DeusWatch has no normalizer for yet (mail, AV, PBX, vendor firewalls, ...).
//
// Output goes to a STAGING dir (default ./rules/wazuh-imported), NOT rules/sigma, so nothing is
// auto-enabled: review, then move the ones you want into rules/sigma/.
//
//	go run ./tools/wazuh2sigma [wazuhDir] [outDir]
package main

import (
	"crypto/sha1"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type wazuhGroup struct {
	Name  string      `xml:"name,attr"`
	Rules []wazuhRule `xml:"rule"`
}

type wazuhRule struct {
	ID          string   `xml:"id,attr"`
	Level       int      `xml:"level,attr"`
	NoAlert     string   `xml:"noalert,attr"`
	Frequency   string   `xml:"frequency,attr"`
	Match       string   `xml:"match"`
	Description string   `xml:"description"`
	Groups      []string `xml:"group"`
	MitreIDs    []string `xml:"mitre>id"`
}

type root struct {
	Groups []wazuhGroup `xml:"group"`
}

func main() {
	wazuhDir, outDir := "Wazuh_Rules", filepath.Join("rules", "wazuh-imported")
	if len(os.Args) > 1 {
		wazuhDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		outDir = os.Args[2]
	}

	files, err := filepath.Glob(filepath.Join(wazuhDir, "*.xml"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no .xml files in %s\n", wazuhDir)
		os.Exit(1)
	}

	var seen, converted int
	skip := map[string]int{}
	byCategory := map[string]int{}
	dedup := map[string]bool{} // category|keywords -> avoid identical rules

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		// Wazuh files are XML fragments (multiple top-level <group>, plus comments) with no
		// single root - wrap them so the standard decoder can read them.
		var r root
		if err := xml.Unmarshal([]byte("<root>"+string(data)+"</root>"), &r); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", filepath.Base(f), err)
			continue
		}
		for _, g := range r.Groups {
			cat, ok := category(g.Name)
			for _, ru := range g.Rules {
				seen++
				if !ok {
					skip["unsupported source (no DeusWatch normalizer)"]++
					continue
				}
				if ru.NoAlert != "" || ru.Level == 0 {
					skip["noalert / level 0"]++
					continue
				}
				if ru.Frequency != "" {
					skip["frequency/correlation (not single-event)"]++
					continue
				}
				if strings.TrimSpace(ru.Match) == "" {
					skip["no literal <match> pattern"]++
					continue
				}
				if ru.Level < 5 && len(ru.MitreIDs) == 0 {
					skip["low level (<5) without MITRE"]++
					continue
				}
				kws := keywords(ru.Match)
				if len(kws) == 0 {
					skip["match too generic (<4 chars)"]++
					continue
				}
				key := cat + "|" + strings.ToLower(strings.Join(kws, "\x00"))
				if dedup[key] {
					skip["duplicate pattern"]++
					continue
				}
				dedup[key] = true

				yaml := renderRule(ru, cat, kws)
				dir := filepath.Join(outDir, cat)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", dir, err)
					os.Exit(1)
				}
				out := filepath.Join(dir, "wazuh-"+ru.ID+".yml")
				if err := os.WriteFile(out, []byte(yaml), 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
					os.Exit(1)
				}
				converted++
				byCategory[cat]++
			}
		}
	}

	fmt.Printf("Wazuh rules seen: %d\nConverted: %d -> %s\n\nBy category:\n", seen, converted, outDir)
	for _, c := range sortedKeys(byCategory) {
		fmt.Printf("  %-16s %d\n", c, byCategory[c])
	}
	fmt.Printf("\nSkipped:\n")
	for _, k := range sortedKeys(skip) {
		fmt.Printf("  %-42s %d\n", k, skip[k])
	}
	fmt.Printf("\nReview them, then move the ones you want into rules/sigma/ (e.g. a wazuh-auth/ dir).\n")
}

// category maps a Wazuh group name to the DeusWatch event.category the log normalizes to.
// Only sources DeusWatch actually normalizes are returned (so a scoped rule can fire); the
// rest are reported as unsupported.
func category(group string) (string, bool) {
	g := strings.ToLower(group)
	switch {
	case containsAny(g, "sshd", "pam", "telnet", "ssh,", "authentication"):
		return "authentication", true
	case containsAny(g, "apache", "nginx", "web", "wordpress", "joomla", "squid", "iis", "php", "waf", "cloudflare", "modsec"):
		return "web", true
	case containsAny(g, "firewall", "iptables", "netfilter", "ufw", "pf,", "pix", "cisco", "netscreen", "sonicwall", "fortigate"):
		return "network", true
	case containsAny(g, "syscheck", "ossec_fim", "file_integrity"):
		return "file", true
	}
	return "", false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// keywords turns a Wazuh literal <match> into Sigma keyword strings: split on OR (|), strip the
// OSSEC ^/$ anchors, drop patterns shorter than 4 runes (too generic), and dedup.
func keywords(match string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(match, "|") {
		p = strings.TrimSpace(p)
		p = strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$")
		p = strings.TrimSpace(p)
		if len([]rune(p)) < 4 {
			continue
		}
		low := strings.ToLower(p)
		if seen[low] {
			continue
		}
		seen[low] = true
		out = append(out, p)
	}
	return out
}

func sigmaLevel(l int) string {
	switch {
	case l >= 12:
		return "critical"
	case l >= 9:
		return "high"
	case l >= 6:
		return "medium"
	case l >= 3:
		return "low"
	default:
		return "informational"
	}
}

// renderRule emits the DeusWatch Sigma YAML for one converted Wazuh rule.
func renderRule(ru wazuhRule, cat string, kws []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "title: %s\n", yamlStr(cleanDesc(ru.Description)))
	fmt.Fprintf(&b, "id: %s\n", uuidFrom("wazuh-"+ru.ID))
	b.WriteString("status: experimental\n")
	fmt.Fprintf(&b, "description: >\n  Imported from Wazuh rule %s (%s).\n",
		ru.ID, yamlSafeInline(strings.Join(ru.Groups, " ")))
	b.WriteString("author: DeusWatch (imported from Wazuh)\n")
	fmt.Fprintf(&b, "level: %s\n", sigmaLevel(ru.Level))
	fmt.Fprintf(&b, "logsource:\n  category: %s\n", cat)
	b.WriteString("detection:\n  keywords:\n")
	for _, k := range kws {
		fmt.Fprintf(&b, "    - %s\n", yamlStr(k))
	}
	b.WriteString("  condition: keywords\n")
	if len(ru.MitreIDs) > 0 {
		b.WriteString("tags:\n")
		for _, id := range ru.MitreIDs {
			if id = strings.TrimSpace(id); id != "" {
				fmt.Fprintf(&b, "  - attack.%s\n", strings.ToLower(id))
			}
		}
	}
	return b.String()
}

func cleanDesc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "Imported Wazuh rule"
	}
	return s
}

// yamlStr renders a single-quoted YAML scalar (doubling embedded quotes).
func yamlStr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// yamlSafeInline strips characters that would break the folded description line.
func yamlSafeInline(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// uuidFrom derives a stable UUID (v5-style) from a name so re-running is idempotent.
func uuidFrom(name string) string {
	h := sha1.Sum([]byte("deuswatch-wazuh:" + name))
	var b [16]byte
	copy(b[:], h[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
