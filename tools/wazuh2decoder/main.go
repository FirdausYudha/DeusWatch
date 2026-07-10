// Command wazuh2decoder reverse-engineers Wazuh XML decoders into DRAFT DeusWatch decoders.
//
// It converts the OSSEC os_regex to Go RE2 (notably swapping the inverted "." / "\." semantics -
// in os_regex "." is a literal dot and "\." is "any char"), names the positional capture groups
// from the decoder's <order>, and derives a dataset from the decoder name. The output is a
// STARTING DRAFT, not production-ready: os_regex "offset" context, PCRE2-only features, and
// complex alternations do not translate cleanly, so every generated decoder MUST be reviewed and
// tested (use the Decoders page "Test against real log lines") before enabling.
//
// Output goes to a STAGING dir (default ./decoders/wazuh-imported), which is gitignored - Wazuh
// content is GPLv2, so derived decoders are for local use, not this public repo.
//
//	go run ./tools/wazuh2decoder [wazuhDir] [outDir]
package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type wdecoder struct {
	Name        string `xml:"name,attr"`
	Parent      string `xml:"parent"`
	ProgramName string `xml:"program_name"`
	Prematch    string `xml:"prematch"`
	Regex       struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"regex"`
	Order string `xml:"order"`
}

type root struct {
	Decoders []wdecoder `xml:"decoder"`
}

// fieldMap maps a Wazuh <order> field name to a DeusWatch decoder capture-group name (empty =
// no DCS field, left as a plain unnamed group).
var fieldMap = map[string]string{
	"srcip": "source_ip", "src_ip": "source_ip", "source_ip": "source_ip",
	"dstip": "destination_ip", "dst_ip": "destination_ip",
	"srcport": "source_port", "src_port": "source_port",
	"dstport": "destination_port", "dst_port": "destination_port",
	"user": "user_name", "username": "user_name", "dstuser": "user_name", "srcuser": "user_name",
	"hostname": "host_name", "host": "host_name",
	"process": "process_name", "process_name": "process_name",
}

func main() {
	wazuhDir, outDir := "Wazuh_Decoders", filepath.Join("decoders", "wazuh-imported")
	if len(os.Args) > 1 {
		wazuhDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		outDir = os.Args[2]
	}
	files, _ := filepath.Glob(filepath.Join(wazuhDir, "*.xml"))
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no .xml in %s\n", wazuhDir)
		os.Exit(1)
	}

	var seen, converted int
	skip := map[string]int{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r root
		if xml.Unmarshal([]byte("<root>"+string(data)+"</root>"), &r) != nil {
			continue
		}
		for _, d := range r.Decoders {
			seen++
			rx := strings.TrimSpace(d.Regex.Value)
			if rx == "" || strings.TrimSpace(d.Order) == "" {
				skip["no <regex> + <order> to map"]++
				continue
			}
			re2, ok := toRE2(rx, d.Regex.Type)
			if !ok {
				skip["regex not RE2-translatable"]++
				continue
			}
			named, err := nameGroups(re2, splitOrder(d.Order))
			if err != nil {
				skip["group naming / RE2 compile failed"]++
				continue
			}
			ds := datasetOf(d)
			if ds == "" {
				skip["no derivable dataset"]++
				continue
			}
			yaml := render(d.Name, ds, named)
			dir := filepath.Join(outDir)
			_ = os.MkdirAll(dir, 0o755)
			if os.WriteFile(filepath.Join(dir, "wazuh-"+safe(d.Name)+".yml"), []byte(yaml), 0o644) == nil {
				converted++
			}
		}
	}
	fmt.Printf("Wazuh decoders seen: %d\nConverted (DRAFT): %d -> %s\n\nSkipped:\n", seen, converted, outDir)
	for _, k := range sortedKeys(skip) {
		fmt.Printf("  %-38s %d\n", k, skip[k])
	}
	fmt.Printf("\nEVERY draft must be reviewed + tested (Decoders page) before enabling.\n")
}

// toRE2 converts an os_regex (or passes through a pcre2) to a Go RE2 pattern. Returns false if it
// cannot be made to compile under RE2.
func toRE2(rx, typ string) (string, bool) {
	out := rx
	if typ != "pcre2" {
		out = os2re2(rx)
	}
	if _, err := regexp.Compile(out); err != nil {
		return "", false
	}
	return out, true
}

// os2re2 translates the OSSEC os_regex dialect to RE2. The critical transform is the inverted
// dot: os_regex "." is a literal dot and "\." matches ANY char (RE2's ".").
func os2re2(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' && i+1 < len(rs) {
			n := rs[i+1]
			i++
			switch n {
			case '.': // os_regex "any char" -> RE2 "."
				b.WriteByte('.')
			case 'w', 'W', 's', 'S', 'd', 'D', 't':
				b.WriteByte('\\')
				b.WriteRune(n)
			case 'p': // os_regex punctuation class
				b.WriteString("[[:punct:]]")
			default:
				b.WriteByte('\\')
				b.WriteRune(n)
			}
			continue
		}
		switch c {
		case '.': // os_regex literal dot
			b.WriteString("\\.")
		case '(', ')', '|', '+', '*', '^', '$':
			b.WriteRune(c)
		case '[', ']', '{', '}', '?':
			b.WriteByte('\\')
			b.WriteRune(c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// nameGroups injects (?P<field>) names into the first capturing groups, per the mapped order.
func nameGroups(re2 string, order []string) (string, error) {
	var b strings.Builder
	rs := []rune(re2)
	group := 0
	for i := 0; i < len(rs); i++ {
		if rs[i] == '(' && !(i+1 < len(rs) && rs[i+1] == '?') { // a capturing group
			name := ""
			if group < len(order) {
				name = fieldMap[strings.ToLower(strings.TrimSpace(order[group]))]
			}
			group++
			if name != "" {
				b.WriteString("(?P<" + name + ">")
				continue
			}
		}
		b.WriteRune(rs[i])
	}
	out := b.String()
	if _, err := regexp.Compile(out); err != nil {
		return "", err
	}
	return out, nil
}

func splitOrder(order string) []string {
	parts := strings.Split(order, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// datasetOf derives a dataset from the decoder name (before the first '-') or its parent.
func datasetOf(d wdecoder) string {
	name := d.Name
	if d.Parent != "" {
		name = d.Parent
	}
	if i := strings.IndexAny(name, "-_ "); i > 0 {
		name = name[:i]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

func render(name, dataset, regex string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\n", yamlStr(name))
	fmt.Fprintf(&b, "dataset: %s\n", yamlStr(dataset))
	b.WriteString("category: ''   # REVIEW: set the DCS category (web/mail/authentication/...)\n")
	fmt.Fprintf(&b, "regex: %s\n", yamlStr(regex))
	b.WriteString("# DRAFT converted from a Wazuh decoder - review + test before enabling.\n")
	return b.String()
}

func yamlStr(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func sortedKeys(m map[string]int) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
