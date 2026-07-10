package ingest

// Custom decoders: the data-driven, config-file equivalent of the built-in normalize* functions
// (the DeusWatch answer to Wazuh decoders). A decoder matches raw lines of a dataset with a Go
// RE2 regex and maps its named capture groups into DCS fields, so a new log source can be
// supported WITHOUT code. Performance is bounded: regexes are compiled once, indexed by dataset
// (a line only tries the decoders for its own dataset, usually one), and run only as a fallback
// for datasets that have no built-in normalizer. RE2 is linear-time, so there is no ReDoS risk
// from operator-supplied patterns.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// Decoder is one compiled, data-driven decoder.
type Decoder struct {
	Name     string
	Dataset  string
	Category string
	Action   string
	Outcome  string
	Severity Severity
	re       *regexp.Regexp
}

// DecoderSet is an immutable, dataset-indexed collection of decoders.
type DecoderSet struct {
	byDataset map[string][]*Decoder
}

// Count returns the number of decoders in the set.
func (s *DecoderSet) Count() int {
	n := 0
	for _, ds := range s.byDataset {
		n += len(ds)
	}
	return n
}

// activeDecoders holds the installed set; swapped atomically so Normalize is lock-free.
var activeDecoders atomic.Pointer[DecoderSet]

// SetDecoders installs the active decoder set (called at startup / on reload).
func SetDecoders(s *DecoderSet) { activeDecoders.Store(s) }

// DecoderSpec is the declarative form of a decoder (on-disk YAML or a DB row).
type DecoderSpec struct {
	Name     string `yaml:"name" json:"name"`
	Dataset  string `yaml:"dataset" json:"dataset"`
	Category string `yaml:"category" json:"category"`
	Action   string `yaml:"action" json:"action"`
	Outcome  string `yaml:"outcome" json:"outcome"`
	Level    string `yaml:"level" json:"level"` // info|low|medium|high|critical
	Regex    string `yaml:"regex" json:"regex"`
}

// BuildDecoderSet compiles specs into a dataset-indexed set. A bad spec fails the whole build so
// callers can surface the error (the DB store validates each spec on write, so this rarely fails).
func BuildDecoderSet(specs []DecoderSpec) (*DecoderSet, error) {
	set := &DecoderSet{byDataset: map[string][]*Decoder{}}
	for _, sp := range specs {
		d, err := sp.compile()
		if err != nil {
			return nil, fmt.Errorf("decoder %q: %w", sp.Name, err)
		}
		key := datasetKind(d.Dataset)
		set.byDataset[key] = append(set.byDataset[key], d)
	}
	return set, nil
}

// ValidateDecoder reports whether a spec is well-formed (dataset + compilable regex). Used by the
// API before storing operator input.
func ValidateDecoder(sp DecoderSpec) error {
	_, err := sp.compile()
	return err
}

// TestDecoder applies a spec to a single raw line and reports whether it matched plus the
// resulting event (so the UI can show the operator exactly which fields a decoder extracts from
// a real log line). It does not touch the installed decoder set.
func TestDecoder(sp DecoderSpec, line string) (matched bool, ev *Event, err error) {
	d, err := sp.compile()
	if err != nil {
		return false, nil, err
	}
	e := &Event{Event: EventFields{Dataset: sp.Dataset, Original: line, Severity: SeverityInfo}}
	set := &DecoderSet{byDataset: map[string][]*Decoder{datasetKind(sp.Dataset): {d}}}
	return set.apply(datasetKind(sp.Dataset), line, e), e, nil
}

// LoadDecoderDir loads *.yml / *.yaml decoders from dir (non-recursive). A missing dir yields an
// empty set (not an error), so decoders are optional.
func LoadDecoderDir(dir string) (*DecoderSet, error) {
	var specs []DecoderSpec
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("decoder: read %s: %w", f, err)
			}
			var sp DecoderSpec
			if err := yaml.Unmarshal(data, &sp); err != nil {
				return nil, fmt.Errorf("decoder: parse %s: %w", filepath.Base(f), err)
			}
			specs = append(specs, sp)
		}
	}
	return BuildDecoderSet(specs)
}

func (sp DecoderSpec) compile() (*Decoder, error) {
	if strings.TrimSpace(sp.Dataset) == "" {
		return nil, fmt.Errorf("dataset is required")
	}
	if strings.TrimSpace(sp.Regex) == "" {
		return nil, fmt.Errorf("regex is required")
	}
	re, err := regexp.Compile(sp.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	return &Decoder{
		Name: sp.Name, Dataset: sp.Dataset, Category: sp.Category,
		Action: sp.Action, Outcome: sp.Outcome,
		Severity: ParseSeverity(sp.Level, SeverityInfo),
		re:       re,
	}, nil
}

// applyDecoders runs the custom decoders registered for a dataset kind against msg, filling e.
// Returns true if one matched. Called by Normalize as a fallback for datasets with no built-in.
func applyDecoders(kind, msg string, e *Event) bool {
	set := activeDecoders.Load()
	if set == nil {
		return false
	}
	return set.apply(kind, msg, e)
}

// apply runs this set's decoders for a dataset kind against msg, filling e.
func (set *DecoderSet) apply(kind, msg string, e *Event) bool {
	for _, d := range set.byDataset[kind] {
		m := d.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		if d.Category != "" {
			e.Event.Category = d.Category
		}
		if d.Action != "" {
			e.Event.Action = d.Action
		}
		if d.Outcome != "" {
			e.Event.Outcome = d.Outcome
		}
		if d.Severity != SeverityInfo {
			e.Event.Severity = d.Severity
		}
		for i, name := range d.re.SubexpNames() {
			if name == "" || i >= len(m) || m[i] == "" {
				continue
			}
			setDecodedField(e, name, m[i])
		}
		return true
	}
	return false
}

// setDecodedField maps a named capture group to a DCS field. Unknown group names are ignored
// (they can still document intent without breaking).
func setDecodedField(e *Event, name, val string) {
	switch strings.ToLower(name) {
	case "source_ip", "src_ip", "srcip":
		ensureSource(e).IP = val
	case "source_port", "src_port":
		if p, err := strconv.Atoi(val); err == nil && p > 0 && p <= 65535 {
			ensureSource(e).Port = uint16(p)
		}
	case "destination_ip", "dest_ip", "dst_ip":
		ensureDest(e).IP = val
	case "destination_port", "dest_port", "dst_port":
		if p, err := strconv.Atoi(val); err == nil && p > 0 && p <= 65535 {
			ensureDest(e).Port = uint16(p)
		}
	case "user_name", "user", "username":
		if e.User == nil {
			e.User = &User{}
		}
		e.User.Name = val
	case "host_name", "host", "hostname":
		if e.Host == nil {
			e.Host = &Host{}
		}
		e.Host.Name = val
	case "process_name", "process":
		if e.Process == nil {
			e.Process = &Process{}
		}
		e.Process.Name = val
	case "process_command_line", "command_line", "cmdline":
		if e.Process == nil {
			e.Process = &Process{}
		}
		e.Process.CommandLine = val
	case "file_path", "path":
		if e.File == nil {
			e.File = &File{}
		}
		e.File.Path = val
	}
}

func ensureSource(e *Event) *Endpoint {
	if e.Source == nil {
		e.Source = &Endpoint{}
	}
	return e.Source
}

func ensureDest(e *Event) *Endpoint {
	if e.Destination == nil {
		e.Destination = &Endpoint{}
	}
	return e.Destination
}
