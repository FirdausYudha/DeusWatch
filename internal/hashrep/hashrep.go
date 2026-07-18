// Package hashrep is the DeusWatch file-hash reputation engine (FIM Phase): given a
// file's SHA-256 (from the FIM collector), it classifies the hash as known-good
// (NSRL/CIRCL), known-bad (VirusTotal detections / CIRCL malicious set), or unknown.
//
// Results are cached as TTL-bearing Postgres rows (see cache.go), mirroring the CTI
// cache pattern — never an in-memory cache, so look-ups are deterministic and the free
// VirusTotal rate limit (≈4/min) is respected by only querying changed/unknown hashes.
package hashrep

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Verdict is a file-hash reputation classification.
type Verdict string

const (
	VerdictKnownGood Verdict = "known_good" // in a known-software set (NSRL/CIRCL) or 0 AV detections
	VerdictKnownBad  Verdict = "known_bad"  // flagged malicious by VirusTotal / CIRCL
	VerdictUnknown   Verdict = "unknown"    // not found in any source
)

// Indicator is the reputation result for one hash.
type Indicator struct {
	Verdict Verdict `json:"verdict"`
	Source  string  `json:"source"` // e.g. "virustotal,circl"
	Detail  string  `json:"detail"` // e.g. "12/70 engines flagged" or "NSRL known-good"
}

// Provider performs a file-hash reputation lookup.
type Provider interface {
	LookupHash(ctx context.Context, sha256 string) (Indicator, error)
}

var reSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// IsSHA256 reports whether s is a 64-char hex SHA-256.
func IsSHA256(s string) bool { return reSHA256.MatchString(s) }

// CompositeProvider merges the configured sub-clients into one verdict. VirusTotal is
// authoritative for "malicious"; CIRCL adds free known-good/known-bad coverage. A single
// source failing is tolerated as long as another succeeds.
type CompositeProvider struct {
	VT    *VirusTotalClient
	MB    *MalwareBazaarClient
	CIRCL *CIRCLClient
}

// LookupHash satisfies Provider. known_bad outranks known_good outranks unknown.
func (p *CompositeProvider) LookupHash(ctx context.Context, sha256 string) (Indicator, error) {
	h := strings.ToLower(strings.TrimSpace(sha256))
	if !IsSHA256(h) {
		return Indicator{Verdict: VerdictUnknown}, nil
	}
	ind := Indicator{Verdict: VerdictUnknown}
	var feeds, errs []string
	ok := false

	apply := func(v Verdict, detail, feed string) {
		feeds = append(feeds, feed)
		ok = true
		switch {
		case v == VerdictKnownBad:
			ind.Verdict, ind.Detail = VerdictKnownBad, detail
		case v == VerdictKnownGood && ind.Verdict == VerdictUnknown:
			ind.Verdict = VerdictKnownGood
			if ind.Detail == "" {
				ind.Detail = detail
			}
		}
	}

	if p.VT != nil {
		if v, detail, err := p.VT.Lookup(ctx, h); err != nil {
			errs = append(errs, err.Error())
		} else {
			apply(v, detail, "virustotal")
		}
	}
	// MalwareBazaar (known-bad only) — skip once something already flagged it bad.
	if p.MB != nil && ind.Verdict != VerdictKnownBad {
		if v, detail, err := p.MB.Lookup(ctx, h); err != nil {
			errs = append(errs, err.Error())
		} else {
			apply(v, detail, "malwarebazaar")
		}
	}
	// Skip CIRCL once something already flagged it bad — nothing it can add.
	if p.CIRCL != nil && ind.Verdict != VerdictKnownBad {
		if v, detail, err := p.CIRCL.Lookup(ctx, h); err != nil {
			errs = append(errs, err.Error())
		} else {
			apply(v, detail, "circl")
		}
	}

	if !ok && len(errs) > 0 {
		return Indicator{}, fmt.Errorf("hashrep: all sources failed: %s", strings.Join(errs, "; "))
	}
	ind.Source = strings.Join(feeds, ",")
	return ind, nil
}

// BuildProvider assembles a reputation provider. vtKey enables VirusTotal; mbKey enables
// MalwareBazaar; circlOn enables the free CIRCL hashlookup. Returns (nil, false) when nothing
// is configured.
func BuildProvider(vtKey, mbKey string, circlOn bool) (Provider, bool) {
	if vtKey == "" && mbKey == "" && !circlOn {
		return nil, false
	}
	cp := &CompositeProvider{}
	if vtKey != "" {
		cp.VT = NewVirusTotalClient(vtKey)
	}
	if mbKey != "" {
		cp.MB = NewMalwareBazaarClient(mbKey)
	}
	if circlOn {
		cp.CIRCL = NewCIRCLClient()
	}
	return cp, true
}
