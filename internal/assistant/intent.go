package assistant

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Intent parsing for the assistant's propose-only actions (ADR 0003, phase 2).
//
// This is deliberately a plain parser with NO model in it, and that is the security property, not
// a shortcut. A proposal must originate from a sentence the operator typed. If the model were
// allowed to propose actions from what it read in the event context, an attacker could write a log
// line that steers it, and even though a human approves at the end, filling the approval queue
// with attacker-chosen proposals is itself an attack: the twentieth bogus card is the one somebody
// waves through.
//
// Parsing the operator's own text closes that completely. It also costs no tokens, adds no
// latency, cannot hallucinate an address, and behaves the same on a 3B local model as on Claude.
// The trade is coverage: an unusual phrasing is simply not recognised and the operator rephrases,
// which is a far better failure than a confidently wrong IP.

// ProposalKind is the action an operator asked for.
type ProposalKind string

const (
	KindBan       ProposalKind = "ban"
	KindWhitelist ProposalKind = "whitelist"
	// KindRule is drafted by the model rather than parsed from the operator's sentence, which is
	// why it is validated with the real engine before it is ever shown. See rulecraft.go.
	KindRule ProposalKind = "rule"
)

// Proposal is a parsed request, rendered to the operator as a confirmation card. Nothing happens
// until they confirm it, and the confirmation calls the ordinary API endpoint under their own
// session, so the permission checked is the endpoint's (execute_block / manage_settings), never
// the weaker one that merely lets someone talk to the assistant.
type Proposal struct {
	Kind ProposalKind `json:"kind"`
	// Target is a validated IP, or a CIDR for a whitelist entry.
	Target string `json:"target"`
	// Minutes is the ban duration. 0 means "use the configured progressive-ban ladder", which is
	// what the ban endpoint already does with an omitted duration.
	Minutes int `json:"minutes"`
	// YAML is the drafted rule, for KindRule only. The operator reviews this text itself: they are
	// approving code, and a summary of code is not something anyone can approve responsibly.
	YAML string `json:"yaml,omitempty"`
}

var (
	// Matched loosely, then validated with net.Parse*, so a port, a version string or a hash
	// fragment that merely looks address-shaped is rejected rather than acted on.
	reAddr = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b|([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/\d{1,3})?)`)
	reDur  = regexp.MustCompile(`(?i)\b(\d{1,5})\s*(menit|minutes?|mins?|jam|hours?|hrs?|hari|days?)\b`)

	banWords       = []string{"ban", "block", "blokir", "blok", "blacklist", "cekal", "banned"}
	whitelistWords = []string{"whitelist", "allowlist", "allow", "izinkan", "percayai", "trust", "kecualikan"}
	// Checked before the ban words: these contain "ban"/"block" as a substring but mean the
	// opposite, and lifting a ban is a different operation with its own UI.
	negations = []string{"unban", "un-ban", "unblock", "un-block", "buka blokir", "lepas blokir", "jangan blokir", "jangan ban", "batalkan"}
)

// ParseProposal extracts an action request from the operator's message. ok is false when the
// message is an ordinary question, which is the common case and must stay cheap.
func ParseProposal(msg string) (Proposal, bool) {
	low := strings.ToLower(msg)
	for _, n := range negations {
		if strings.Contains(low, n) {
			return Proposal{}, false
		}
	}

	kind, found := ProposalKind(""), false
	// Whitelist is tested first: "whitelist" and "allow" are unambiguous, while a sentence can
	// easily mention both ("whitelist it instead of blocking").
	if containsWord(low, whitelistWords) {
		kind, found = KindWhitelist, true
	} else if containsWord(low, banWords) {
		kind, found = KindBan, true
	}
	if !found {
		return Proposal{}, false
	}

	target, ok := firstAddress(msg, kind == KindWhitelist)
	if !ok {
		return Proposal{}, false // a verb with no address is conversation, not a command
	}

	p := Proposal{Kind: kind, Target: target}
	if kind == KindBan {
		p.Minutes = parseMinutes(low)
	}
	return p, true
}

// containsWord reports whether any of words appears as a whole word, so "ban" does not fire on
// "banner", "urban" or "bandwidth".
func containsWord(low string, words []string) bool {
	for _, w := range words {
		for _, idx := range indexAll(low, w) {
			beforeOK := idx == 0 || !isWordByte(low[idx-1])
			end := idx + len(w)
			afterOK := end == len(low) || !isWordByte(low[end])
			if beforeOK && afterOK {
				return true
			}
		}
	}
	return false
}

func indexAll(s, sub string) []int {
	var out []int
	for off := 0; ; {
		i := strings.Index(s[off:], sub)
		if i < 0 {
			return out
		}
		out = append(out, off+i)
		off += i + len(sub)
	}
}

func isWordByte(b byte) bool {
	return b == '-' || b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// firstAddress returns the first syntactically valid address in the message. A CIDR is accepted
// only for a whitelist: whitelisting a range is ordinary, while banning one through this path is
// not, and silently widening a ban to a /8 because someone typed a prefix is not a mistake worth
// making possible.
func firstAddress(msg string, allowCIDR bool) (string, bool) {
	for _, loc := range reAddr.FindAllStringIndex(msg, -1) {
		if !addressBoundaryOK(msg, loc[0], loc[1]) {
			continue
		}
		m := msg[loc[0]:loc[1]]
		if strings.Contains(m, "/") {
			if !allowCIDR {
				continue
			}
			if _, n, err := net.ParseCIDR(m); err == nil {
				return n.String(), true
			}
			continue
		}
		// IsUnspecified rejects "0.0.0.0" and the "::" that the v6 pattern happily finds inside
		// ordinary punctuation. Neither is ever a thing anyone means to ban or whitelist.
		if ip := net.ParseIP(m); ip != nil && !ip.IsUnspecified() {
			return ip.String(), true
		}
	}
	return "", false
}

// addressBoundaryOK rejects a match that is really a slice of a longer dotted string. A word
// boundary is not enough: "version 1.2.3.4.5.6" contains a perfectly valid-looking 1.2.3.4, and
// proposing a ban on a fragment of a version number is exactly the kind of confident mistake that
// teaches operators to stop reading confirmation cards.
//
// A trailing period is fine, since a sentence may simply end after the address; only a period
// followed by another digit means the match was cut out of something longer.
func addressBoundaryOK(s string, start, end int) bool {
	if start > 0 {
		if c := s[start-1]; c == '.' || isDigit(c) {
			return false
		}
	}
	if end < len(s) {
		if c := s[end]; isDigit(c) {
			return false
		}
		if s[end] == '.' && end+1 < len(s) && isDigit(s[end+1]) {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// parseMinutes reads a duration out of the message. 0 (nothing recognised) means the ban endpoint
// applies the configured progressive ladder, which is the right default.
func parseMinutes(low string) int {
	m := reDur.FindStringSubmatch(low)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0
	}
	switch {
	case strings.HasPrefix(m[2], "jam"), strings.HasPrefix(m[2], "hour"), strings.HasPrefix(m[2], "hr"):
		n *= 60
	case strings.HasPrefix(m[2], "hari"), strings.HasPrefix(m[2], "day"):
		n *= 60 * 24
	}
	// A year is far past any plausible typed ban and well past what the UI can show sensibly.
	if n > 525600 {
		n = 525600
	}
	return n
}

// Reply is the assistant's own answer to a recognised command. It is written here rather than
// generated, because the card beside it is the thing that matters: a model asked to narrate an
// action it is not performing tends to either claim it did it or deny it can, and both are wrong.
func (p Proposal) Reply() string {
	if p.Kind == KindWhitelist {
		return fmt.Sprintf("Prepared a whitelist entry for %s. Review it below: the response engine will never ban anything matching it, so check the range before confirming. Nothing is saved until you do.", p.Target)
	}
	if p.Minutes > 0 {
		return fmt.Sprintf("Prepared a %s block for %s. Review it below. Nothing is applied until you confirm.", humanMinutes(p.Minutes), p.Target)
	}
	return fmt.Sprintf("Prepared a block for %s using the configured ban ladder, so the duration follows this IP's history. Review it below. Nothing is applied until you confirm.", p.Target)
}

func humanMinutes(m int) string {
	switch {
	case m%(60*24) == 0:
		return fmt.Sprintf("%d-day", m/(60*24))
	case m%60 == 0:
		return fmt.Sprintf("%d-hour", m/60)
	default:
		return fmt.Sprintf("%d-minute", m)
	}
}
