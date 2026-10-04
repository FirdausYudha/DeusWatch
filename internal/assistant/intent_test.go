package assistant

import "testing"

func TestParseProposalRecognises(t *testing.T) {
	cases := []struct {
		msg     string
		kind    ProposalKind
		target  string
		minutes int
	}{
		{"ban 45.134.26.9", KindBan, "45.134.26.9", 0},
		{"tolong blokir IP 45.134.26.9 dong", KindBan, "45.134.26.9", 0},
		{"block 45.134.26.9 for 60 minutes", KindBan, "45.134.26.9", 60},
		{"blokir 45.134.26.9 selama 2 jam", KindBan, "45.134.26.9", 120},
		{"ban 45.134.26.9 for 3 days", KindBan, "45.134.26.9", 4320},
		{"ban 2001:db8::1", KindBan, "2001:db8::1", 0},
		{"whitelist 10.0.0.0/8", KindWhitelist, "10.0.0.0/8", 0},
		{"izinkan 192.168.1.50", KindWhitelist, "192.168.1.50", 0},
		// A sentence naming both verbs is a whitelist request: "allow it rather than blocking".
		{"whitelist 10.0.0.5 instead of blocking it", KindWhitelist, "10.0.0.5", 0},
	}
	for _, c := range cases {
		p, ok := ParseProposal(c.msg)
		if !ok {
			t.Errorf("%q: not recognised", c.msg)
			continue
		}
		if p.Kind != c.kind || p.Target != c.target || p.Minutes != c.minutes {
			t.Errorf("%q: got %+v, want kind=%s target=%s minutes=%d", c.msg, p, c.kind, c.target, c.minutes)
		}
	}
}

func TestParseProposalIgnores(t *testing.T) {
	// Each of these must stay an ordinary question. A false positive here is a confirmation card
	// offering to block something nobody asked about, which trains operators to click past cards.
	for _, msg := range []string{
		"what happened in the last 24 hours?",
		"is 45.134.26.9 dangerous?",           // an address with no verb
		"should I ban someone?",               // a verb with no address
		"unban 45.134.26.9",                   // the opposite operation, and it contains "ban"
		"unblock 45.134.26.9",                 //
		"jangan blokir 45.134.26.9",           // explicit negation
		"batalkan blokir untuk 45.134.26.9",   //
		"the banner image is broken",          // "ban" inside a longer word
		"urban traffic from 10.0.0.1 is high", //
		"bandwidth to 10.0.0.1 is saturated",  //
		"block the agent version 1.2.3.4.5.6", // not a valid address
		"ban 10.0.0.0/8",                      // a CIDR ban is refused on purpose
	} {
		if p, ok := ParseProposal(msg); ok {
			t.Errorf("%q: should not be a proposal, got %+v", msg, p)
		}
	}
}

func TestProposalReplyStatesNothingHappenedYet(t *testing.T) {
	for _, p := range []Proposal{
		{Kind: KindBan, Target: "1.2.3.4"},
		{Kind: KindBan, Target: "1.2.3.4", Minutes: 120},
		{Kind: KindWhitelist, Target: "10.0.0.0/8"},
	} {
		got := p.Reply()
		if !contains(got, p.Target) {
			t.Errorf("%+v: reply omits the target: %s", p, got)
		}
		// The operator must never read the reply as "done".
		if !contains(got, "until you") {
			t.Errorf("%+v: reply does not say it is not applied yet: %s", p, got)
		}
	}
}

func TestHumanMinutes(t *testing.T) {
	for in, want := range map[int]string{90: "90-minute", 120: "2-hour", 1440: "1-day", 4320: "3-day"} {
		if got := humanMinutes(in); got != want {
			t.Errorf("humanMinutes(%d) = %q, want %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
