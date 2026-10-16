package compliance

import (
	"strings"
	"testing"
)

// The report's honesty rests on two sentences, and both live in constants so a future export
// format cannot quietly ship without them. This is the control on the control report.
func TestDisclaimerRefusesTheStrongerClaim(t *testing.T) {
	low := strings.ToLower(Disclaimer)
	// It must say what it is NOT, because "ISO 27001 report" is read as "we are certified" by
	// everyone who did not write it.
	for _, want := range []string{"evidence", "not a compliance determination", "confirm the control mapping"} {
		if !strings.Contains(low, strings.ToLower(want)) {
			t.Errorf("the disclaimer must contain %q:\n%s", want, Disclaimer)
		}
	}
	// And it must name what DeusWatch cannot see, or the boundary is left to the reader's
	// imagination, which is generous.
	for _, want := range []string{"policy", "risk assessment", "training", "physical"} {
		if !strings.Contains(low, want) {
			t.Errorf("the disclaimer should name %q as outside what DeusWatch can see:\n%s", want, Disclaimer)
		}
	}
}

// A catalogue entry with no gatherer produces a row that looks like "nothing happened" rather than
// "nobody asked". The store switches on Kind, so this is what keeps the two in step.
func TestEveryControlHasAKindAndIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Controls {
		if c.ID == "" || c.Title == "" || c.Covers == "" {
			t.Errorf("incomplete control: %+v", c)
		}
		if c.Kind == "" {
			t.Errorf("%s has no evidence kind, so it would report an empty row", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("%s appears twice", c.ID)
		}
		seen[c.ID] = true
		if !strings.HasPrefix(c.ID, "A.") {
			t.Errorf("%s does not look like an Annex A reference", c.ID)
		}
	}
	if len(Controls) == 0 {
		t.Fatal("the catalogue is empty")
	}
}

// Covers describes the EVIDENCE, never the control's full requirement. The gap between those two
// is where an over-claim starts, so the wording is kept away from the language of compliance.
func TestCoversDoesNotClaimCompliance(t *testing.T) {
	banned := []string{"compliant", "compliance", "certified", "certification", "meets the requirement", "satisfies"}
	for _, c := range Controls {
		low := strings.ToLower(c.Covers)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("%s claims %q, which this report cannot know: %s", c.ID, b, c.Covers)
			}
		}
	}
}

// The report states its own boundary. Sixteen controls out of ninety-three needs the reader to
// know the other seventy-seven were excluded deliberately rather than never considered.
func TestNotCoveredNamesTheBoundary(t *testing.T) {
	if len(NotCovered) < 5 {
		t.Errorf("the excluded list is too thin to describe the boundary: %v", NotCovered)
	}
	joined := strings.ToLower(strings.Join(NotCovered, " "))
	for _, want := range []string{"policy", "risk assessment", "physical", "supplier"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the excluded list should mention %q", want)
		}
	}
}

func TestKindsAreDistinct(t *testing.T) {
	ks := Kinds()
	seen := map[Kind]bool{}
	for _, k := range ks {
		if seen[k] {
			t.Errorf("Kinds returned %q twice", k)
		}
		seen[k] = true
	}
	for _, c := range Controls {
		if !seen[c.Kind] {
			t.Errorf("Kinds omitted %q, used by %s", c.Kind, c.ID)
		}
	}
}
