// Package compliance maps what DeusWatch already records to the ISO/IEC 27001:2022 Annex A
// controls an auditor asks about.
//
// Gap 10 from the field insight. The hospital has accreditation, but none of it covers information
// security: "Kalau dari security, belum. Karena security sisi IT ya, belum ada ISO." An
// organisation starting that path spends most of its effort proving that controls OPERATE, and the
// product that already watches the estate is holding most of that proof in tables nobody exports.
//
// THE ONE THING THIS PACKAGE MUST NOT DO is say an organisation is compliant. It cannot know that.
// Certification covers policy, governance, risk assessment, training, physical security and
// supplier management, and DeusWatch sees none of those. What it can honestly produce is evidence
// that a control was operating during a period, which is one input an auditor weighs among many.
// Every string in here is written so that an operator who skims it cannot come away believing the
// stronger claim. See Disclaimer.
//
// The second rule: a control with nothing to show is REPORTED AS A GAP, never omitted. A report
// that silently drops the controls with no evidence reads as complete coverage, which is worse
// than useless in an audit, because it is the one place a reader assumes the absence of a row
// means the question was not asked rather than that the answer was empty.
package compliance

// Disclaimer heads every rendering of this report. It is a constant rather than UI text so it
// cannot be dropped by whoever is building the next export format.
const Disclaimer = "This is EVIDENCE, not a compliance determination. It shows what DeusWatch " +
	"recorded for each control during the period. ISO/IEC 27001 certification also covers policy, " +
	"risk assessment, training, physical security and supplier management, none of which DeusWatch " +
	"can see. Confirm the control mapping with your auditor: it is a starting point, not an " +
	"authoritative reading of the standard."

// Kind names the evidence query that feeds a control. The store switches on it, so adding a
// control without a gatherer is caught by a test rather than producing a silently empty row.
type Kind string

const (
	KindEvents        Kind = "events"         // volume and alert counts
	KindRules         Kind = "rules"          // detection coverage
	KindAgents        Kind = "agents"         // estate reporting in
	KindAccessReview  Kind = "access_review"  // account and permission changes from the audit log
	KindAccounts      Kind = "accounts"       // who holds what today
	KindAuthFailures  Kind = "auth_failures"  // failed sign-ins, the access-control control's bread and butter
	KindMalware       Kind = "malware"        // process classifications and hash verdicts
	KindVulns         Kind = "vulns"          // findings and scan freshness
	KindFIM           Kind = "fim"            // file integrity, configuration and change
	KindIncidents     Kind = "incidents"      // tickets raised, resolved, and how fast
	KindResponse      Kind = "response"       // blocks and containment actions
	KindThreatIntel   Kind = "threat_intel"   // CTI lookups performed
	KindPlaybooks     Kind = "playbooks"      // documented response procedures
	KindRetention     Kind = "retention"      // how far back the evidence itself reaches
	KindAdminActivity Kind = "admin_activity" // what administrators did, from the audit log
)

// Control is one Annex A control DeusWatch can speak to.
type Control struct {
	// ID is the Annex A reference, e.g. "A.8.16".
	ID string
	// Title is the control's name in the standard.
	Title string
	// Covers says, in an operator's words, what DeusWatch contributes. Deliberately narrow: it
	// describes the evidence, never the control's full requirement, because the difference between
	// the two is exactly where an over-claim would start.
	Covers string
	// Kind selects the evidence query.
	Kind Kind
}

// Controls is the catalogue, in Annex A order.
//
// Sixteen of the standard's ninety-three. The rest are not listed at all rather than listed as
// "not applicable", because declaring a control inapplicable is the organisation's judgement to
// make and record, not a security tool's. NotCovered says so.
var Controls = []Control{
	{"A.5.7", "Threat intelligence",
		"Reputation and intelligence lookups performed against observed indicators, with their source and date.", KindThreatIntel},
	{"A.5.15", "Access control",
		"Failed and successful sign-ins to DeusWatch and to monitored endpoints over the period.", KindAuthFailures},
	{"A.5.16", "Identity management",
		"The accounts that exist today, their roles, and which are disabled.", KindAccounts},
	{"A.5.18", "Access rights",
		"Every account creation, deletion, role change and permission change in the period, with who made it.", KindAccessReview},
	{"A.5.24", "Information security incident management planning and preparation",
		"The response playbooks defined, and whether each is enabled.", KindPlaybooks},
	{"A.5.25", "Assessment and decision on information security events",
		"Alerts raised and how many became tickets, which is the decision being evidenced.", KindIncidents},
	{"A.5.26", "Response to information security incidents",
		"Blocks and host containment actions carried out, with who approved them.", KindResponse},
	{"A.5.28", "Collection of evidence",
		"How far back the event record actually reaches, and the file versions retained for restoration.", KindRetention},
	{"A.6.8", "Information security event reporting",
		"Tickets raised in the period, by whom, and how many were raised automatically from alerts.", KindIncidents},
	{"A.8.7", "Protection against malware",
		"Process classifications and file-hash verdicts produced in the period.", KindMalware},
	{"A.8.8", "Management of technical vulnerabilities",
		"Findings per endpoint by severity, and when each endpoint was last scanned.", KindVulns},
	{"A.8.9", "Configuration management",
		"Monitored configuration paths and the changes detected on them.", KindFIM},
	{"A.8.15", "Logging",
		"Event volume collected, and how many enrolled endpoints actually reported.", KindEvents},
	{"A.8.16", "Monitoring activities",
		"Detection rules enabled and the alerts they produced in the period.", KindRules},
	{"A.8.20", "Networks security",
		"Addresses blocked at the network edge and the backend that carried each block.", KindResponse},
	{"A.8.32", "Change management",
		"File integrity changes on monitored paths, with the account responsible where who-data is available.", KindFIM},
}

// NotCovered lists the themes DeusWatch contributes nothing to, so the report states its own
// boundary. An auditor reading a report that covers sixteen controls needs to know whether the
// other seventy-seven were considered and excluded, or simply never looked at.
var NotCovered = []string{
	"Policy, governance and management review (A.5.1 to A.5.6)",
	"Risk assessment and treatment, which sits outside Annex A entirely",
	"People controls: screening, terms of employment, awareness, discipline (A.6 except A.6.8)",
	"Physical controls: perimeters, entry, equipment siting, secure disposal (A.7)",
	"Supplier and cloud-service management (A.5.19 to A.5.23)",
	"Business continuity and ICT readiness (A.5.29, A.5.30)",
	"Backup, capacity planning and clock synchronisation (A.8.13, A.8.6, A.8.17)",
}

// Kinds returns the distinct evidence kinds the catalogue needs, so the store can be checked
// against it.
func Kinds() []Kind {
	seen := map[Kind]bool{}
	out := make([]Kind, 0, len(Controls))
	for _, c := range Controls {
		if !seen[c.Kind] {
			seen[c.Kind] = true
			out = append(out, c.Kind)
		}
	}
	return out
}
