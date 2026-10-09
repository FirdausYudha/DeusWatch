package assistant

import "strings"

// Product knowledge, pulled in when the question is conceptual rather than operational.
//
// Gated for the same reason as the setup and rule-authoring guides: it is paid for on every message
// it rides along with, and most messages are "what happened" rather than "what does degraded mean".
// Without it the model answers from generic SIEM knowledge, which is close enough to sound right and
// wrong in the details that matter here, such as calling the response engine automatic when this
// deployment has auto-approve off.
var conceptWords = []string{
	"what is", "what's a", "what does", "what do you mean", "how does", "how do", "explain", "meaning",
	"difference between", "why does", "why is", "what counts as", "what are",
	"apa itu", "apa maksud", "apa bedanya", "bedanya", "jelaskan", "kenapa", "maksudnya", "artinya",
	"bagaimana cara kerja", "cara kerjanya",
	// "what's it for" style questions, which ask for meaning just as much as "what is".
	"apa fungsi", "fungsinya", "fungsi dari", "untuk apa", "gunanya", "kegunaan",
}

// NeedsPrimer reports whether the message is asking what something means.
func NeedsPrimer(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range conceptWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// Primer is how DeusWatch actually works, as opposed to how SIEMs generally work.
//
// Everything here is a thing a model would otherwise get subtly wrong by analogy to other products:
// the severity ladder, what each agent status really means, that response is approval-gated rather
// than automatic, and that detection has two paths rather than one.
const Primer = `HOW DEUSWATCH WORKS (use this instead of general SIEM knowledge; other products do these differently)

PIPELINE. Agents on each endpoint tail log sources and ship them over mTLS to the gateway. The gateway normalises each line into a common event shape and publishes it. The worker is the only consumer: it evaluates every detection rule, enriches with threat intelligence, and writes the events and alerts. If the worker stops, agents keep shipping and the queue keeps filling, but nothing is detected or stored. That is why its liveness outranks every other answer.

SEVERITY. informational, low, medium, high, critical. A single failed login is low; the brute-force aggregation that counts many of them is high. Severity describes the finding, not the host.

AGENT STATUS. online = heartbeating and healthy. degraded = heartbeating but the agent reports a problem about ITSELF, usually a log-shipping backlog. disconnected = missed heartbeats past the threshold, which raises a high-severity alert because an agent going quiet is a known adversary technique. stale = quiet for over a day, already alerted, kept from re-alerting. unknown = enrolled but has never once checked in, which usually means the install did not finish.

DETECTION HAS TWO PATHS. Single-event rules match one event in isolation. Aggregation rules count events over a window ("more than 20 failures from one IP in 5 minutes") and run as SQL queries, not against individual events. A rule's detection block tells you which it is: a count() pipe means aggregation.

RESPONSE IS APPROVAL-GATED. A rule firing does not ban anyone. It produces a recommendation on the Response page, and a human with the right permission approves it before any firewall is touched. Progressive ban means a repeat offender gets a longer ban than a first-time one. The whitelist is checked before every ban, so a whitelisted address is refused even by an explicit request.

FIM watches files for change and keeps versioned snapshots, so a changed file can be compared with and restored to a known-good version. A change by an admin during a trusted session is recorded as an authorised change rather than alerted on.

AGENT HEALTH is two separate scans. Vulnerability assessment checks the OS packages installed on each endpoint against the OSV database. SCA checks application dependencies found in lockfiles. Both report findings per package with a severity and, where published, a CVSS score. Neither changes anything on the host.

PLAYBOOKS map a MITRE tactic to a recommended response. DECODERS turn an unrecognised log format into normalised fields. INTEGRATIONS are the outbound connectors: threat intelligence, firewalls, notification channels and the model you are running on.

MULTI-TENANCY. Workspaces and tenants separate data. Row-level security in the database enforces it, so a user only ever sees their own tenant's events, and that is not something the UI merely hides.`
