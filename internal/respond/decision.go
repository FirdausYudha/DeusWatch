package respond

import "deuswatch/internal/ingest"

// The response decision-table — the explicit mapping from an alert's *entity type* to the
// response DeusWatch takes for it. One alert can concern several entities at once (an external
// IP attacking one of our hosts over a request that carried a known-bad file hash), and each
// entity type has its own policy and its own owning engine. This file is the single source of
// truth: the alert dispatcher routes by it and the API/UI display it, so the policy a user
// sees is exactly the policy that runs.

// EntityType is the kind of security entity an alert concerns — the axis the decision-table
// is keyed on.
type EntityType string

const (
	EntityExternalIP EntityType = "external_ip" // an attacker's source address (perimeter)
	EntityHost       EntityType = "host"        // one of our own agent endpoints
	EntityUser       EntityType = "user"        // an account identity
	EntityHash       EntityType = "hash"        // a file identified by its SHA-256
)

// Decision is the response policy for one entity type: the action DeusWatch takes, whether an
// engine automatically enforces that action today (vs. surfacing it for an analyst), the
// owning engine, and a human-readable rationale.
type Decision struct {
	Entity      EntityType `json:"entity_type"`
	Action      string     `json:"action"`   // block | network_containment | alert
	Enforced    bool       `json:"enforced"` // true = an engine executes it automatically
	Engine      string     `json:"engine"`   // owning component ("" when alert-only)
	Description string     `json:"description"`
}

// DefaultDecisionTable is the canonical entity_type → response mapping. external_ip and host
// are enforced by their engines; user and hash are alert-only today — they are surfaced with
// full context (a known-bad hash already raises the event to High via hash reputation), but
// DeusWatch does not yet auto-disable accounts or quarantine files. Documenting them here
// keeps the policy honest and gives those actions a defined home when enforcement is added.
func DefaultDecisionTable() []Decision {
	return []Decision{
		{
			Entity: EntityExternalIP, Action: "block", Enforced: true, Engine: "ban engine",
			Description: "Ban the source IP at the firewall/router with a progressive duration; whitelisted IPs are never banned.",
		},
		{
			Entity: EntityHost, Action: "network_containment", Enforced: true, Engine: "containment engine",
			Description: "Isolate the compromised endpoint from the LAN (host self-isolation plus a best-effort edge block) when a rule authorizes it.",
		},
		{
			Entity: EntityUser, Action: "alert", Enforced: false, Engine: "",
			Description: "Surface the account for analyst review. DeusWatch does not auto-disable accounts.",
		},
		{
			Entity: EntityHash, Action: "alert", Enforced: false, Engine: "",
			Description: "A known-bad file hash raises the event to High via hash reputation; the file itself is not auto-quarantined.",
		},
	}
}

// DecisionFor returns the decision for one entity type from the default table (ok=false if
// the entity type is unknown).
func DecisionFor(e EntityType) (Decision, bool) {
	for _, d := range DefaultDecisionTable() {
		if d.Entity == e {
			return d, true
		}
	}
	return Decision{}, false
}

// Entities returns the entity types an alert concerns, in decision-table order. The dispatcher
// uses it to route the alert to each responsible engine, and the API uses it to show which
// policies applied to a given event.
func Entities(ev *ingest.Event) []EntityType {
	if ev == nil {
		return nil
	}
	var out []EntityType
	if ev.Source != nil && ev.Source.IP != "" {
		out = append(out, EntityExternalIP)
	}
	if ev.Agent != nil && ev.Agent.ID != "" {
		out = append(out, EntityHost)
	}
	if ev.User != nil && ev.User.Name != "" {
		out = append(out, EntityUser)
	}
	if ev.File != nil && ev.File.HashSHA256 != "" {
		out = append(out, EntityHash)
	}
	return out
}
