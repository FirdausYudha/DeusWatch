package store

// Evidence gathering for the ISO 27001 control report (internal/compliance).
//
// Each gatherer answers one question for one period and says plainly when it has nothing. A
// control with no evidence becomes a GAP with a reason, never a blank row: in an audit, a missing
// line reads as "not asked", which is the one impression this report must not leave.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"deuswatch/internal/compliance"
)

// ControlEvidence is one control plus what the period actually holds for it.
type ControlEvidence struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Covers string `json:"covers"`
	// Summary is the finding in one line, ready to paste into a working paper.
	Summary string `json:"summary"`
	// Samples are a few concrete records, so the auditor can follow one through to the raw table
	// rather than taking a count on trust.
	Samples []string `json:"samples,omitempty"`
	// Gap is true when the period holds nothing for this control. Why says what to do about it.
	Gap bool   `json:"gap"`
	Why string `json:"why,omitempty"`
}

// ComplianceReport is the whole thing, including its own boundary.
type ComplianceReport struct {
	Standard   string            `json:"standard"`
	Disclaimer string            `json:"disclaimer"`
	From       time.Time         `json:"from"`
	To         time.Time         `json:"to"`
	Controls   []ControlEvidence `json:"controls"`
	NotCovered []string          `json:"not_covered"`
	// Gaps counts the controls with no evidence, so the headline cannot be read as full coverage.
	Gaps int `json:"gaps"`
}

// ISO27001Evidence builds the report for a period.
//
// One gatherer per Kind, and a Kind with no gatherer produces a visible "no gatherer" gap rather
// than an empty row. That is deliberate: a control added to the catalogue without the query to
// feed it would otherwise look like a control with nothing to report.
func (s *Store) ISO27001Evidence(ctx context.Context, from, to time.Time) (ComplianceReport, error) {
	rep := ComplianceReport{
		Standard:   "ISO/IEC 27001:2022 Annex A",
		Disclaimer: compliance.Disclaimer,
		From:       from, To: to,
		NotCovered: compliance.NotCovered,
	}
	// Gathered once per kind, not once per control: A.5.25 and A.6.8 share incidents, A.8.9 and
	// A.8.32 share file integrity, and running those queries twice would only cost time.
	cache := map[compliance.Kind]ControlEvidence{}

	for _, c := range compliance.Controls {
		ev, ok := cache[c.Kind]
		if !ok {
			got, err := s.gatherEvidence(ctx, c.Kind, from, to)
			if err != nil {
				// A broken gatherer becomes ONE visible defect row, not a failed report. This is
				// the same rule the package applies to empty evidence, and it was missing here:
				// a wrong column name in one query returned a bare error and took fifteen working
				// controls down with it, leaving the operator with nothing to read and no way to
				// tell which control was at fault.
				got = gap("This control could not be gathered.",
					"A DeusWatch defect, not a finding about your deployment: "+err.Error()+
						". Every other control in this report is unaffected.")
			}
			ev = got
			cache[c.Kind] = ev
		}
		ev.ID, ev.Title, ev.Covers = c.ID, c.Title, c.Covers
		if ev.Gap {
			rep.Gaps++
		}
		rep.Controls = append(rep.Controls, ev)
	}
	return rep, nil
}

func (s *Store) gatherEvidence(ctx context.Context, k compliance.Kind, from, to time.Time) (ControlEvidence, error) {
	switch k {
	case compliance.KindEvents:
		return s.evidenceEvents(ctx, from, to)
	case compliance.KindRules:
		return s.evidenceRules(ctx, from, to)
	case compliance.KindAgents:
		return s.evidenceAgents(ctx)
	case compliance.KindAccessReview:
		return s.evidenceAuditActions(ctx, from, to,
			[]string{"create_user", "delete_user", "update_user"},
			"account and permission changes",
			"No account was created, removed or changed in this period. For a review control that is a "+
				"valid finding, but confirm it matches your own records.")
	case compliance.KindAdminActivity:
		return s.evidenceAuditActions(ctx, from, to, nil, "administrator actions",
			"The audit log holds nothing for this period, which on a running deployment means nobody "+
				"signed in. Check that the API is recording audit entries.")
	case compliance.KindAccounts:
		return s.evidenceAccounts(ctx)
	case compliance.KindAuthFailures:
		return s.evidenceAuthFailures(ctx, from, to)
	case compliance.KindMalware:
		return s.evidenceMalware(ctx, from, to)
	case compliance.KindVulns:
		return s.evidenceVulns(ctx)
	case compliance.KindFIM:
		return s.evidenceFIM(ctx, from, to)
	case compliance.KindIncidents:
		return s.evidenceIncidents(ctx, from, to)
	case compliance.KindResponse:
		return s.evidenceResponse(ctx, from, to)
	case compliance.KindThreatIntel:
		return s.evidenceThreatIntel(ctx, from, to)
	case compliance.KindPlaybooks:
		return s.evidencePlaybooks(ctx)
	case compliance.KindRetention:
		return s.evidenceRetention(ctx)
	default:
		return ControlEvidence{Gap: true, Summary: "No evidence gatherer.",
			Why: fmt.Sprintf("This control is in the catalogue as kind %q but nothing queries for it. "+
				"That is a defect in DeusWatch, not a finding about your deployment.", k)}, nil
	}
}

// one runs a query returning a single row of counts plus an optional sample list.
func (s *Store) scalar(ctx context.Context, sql string, args ...any) (int64, error) {
	var n int64
	err := s.q(ctx).QueryRow(ctx, sql, args...).Scan(&n)
	return n, err
}

func (s *Store) samples(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.q(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 5)
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	return out, rows.Err()
}

func gap(summary, why string) ControlEvidence {
	return ControlEvidence{Gap: true, Summary: summary, Why: why}
}

func (s *Store) evidenceEvents(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	var total, alerts, agents int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE dw_label IS NOT NULL AND dw_label <> ''),
		       count(DISTINCT agent_id) FILTER (WHERE agent_id IS NOT NULL AND agent_id <> '')
		  FROM events WHERE time >= $1 AND time < $2`, from, to).Scan(&total, &alerts, &agents)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence events: %w", err)
	}
	if total == 0 {
		return gap("No events were collected in this period.",
			"Logging is the control. An empty period means nothing was being collected, which is a "+
				"finding to act on before an audit rather than a figure to report."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s events collected from %d endpoint(s); %s became alerts.",
			thousands(total), agents, thousands(alerts)),
	}, nil
}

func (s *Store) evidenceRules(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	alerts, err := s.scalar(ctx, `
		SELECT count(*) FROM events
		 WHERE time >= $1 AND time < $2 AND dw_label IS NOT NULL AND dw_label <> ''`, from, to)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence rules: %w", err)
	}
	top, err := s.samples(ctx, `
		SELECT COALESCE(NULLIF(rule_name,''), rule_id) || ': ' || count(*)::text || ' alert(s)'
		  FROM events
		 WHERE time >= $1 AND time < $2 AND dw_label IS NOT NULL AND dw_label <> ''
		   AND COALESCE(rule_id,'') <> ''
		 GROUP BY 1 ORDER BY count(*) DESC LIMIT 5`, from, to)
	if err != nil {
		return ControlEvidence{}, err
	}
	if alerts == 0 {
		return gap("No alerts were raised in this period.",
			"Either the estate was quiet or detection is not reaching it. The two look identical here, "+
				"so check that rules are enabled and agents are reporting before recording this as calm."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s alert(s) raised by the enabled rule set.", thousands(alerts)),
		Samples: top,
	}, nil
}

func (s *Store) evidenceAgents(ctx context.Context) (ControlEvidence, error) {
	var enrolled, online int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE last_seen_at > now() - interval '15 minutes')
		  FROM agents WHERE deleted_at IS NULL AND NOT revoked`).Scan(&enrolled, &online)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence agents: %w", err)
	}
	if enrolled == 0 {
		return gap("No endpoints are enrolled.", "Nothing is being monitored."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d endpoint(s) enrolled, %d reporting in the last 15 minutes.", enrolled, online),
	}, nil
}

func (s *Store) evidenceAuditActions(ctx context.Context, from, to time.Time, actions []string, label, emptyWhy string) (ControlEvidence, error) {
	filter, args := "", []any{from, to}
	if len(actions) > 0 {
		filter = " AND action = ANY($3)"
		args = append(args, actions)
	}
	n, err := s.scalar(ctx, `SELECT count(*) FROM audit_log WHERE time >= $1 AND time < $2`+filter, args...)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence audit: %w", err)
	}
	if n == 0 {
		return gap(fmt.Sprintf("No %s recorded in this period.", label), emptyWhy), nil
	}
	rows, err := s.samples(ctx, `
		SELECT to_char(time,'YYYY-MM-DD HH24:MI') || '  ' || actor || ' (' || actor_role || ')  ' ||
		       action || COALESCE('  ' || NULLIF(target,''), '')
		  FROM audit_log WHERE time >= $1 AND time < $2`+filter+`
		 ORDER BY time DESC LIMIT 10`, args...)
	if err != nil {
		return ControlEvidence{}, err
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s %s recorded, each with the acting account and source address.", thousands(n), label),
		Samples: rows,
	}, nil
}

func (s *Store) evidenceAccounts(ctx context.Context) (ControlEvidence, error) {
	rows, err := s.samples(ctx, `
		SELECT username || '  ' || role || CASE WHEN disabled THEN '  (disabled)' ELSE '' END
		  FROM users ORDER BY role, username`)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence accounts: %w", err)
	}
	if len(rows) == 0 {
		return gap("No accounts exist.", "This should be impossible on a running deployment."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d account(s) exist, listed with their role. This is the roster as of now, not a history.", len(rows)),
		Samples: rows,
	}, nil
}

func (s *Store) evidenceAuthFailures(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	var failed, ok int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE event_outcome = 'failure'),
		       count(*) FILTER (WHERE event_outcome = 'success')
		  FROM events
		 WHERE time >= $1 AND time < $2 AND event_category = 'authentication'`, from, to).Scan(&failed, &ok)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence auth: %w", err)
	}
	if failed == 0 && ok == 0 {
		return gap("No authentication events were collected in this period.",
			"Access control cannot be evidenced without them. Check that endpoint auth logs are being "+
				"shipped: on Windows the Security channel needs the agent running elevated."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s failed and %s successful authentications recorded across the estate.",
			thousands(failed), thousands(ok)),
	}, nil
}

func (s *Store) evidenceMalware(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	var mal, sus int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE threat_level = 'MALICIOUS'),
		       count(*) FILTER (WHERE threat_level = 'SUSPICIOUS')
		  FROM process_threats WHERE detected_at >= $1 AND detected_at < $2`, from, to).Scan(&mal, &sus)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence malware: %w", err)
	}
	if mal == 0 && sus == 0 {
		return gap("No process classifications were produced in this period.",
			"Nothing malicious found is one explanation; process snapshots not reaching the analyzer is "+
				"the other, and they are indistinguishable from here. Confirm agents are shipping process "+
				"snapshots before recording a clean period."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d malicious and %d suspicious process classification(s).", mal, sus),
	}, nil
}

func (s *Store) evidenceVulns(ctx context.Context) (ControlEvidence, error) {
	var crit, high, total, agents int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE severity = 'critical'), count(*) FILTER (WHERE severity = 'high'),
		       count(*), count(DISTINCT agent_name)
		  FROM agent_vulnerabilities`).Scan(&crit, &high, &total, &agents)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence vulns: %w", err)
	}
	if total == 0 {
		return gap("No vulnerability findings are recorded.",
			"Either nothing was found or no scan has completed. Check the Agent Health page: an endpoint "+
				"that has never been scanned reports no findings, which is not the same as having none."), nil
	}
	// Per-agent freshness comes from the findings themselves, NOT from scan_status: that table is
	// keyed by scanner (trivy, osv) with one row each, so it answers "is the scanner healthy", not
	// "when was this endpoint last looked at". Reading it per agent was both the wrong column and
	// the wrong question, and it took the whole report down with it.
	stale, err := s.samples(ctx, `
		SELECT agent_name || ': findings last updated ' || to_char(max(detected_at),'YYYY-MM-DD')
		  FROM agent_vulnerabilities
		 GROUP BY agent_name ORDER BY max(detected_at) LIMIT 5`)
	if err != nil {
		return ControlEvidence{}, err
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s finding(s) across %d endpoint(s): %d critical, %d high. Current state, not a period count.",
			thousands(total), agents, crit, high),
		Samples: stale,
	}, nil
}

func (s *Store) evidenceFIM(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	changes, err := s.scalar(ctx, `
		SELECT count(*) FROM events
		 WHERE time >= $1 AND time < $2 AND event_category = 'file'`, from, to)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence fim: %w", err)
	}
	if changes == 0 {
		return gap("No file integrity changes were recorded in this period.",
			"A quiet estate looks the same as file integrity monitoring that was never configured. "+
				"Confirm that watched paths are set on the agents before reporting this as stability."), nil
	}
	top, err := s.samples(ctx, `
		SELECT file_path || ': ' || count(*)::text || ' change(s)'
		  FROM events
		 WHERE time >= $1 AND time < $2 AND event_category = 'file' AND COALESCE(file_path,'') <> ''
		 GROUP BY 1 ORDER BY count(*) DESC LIMIT 5`, from, to)
	if err != nil {
		return ControlEvidence{}, err
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%s change(s) detected on monitored paths.", thousands(changes)),
		Samples: top,
	}, nil
}

func (s *Store) evidenceIncidents(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	var opened, resolved int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE created_at >= $1 AND created_at < $2),
		       count(*) FILTER (WHERE resolved_at >= $1 AND resolved_at < $2)
		  FROM tickets`, from, to).Scan(&opened, &resolved)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence incidents: %w", err)
	}
	if opened == 0 && resolved == 0 {
		return gap("No tickets were opened or resolved in this period.",
			"An incident management control with no incidents is hard to evidence. If incidents were "+
				"handled outside DeusWatch, say so in the working paper rather than leaving this blank."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d ticket(s) opened and %d resolved in the period.", opened, resolved),
	}, nil
}

func (s *Store) evidenceResponse(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	var executed, pending int64
	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'executed'),
		       count(*) FILTER (WHERE status IN ('recommended','approved'))
		  FROM response_actions WHERE created_at >= $1 AND created_at < $2`, from, to).Scan(&executed, &pending)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence response: %w", err)
	}
	if executed == 0 && pending == 0 {
		return gap("No response actions were recorded in this period.",
			"Nothing needed blocking is one reading; response not being configured is the other. Check "+
				"whether an enforcement backend is connected before recording this as a quiet period."), nil
	}
	rows, err := s.samples(ctx, `
		SELECT to_char(created_at,'YYYY-MM-DD HH24:MI') || '  ' || host(source_ip) || '  ' || status ||
		       COALESCE('  via ' || NULLIF(responder,''), '') || COALESCE('  by ' || NULLIF(decided_by,''), '')
		  FROM response_actions WHERE created_at >= $1 AND created_at < $2
		 ORDER BY created_at DESC LIMIT 10`, from, to)
	if err != nil {
		return ControlEvidence{}, err
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d block(s) carried out and %d awaiting approval.", executed, pending),
		Samples: rows,
	}, nil
}

func (s *Store) evidenceThreatIntel(ctx context.Context, from, to time.Time) (ControlEvidence, error) {
	n, err := s.scalar(ctx, `SELECT count(*) FROM cti_indicators WHERE checked_at >= $1 AND checked_at < $2`, from, to)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence threat intel: %w", err)
	}
	if n == 0 {
		return gap("No threat-intelligence lookups were performed in this period.",
			"Configure AbuseIPDB or OTX under Integrations if this control is in scope for you."), nil
	}
	return ControlEvidence{Summary: fmt.Sprintf("%s indicator lookup(s) performed and cached.", thousands(n))}, nil
}

func (s *Store) evidencePlaybooks(ctx context.Context) (ControlEvidence, error) {
	rows, err := s.samples(ctx, `
		SELECT name || CASE WHEN enabled THEN '  (enabled)' ELSE '  (disabled)' END
		  FROM playbooks ORDER BY name`)
	if err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence playbooks: %w", err)
	}
	if len(rows) == 0 {
		return gap("No response playbooks are defined.",
			"This control is about having a documented, prepared response. An empty list is a real gap."), nil
	}
	return ControlEvidence{
		Summary: fmt.Sprintf("%d response playbook(s) defined. Current state, not a period count.", len(rows)),
		Samples: rows,
	}, nil
}

func (s *Store) evidenceRetention(ctx context.Context) (ControlEvidence, error) {
	var oldest *time.Time
	if err := s.q(ctx).QueryRow(ctx, `SELECT min(time) FROM events`).Scan(&oldest); err != nil {
		return ControlEvidence{}, fmt.Errorf("store: evidence retention: %w", err)
	}
	if oldest == nil {
		return gap("The event record is empty.", "There is no evidence to retain."), nil
	}
	days := int(time.Since(*oldest).Hours() / 24)
	versions, _ := s.scalar(ctx, `SELECT count(*) FROM fim_snapshots`)
	return ControlEvidence{
		Summary: fmt.Sprintf("The event record reaches back %d day(s), to %s. %s retained file version(s) "+
			"are available for restoration.", days, oldest.UTC().Format("2006-01-02"), thousands(versions)),
	}, nil
}

// thousands formats a count with separators, because a six-figure number without them is misread
// at a glance and this report is read at a glance.
func thousands(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
