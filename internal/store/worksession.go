package store

// Who was at a shared workstation, and when.
//
// Gap 5 from the field insight. A nurse station is used by a different person every shift:
//
//	"Nurse station tuh ada beberapa perawat, dokter, sif. Dokter kalau sesuai security itu harusnya
//	 waktu login Windows memakai login-nya sendiri dan terintegrasi dengan web-nya."
//
// The question underneath is an access audit, not an antivirus one: who opened a medical record
// from this machine. DeusWatch already records the logons; what it could not answer is "who was at
// PC-WARD3 at 14:20", because a logon on its own is a point in time and every account that ever
// signed in looks like it is still signed in.
//
// Sessions are DERIVED from the events table rather than kept in one of their own. There is no
// second copy to drift, no worker loop to fall behind, and a session recomputed next week from the
// same events gives the same answer, which is the property an audit needs. The cost is a query per
// question instead of a lookup, bounded by one agent and one window.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// WorkSession is one person's time at one machine. End is zero while the session is still open.
type WorkSession struct {
	Agent    string     `json:"agent"`
	Host     string     `json:"host"`
	User     string     `json:"user"`
	Start    time.Time  `json:"start"`
	End      *time.Time `json:"end,omitempty"`
	Platform string     `json:"platform"` // windows | ssh
}

// Open reports whether the session had not ended by the time the window closed.
func (s WorkSession) Open() bool { return s.End == nil }

// sessionActions are the normalised actions that open and close a session, per platform.
var sessionOpen = map[string]string{
	"windows_logon": "windows",
	"ssh_login":     "ssh",
}

var sessionClose = map[string]string{"windows_logoff": "windows"}

// isMachineAccount reports whether a name belongs to the computer rather than to a person.
//
// This is the filter that keeps a workstation's session list readable without storing the Windows
// logon type. A boot produces a stream of SYSTEM, LOCAL SERVICE and NETWORK SERVICE logons, and a
// domain machine signs in as its own name with a trailing "$". None of them is somebody sitting at
// the keyboard, and all of them would bury the three humans who used the machine that day.
//
// The limit this accepts: a type 3 (network) logon by a REAL account is counted as a session. On a
// server that would be noise; on a nurse station it is uncommon, and when it happens it still
// means that account touched this machine, which is the thing being audited.
func isMachineAccount(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	switch n {
	case "", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0", "UMFD-1":
		return true
	}
	// A domain computer account. Also covers DWM-N / UMFD-N variants on later Windows builds.
	return strings.HasSuffix(n, "$") || strings.HasPrefix(n, "DWM-") || strings.HasPrefix(n, "UMFD-")
}

// WorkSessions reconstructs who was signed in to one agent during a window, newest first.
//
// Pairing is done here rather than in SQL on purpose: the rule is "a logoff closes that user's most
// recent open session", and a window function expressing that is something nobody can check at
// 3am, while this loop can be read and tested against a fixed list of events.
func (s *Store) WorkSessions(ctx context.Context, agent string, from, to time.Time) ([]WorkSession, error) {
	if strings.TrimSpace(agent) == "" {
		return nil, fmt.Errorf("store: work sessions need an agent")
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT time, COALESCE(user_name,''), COALESCE(event_action,''), COALESCE(host_name,'')
		  FROM events
		 WHERE agent_id = $1
		   AND event_outcome = 'success'
		   AND event_action IN ('windows_logon','windows_logoff','ssh_login')
		   AND time >= $2 AND time < $3
		 ORDER BY time`, agent, from, to)
	if err != nil {
		return nil, fmt.Errorf("store: work sessions: %w", err)
	}
	defer rows.Close()

	// open holds the index in out of each user's current session.
	open := map[string]int{}
	out := make([]WorkSession, 0, 32)
	for rows.Next() {
		var at time.Time
		var user, action, host string
		if err := rows.Scan(&at, &user, &action, &host); err != nil {
			return nil, err
		}
		if isMachineAccount(user) {
			continue
		}
		key := strings.ToLower(user)
		if platform, ok := sessionOpen[action]; ok {
			// A second logon while one is open is the same person still there (Windows raises
			// several 4624s for one sign-in), not a new visit. Keep the earlier start.
			if _, already := open[key]; already {
				continue
			}
			out = append(out, WorkSession{Agent: agent, Host: host, User: user, Start: at, Platform: platform})
			open[key] = len(out) - 1
			continue
		}
		if _, ok := sessionClose[action]; ok {
			if i, ok := open[key]; ok {
				end := at
				out[i].End = &end
				delete(open, key)
			}
			// A logoff with no logon in the window is not an error: the session started before it.
			// Dropping it is right, because inventing a start time would be inventing evidence.
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Newest first, which is the order someone reading a machine's history wants.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// WhoWasOn answers the question the audit actually asks: which accounts were signed in to this
// machine at this moment.
//
// It looks back over lookback rather than from the start of time, so the answer is bounded. A
// session that opened before that window is not reported, and the caller is told how far back the
// search went rather than being given a confident empty answer.
func (s *Store) WhoWasOn(ctx context.Context, agent string, at time.Time, lookback time.Duration) ([]WorkSession, error) {
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	// The window ends slightly after `at` so a session that closed in the same second still counts.
	sessions, err := s.WorkSessions(ctx, agent, at.Add(-lookback), at.Add(time.Second))
	if err != nil {
		return nil, err
	}
	out := make([]WorkSession, 0, 4)
	for _, ws := range sessions {
		if ws.Start.After(at) {
			continue
		}
		if ws.End == nil || !ws.End.Before(at) {
			out = append(out, ws)
		}
	}
	return out, nil
}

// AttributedEvent is one thing that happened on a machine, with the person who was signed in to
// that machine when it happened.
type AttributedEvent struct {
	Time     time.Time `json:"time"`
	Category string    `json:"event_category"`
	Action   string    `json:"event_action"`
	Dataset  string    `json:"event_dataset"`
	Original string    `json:"event_original"`
	// EventUser is the account the event itself named, which for an application log is the person
	// who did it. Often empty: a file change has no user unless who-data is on.
	EventUser string `json:"event_user"`
	// SessionUsers are the accounts signed in to the workstation at that moment. Plural because a
	// Windows machine can have two at once, and naming one would be a guess.
	SessionUsers []string `json:"session_users"`
}

// AttributeEvents answers the question gap 5 is really about: what happened on this shared machine,
// and who was sitting at it.
//
// This is where the SIMRS half lands. DeusWatch cannot read a hospital information system directly,
// and there is no single SIMRS to write a parser for: every site runs a different one. What it can
// do is read that system's log through a custom decoder (docs/simrs.md), which turns a line into an
// event carrying user.name. From there the account the application names and the account signed in
// to the workstation are the same string, and the trail runs from the record back to the person.
//
// The two are reported SEPARATELY and never merged. EventUser is what the application claims;
// SessionUsers is who the operating system says was at the keyboard. When they disagree that is the
// finding, not an inconsistency to smooth over: an application account used while somebody else was
// signed in to the machine is exactly the shared-password habit this audit exists to surface.
func (s *Store) AttributeEvents(ctx context.Context, agent, dataset string, from, to time.Time, limit int) ([]AttributedEvent, error) {
	if strings.TrimSpace(agent) == "" {
		return nil, fmt.Errorf("store: attribution needs an agent")
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	sessions, err := s.WorkSessions(ctx, agent, from, to)
	if err != nil {
		return nil, err
	}

	rows, err := s.q(ctx).Query(ctx, `
		SELECT time, COALESCE(event_category,''), COALESCE(event_action,''),
		       COALESCE(event_dataset,''), COALESCE(event_original,''), COALESCE(user_name,'')
		  FROM events
		 WHERE agent_id = $1
		   AND ($2 = '' OR event_dataset ILIKE $2 || '%')
		   AND time >= $3 AND time < $4
		   -- The logon traffic is what BUILDS the sessions; listing it back as activity would fill
		   -- the answer with the scaffolding instead of what the person did.
		   AND COALESCE(event_action,'') NOT IN ('windows_logon','windows_logoff','ssh_login')
		 ORDER BY time DESC
		 LIMIT $5`, agent, strings.TrimSpace(dataset), from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("store: attribute events: %w", err)
	}
	defer rows.Close()

	out := make([]AttributedEvent, 0, limit)
	for rows.Next() {
		var e AttributedEvent
		if err := rows.Scan(&e.Time, &e.Category, &e.Action, &e.Dataset, &e.Original, &e.EventUser); err != nil {
			return nil, err
		}
		e.SessionUsers = usersAt(sessions, e.Time)
		out = append(out, e)
	}
	return out, rows.Err()
}

// usersAt returns the accounts whose session covers t. Linear over the sessions, which number in
// the handful per day on a workstation; an index would be more code than the scan it replaces.
func usersAt(sessions []WorkSession, t time.Time) []string {
	var out []string
	for _, s := range sessions {
		if s.Start.After(t) {
			continue
		}
		if s.End == nil || !s.End.Before(t) {
			out = append(out, s.User)
		}
	}
	return out
}

// UserMachines lists where one account has signed in, newest first. The other direction of the
// same question: an account that appears on six wards in one shift is worth a look, and a shared
// workstation is exactly where that goes unnoticed.
func (s *Store) UserMachines(ctx context.Context, user string, from, to time.Time) ([]WorkSession, error) {
	if strings.TrimSpace(user) == "" {
		return nil, fmt.Errorf("store: user machines need a username")
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT time, COALESCE(agent_id,''), COALESCE(host_name,''), COALESCE(event_action,'')
		  FROM events
		 WHERE lower(user_name) = lower($1)
		   AND event_outcome = 'success'
		   AND event_action IN ('windows_logon','ssh_login')
		   AND time >= $2 AND time < $3
		 ORDER BY time DESC
		 LIMIT 200`, user, from, to)
	if err != nil {
		return nil, fmt.Errorf("store: user machines: %w", err)
	}
	defer rows.Close()
	out := make([]WorkSession, 0, 32)
	for rows.Next() {
		var ws WorkSession
		var action string
		if err := rows.Scan(&ws.Start, &ws.Agent, &ws.Host, &action); err != nil {
			return nil, err
		}
		ws.User = user
		ws.Platform = sessionOpen[action]
		out = append(out, ws)
	}
	return out, rows.Err()
}
