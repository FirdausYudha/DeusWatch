package store

// Vendor accounts and their access windows (RV-01, S5). The judgement lives in
// internal/vendorwindow; this holds the rows and the two queries the worker sweep needs: which
// vendor logins happened recently, and whether one has already been alerted.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/vendorwindow"
)

// VendorAccount is one vendor login and its agreed window, as stored.
type VendorAccount struct {
	ID        string    `json:"id"`
	Account   string    `json:"account"`
	Days      []int     `json:"days"`
	StartTime string    `json:"start_time"` // HH:MM, as the UI and API speak it
	EndTime   string    `json:"end_time"`
	Timezone  string    `json:"timezone"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VendorLogin is a successful login by a vendor account, paired with that account's window so the
// worker can judge it in one pass without a second lookup.
type VendorLogin struct {
	Window   vendorwindow.Window
	When     time.Time
	SourceIP string
	Host     string
}

// ListVendorAccounts returns the tenant's vendor accounts.
func (s *Store) ListVendorAccounts(ctx context.Context) ([]VendorAccount, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT id::text, account, days, to_char(start_time,'HH24:MI'), to_char(end_time,'HH24:MI'),
		       timezone, enabled, note, updated_at
		  FROM vendor_accounts ORDER BY account`)
	if err != nil {
		return nil, fmt.Errorf("store: list vendor accounts: %w", err)
	}
	defer rows.Close()
	out := []VendorAccount{}
	for rows.Next() {
		var v VendorAccount
		var days []int16
		if err := rows.Scan(&v.ID, &v.Account, &days, &v.StartTime, &v.EndTime,
			&v.Timezone, &v.Enabled, &v.Note, &v.UpdatedAt); err != nil {
			return nil, err
		}
		for _, d := range days {
			v.Days = append(v.Days, int(d))
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// UpsertVendorAccount creates or replaces a vendor account by name within the tenant, bumping
// updated_at. start and end are HH:MM strings; days are ISO weekday numbers.
func (s *Store) UpsertVendorAccount(ctx context.Context, account string, days []int, start, end, tz, note string, enabled bool) error {
	if account == "" {
		return fmt.Errorf("store: vendor account needs a name")
	}
	d16 := make([]int16, 0, len(days))
	for _, d := range days {
		d16 = append(d16, int16(d))
	}
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO vendor_accounts (account, days, start_time, end_time, timezone, note, enabled)
		VALUES ($1, $2, $3::time, $4::time, $5, $6, $7)
		ON CONFLICT (tenant_id, account) DO UPDATE
		   SET days = EXCLUDED.days, start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time,
		       timezone = EXCLUDED.timezone, note = EXCLUDED.note, enabled = EXCLUDED.enabled,
		       updated_at = now()`,
		account, d16, start, end, tz, note, enabled)
	if err != nil {
		return fmt.Errorf("store: upsert vendor account: %w", err)
	}
	return nil
}

// DeleteVendorAccount removes one by id.
func (s *Store) DeleteVendorAccount(ctx context.Context, id string) error {
	tag, err := s.q(ctx).Exec(ctx, `DELETE FROM vendor_accounts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete vendor account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: vendor account not found")
	}
	return nil
}

// RecentVendorLogins returns successful logins since `since` whose user is an enabled vendor
// account, each paired with that account's window. The join is what keeps this to one query: an
// ordinary login event for a non-vendor user is never returned.
func (s *Store) RecentVendorLogins(ctx context.Context, since time.Time) ([]VendorLogin, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT v.account, v.days, to_char(v.start_time,'HH24:MI'), to_char(v.end_time,'HH24:MI'),
		       v.timezone, e.time, COALESCE(host(e.source_ip),''), COALESCE(e.host_name,'')
		  FROM events e
		  JOIN vendor_accounts v ON v.account = e.user_name AND v.enabled
		 WHERE e.event_category = 'authentication'
		   AND e.event_outcome = 'success'
		   AND e.time > $1
		 ORDER BY e.time`, since)
	if err != nil {
		return nil, fmt.Errorf("store: recent vendor logins: %w", err)
	}
	defer rows.Close()
	out := []VendorLogin{}
	for rows.Next() {
		var vl VendorLogin
		var days []int16
		var start, end string
		if err := rows.Scan(&vl.Window.Account, &days, &start, &end, &vl.Window.Timezone,
			&vl.When, &vl.SourceIP, &vl.Host); err != nil {
			return nil, err
		}
		for _, d := range days {
			vl.Window.Days = append(vl.Window.Days, int(d))
		}
		// Parse the HH:MM strings back into the clock-only times the evaluator reads.
		vl.Window.Start, _ = time.Parse("15:04", start)
		vl.Window.End, _ = time.Parse("15:04", end)
		out = append(out, vl)
	}
	return out, rows.Err()
}

// VendorWindowAlertExists reports whether an out-of-window alert was already stored for this exact
// login, so a sweep that overlaps the previous one does not raise it twice.
//
// The key is (label, account, login time, source IP), not a watermark in memory: that way the
// dedup survives a worker restart, and the events table stays the single ledger the rest of the
// system already treats it as. The alert is stored with the LOGIN's timestamp for this reason,
// not now().
func (s *Store) VendorWindowAlertExists(ctx context.Context, account string, when time.Time, sourceIP string) (bool, error) {
	ip := strOrNil(sourceIP)
	var n int
	err := s.q(ctx).QueryRow(ctx, `
		SELECT 1 FROM events
		 WHERE dw_label = 'vendor_window_violation'
		   AND user_name = $1
		   AND time = $2
		   AND source_ip IS NOT DISTINCT FROM $3::inet
		 LIMIT 1`, account, when, ip).Scan(&n)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: vendor alert exists: %w", err)
	}
	return true, nil
}
