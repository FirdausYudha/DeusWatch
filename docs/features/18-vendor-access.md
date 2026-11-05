# 18. Vendor Access

Manage the hours each **vendor account** is allowed to log in, and alert on any login outside that
window.

It exists because an outside vendor is often given an account on a sensitive server (a SIMRS box, a
database host) to maintain it - but only during agreed hours. A vendor login at 3am is the signal.
That signal is one a plain Sigma rule **cannot** express: Sigma matches the fields of a single
event and has no notion of "the clock says it is now outside the allowed window". So the window
lives in a table and a periodic evaluator in the worker judges each login against it (RV-01).

**Read is `view_dashboard`.** Every write (create / edit / delete a window) gates on
`manage_settings`, because a login window is an access control and widening it quietly is exactly
what an attacker would want.

## How it works

1. You define a window per account on this page: the allowed weekdays, a start/end time, and the
   account's IANA timezone (e.g. `Asia/Jakarta`). Stored in `vendor_accounts` (migration `000085`),
   one window per account per tenant.
2. The worker sweeps periodically (`cmd/worker/vendorwindow.go`): it reads recent **successful**
   authentication events whose user matches an enabled vendor account, and judges each login's time
   against that account's window.
3. A login outside the window raises a `vendor_window_violation` alert (`T1078`, Valid Accounts).
   The alert is stamped with the **login's** timestamp, and de-duplicated by
   `(label, account, login time, source IP)` so an overlapping sweep never raises it twice - the
   dedup survives a worker restart because it is keyed in the events table, not in memory.

The judgement itself is a pure, tested evaluator (`internal/vendorwindow/vendorwindow.go`): it
handles windows that wrap midnight, never falls back to UTC (a missing timezone is an error, not a
silent wrong answer), and treats a zero-length window as "always outside".

### The `vnd-` convention

The field report expects vendor accounts to carry a `vnd-` prefix (e.g. `vnd-acme`). That prefix is
a **reminder for humans**, not an access control: this table is the authority on which accounts are
vendor accounts, so the evaluator matches on the account name in the table, not on the prefix.

## How to use it

1. Open **Vendor Access** in the sidebar.
2. **Add vendor account**: enter the login name (e.g. `vnd-acme`), tick the allowed weekdays, set
   the start/end time and timezone, and save.
3. Any later login by that account outside the window appears as an alert on the Dashboard and in
   the normal response flow.

## Ports / tech / variables

- **Tech**: Go (pure evaluator + worker sweep + store + API), React/TypeScript page
  (`web/src/vendor/Vendor.tsx`).
- **Ports**: none of its own - the page talks to the API over HTTP.
- **Endpoints**: `GET/POST /api/vendor-accounts`, `DELETE /api/vendor-accounts/{id}`.
- **Sweep cadence / lookback**: `vendorSweepInterval` and `vendorLookback` in
  `cmd/worker/vendorwindow.go`.
