# Demo data

Populates a DeusWatch database with realistic sample events so the dashboard can be demonstrated
or reviewed without waiting for real traffic.

> **Never run this against a production database.** It inserts fabricated events. Everything it
> writes is tagged `event_dataset LIKE 'demo%'` so it can be removed again in one statement, but
> fabricated security events in a real system are worse than no events at all.

## Run

```bash
# 1. Insert the events (safe to re-run — it clears previous demo rows first)
docker exec -i deuswatch-db-1 psql -U deuswatch -d deuswatch -v ON_ERROR_STOP=1 \
  < tools/demoseed/seed.sql

# 2. Recompute the derived score tables the dashboard reads
go run ./tools/demorefresh
```

Step 2 matters: the risky-IP and slow-scanner widgets read `ip_scores` / `slow_scanners`, which the
worker normally refreshes on a timer. `demorefresh` runs that same code path once so you don't have
to wait for a tick.

## Remove

```sql
DELETE FROM events WHERE event_dataset LIKE 'demo%';
```

Then run `go run ./tools/demorefresh` again so the score tables stop referencing the deleted rows.

## What it generates

Roughly 2,700 events over 14 days, built so the widgets agree with each other rather than telling
contradictory stories:

- **12 source IPs** with countries and a "nastiness" rating that drives severity, AbuseIPDB
  confidence and OTX counts together — so a red IP looks red in every widget.
- **Short campaigns, not constant trickle.** Each loud actor is active on a couple of adjacent days
  starting on a day derived from its address. Different actors start on different days, so the
  timeline is busy across the window while no burst attacker is mistaken for a patient scanner.
- **One genuine slow scanner** (`203.0.113.77`): two probes a day across seven separate days.
  It should sit at the *top* of the slow-scanner watchlist with the *lowest* event count — that
  contrast is the whole point of the feature, and it is what this data is shaped to show.
- **LLM verdicts** derived from severity, so the verdict donut and the severity chart cannot
  disagree.
- **A recent 24-hour campaign**, because the dashboard opens on a 24-hour window by default. Without
  it the default view would look empty while the 14-day view looked busy.
