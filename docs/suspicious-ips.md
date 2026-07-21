# Suspicious IPs — low-and-slow reconnaissance watchlist

Some of the most dangerous scanning is **quiet**: an attacker touches you a handful of times
over hours or days, probing different endpoints or ports, staying **under the radar** of the
things that usually catch attackers —

- **CTI feeds** (AbuseIPDB / OTX / ET Open) — the IP isn't "bad enough" to be listed yet.
- **WAF / ModSecurity signatures** — the requests don't match a rule, or aren't blocked.
- **Short-window rules** (brute-force, port-scan) — those fire on a burst in ~1 minute; 10 hits
  spread across 24 hours never crosses the threshold.

The **Suspicious IPs** watchlist is a separate detection dimension for exactly this: **behaviour
over a long window**, independent of CTI and signatures.

## How it works

Every few minutes the worker aggregates the last **24 hours** (`SUSPICIOUS_WINDOW`) of events per
**external** source IP and scores the behaviour, not the reputation:

| Signal | Why it matters | Weight |
|---|---|---|
| **fan-out** — distinct URIs / ports probed | one client hitting many *different* things is the scanner tell | 0.40 |
| **failure ratio** — blocked / denied / 4xx / auth-fail | recon mostly bounces off | 0.30 |
| **time spread** — distinct clock-hours seen | spread out = *deliberately* slow | 0.20 |
| **volume** — total contacts | some weight to sheer persistence | 0.10 |

→ a **0–100 suspicion score** with a band (low → critical), on the dashboard's **Suspicious IPs**
widget. The score is **CTI-independent by design** — a quiet IP with no AbuseIPDB record can still
top the list.

### SSH pre-auth probes feed this, but are never alerts

Lines like `banner exchange: Connection from … invalid format`, `Connection closed/reset by … [preauth]`,
`Bad protocol version identification …`, and `Did not receive identification string from …` are SSH
**reconnaissance** — a scanner touched the port without attempting a login. They carry the attacker
IP but are **not** authentication failures.

DeusWatch ingests them as `event.action = ssh_probe`, severity **Info**, with the source IP
extracted **but no failure outcome**. The deliberate design (the enterprise tiered model):

- **Individually they are telemetry, never alerts** — internet-facing SSH sees thousands daily, so
  alerting per-probe would only cause alert fatigue.
- **They still feed correlation** — because the IP is populated, a probe counts as a *contact* here
  (and toward the composite score and the multi-day slow-scanner watchlist). A scanner that returns
  often, or across many hosts/days, rises up the list on its own.
- **They do NOT inflate the failure signal** — `ssh_probe` carries no `failure` outcome, so a
  scanner that only probes stays distinguishable from one actually guessing passwords.

The real fix for the underlying noise is attack-surface reduction (key-only auth, SSH behind a
bastion/VPN, source-IP restrictions) — detection is the complement, not the substitute.

**The AI executive summary** (Report) receives the watchlist too, so it can describe the pattern
in words — e.g. *"203.0.113.9 touched 20 distinct login endpoints over 12 hours, almost all
403 — credential-stuffing reconnaissance."*

## What you need for it to work

This is only meaningful if DeusWatch sees the **raw** access/connection telemetry — not just
alerts. Feed it:

- **Web / proxy access logs** (so URIs give the fan-out), or ModSecurity (see
  [docs/modsecurity.md](modsecurity.md)),
- **Firewall accept/deny** logs (destination ports give the fan-out),
- or any device over the [native syslog input](syslog.md).

If DeusWatch only receives *alerts*, there's nothing "below the radar" to count.

## Honest caveats

- It's a **heuristic — "worth a look", not "confirmed malicious"**. Treat a high score as a
  prompt to investigate, then ban from the Response page if warranted.
- **False positives**: recurring legitimate clients (uptime monitors, CDNs, partners) can be
  chatty. Fan-out + failure ratio suppress most of them (a monitor hits *one* URL and succeeds),
  and **RFC1918 / loopback are excluded** so internal health-checks don't show up. An IP that is
  genuinely benign but noisy can be added to the Response **whitelist**.
- Only **external** IPs are listed (internal lateral-movement recon is out of scope here).

## Tuning

| Env | Default | Meaning |
|---|---|---|
| `SUSPICIOUS_WINDOW` | `24h` | how far back the behaviour is measured |
| `SUSPICIOUS_INTERVAL` | `5m` | how often the watchlist is recomputed |

The signal weights live in `internal/score.DefaultSuspicionWeights()`.
