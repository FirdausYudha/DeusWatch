# ML anomaly bridge (external Isolation Forest → composite score)

DeusWatch ships a built-in **heuristic** watchlist for low-and-slow reconnaissance
([suspicious IPs](suspicious-ips.md)). If you want a real **machine-learning** model instead — an
hourly Python batch (e.g. an Isolation Forest, as in the LST Tameng architecture) — DeusWatch
exposes a two-endpoint bridge: your model **pulls per-IP features**, and **writes an anomaly_score
back**, which DeusWatch folds into the composite threat score.

DeusWatch stays the scoring/decision core; the ML lives outside it and plugs in here.

## Enable

Set a token in the worker/api environment (empty = the endpoints return 404):

```dotenv
# Generate: openssl rand -hex 24
ML_API_TOKEN=paste-a-long-random-token
```

## 1. Pull the features

```
GET /api/ml/ip-features?token=<TOKEN>&window=24h&limit=1000
```

Returns one object per external source IP over the window (RFC1918/loopback excluded):

| field | meaning |
|---|---|
| `contacts` | total events |
| `distinct_uris` | unique URIs probed |
| `distinct_ports` | unique destination ports probed |
| `distinct_hours` | unique clock-hours seen (time spread) |
| `failures` | blocked / denied / 4xx / auth-fail |
| `span_secs` | last_seen − first_seen |
| `avg_gap_secs`, `gap_stddev_secs` | inter-event interval + its stddev (regularity: low CV = very regular = bot-like) |
| `first_seen`, `last_seen` | timestamps |

## 2. Write the anomaly_score back

```
POST /api/ml/anomaly?token=<TOKEN>
Content-Type: application/json

[{"ip":"165.22.76.50","anomaly":85}, {"ip":"203.0.113.9","anomaly":40}]
```

`anomaly` is 0–100. Scores older than 24h age out automatically (send fresh ones each run).

## 3. Fold it into the score

By default the **anomaly weight is 0**, so writing scores back changes nothing until you opt in.
In **Settings → Threat-scoring weights → Composite → Anomaly (ML)**, give it a weight (e.g. the
same as the others). The composite scorer then blends the ML anomaly with fired-times + AbuseIPDB
+ OTX + severity on its next run, and the score shows up as usual (dashboard doughnut, scenario
ban, etc.).

## Example — a minimal hourly batch

```python
import requests
from sklearn.ensemble import IsolationForest
import numpy as np

BASE, TOKEN = "http://deuswatch:9080", "…"
feats = requests.get(f"{BASE}/api/ml/ip-features",
                     params={"token": TOKEN, "window": "24h"}).json()
if feats:
    X = np.array([[f["contacts"], f["distinct_uris"], f["distinct_ports"],
                   f["distinct_hours"], f["failures"], f["gap_stddev_secs"]] for f in feats])
    raw = -IsolationForest(contamination="auto").fit(X).score_samples(X)  # higher = more anomalous
    norm = (100 * (raw - raw.min()) / (raw.ptp() or 1)).round().astype(int)
    body = [{"ip": f["ip"], "anomaly": int(a)} for f, a in zip(feats, norm)]
    requests.post(f"{BASE}/api/ml/anomaly", params={"token": TOKEN}, json=body)
```

Run it from cron every hour. This is **Lapis 5 ↔ Lapis 3** of the LST Tameng architecture.

## Note

The endpoints are **token-authed** (a machine credential), not tied to a UI session, so a cron job
can call them. Keep the token secret and serve over HTTPS / a trusted network — the feature export
is your enriched telemetry.
