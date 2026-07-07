# Suricata / Emerging Threats (ET Open / ET Pro) integration

DeusWatch is **log-based**: it does not inspect raw network packets. **Suricata** does. So for
network intrusion detection with the Emerging Threats rulesets you run Suricata as a **network
sensor** and let DeusWatch **ingest its alerts** as a log source. Roles:

- **Suricata (+ ET Open/Pro)** - the eyes on the wire. Inspects traffic, matches signatures,
  writes alerts to `eve.json`. Runs on a **network sensor box**, not on every endpoint.
- **DeusWatch** - the brain. Ingests those alerts, correlates them with your other logs, adds
  threat-intel, and drives response (ban IP / containment) and reporting.
- **Firewall (nftables / MikroTik / CrowdSec)** - the hands. Actually drops the traffic, on
  DeusWatch's command.

The coupling is loose: Suricata never needs to know DeusWatch exists - it just writes a log,
and one DeusWatch agent on the sensor box reads it. **ET Open and ET Pro produce the same
`eve.json`, so upgrading later needs zero DeusWatch changes.**

```
   traffic ──► [ Suricata + ET ruleset ]  (mirror/SPAN port, or inline)
                        │ writes alerts
                        ▼
               /var/log/suricata/eve.json
                        │  1 DeusWatch agent on the sensor tails it (mTLS 9443)
                        ▼
                  DeusWatch  ──► ban IP / contain / alert / report
```

## 1. Install Suricata on a sensor

Put the sensor where it can **see** the traffic: a switch **mirror/SPAN port** or a **TAP**
(passive IDS, safest to start), or inline on the gateway (IPS, can drop). Then:

```bash
sudo apt install suricata            # or your distro's package / official repo
# set your internal range so direction (HOME_NET) is correct
sudo sed -i 's#HOME_NET:.*#HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"#' /etc/suricata/suricata.yaml
```

### Rulesets (this is where ET Open / ET Pro plug in)

Rules are managed by **`suricata-update`** - a bulk fetch, not one-by-one, auto-updatable via
cron:

```bash
# ET Open (free) - good to learn the flow:
sudo suricata-update

# ET Pro (paid) - enable the source with your subscription oinkcode:
sudo suricata-update enable-source et/pro
#   (prompts for the ET Pro secret-code / oinkcode from your subscription)
sudo suricata-update
```

Add a daily cron so the ruleset stays current:

```
0 3 * * *  suricata-update && suricatasc -c reload-rules
```

> The oinkcode lives **on the sensor**, not in DeusWatch - DeusWatch consumes Suricata's alert
> output, not the `.rules` files.

## 2. Make Suricata emit alerts only (keep volume sane)

`eve.json` can also carry flow/http/dns/tls telemetry, which is huge. DeusWatch only maps
`alert` records; point the agent at an alert-only stream. In `/etc/suricata/suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert            # keep only alerts for DeusWatch
```

Restart Suricata after config changes.

## 3. Ingest it into DeusWatch (one agent on the sensor)

Enroll a DeusWatch agent on the sensor box (Agents -> + Add agent), then add a source to that
agent (Agents -> the sensor -> its sources) - **Save & push**:

| Field | Value |
|---|---|
| Dataset | `suricata` |
| Type | `file` |
| Path | `/var/log/suricata/eve.json` |

That is the whole DeusWatch side. Each alert becomes a DCS event: the **signature** is the rule
name (`suricata-<sid>`), source/dest IP+port and protocol are carried, the Suricata priority
maps to severity, and MITRE tags are mapped when the ruleset provides them (ET Pro does).
Suricata alerts are pre-labeled, so they show in **Alerts** and drive **response** immediately.

## 4. Response / containment on Suricata alerts

Because a Suricata alert carries a **source IP**, DeusWatch's ban engine can act on it just like
an SSH-brute-force alert (recommend a block; approve or auto-approve; enforce via
nftables/MikroTik/CrowdSec).

- **Whitelist your internal ranges** (Response -> IP whitelist), e.g. `10.0.0.0/8`,
  `192.168.0.0/16`. Many ET signatures fire on *outbound* traffic where the source is your own
  host - the whitelist stops DeusWatch from banning your own machines; the alert still shows.
- Suricata in **inline/IPS** mode can also drop on its own (`action: blocked` shows on the
  event as outcome `blocked`) - that is independent of DeusWatch and complementary.

## Notes

- Suricata for a full ET Pro ruleset at line rate is CPU/RAM heavy - size the sensor box
  accordingly; do not spread it across endpoints.
- The dataset label is free-form: `suricata`, `suricata (eve)`, `snort` all route to the same
  normalizer.
