# Monitor network devices with SNMP

DeusWatch polls switches, access points and routers over SNMP and puts them on one board
(**Network** in the sidebar), instead of one tool per device type.

Nothing is installed on the devices — they already speak SNMP.

---

## The one thing to understand first

SNMP standardises much less than people expect.

| | Standard everywhere | Vendor-specific |
|---|---|---|
| Uptime, device name, description | ✅ read automatically | |
| Interface table: port names, up/down, counters, errors | ✅ read automatically | |
| **CPU load** | | ❌ no standard OID |
| **Temperature** | | ❌ no standard OID |
| **Power supply, fans, free memory** | | ❌ no standard OID |

So DeusWatch reads the standard tree itself, and takes the rest as **sensors you define**: a name,
an OID, a unit and a threshold.

That is deliberate. It means this works on Ruijie, and keeps working on Aruba after a contract
change, without DeusWatch shipping a vendor OID list that nobody verified against your actual
hardware. If you already pull CPU and temperature through The Dude, Zabbix or similar, you already
have the OIDs you need here.

---

## 1. On the device: enable SNMP read-only

Use a **read-only** community or v3 user. DeusWatch only ever reads; it never writes a device's
configuration.

Restrict it to the DeusWatch host where the device supports it. A community string is a password
that happens to have a friendly name — anyone who can reach the device with it can read the whole
thing.

---

## 2. In DeusWatch: Network → Add device

| Field | Notes |
|---|---|
| Name | what it is called on the board, e.g. `sw-lantai3` |
| Location | groups the board — the first question about a dead switch is which building |
| Host | bare IP or hostname, **no scheme and no port** |
| Port | 161 unless you changed it |
| SNMP version | `2c` (community) or `3` (user + auth + privacy) |
| Poll every | seconds, minimum 10 |
| Failed polls before alerting | SNMP runs over UDP, so one lost packet is not an outage; 3 is a sane default |
| Poll interfaces | per-port state — see the cost note below |

Credentials (the community string, and both v3 passphrases) are encrypted at rest and never sent
back to the browser. On an edit, leaving them empty keeps what is stored, so changing a poll
interval does not wipe them.

### Port monitoring costs rows

Walking the interface table produces **one row per port per poll**. A 48-port switch polled every
60 seconds is ~69,000 rows a day; twenty of them is over 1.3 million. Worth it where port state
matters, wasteful where only the device's own health does — so it is per device and defaults to
**off**. Interface history is kept 14 days; sensor history 30.

---

## 3. Add sensors for CPU and temperature

Each sensor is one OID.

| Field | Meaning |
|---|---|
| Name | what the board shows, e.g. `CPU`, `Suhu` |
| OID | the numeric OID, e.g. `1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0` |
| Unit | `%`, `C`, `RPM` — display only |
| Multiply raw value by | devices often report tenths: `0.1` turns a reported `345` into `34.5 °C` |
| Warn above | alert when the value goes over this |
| Warn below | alert when the value drops under this — for free memory, fan RPM, a PSU where `1` means healthy |

Finding your OIDs: `snmpwalk -v2c -c <community> <host> 1.3.6.1.4.1` lists the vendor subtree, or
copy them from whatever already polls these devices today. Your vendor's MIB file names them.

A sensor whose OID the device does not have is reported on that sensor alone — the rest of the
device keeps working, so a typo does not blank the board.

A sensor that returns text rather than a number is shown as text and is not compared against a
threshold.

---

## Alerts

| What | Severity | When |
|---|---|---|
| Device unreachable | **HIGH** | after `fail_threshold` consecutive failed polls |
| Device back | Info | on the next successful poll |
| Sensor over/under its threshold | Medium | each poll where the rule is broken |

Device alerts are latched: one outage produces one "down" and one "recovered", not one per poll.

Sensor breaches are **suppressed while the device is unreachable**. Every sensor fails when the
switch is off, and firing one alert each would bury the one alert that says the switch is off.

A switch at 86% CPU is Medium, not High: it is something to look at today, and the device is still
working. The unreachable device is the one that earns High.

They flow through the same pipeline as every other alert, so Telegram, email and ticket automation
all apply.

---

## Troubleshooting

Check the worker log: `docker compose logs -f worker | grep -i snmp`

| Symptom | Cause |
|---|---|
| `SNMP get failed … request timeout` | wrong community string, SNMP not enabled, ACL on the device excludes the DeusWatch host, or a firewall blocking UDP/161 |
| `cannot reach <host>` | name does not resolve, or no route |
| `skipped: credentials are stored but the secrets cipher is unavailable` | `SECRETS_KEY` is not set — the device is not polled rather than polled anonymously, because an anonymous poll would time out and be reported as the device being down |
| `the device has no <oid>` | the OID is wrong for this model; the rest of the device still polls |
| A sensor shows `—` | never read yet, or it returned something non-numeric |
| Ports section says port monitoring is off | turn on *Poll interfaces* for that device |

SNMPv3 with an unrecognised security level falls back to **authPriv**, never to cleartext.
