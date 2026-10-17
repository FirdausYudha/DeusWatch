# Environmental monitoring

Room temperature, humidity, door contacts, power. DeusWatch takes readings from whatever already
talks to your sensors and alerts on the limits you set.

The driver here is accreditation rather than comfort. A hospital IT team put it plainly:

> "Ruangan suhu, batasnya kan 18 derajat sampai 23 dengan kelembapannya 60%. Karena finger juga
> peraturan dari rumah sakit sama BPJS, akreditasinya: CCTV, finger, suhu, APAR, alat kelembapan."

A server room held between 18 and 23 degrees is a number somebody has to be able to show an
assessor, for the whole quarter, not just today.

## There is no Bardi integration, and there will not be one

The hospital this came from uses Bardi. The next site uses something else. A vendor integration
written here is a guess about an API nobody on this project can test against, and the same call was
made twice before in this codebase for the same reason: Ruijie got a generic SSH responder, and
SNMP got operator-supplied OIDs. Both still work after a hardware contract changes.

So readings are **pushed**. Whatever already speaks to your device posts a number: a few lines of
script against the vendor's cloud, a Home Assistant automation, a Modbus gateway, a cron job
reading a USB probe.

## Setting up a sensor

**Sensors page → Add.** One entry per measurement point.

| Field | Notes |
|---|---|
| Name | What it measures, as you would say it out loud |
| Location | The room. An alert nobody can walk to is not actionable |
| Unit | `C`, `%`, `bar`, whatever you post |
| Warn above / Warn below | Either, or both. Leave one blank when only one direction is a fault |
| Stale after | How long silence may last before the sensor itself is the alert |

Saving returns an **ingest key**. It is shown only to someone with `manage_settings`, and it is
per-sensor on purpose: a script on a ward PC that is compromised can write readings for the one
sensor it was given and nothing else.

## Posting a reading

```bash
curl -X POST https://deuswatch.example/api/sensors/ingest \
  -H 'Content-Type: application/json' \
  -d '{"key":"YOUR_INGEST_KEY","value":22.4}'
```

The key may ride in an `Authorization: Bearer` header instead, because some vendor webhook forms
have nowhere to put a body field. A non-numeric sensor posts `text` instead of `value`, for a door
contact or a panel state.

Every failure answers `401` with the same words. A caller holding a wrong key cannot learn from the
reply whether the sensor exists, which is the only thing that endpoint has to protect.

## Silence is an alert

This is the part worth reading twice.

**A pushed sensor that stops reporting is its most dangerous state.** Its last reading sits on the
board looking perfectly healthy, for days, while the room it is supposed to be watching does
whatever it likes. Nothing on that screen says the number is old. A threshold breach announces
itself; silence does not, and silence is what an assessor asks about.

So **Stale after** raises an alert in its own right, at the same severity as a breach. A sensor
that has never reported since it was configured is flagged too, which catches a key typed into a
script wrongly on the day it was set up rather than during the incident it was meant to cover.

Set it to zero only for a reading somebody enters by hand.

## What else it refuses to assume

**A reading that is not a number is a failed probe, not a passing one.** Broken sensors often
report `NaN` rather than going quiet, and every comparison against `NaN` is false, so a naive
threshold check decides silently that everything is fine. It is treated as a breach and the message
points at the probe rather than at the room.

**One breach is one alert.** A probe sampling every 30 seconds in a room two degrees too warm would
otherwise raise 2,880 alerts a day, and a channel everyone mutes is worse than no channel. The
state is latched, so you get the breach, then the recovery, and nothing in between.

**A limit is inclusive.** Exactly 23.0 on a `warn_above: 23` sensor is inside the range. Say 22.9
if you want headroom.

## Where the alerts go

Through the ordinary pipeline: an event, then notifications, tickets and the dashboard, the same
path a detection rule takes. There is no separate environmental channel to configure or forget.

Breaches and silence are **high** severity; a recovery is informational, because paging people on
good news is how a channel gets muted.
