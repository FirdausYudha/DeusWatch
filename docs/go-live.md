# Turning a watching deployment into an acting one

Three settings separate a DeusWatch that observes from one that protects. A deployment can run for
months looking healthy with all three off, because nothing about the dashboard says they are.

This came out of a real ISO 27001 evidence run: 1,549 block decisions over 90 days, **none
enforced**; zero retained file versions; and integration credentials sealed with the shipped
development key.

Do them in this order. The order matters in step 1, and skipping ahead there cuts off your own
network.

## 1. Enforcement: whitelist first, then go live

**Whitelist before enabling, not after.** A deployment that has been recording decisions for months
is holding a queue of them, and the first thing enforcement does is act. If your own management
range is in that queue, you lock yourself out of the thing you just enabled.

**Response page → Whitelist.** Add, at minimum:

- the management subnet you administer from,
- the server subnet (SIMRS, database, the DeusWatch host itself),
- any monitoring or backup system that polls endpoints and looks like a scanner.

`kind` is free text; use it to say why, because an entry nobody can explain is an entry nobody
dares remove.

Then in `deploy/.env`:

```
RESPONSE_LIVE=1
```

Restart the worker. From that moment blocks reach a real firewall, so confirm one before trusting
it: ask the assistant "is the firewall connected?", or watch the worker log at startup, which
probes the backend and says which one it found.

**With no enforcement backend configured, `RESPONSE_LIVE=1` changes nothing.** Decisions still land
in dry-run. Connect nftables, MikroTik, CrowdSec or an SSH device under Integrations first, or this
step is a no-op that looks like progress.

## 2. SECRETS_KEY: rotate, then re-enter every credential

With `SECRETS_KEY` unset, integration credentials are encrypted with a key derived from a constant
in the source of a public repository. That is obfuscation, not encryption.

The value must be **base64 of exactly 32 bytes**. Anything else is refused at startup:

```bash
openssl rand -base64 32
```

Put it in `deploy/.env` as `SECRETS_KEY=...` and restart the api and worker.

**Then re-enter every integration credential from the Integrations page.** Values sealed with the
old key cannot be decrypted with the new one and cannot be recovered. That is the intended
behaviour of a key rotation, not a fault.

Until you do, each affected connector fails as though its password were wrong. Since v2.59.0 the
log says which one and why:

```
integrations: "core-switch" (ssh_cli): cannot decrypt "password". If SECRETS_KEY was changed,
re-enter this credential on the Integrations page; the stored value was sealed with the previous
key and cannot be recovered.
```

Before that release the failure was silent: the raw ciphertext was handed to the connector as if it
were the password, and a dozen authentication failures appeared with nothing pointing at the key.

## 3. File integrity: watch something

Zero retained file versions means file integrity monitoring is configured nowhere. Three things
depend on it and all three are quietly inert until it is set up:

- Restoring a file after a ransomware encryption, which is the capability most often demonstrated.
- ISO 27001 controls A.8.9 and A.8.32, which stay empty regardless of any other fix.
- The medical-record access trail, which has no file events to attribute to a person.

**Agents page → the agent → Sources.** Add a source of type `fim` per path that matters:

| Field | Value |
|---|---|
| Type | `fim` |
| Path | the directory to watch |
| Dataset | `fim` |
| Snapshot mode | `on_change` (or `both` to also capture on a schedule) |

**`snapshot_mode` is the field that decides whether restore works at all.** Left empty it keeps a
single first-seen baseline, which detects that a file changed but gives you one version to go back
to. `on_change` keeps a dated version each time, which is what "restore the file to how it was
before the encryption" needs.

Worth watching in a hospital: the SIMRS configuration directory, the web root if one is served,
`/etc` on servers, and the database configuration. Watching everything is worse than watching the
right things: a busy directory produces changes all day and teaches everyone to skim the alerts.

## Confirming it worked

Run the evidence report again a week later:

```
GET /api/compliance/iso27001?days=7
```

A.5.26 and A.8.20 should report blocks **enforced** rather than a dry-run gap. A.8.9 and A.8.32
should have changes to show. A.5.28 should report retained file versions above zero.

If any of them still reads as a gap, the gap text says which direction to look.
