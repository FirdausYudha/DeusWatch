# Changelog

Releases are git tags (`vX.Y.Z`). Pushing one publishes a GitHub Release with the agent binaries,
which is what the in-app **Settings -> Software updates** check compares against. Versions before
v2.42.0 are documented in their tag annotations and GitHub Releases rather than here.

Entries say what changed and, where it matters, what an operator has to do about it. A fix that
needs nothing from you does not say so; assume silence means nothing to do.

## v2.58.0

### Added

**ISO 27001 control evidence.** Gap 10. The hospital has accreditation, but none of it covers
information security: *"Kalau dari security, belum. Karena security sisi IT ya, belum ada ISO."* An
organisation starting that path spends most of its effort proving that controls **operate**, and
the product already watching the estate is holding most of that proof in tables nobody exports.

```
GET /api/compliance/iso27001?days=90
GET /api/compliance/iso27001?days=90&format=csv
```

Sixteen Annex A controls, each with the period's figures and a few concrete records so an auditor
can follow one through to the raw table rather than taking a count on trust. Behind
`manage_settings`: every part is readable elsewhere by someone with the right permission, but one
document combining the account roster, the audit log and the response history deserves the higher
bar. See [docs/iso27001.md](docs/iso27001.md).

### What it refuses to say

**It never says "compliant".** DeusWatch cannot know that. Certification covers policy, governance,
risk assessment, training, physical security and supplier management, and it sees none of them. The
disclaimer is a constant rather than UI text so a future export format cannot ship without it, it
is written into the CSV itself rather than only onto the screen that produced it, and a test fails
if any control description drifts into the language of compliance.

**A control with no evidence is reported as a GAP, never omitted.** In a document like this a
missing row reads as "not asked" rather than "the answer was empty", which is the one impression an
evidence report must not leave.

**The gap text names the ambiguity.** "No alerts were raised" has two readings, and the report says
so: the estate was quiet, or detection is not reaching it. A quiet period and a broken sensor
produce the same zero and only one is good news, so the report refuses to pick.

**The report states its own boundary.** The export ends with the themes it does not cover, because
an auditor reading sixteen of ninety-three controls needs to know the rest were excluded on purpose
rather than never considered. Which control a piece of evidence supports is a judgement the
auditor makes; the mapping here is written to be argued with.

## v2.57.0

### Added

**Medical-record access, attributed to a person.** The rest of gap 5. v2.56.0 answered who was at a
shared workstation; this joins that to what the application did, so the trail runs from the record
back to the person rather than stopping at the machine name.

```
GET /api/sessions?agent=PC-WARD3&activity=1&dataset=simrs&hours=24
```

Each row carries what the application said and who the operating system had signed in at that
moment. The assistant answers the same in words.

**There is no SIMRS decoder in the box, deliberately.** SIMRS is a category, not a product: Khanza,
SIMRS GOS and a dozen vendor-built systems all write different logs, and some write none until
logging is turned on. A decoder shipped here would be a guess about a format nobody on this project
can test against, and one that silently fails to match is worse than none at all: the events still
arrive, carry no user, and the audit trail looks complete while naming nobody.

So you build it once against your own log, with the tester already in the product. The username is
the only field that matters, because that is what meets the Windows session.
[docs/simrs.md](docs/simrs.md) walks it end to end.

### The two accounts are never merged

`event_user` is who the **application** says did it. `session_users` is who the **operating system**
says was at the keyboard. They sit side by side and the product never picks one.

When they disagree, that disagreement **is the finding**. An application account used while
somebody else was signed in to the machine is the shared-password habit this audit exists to
surface, and a tool that quietly reconciled the two would delete the evidence of it.
`session_users` is a list for the same reason: a Windows machine can have two people signed in at
once, and the handover second belongs to both.

### What it still cannot do

It reads logs, so an action SIMRS does not log is one DeusWatch cannot see; if record views are not
logged today, that is a change in SIMRS rather than here. It reports accounts rather than proving
identity, so three nurses sharing one login appear as that login, which is the finding and the
argument for per-person accounts. Active Directory remains unintegrated: accounts match by name,
which works when SIMRS and Windows agree on usernames and does not when they do not.

## v2.56.0

### Added

**Who was at a shared workstation.** Gap 5, the first half. A nurse station is used by a different
person every shift, and the engineer's framing is an access audit rather than an antivirus one:
*"Dokter kalau sesuai security itu harusnya waktu login Windows memakai login-nya sendiri."* The
question underneath is who opened a medical record from this machine.

DeusWatch already recorded the logons. What it could not answer was "who was at PC-WARD3 at 14:20",
because **a logon on its own is a point in time**: every account that ever signed in looks like it
is still signed in. Windows logoff events (4634 and 4647) are now mapped, which is what turns a
point into a session.

`GET /api/sessions?agent=&at=` answers who was signed in at a moment, `?agent=&hours=` lists a
machine's history, and `?user=` turns it around to show where an account has been. The assistant
can answer the same questions in words, which is how this is usually asked: "siapa yang login di
PC-WARD3 jam 2 siang".

**Sessions are derived from the events table, not stored in one of their own.** No second copy to
drift, no worker loop to fall behind, and a session recomputed next week from the same events gives
the same answer, which is the property an audit needs.

### Two limits, stated rather than hidden

**Service and machine accounts are filtered by name**, not by Windows logon type. A boot produces a
stream of SYSTEM, LOCAL SERVICE and NETWORK SERVICE logons and a domain machine signs in as its own
name with a trailing `$`; all of them would bury the three humans who used the machine that day.
The cost is that a type 3 network logon by a real account counts as a session. On a server that
would be noise; on a nurse station it is uncommon, and it still means that account touched the
machine.

**A logoff with no matching logon in the window creates nothing.** Inventing a start time nobody
observed is inventing evidence, and this is an audit trail.

### Still to come in gap 5

Correlating the Windows session with the SIMRS application session, so the trail runs from the
person to the record they opened, needs the application's own log. That is a decoder away rather
than a feature away: point an agent at the SIMRS log, write a decoder that extracts its username,
and the two line up on the account. Active Directory integration remains unbuilt.

## v2.55.0

### Added

**The asset register gains the half no machine can report.** v2.51.0 collected what an endpoint
knows about itself: manufacturer, model, serial number. The field engineer asked for one more thing
in the same breath, and it is the one no API can answer: *"Merek komputer juga bisa. Jadi lokasinya
nanti ketahuan."* Where the machine physically is. Which ward, which nurse station, which floor.

So **Location**, an **asset tag** (the organisation's own number on the sticker, which is a
different identifier from the manufacturer's serial and is what a stock-take reconciles against it)
and a free note are typed in the Inventory page by whoever put the machine there. The card records
who set it and when, because a location nobody has confirmed in a year is a different claim from
one checked last week.

**These fields are the opposite of every other column on that row.** Everything else is overwritten
by the agent's next report; these must survive it. The inventory upsert never names them, which is
what protects them, and migration 000077 says so where someone changing that query will read it.

**Export as CSV**, from the Inventory header. Their register lives in GLPI under an ITIL frame, so
the job here is to hand the list over rather than ask anyone to retype what DeusWatch already sees
on every endpoint. CSV rather than a GLPI asset push on purpose: their register carries fields
DeusWatch knows nothing about, such as owner, cost centre and purchase date, so merging the two
belongs to the person who understands both sides.

**Operator action.** Run the migrations: **000077** is added. Writing a location needs
`manage_settings`, since a wrong one sends somebody to the wrong ward; exporting needs only the
permission that already shows the same rows on screen.

Setting a location for an agent that has never reported is refused rather than created. A register
entry for a machine DeusWatch has never seen is the one row an asset register must not contain: one
nobody can walk to.

## v2.54.0

### Added

**Auto-block on any network device, over SSH.** Gap 3, and the reason it is worth doing first: the
hospital runs full Ruijie at the edge, and the responders were nftables, MikroTik REST and
CrowdSec, so auto-blocking, one of the capabilities the product leads with, could not touch a
single one of their devices.

**There is no Ruijie driver, deliberately.** Their engineer gave the reason without being asked:
*"Switch kita biasanya pakai Ruijie, terus nanti ada perubahan kontrak, ada Aruba."* A driver per
vendor expires with the procurement contract, so the block and unblock commands are a field the
operator fills in. They already have them, since these switches are configured by script today,
and a guess about hardware nobody here can test is worse than a blank. Same choice the SNMP sensors
made, for the same reason, and it means a site that swaps vendors keeps working with no release.

Several lines run in one session, so a device needing `configure terminal` before the rule and
`end` after it gets them together. A site with both a MikroTik and SSH devices fans a ban out to
all of them: neither takes precedence, because picking one would leave half the edge unblocked
without saying so.

**Operator action.** Configure under **Integrations → Network device over SSH**, and supply the
host key fingerprint from `ssh-keyscan`. Verification is on unless you explicitly turn it off: an
unverified SSH session to the device that enforces your blocks is a machine-in-the-middle away from
someone who watches every address you ban and answers as the switch while blocking nothing. See
[docs/ssh-cli.md](docs/ssh-cli.md).

### Three limits worth knowing

**No blocklist reconciliation.** MikroTik has a periodic sync that self-heals after a reboot; this
has Block and Unblock only. Reading an ACL back and parsing it is different on every vendor and is
exactly the knowledge this responder exists to avoid, so a device that reboots and loses its rules
is a gap you should know about rather than one papered over by an untestable parser.

**A device that answers `% Invalid input` is a failure**, even though CLI devices exit zero after
saying it. The output is judged, not the exit status. Without that, a mistyped command reports a
block that never happened.

**`{{ip}}` is required in the command**, and what is substituted is the parsed address, never the
text that arrived. A value like `1.2.3.4; reboot` is refused rather than escaped: this is the last
gate before a command runs with privilege on a switch.

## Releases v2.50.0 to v2.53.0: what a hospital IT team asked for

These four releases come from one source: a field discussion with the infrastructure team of a
vendor running the IT for around 20 hospitals, written up as a prioritised gap list in
[docs/insight-lapangan-rs.md](docs/insight-lapangan-rs.md). Four of its ten gaps are closed here.

**Before deploying any of them, run the migrations.** Five are added, `000072` through `000076`,
and nothing in these releases works without them.

## v2.53.0

### Added

**SNMP monitoring of network devices.** Gap 7. Their SNMP data was split across three tools, The
Dude for switches, WIS Cloud for access points, Grafana at head office, and the ask was one
dashboard. Nothing is installed on the devices: they already speak SNMP.

The design turns on one fact: SNMP standardises much less than people expect. Uptime, device
identity and the interface table are identical on every vendor, so they are read automatically.
**CPU load, temperature and power-supply state have no standard OID**, and those are exactly what
the field team named, so they are operator-defined sensors: name, OID, unit, scale, thresholds.

**Operator action.** You supply the OIDs for CPU, temperature and PSU. That is deliberate rather
than missing: it is why this works on their Ruijie gear without shipping vendor OIDs nobody could
verify, and why it keeps working after a contract change to different hardware. The team already
pull these values through The Dude, so the OIDs are something they have rather than something they
must research. Credentials go in under **Integrations**; v2c and v3 are supported, and an
unrecognised v3 security level falls back to authPriv, never to cleartext.

Interface history is kept 14 days against the sensors' 30: it is by far the largest table and worth
less per row.

## v2.52.0

### Added

**Alert-to-ticket, SLA scorecard, and a GLPI mirror.** Gap 4. Two problems the team described,
which are the same problem from both ends: nobody fills in tickets ("user paling malas isi
ticketing, jadi dia lebih ke chatting, jadi kita kadang dobel"), and the queue is how the team is
judged ("nanti bisa jadi rapot"). A queue that depends on somebody remembering to fill it in
under-reports the work, and that under-reporting lands on the people doing it.

So alerts open their own tickets, tickets reach the chat where people actually answer, and the
queue reports its own times.

**Response and resolution are reported separately, never averaged together.** A team can be quick
to pick things up and slow to finish, and one number hides exactly the problem a scorecard exists
to show. Medians and p90s, never means: one ticket left over a long weekend drags a mean until it
describes nothing.

`acked_at` is stamped by taking a ticket, moving it off open, or writing the first note. Editing a
title deliberately does not count, because a passing typo fix must not register as a response and
flatter the scorecard.

**The GLPI sync is one-way for content and read-only for status.** DeusWatch owns what a ticket
says, GLPI owns how far along it is. Nothing writes a field GLPI considers its own, which is what
makes conflict resolution unnecessary rather than merely postponed: there is no "which side wins"
setting because the question never arises. This is a deliberate limit, not a stage toward two-way
sync. Editing a ticket's text in DeusWatch after it is pushed does not update GLPI, and tickets
created in GLPI are not imported.

**Operator action.** Configure GLPI under **Integrations** (URL, app token, user token; the
instance root or its `/apirest.php`, either works). Only **live** tickets are pushed: switching
this on at a site with a long history would otherwise push every ticket it ever had into GLPI, and
the first impression of the feature would be a cleanup job.

## v2.51.0

### Added

**Service and API health monitoring.** Gap 1, and the longest-discussed complaint in the field.
The blind spot is not a host going down. It is an endpoint that answers HTTP 200 with a failure
inside the payload, or answers in nine seconds: *"Di dashboard kita ping-nya oke. Tapi di
pendaftaran di loket, ini enggak bisa."* Host monitoring structurally cannot see that.

So the **Service Health** page watches the endpoints a business function depends on, and groups
the board by that function rather than by host, which makes the screen answer "what is broken for
patients right now" instead of "which machines are alive". HTTP and TCP, with three rules per
check: status code, expected body content, and a latency budget. An up or down transition sits
behind a failure threshold so one blip pages nobody, and a 24 hour timeline answers "since when".

Request credentials are sealed with the secrets cipher at the API boundary, so plaintext exists
only inside the request that carried it; a save is refused rather than storing them readable, and
an edit that omits them keeps what was there.

**Hardware asset inventory.** Gap 2. Asset management is one of the two GLPI modules the team uses
daily, and the engineer named the exact fields: computer name, brand, model, and above all the
serial number. DeusWatch collected none of it, so the register was typed by hand next to a tool
that already talks to every endpoint. The agent now also reports manufacturer, model, serial
number, CPU cores, memory, and the primary IP and MAC.

Firmware placeholders are dropped at the agent: "To Be Filled By O.E.M." looks like real data in a
register, and every machine in a batch reports that identical string, so a register keyed on serial
number would collapse them into one asset. An upsert only overwrites a field with a non-empty
reading, because the DMI serial is root-only and an agent that lost privilege would otherwise blank
a value nothing else in the deployment holds.

**Operator action.** Two things. Define your checks under **Service Health**, since nothing is
probed until you say what matters. And **upgrade the agents on your endpoints**: the hardware facts
are collected agent-side, so an endpoint still running an older agent reports software only.

## v2.50.0

### Changed

**The assistant answers with structure.** The default persona now returns a list when there are
several items, and a headline plus notables for a summary, instead of a paragraph the reader has to
mine. Small talk stays one line.

**Report mirrors the dashboard's network widgets:** top destination port, top destination IP, top
source country, traffic direction, and top risky IP.

### Added

[docs/llm-providers.md](docs/llm-providers.md) documents the `assistant` purpose and recommends a
model per provider and per job (triage, report, assistant), which was previously something you
found out by trying.

## v2.49.0

### Fixed

**A list of addresses prepared a block for the first one.** Asked to block nine IPs, the assistant
parsed one and replied "Prepared a 7-day block for 43.173.126.86", a sentence that mentions no
others. An operator reads that, presses confirm, and comes away believing nine networks are cut
off. `ParseProposal` took the first address it found; it now takes all of them, in the order they
were typed, de-duplicated.

### Added

**The confirmation card is a checklist.** Several addresses arrive with a tick box each, ticked by
default since you just named them, and the **duration is editable on the card**, because that is
the thing most often reconsidered while reading the list. Confirm applies one call per ticked
address under your own session and reports a partial result rather than failing the whole card: a
list where one address was already blocked is a normal outcome, not an error.

Every address is listed, never summarised to a count. One card holds at most 20; anything beyond
that is reported in the reply so it can be sent separately, since quietly keeping the first twenty
is the same bug as quietly keeping the first one.

A CIDR is still refused for a ban even inside a list, while a whitelist accepts several ranges.

## v2.48.0

### Fixed

**A new user saw nothing at all.** Access flows user to workspace to tenant and `ResolveUserScope`
fails closed, so an account belonging to no workspace resolves to an empty tenant set: no agents,
no events, no blocklist, and no error anywhere explaining it. Migration 000049 backfilled the users
who existed when it ran, and nothing assigned a workspace to anyone created afterwards, so every
account added through the UI since then landed in an empty product.

It stayed hidden because **admins never hit it**. They carry `manage_tenants`, which takes the RLS
bypass and does not consult membership at all. Only the analyst and viewer accounts, the ones
created for other people, saw the empty deployment. On a fresh install the seeded `admin` is in the
same position, since 000049's backfill runs against an empty users table and `seedAdmin` inserts
afterwards.

`CreateUser` now adds the Default workspace membership in the same transaction as the user row, so
an account cannot exist in the scopeless state. Migration 000071 repairs the accounts that already
do, touching only users with no membership anywhere: someone deliberately moved to another tenant
is left where they were put.

### Operator note: moving someone out of Default is two steps

A user's scope is the **union** of every workspace they belong to, and the Workspaces page replaces
the member list of the workspace being edited without touching any other. So assigning someone to a
new workspace does not remove Default; you also have to edit Default and take them out of its
member list. Skipping that leaves them seeing both, which reads like isolation failing when it is
membership behaving as described. Not automatic on purpose: silently revoking a membership nobody
asked to revoke is the worse surprise.

## v2.47.0

### Changed

**No shipped default admin password.** With `ADMIN_PASSWORD` unset, the api now generates one on
first start and prints it once in its log. It used to fall back to a constant that is published in
this repository's public README, and which the product's own password policy already refuses as too
weak to choose: the seed was planting a credential no user would have been allowed to pick.

**Operator action, and it is not optional.** A deployment seeded before this release without
`ADMIN_PASSWORD` set has an `admin` account whose password is public knowledge. Create your own
named administrator, sign in as them, and delete `admin`. Changing its password is the lesser fix,
because the account name stays the obvious target.

### Added

**Last-administrator protection.** Delete and role-change now refuse when the change would leave
nobody holding `manage_users`. Deleting the seeded `admin` is meant to work and is encouraged;
deleting or demoting the only account that can administer the deployment is a lockout with no
recovery path inside the product. There is no second console and no break-glass account, and the
seed does not help because it only runs on a completely empty users table, so the way out was
editing the database by hand.

The check reuses `User.Can` rather than restating the rule in SQL, so it asks exactly the question
the request middleware asks. An explicit permission override replaces the role's defaults entirely:
an `admin` whose override omits `manage_users` does not count, and a `viewer` who was granted it
does. Disabled users do not count either, since login rejects them.

## v2.46.0

### Fixed

**A request-supplied value reached a path segment on the agent.** `POST /api/fim/restore-version`
takes `{agent, path, sha256}`, queues it, and the agent joins that sha into
`<snapshot-dir>/blobs/<sha>` to read a blob and write it to `path`. The API and the store both
checked `len(sha) == 64`, which is not the same as checking it is a digest: `"../"` repeated with
padding is also 64 characters, and `filepath.Join` cleans it into an escape from the blobs
directory. With `approve_remediation` that was arbitrary file read and write as root on any
enrolled endpoint.

The key is now required to be 64 hexadecimal digits, enforced at the API boundary so a bad request
gets a 400, and again on the agent before anything touches the filesystem. Nothing legitimate is
lost: a real key comes from `sha256.Sum256` and can never contain a separator or a dot.

**A corrupt VirusTotal cache row read as a clean verdict.** `GetCachedVirusTotalResult` ignored the
error from `json.Unmarshal` and returned `(result, true)`, so a row that failed to decode reported
"VirusTotal has an opinion and it is empty". It now reports a cache miss, so the lookup is retried
against the real provider.

**A replaced binary kept its old clean hash.** The agent's executable-hash cache was keyed by path
with no invalidation and no expiry, so once `/usr/bin/something` had been hashed, overwriting it in
place kept the original SHA-256 shipped for the lifetime of the agent process, and every reputation
lookup was performed on the file the attacker replaced. The cache is now keyed by path plus size
plus mtime, with a 30-minute TTL because size and mtime are both forgeable, and a bound so it
cannot grow without limit on a host running many short-lived processes.

**The executable hash guard failed open.** `computeFileHash` only applied the size and regular-file
checks when `f.Stat()` succeeded, so a Stat error fell through to hashing the first 64MiB, which is
the truncated-prefix digest the guard was added to prevent in v2.44.0. It fails closed now, and a
short read is also an error: a digest of a file that changed underneath the read matches nothing.

### Changed

**G104, G703 and G704 came off the gosec exclusion list.** A blanket exclusion silences a rule for
all future code, which is the opposite of what these three are worth. Taking G104 off is what found
the VirusTotal cache bug above, and taking G703 off is what found the path traversal. Best-effort
calls are now written `_ = f.Close()`, which gosec accepts and which says so in the code, and the
handful of intended sites carry an inline `#nosec <rule> -- reason`.

## v2.45.0

### Added

**The assistant detects a context window that is too small.** This closes the one failure in the
feature that never produced an error anywhere. Ollama allocates a context window and silently drops
the oldest tokens when a prompt exceeds it. The system prompt is ordered stable-first so the cache
can be reused, which means the oldest tokens are the persona: the assistant keeps answering
questions about the data correctly while its character disappears. Nothing is logged, nothing
returns 500, and the only symptom is a personality that will not stick. It cost two rounds of
guessing on a live deployment before anyone thought to read `n_ctx` out of the container logs.

The status endpoint now asks Ollama what window the configured model runs with and compares it
against the system prompt actually sent, and the chat panel shows a warning naming both numbers and
what to change. `/api/ps` is preferred because a loaded model reports the real window after the
server default, any baked `num_ctx` and the architecture maximum have been resolved against each
other; `/api/show` supplies a baked `num_ctx` when nothing is loaded yet.

A provider that is not Ollama has neither endpoint, so nothing is reported and nothing is warned
about. The silence is deliberate: a false alarm would send an operator to change a setting that was
already correct.

What is compared against the window is the whole request, system prompt plus conversation plus the
message. The system prompt is fixed and the history is not, so the history is what overflows: the
same server reported 5137 tokens on a fresh thread and 6331 a few turns later with an identical
system prompt.

The conversion is 3.5 characters per token rather than the usual 4, measured against a live server
that logged `task.n_tokens = 5137` for a prompt the 4:1 rule put at 4472. The error matters in one
direction only: understating it means the warning fires late or never.

**Operator note.** A derived model carries its own `num_ctx` and a baked parameter beats the server
default, so `OLLAMA_CONTEXT_LENGTH=16384` on the container does **not** lift a `deuswatch-llama`
built with 8192. Set the variable and point **Model** at a base model such as `llama3.1:8b`, which
has no `num_ctx` of its own and therefore takes the server default.

## v2.44.2

### Fixed

**The persona anchor repeated the role instead of the voice.** The closing line of the prompt, the
last thing the model reads before generating, echoed the persona's opening sentence. For Mia that
was "You are Mia, a catgirl working the quiet shift in a SOC", a title an 8B model has no trouble
keeping, while the stammer and the emoji that make the character recognisable were never mentioned
at that position at all. Replies came back warm, fluent and entirely generic, which reads exactly
like the persona being ignored.

A persona can now declare its own anchor by starting a line with `VOICE:`, and both shipped
personas do. The fallback stays the opening sentence, so a persona written before this still works.
**If you wrote a custom persona, give it a `VOICE:` line**, under about 200 characters, naming the
two or three tells a reader would notice immediately if they went missing. See
[docs/features/16-ai-assistant.md](docs/features/16-ai-assistant.md).

**It answered questions about the world from imagination.** Asked about the weather, the assistant
described the night sky. It has no weather, no news and no access to anything outside DeusWatch.
The grounding rule lived in the persona and enumerated DeusWatch things (hostnames, IPs, figures,
menu paths), which a smaller model does not generalise to the open world. The rule now sits in the
capability map, part of the framework rather than any one persona, so custom personas inherit it.

**`clip()` cut on bytes**, so a voice line ending in emoji could be sliced mid-rune and put invalid
UTF-8 into the prompt.

## v2.44.1

### Fixed

**The prompt budget measured the wrong thing.** A persona replaces the built-in one wholesale, so
it is the one part of the prompt the project does not control. The test measured the total against
the ~5.5k-character default while the shipped Mia persona is 8.3k, so a build that passed was
already about 3k over on any install that picked Mia from the dropdown. The number also moved
whenever someone edited the default persona, which says nothing about whether a new block is
affordable.

The framework ceiling now covers what the project ships, persona excluded, and is the number a new
block spends. The window ceilings add the largest selectable persona instead of the default. A new
test checks the framework still leaves room for a persona at the full `store.MaxPersonaLen` inside
the 16384-token window the docs recommend.

**The default persona named a block that no longer existed.** It twice told the model its facts
come from "the SECURITY CONTEXT below". That block was renamed `REFERENCE DATA`, so both references
pointed at a label the model would not find, and one of them was the prompt-injection boundary, the
single rule that most needs to land.

## v2.44.0

### Added

**Verified enforcement backends.** `Verify()` for the nftables and CrowdSec responders, probed by
the worker on a timer and recorded under `service="responder"`. The assistant can now distinguish
reachable-and-working, configured-but-dry-run, and live-but-probe-failed, instead of only reading
what the config claims. No migration: it reuses `service_heartbeats`.

**A capability map on every message**, plus broader gates for setup, file analysis, concepts and
rule authoring, including Indonesian phrasings. A question about a real feature whose keyword gate
did not fire used to produce a flat "DeusWatch can't do that".

**Persona re-anchoring** at the generation boundary. Reworked in v2.44.2; see above.

### Fixed

**The YARA scanner had never compiled.** `internal/malware/yara_scanner.go` is behind
`//go:build cgo` and was written against an API the binding does not have: `Close` where the
binding says `Destroy`, a function where it takes a `ScanCallback` interface, a callback parameter
shadowing the result map, and `Meta.Identifier`/`Meta.Value` called as methods when they are
fields.

Three layers hid it. A developer machine with no C toolchain falls back to `CGO_ENABLED=0` and
picks the no-op stub. The Docker build runs `go build ./cmd/<name>`, and the cgo image is the
gateway, which does not import this package. Only `go build ./...` reaches it, and that job was
already failing for an unrelated reason. **Process malware scanning ran the no-op stub on every
deployment until this release.**

**mTLS skipped the chain check on a resumed session.** `VerifyPeerCertificate` is not called when a
session resumes, because no certificate message is sent. With `InsecureSkipVerify` on (deliberately,
to skip only the hostname check) that left resumption verifying nothing. `VerifyConnection` runs on
every handshake, resumed included, and now carries the same check.

**A root agent followed symlinks.** The SCA inventory walk ran `os.ReadFile` on any file named like
a lockfile, in directories any local user can write. `WalkDir` does not follow symlinks while
traversing, but `ReadFile` follows one at the final path element, so a symlink named
`package-lock.json` pointing at `/etc/shadow` would have been read and shipped to the manager.
Regular files only now.

**Executable hashes were wrong as well as weak.** The agent sent the MD5 of a file's first 32MB.
For a binary over that size the digest belongs to no file, so every VirusTotal lookup missed, and a
miss reads exactly like a clean verdict. MD5 is also the wrong primitive for the one value an
attacker would want to forge, and the rest of DeusWatch keys hashes by SHA-256
(`file_hash_reputation.sha256`, FIM sightings), so this value could never be cross-referenced with
either. Now SHA-256 over the whole file, skipping rather than truncating past FIM's existing
`maxHashBytes`.

**`DB_MAX_CONNS` above 2147483647** wrapped to a negative `int32`, after which the pool refused
every connection with nothing in the message pointing at the typo.

**`golang.org/x/text` to v0.41.0** for GO-2026-6629, which `govulncheck` reports as reachable.

### Changed

CI is green for the first time in several releases. See **Continuous integration** below.

## v2.43.0

### Added

**Six database decoders**, shipped as seeds: `postgresql`, `mysql`, `mariadb`, `clickhouse`,
`mongodb`, `mssql`. A failed database login becomes `event.category: authentication` plus
`event.outcome: failure`, with `source.ip` and `user.name` extracted.

**No new rule is needed.** The brute-force aggregations in `rules/sigma/agg/` select on the
category, not the dataset, so `auth_fail_by_ip` and `auth_fail_by_user` start counting database
logins as soon as an agent ships them.

**Each engine needs its own logging turned on first**, and most are quiet by default. PostgreSQL
needs `%h` in `log_line_prefix` or the failures carry no client address and nothing can be banned.
MySQL 8 needs `log_error_verbosity = 3`, MariaDB `log_warnings = 2`, SQL Server failed-login
auditing. MongoDB logs the address already. ClickHouse logs the failure but not the address, which
no setting changes: it is on a separate Debug line, and a decoder sees one line at a time.

The full table is in [docs/features/11-decoders.md](docs/features/11-decoders.md).

## v2.42.0

### Fixed

**A follow-up question lost the address it was about.** The address lookup only read the message in
front of it, so a conversation about one IP lost its subject the moment the operator stopped
retyping it. The reported shape was the worst one: the assistant asked "what is the status of the
ban on 2.57.122.245?" and, when answered without the digits repeated exactly, replied that the
address was unknown to the deployment. It had the data; that turn's message just did not contain
the IP.

The two most recent addresses from earlier turns are now looked up alongside anything in the
current message, and the assistant's own turns count. Carried addresses are read from the local
database only and never trigger a live reputation call, because one of them may be an address the
model invented.

## Continuous integration

All three Go jobs had been failing on `main` for several releases, and none of the failures were
about the code being tested. The sequence is worth recording, because each layer hid the next.

1. `internal/malware` links libyara through cgo and the runner defaults to `CGO_ENABLED=1`, but the
   headers were never installed. `vet`, `build`, `test`, `govulncheck` and `gosec` all died at
   compile time before reaching anything. Setting `CGO_ENABLED=0` would have turned the jobs green
   and been wrong twice: `deploy/Dockerfile` builds the gateway with cgo and `yara-dev`, so the stub
   is not what ships, and `go test -race` requires cgo.
2. With the headers installed, the real error appeared: the YARA scanner had never compiled. See
   v2.44.0.
3. With it compiling, `gosec` reported 56 findings. Four were real (v2.44.0); the rest were the
   tool not knowing this codebase.
4. `govulncheck` reported genuine advisories against `golang.org/x/text` and the Go toolchain.

### Changed

**gosec is pinned** to v2.29.0. It was installed with `@latest`, so upstream shipping a new rule
turned CI red on days nobody touched the code, and a red build nobody caused is a red build nobody
reads. Bump it deliberately and fix what the new rules find in the same commit.

**govulncheck stays unpinned**, on purpose. It reports CVEs, and a stale scanner that misses a new
advisory fails the wrong way round: there, red is meant to be news.

**The Go toolchain is pinned** to 1.26.9. `govulncheck` checks stdlib advisories against the
toolchain that compiled the code, and `'1.26'` resolved to the 1.26.4 `setup-go` had cached, which
carried seven `net/http`, `net/textproto` and `crypto/tls` advisories that no change to this repo
could clear.

**A gofmt check was added**, and the three files that had drifted were formatted. `gofmt -l` exits
0 even when it lists files, so the failure is raised explicitly and names both the files and the
command that fixes them.

**Exclusions are scoped.** `tools/` is developer utilities that take a path on the command line and
never ship. `G703`, `G704` and `G104` joined the list with their reasons. `G402`, `G302`, `G118`
and `G122` are deliberately **not** excluded, so they keep working on new code; the few intended
sites carry an inline `#nosec <rule> -- reason` instead.
