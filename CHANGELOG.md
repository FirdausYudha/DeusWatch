# Changelog

Releases are git tags (`vX.Y.Z`). Pushing one publishes a GitHub Release with the agent binaries,
which is what the in-app **Settings -> Software updates** check compares against. Versions before
v2.42.0 are documented in their tag annotations and GitHub Releases rather than here.

Entries say what changed and, where it matters, what an operator has to do about it. A fix that
needs nothing from you does not say so; assume silence means nothing to do.

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
