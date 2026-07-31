# Host YARA rules directory

Bind-mounted into the gateway container at `/rules/yara`. Drop any `*.yar` / `*.yara` file here and
restart the gateway to pick them up:

```bash
docker compose -f deploy/docker-compose.yml restart gateway
```

Look for `gateway: yara: loaded N ruleset(s) from /rules/yara` in the startup log.

Shipped by default:

- `deuswatch_starter.yar` — a minimal proof-of-life set (EICAR test string, PHP webshell,
  bash reverse shell, PowerShell downloader). Safe to keep or delete once you have real rules.

For a real ruleset see `docs/yara.md` (Neo23x0/signature-base, YARA-Rules/rules).
