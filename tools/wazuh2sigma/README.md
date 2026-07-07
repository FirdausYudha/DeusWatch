# wazuh2sigma

Reverse-engineers Wazuh XML rules into DeusWatch Sigma **keyword** rules (matching
`event.original`, scoped by logsource category).

```bash
go run ./tools/wazuh2sigma [wazuhDir] [outDir]
# defaults: Wazuh_Rules  ->  rules/wazuh-imported
```

It converts only the safely-translatable slice: single-event rules with a literal `<match>`
pattern, on a log source DeusWatch normalizes (auth / web / network / file). It maps the Wazuh
level to a Sigma level and `<mitre><id>` to `attack.*` tags. It does **not** convert decoder
parents (`if_sid`), frequency/correlation rules, OSSEC `<regex>`, or sources DeusWatch has no
normalizer for (mail, AV, PBX, sysmon, vendor firewalls, ...) - those are reported as skipped.

## License note (important)

The Wazuh ruleset is **GPLv2, Copyright Wazuh Inc.** Rules produced by this tool are a
**derivative work**. The converter itself is original DeusWatch code and is tracked in this
repo, but its **input** (`Wazuh_Rules/`) and **output** (`rules/wazuh-imported/`) are
**gitignored** and must NOT be published in this (public) repo. Use the generated rules
locally, or only in a GPL-compatible context.

## Coverage reality

Most Wazuh rules target log sources DeusWatch does not ingest/normalize yet, so they convert to
rules that cannot fire. The real lever for broader coverage is **adding normalizers** for the
sources you care about (then both imported and native rules light up), not converting more XML.
