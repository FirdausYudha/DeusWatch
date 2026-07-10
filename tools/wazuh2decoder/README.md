# wazuh2decoder

Reverse-engineers Wazuh XML decoders into **DRAFT** DeusWatch decoders (regex + field mapping).

```bash
go run ./tools/wazuh2decoder [wazuhDir] [outDir]
# defaults: Wazuh_Decoders  ->  decoders/wazuh-imported
```

It translates the OSSEC **os_regex** dialect to Go **RE2** - most importantly swapping the
inverted dot (`.` is a literal dot in os_regex; `\.` matches any char) - names the positional
capture groups from each decoder's `<order>` (mapping `srcip -> source_ip`, `user -> user_name`,
...), and derives a `dataset` from the decoder name.

## These are DRAFTS - review before enabling

os_regex `offset` context, PCRE2-only features, and complex alternations do not translate
cleanly. Every generated file needs a human pass: set the `category`, then **test it on the
Decoders page** ("Test against real log lines") against your own logs. Compilation is verified,
but a compiling regex can still match the wrong thing.

## License

The Wazuh decoders are **GPLv2, Copyright Wazuh Inc.** This converter is original DeusWatch code
and is tracked; its input (`Wazuh_Decoders/`) and derived output (`decoders/wazuh-imported/`) are
**gitignored** and must not be published in this public repo. Use the drafts locally.

## Binding with rules

A decoder sets a `category`; a rule scoped to that category then fires on the decoded events.
Pair this with `tools/wazuh2sigma` (rules) for the same source, and the two work together - the
decoder extracts the fields, the rule detects on them.
