# Custom decoders

Data-driven, regex-based decoders - the DeusWatch equivalent of Wazuh decoders. They let you
support a **new log source without writing Go**: match a dataset's raw lines with a regex and map
named capture groups into DCS fields. Then normal (keyword/field) rules, scoped by the category
you set, fire on that source.

Decoders run in the **gateway**, only as a fallback for datasets that have no built-in decoder
(sshd, web, firewall, fim, windows, suricata are built in). They are compiled once and indexed by
dataset, so a line only tries the decoders for its own dataset - the cost is one linear-time
(RE2) regex per line.

**Manage them in the UI** (the **Decoders** page): add/edit/enable/delete without a restart -
the gateway live-reloads within ~30s. The `.yml` files in this directory are **seeds**: on first
start they are loaded into the DB as builtins (and new ones are added on upgrade), then the DB is
the source of truth. `DECODERS_DIR` (default `/decoders`, baked into the image) is where those
seeds live.

## Format

```yaml
name: postfix-client        # label
dataset: postfix            # the agent source dataset this applies to (matched loosely:
                            #   "postfix (mail)" also matches)
category: mail              # event.category to set (so rules can scope to it)
action: ''                  # optional event.action
outcome: ''                 # optional event.outcome (e.g. failure)
level: info                 # optional severity: info|low|medium|high|critical
regex: 'client=[^[]*\[(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\]'
```

The full raw line is always kept as `event.original`, so keyword rules still work even if you
extract no fields.

## Named capture groups -> DCS fields

| group name (any of) | DCS field |
|---|---|
| `source_ip` / `src_ip` / `srcip` | `source.ip` |
| `source_port` / `src_port` | `source.port` |
| `destination_ip` / `dest_ip` / `dst_ip` | `destination.ip` |
| `destination_port` / `dest_port` / `dst_port` | `destination.port` |
| `user_name` / `user` / `username` | `user.name` |
| `host_name` / `host` / `hostname` | `host.name` |
| `process_name` / `process` | `process.name` |
| `process_command_line` / `command_line` / `cmdline` | `process.command_line` |
| `file_path` / `path` | `file.path` |

Unknown group names are ignored (handy for documenting intent). The regex is **Go RE2** - no
backreferences or lookaround, but linear-time and safe for operator input.

## Workflow

1. **Decoders** page -> Add: set the `dataset`, a `category`, and the `regex` (or add a `.yml`
   here to ship it as a seed).
2. Add a rule under `rules/sigma/` scoped to that category (keyword on `event.original`, or a
   field selection on what you extracted).
3. Point the agent at the log with a source whose `dataset` matches. No restart needed - the
   gateway live-reloads decoders.

See `postfix.yml` and `vsftpd.yml` for working examples.
