# macOS agent

The agent runs on macOS, Intel and Apple silicon. It is not a full-capability platform and this
page says exactly where it stops, because an agent that reports in while quietly not doing half
its job is worse than no agent.

## Install

Agents page -> Add agent -> macOS. The generated command is the Linux one pointed at a different
script:

```bash
curl -fsSL http://MANAGER:8080/api/agent/install-macos.sh | sudo MANAGER=<ip> TOKEN=<token> NAME=<name> sh
```

It installs to `/usr/local/bin/deuswatch-agent`, enrolls for a client certificate, and registers a
launchd daemon at `/Library/LaunchDaemons/com.deuswatch.agent.plist`. Re-running it is safe: the
daemon is booted out first, so the binary is never overwritten while running.

Check it with `launchctl print system/com.deuswatch.agent`, and read its output in
`/var/log/deuswatch/agent.log`.

A separate script rather than a branch inside `install.sh`, because macOS has no systemd and no
journald, and one script carrying two service managers tends to break both.

## Give it Full Disk Access

Without it the agent cannot read protected paths, and macOS denies those reads silently rather
than with an error you would notice. **System Settings -> Privacy & Security -> Full Disk Access**,
add `/usr/local/bin/deuswatch-agent`.

## What works, and what does not

| Capability | macOS |
|---|---|
| Log file collection | Yes |
| File integrity monitoring | Yes |
| Software inventory | Yes |
| Process snapshots with executable hashes | Yes, via `ps` |
| Vulnerability assessment (SCA manifests) | Yes |
| Who-data: which process and user changed a file | **No**, needs the Linux audit subsystem |
| Host isolation | **No** |
| Remote process kill | **No** |
| Agent-side firewall auto-block | **No**, nftables is Linux only |
| journald / Windows Event Log collection | Not applicable |

The unsupported actions fail with an explicit "not supported on this platform" rather than
reporting success, so the UI can never imply a containment that did not happen. This matters more
than it sounds: a silent skip on a kill or an isolation is a response you believe happened.

Unified log (`log stream`) collection is not implemented. Point the agent at files under
`/var/log` and at your applications' own logs instead.

## Process collection uses `ps`

macOS has no `/proc`. The agent runs `ps -axwwo pid=,ppid=,user=,rss=,lstart=,comm=` and parses
it, rather than linking libproc through cgo, which would cost the agent its static
`CGO_ENABLED=0` cross-compile and buy nothing this collector needs.

If `ps` runs but nothing parses, the agent reports an error rather than an empty process list: a
host with no processes would otherwise look merely quiet.
