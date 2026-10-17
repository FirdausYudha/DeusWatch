# Rootkit checks (Linux)

Three local-anomaly checks, run on a slow timer, looking for things that have no business being
true on a healthy host.

## What it checks, and why only three

| Check | Severity | What it means |
|---|---|---|
| `hidden_process` | critical | The kernel confirms a PID is alive and `/proc` does not list it |
| `suid_in_writable_dir` | high | A setuid or setgid executable in `/tmp`, `/var/tmp`, `/dev/shm`, `/home` or `/run/user` |
| `file_in_dev` | high | A regular file under `/dev`, which should hold device nodes |

Three, not thirty, and that is the design rather than the first instalment.

A rootkit scanner is only useful if people believe it. Wazuh's rootcheck ships a long list of
checks whose per-check false-positive rate is low and whose combined rate on a busy host is not,
and the usual outcome is that the whole category gets muted. These three were picked because each
one has close to no benign explanation, and the one that does ranks lower.

**A hidden process is the strongest signal in this file.** There is no normal reason for the
kernel to answer a signal probe for a PID that `/proc` denies exists. That is precisely what a
`readdir`-hooking rootkit produces, and it is the one finding here that warrants waking somebody.

Deliberately **not** included:

- **Hidden port scanning.** The technique is to `bind()` each port and infer a hidden listener
  from `EADDRINUSE` with nothing in `/proc/net/tcp`. It works, and it means an agent briefly
  binding thousands of ports on a production host, which can collide with a service restarting.
  Not worth it for the signal.
- **Trojaned-binary string signatures.** The classic list (`/bin/ls` containing `/dev/ttyop`, and
  friends) matches rootkits from the 2000s and nothing current. It would add a page of checks and
  catch nothing.

## Setting it up

Add a source of type **rootcheck** to an agent or an agent group. `Path` is unused. `Interval` is
the scan period in seconds, default **3600**.

An hour is deliberate. These checks walk directories and probe thousands of PIDs, nothing they
look for appears and vanishes within minutes, and an hourly scan nobody disables is worth more
than a minutely one somebody turns off over the I/O. There is one scan at startup, so a host that
is already compromised does not stay quiet for the first hour.

Run the agent as root. Unprivileged, the directory walks miss what they cannot read and the PID
probe still works (`EPERM` answers the question "does this PID exist"), so the hidden-process
check survives but the file checks go partly blind.

## How false positives are kept out

**A hidden process is confirmed across two passes.** Processes start and exit between reading
`/proc` and probing a PID constantly, so a single pass sees phantom disagreements all the time.
Only a PID that looked hidden in both passes and is still alive is reported. The second pass only
runs when the first one found something, so a clean host pays nothing for it.

**The suid check is an allow-list of suspicious places, not a block-list of safe ones.** The
system suid binaries are legitimate, numerous, and differ between distributions; reporting
everything outside a known-good list would bury the one that matters. The directories it watches
are world-writable or user-owned, and nothing a package manager installs lands in them.

**`/dev` has an exclusion list.** `shm`, `mqueue` and `hugepages` hold ordinary files on every
normal system and are not walked at all; the handful of regular files that legitimately sit
directly in `/dev` are listed by name.

**The walks are bounded.** 200,000 entries per scan, and the PID probe stops at 65,536 or the
kernel's `pid_max`, whichever is lower. A host with a pathological `/tmp` cannot turn a scan into
an I/O storm.

## What the alert looks like

`event.category: intrusion_detection`, `event.action: rootcheck_<check>`, MITRE **T1014
(Rootkit)**, and a label stamped by the agent rather than left to a detection rule.

That last part is deliberate: there is nothing a rule could add to "the kernel says this PID
exists and `/proc` denies it". The agent has already decided, and an unlabelled event would sit
behind the alerts-only view that operators actually watch.

`file.path` carries the path for the file checks; `process.pid` carries the PID for a hidden
process. The human explanation is in `event.original`.

## Limits

**Linux only.** The checks read `/proc` and rely on POSIX mode bits and `/dev` semantics. A
rootcheck source pushed to a Windows or macOS endpoint fails with an explicit message in that
agent's log rather than quietly doing nothing, so a misconfigured group does not look like a
scanner that is running.

A kernel-module rootkit good enough to lie to `kill(pid, 0)` as well as to `readdir` will not be
caught by the hidden-process check. Nothing running in userspace on the compromised host can
catch that one; it is a reason to watch the network side too, not a reason to skip this.
