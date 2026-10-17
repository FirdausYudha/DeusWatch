# Configuration benchmarks (CIS)

Hardening checks evaluated on the endpoint, scored per host and per policy.

## It reads Wazuh's policy format, on purpose

DeusWatch does not ship a benchmark content format of its own. A source of type `sca` reads
**Wazuh SCA policy files**, unchanged, whether they were uploaded here or placed on the endpoint.

The value in a CIS benchmark is not the engine, it is the several hundred checks per platform that
somebody keeps current as distributions change. Inventing a format here would mean maintaining
that content here, and that is a promise this project cannot keep: it already lists "a ruleset
nobody updates but us" as a real weakness against Wazuh, and a second content format would add
another.

The same call was made twice before in this codebase and was right both times. The imported
decoders came from Wazuh's, Ruijie got a generic SSH responder rather than a vendor API, and the
SNMP sensors take operator-supplied OIDs. All of them still work when the upstream moves.

## Setting it up

**1. Upload a policy.** Benchmarks page -> **Policies** -> choose a `.yml`. It is parsed and
validated on upload, so a malformed benchmark is rejected by one person who can fix it rather than
fetched by five hundred agents that each log a parse error nobody reads.

Wazuh's own policies (`cis_debian10.yml`, `cis_rhel9_linux.yml`, `cis_win2019.yml` and so on) work
as they are. They ship with a Wazuh agent under `/var/ossec/ruleset/sca/`, and the upstream
repository holds the current set.

**2. Add a source of type `sca`** to the agent or its group. `Path` is unused. `Interval` is the
assessment period in seconds, default **86400**.

A day is the right order of magnitude. A benchmark measures configuration, which changes when
somebody changes it, and running several hundred shell commands on every endpoint every few
minutes is how a monitoring agent earns a reputation for being the thing that slows the servers
down. There is one assessment at startup, so a newly enrolled host reports without waiting a day.

**3. Read the score on the Benchmarks page.**

## Where a policy can come from

| Source | Wins |
|---|---|
| Placed on the endpoint, in the policy directory | **First** |
| Served by the manager (uploaded under Policies) | Second |

```
/etc/deuswatch/sca/            # Linux and macOS
C:\ProgramData\DeusWatch\sca\  # Windows
```

Override the directory with `SCA_POLICY_DIR`. Any `.yml` or `.yaml` in it is loaded, and it is
re-read on every assessment, so adding or changing a file needs no agent restart.

A local policy **overrides** a served one carrying the same `policy.id`. That is the endpoint
administrator's remaining authority over what runs as root on their machine: central management is
the default and the convenient path, and dropping a file in still wins without having to argue
with whoever runs the console.

`SCA_ALLOW_PUSHED=0` on an agent refuses served policies entirely, so a hardened host runs only
what was placed on it.

Served policies are **cached** on the endpoint, so a manager outage does not silently stop
assessment. A compliance page that goes blank because the network blipped looks exactly like a
compliance page for an estate nobody is assessing. The cache is replaced wholesale on each fetch,
so a policy you disable or delete stops being assessed rather than living on in a cache.

## A policy is executable content, and what that costs

A policy's `c:` rules are shell commands run as the agent's user, usually root. So distributing
policies from the manager means a compromised manager can run arbitrary code as root on every
endpoint.

That sounds like a reason not to do it, and it was the reason this feature originally refused to.
It does not survive contact with what the agent already does: **the self-update path downloads a
binary from the manager and replaces the running executable with no signature check.** It pins TLS
to the manager's CA, which authenticates the manager, not the content. A compromised manager
therefore already has root code execution on every agent, by an easier route.

So central policy distribution adds no new trust boundary, and the cost of refusing it, a file per
policy per host forever, was being paid to guard a door while a wider one stood open.

**The actual fix is signing, for both.** The endpoint administrator installs one public key, once;
the manager may then serve binaries and policies, and the agent refuses anything not signed by
that key. A compromised manager becomes a transport that cannot forge content. That is not built,
and it is the honest next step rather than something this page can hand-wave.

Until it is, treat manager access as equivalent to root on every endpoint, which it already was.

## The score

**Only the controls that could be evaluated count.** A policy of 230 checks where 12 could not be
assessed scores out of 218.

Two reasons, and the second is the important one. A control this engine cannot assess must never
be reported as a failure, because a failed CIS check tells an operator to go change something on a
production host and sending them to do that over a gap here would be worse than admitting the gap.
And counting skipped checks as failures would mean a host could improve its score by becoming
*less* assessable, which is the one thing a compliance number must never reward.

The Controls view names the reason a check was skipped, so the gap is visible rather than
implied.

**A policy that does not apply to the host is skipped entirely.** Every real policy opens with a
`requirements` block ("is this actually Debian 10"), and a Debian benchmark on a RHEL box would
otherwise report several hundred failures that are not findings. The agent logs which policy it
skipped and why.

## What the engine supports

| Rule | Meaning |
|---|---|
| `f:/path` | The file exists |
| `f:/path -> r:regex` | Its contents match |
| `d:/path` | The directory exists |
| `d:/path -> r:name -> r:regex` | It holds a file whose contents match |
| `p:name` | A process is running |
| `c:command -> r:regex` | A command's output matches |
| `r:HKLM\...\Key -> Value -> data` | A registry value (Windows) |
| `not <rule>` | Negated |

Tests: `r:regex`, `!r:regex`, a bare literal substring, `n:regex compare >= 90` for the numeric
comparisons, and `&&` to chain them. Conditions: `all`, `any`, `none`.

**Patterns are matched per line**, which is not a detail. Wazuh applies a policy's patterns to each
line of a file, and CIS policies are written on that assumption: half of them are anchored, like
`r:^PermitRootLogin\s+no`. Under the default behaviour of Go's regexp, `^` matches only at the
start of a whole file, so those checks would never match and every hardened host would be reported
as failing.

Not every Wazuh construct is covered. Its regex dialect allows things RE2 refuses, lookahead among
them. Such a rule is reported as **skipped with the reason**, never as a failure.

## Limits

No remediation from the console. A failing check shows the policy's own remediation text and that
is where it stops; applying a CIS fix is a change with a blast radius, and the one that breaks a
hospital's SIMRS at 2am would be ours.

No policy editor. These are upstream files, and a half-edited copy of a benchmark is worse than
the original.

The `p:` check uses the agent's process snapshot, so on macOS it relies on `ps` and on Windows on
the process API; it is not available where process collection is not.
