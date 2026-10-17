# Configuration benchmarks (CIS)

Hardening checks evaluated on the endpoint, scored per host and per policy.

## It reads Wazuh's policy format, on purpose

DeusWatch does not ship a benchmark content format of its own. A source of type `sca` reads
**Wazuh SCA policy files**, unchanged.

The value in a CIS benchmark is not the engine, it is the several hundred checks per platform that
somebody keeps current as distributions change. Inventing a format here would mean maintaining
that content here, and that is a promise this project cannot keep: it already lists "a ruleset
nobody updates but us" as a real weakness against Wazuh, and a second content format would add
another.

The same call was made twice before in this codebase and was right both times. The imported
decoders came from Wazuh's, Ruijie got a generic SSH responder rather than a vendor API, and the
SNMP sensors take operator-supplied OIDs. All of them still work when the upstream moves.

## Setting it up

**1. Put policy files on the endpoint.**

```
/etc/deuswatch/sca/            # Linux and macOS
C:\ProgramData\DeusWatch\sca\  # Windows
```

Override with `SCA_POLICY_DIR`. Any `.yml` or `.yaml` in that directory is loaded. Wazuh's own
policies (`cis_debian10.yml`, `cis_rhel9_linux.yml`, `cis_win2019.yml` and so on) work as they
are; they ship with a Wazuh agent under `/var/ossec/ruleset/sca/`, and the upstream repository
holds the current set.

**2. Add a source of type `sca`** to the agent or its group. `Path` is unused. `Interval` is the
assessment period in seconds, default **86400**.

A day is the right order of magnitude. A benchmark measures configuration, which changes when
somebody changes it, and running several hundred shell commands on every endpoint every few
minutes is how a monitoring agent earns a reputation for being the thing that slows the servers
down. There is one assessment at startup, so a newly enrolled host reports without waiting a day.

**3. Read the score on the Benchmarks page.**

## Policies are not pushed from the manager

This is the one deliberate inconvenience in the feature, and it is not an oversight.

A policy's `c:` rules are shell commands, run as the agent's user, which is normally root. **A
policy file is executable content.** If the manager could push one, a compromised manager would
own every endpoint in the estate, and the whole reason each agent carries its own certificate is
that the manager is not implicitly trusted with arbitrary code on the host.

So policies are placed on an endpoint by whoever administers that endpoint: your configuration
management, your image, your package. Agent groups decide *that* a host runs benchmarks; the host
decides *which*.

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
