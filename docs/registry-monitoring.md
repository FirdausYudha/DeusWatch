# Registry integrity monitoring (Windows)

Watches registry keys the way FIM watches files.

## Why it matters more than it sounds

The registry is where Windows persistence actually lives. A payload dropped on disk is annoying; a
payload written to a Run key, a Winlogon helper, an Image File Execution Options debugger or a
service `ImagePath` **survives a reboot**, which is the difference between an incident and a
foothold. A file-only integrity monitor misses the half of the attack that outlives the machine
being turned off and on again.

## Setting it up

Add a source of type **registry** to an agent or an agent group. `Path` takes one or more keys,
comma separated:

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run,HKLM\System\CurrentControlSet\Services
```

Both long and short hive names work (`HKLM` or `HKEY_LOCAL_MACHINE`, and the same for `HKCU`,
`HKU`, `HKCR`, `HKCC`), because every piece of Windows documentation mixes them. Forward slashes
are accepted and rewritten. The hive is upper-cased in alerts so the spelling is consistent no
matter how it was typed.

`Interval` is the scan period in seconds, default 120. Slower than the FIM default on purpose: the
keys worth watching are small, and a persistence key written by an attacker is not a thing that
un-writes itself, so a minute either way costs nothing while a tight registry loop on a domain
controller does.

### Keys worth starting with

| Key | What it catches |
|---|---|
| `...\CurrentVersion\Run`, `RunOnce` | The ordinary autorun payload |
| `...\Winlogon` | `Userinit` / `Shell` hijacks, which run before the desktop |
| `...\Image File Execution Options` | A debugger attached to a legitimate binary |
| `HKLM\System\CurrentControlSet\Services` | A service whose `ImagePath` was replaced |
| `...\Explorer\User Shell Folders` | Redirected startup folders |

Do not point a source at a hive root. `HKLM` alone is millions of values; the agent refuses past
20,000 and logs that it is no longer monitoring everything, which is a worse outcome than a
narrower scope chosen deliberately.

## What an alert looks like

A registry change reports as `event.category: registry` with `registry_created`,
`registry_modified` or `registry_deleted`, and the key path in `file.path`.

It reuses the file fields on purpose. A registry value is a path and a hash, which is exactly the
shape the normalizer, the rules, the diff view, the ticketing and the timeline already understand,
so the manager needed no changes at all. What it does **not** do is claim to be a file: "file
modified" on a Run key is an alert that sends an operator looking in the wrong place.

**Values are rendered, not just hashed.** Strings, multi-strings and integers come through as
text, so a modified Run key shows the new command line in the diff rather than only telling you
that something changed. Binary blobs are hashed instead: a certificate printed as hex is not
something anybody reads, and the hash is enough to detect the change.

The shipped rule **Registry Autorun Key Changed** fires at `high` on a create or modify under any
of the keys in the table above. Deletion is not alerted by it, because removing an autorun entry
is what cleanup looks like.

## Behaviour worth knowing

**The first scan is silent.** It establishes the baseline. An agent that has just started knows
nothing about what the registry looked like a minute ago, so announcing every watched value as
newly created would bury a real change under thousands of events on every restart, and a service
set to restart on failure restarts often.

**A failed scan is not a thousand deletions.** If a key cannot be read at all, the scan reports
the error and keeps the old baseline rather than concluding that everything under it was deleted.
One unreadable subkey is skipped and the rest of the tree is still monitored.

**Windows only.** A registry source pushed to a Linux endpoint fails with an explicit message in
that agent's log rather than quietly doing nothing, so a misconfigured group does not look like a
monitor that is running.

There is no change-notification wiring (`RegNotifyChangeKeyValue`), so detection is bounded by the
scan interval rather than instant, unlike FIM which has an fsnotify path.
