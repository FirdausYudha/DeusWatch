# Auditing medical-record access on a shared workstation

The question a hospital actually asks after an incident is not "which PC" but **"who opened that
record"**. On a nurse station used by a different person every shift, the two are not the same
question, and the machine name on its own answers neither.

DeusWatch answers it in two halves that meet at the account name:

1. **Who was at the machine**, from the Windows logon and logoff events the agent already ships.
   Nothing to configure. See [features/08-users.md](features/08-users.md) for the session view.
2. **What the application did**, from your SIMRS's own log, read through a custom decoder.

This page is the second half.

## There is no SIMRS decoder in the box, on purpose

SIMRS is a category, not a product. Khanza, SIMRS GOS, and a dozen vendor-built systems all write
different logs, and some write none until you turn logging on. A decoder shipped here would be a
guess about a format nobody on this project can test against, and a decoder that silently fails to
match is worse than no decoder: the events still arrive, carry no user, and the audit trail looks
complete while naming nobody.

So you build it once, against your own log, with the tester already in the product. It takes
minutes, and the result is exact rather than approximate.

## Wiring it, end to end

### 1. Point an agent at the log

On the machine running SIMRS, add a log source with a `dataset` of your choosing. `simrs` is the
obvious one:

| Field | Value |
|---|---|
| Path | `/var/log/simrs/access.log`, or wherever your system writes it |
| Dataset | `simrs` |

### 2. Read your own raw lines

**Decoders → Load recent lines**, with the dataset set to `simrs`. This pulls real lines your
deployment has already ingested, so you write the pattern against what the system actually prints
rather than against the manual.

A line usually looks something like this, and yours will differ:

```
2026-10-16 14:22:31 INFO  user=dr.sari action=view_record patient=RM-00123 ip=10.20.3.41
```

### 3. Write the decoder

**Decoders → Add.** The only field that matters for the audit is the username, because that is
what meets the Windows session:

| Field | Value |
|---|---|
| Dataset | `simrs` |
| Category | `application` |
| Regex | `user=(?P<user_name>[\w.@-]+)\s+action=(?P<process_name>\w+)` |

Press **Test** against a real line before saving. The tester shows which fields were extracted, so
a pattern that matches nothing is caught here rather than discovered during an investigation.

The capture group name is what maps the value: `user_name` becomes `user.name`. The full list is in
[features/11-decoders.md](features/11-decoders.md).

### 4. Ask the question

```
GET /api/sessions?agent=PC-WARD3&activity=1&dataset=simrs&hours=24
```

Each row carries what the application said and who the operating system had signed in at that
moment. Or ask the assistant in words: *"apa saja yang dibuka dari PC-WARD3 sore ini, dan siapa
yang login"*.

## The two accounts are reported separately, never merged

`event_user` is who the **application** says did it. `session_users` is who the **operating system**
says was at the keyboard. They are side by side and the product never picks one.

When they disagree, that disagreement **is the finding**. An application account used while
somebody else was signed in to the machine is the shared-password habit this audit exists to
surface, and a tool that quietly reconciled the two would delete the evidence of it.

`session_users` is a list for the same reason: a Windows machine can have two people signed in at
once, and the handover second belongs to both. Naming one would be a guess presented as a record.

## What this does not do

**It does not read your database.** The trail is built from logs, so an action your SIMRS does not
log is an action DeusWatch cannot see. If record views are not logged today, that is the first
thing to turn on, and it is a change in SIMRS rather than here.

**It does not prove identity, it reports accounts.** If three nurses share one Windows login, the
trail names that login. That is not a gap in the tooling; it is the finding, and it is the argument
for per-person accounts that the engineer was already making:

> "Dokter kalau sesuai security itu harusnya waktu login Windows memakai login-nya sendiri dan
> terintegrasi dengan web-nya."

**Active Directory is not integrated yet.** Accounts are matched by name as they appear in the
logs, which works when SIMRS and Windows use the same usernames and does not when they do not.
