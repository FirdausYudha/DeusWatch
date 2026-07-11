# Getting started: add a new log source (decoder -> test -> rule)

This walks the full path from a log DeusWatch has never seen to a working detection + automatic
ban, end to end. Nothing here needs code - only the **Decoders** and **Rules** menus.

Three pieces fit together:

```
 Agent source        Decoder                         Rule
 (which log)   ->    (regex -> fields + category)  -> (fires on that category) -> alert / ban
```

- The **agent source** tails a log file and tags each line with a **dataset** name.
- The **decoder** turns that dataset's raw lines into DCS fields (source IP, user, ...) and sets a
  **category**.
- A **rule** scoped to that category detects on the decoded events.

We'll use a real example: **Dovecot** (IMAP/POP mail login) brute force. The payoff: once the
decoder sets `category: authentication` + `outcome: failure` + a source IP, the **built-in
"Authentication Failures Burst by Source IP" rule fires with no new rule at all**, and the
progressive-ban engine can block the attacker.

---

## Step 1 - point an agent at the log

On the mail host's agent (**Agents** -> the agent -> its sources), add a source and **Save & push**:

| Field | Value |
|---|---|
| Dataset | `dovecot` |
| Type | `file` |
| Path | `/var/log/mail.log` (or wherever Dovecot logs) |

The agent now ships those lines with `dataset = dovecot`. Because DeusWatch has no built-in
decoder for `dovecot`, they arrive as **raw events** (stored, but no fields/category yet) - which
is exactly what we fix next.

## Step 2 - see your real raw lines

Open **Decoders** -> in the Add form set **Dataset** = `dovecot` -> **Load recent lines for
"dovecot"**. You'll see actual lines from your own logs, e.g.:

```
Jul 11 10:00:00 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<alice>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.5
```

This is the answer to "how do I know what my lines look like?" - you read them straight from your
ingested logs, no guessing.

## Step 3 - write the decoder and test it

In the same Add form:

| Field | Value |
|---|---|
| Dataset | `dovecot` |
| Category | `authentication` |
| Outcome | `failure` |
| Level | `low` |
| Regex | `auth failed.*user=<(?P<user_name>[^>]*)>.*rip=(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})` |

The regex uses **named groups** that map to DCS fields: `user_name` -> `user.name`,
`source_ip` -> `source.ip` (full list: [decoders/README.md](../decoders/README.md)).

Now **test before saving**: paste one of the loaded lines (or click it) -> **Test**. You should
see:

```
✓ matched
event.category   authentication
event.outcome    failure
user.name        alice
source.ip        1.2.3.4
```

Tweak the regex until it extracts what you want, then **Add decoder**. The gateway live-reloads
within ~30s - no restart.

## Step 4 - detection (often already done)

Decoded Dovecot failures now have `category: authentication`, `outcome: failure`, and a source
IP. The **built-in** aggregation rule already matches that:

> *Authentication Failures Burst by Source IP* - `count() by source.ip > 20` in 5m (T1110).

So repeated Dovecot logins from one IP raise a **high** alert automatically, and if the response
engine is enabled the IP is banned via the progressive ladder. **You added one decoder and got
brute-force detection + banning for a brand-new source.**

Want a per-event rule too (e.g. to see every single failure, or tag it distinctly)? Add one under
**Rules** scoped to the category:

```yaml
title: Dovecot - auth failure
id: <generate a uuid>
status: experimental
level: low
logsource:
  category: authentication
detection:
  keywords:
    - 'auth failed'
  condition: keywords
tags:
  - attack.t1110
  - attack.credential_access
```

Because it is scoped to `authentication` and matches `event.original`, it only runs on
authentication events and only fires on Dovecot's own text.

## Step 5 - verify end to end

1. Trigger a few failed IMAP logins from a test IP.
2. **Dashboard** -> Events & Alerts: the Dovecot events show `source.ip` and `authentication`;
   click a row for the full JSON.
3. After enough failures, the *Authentication Failures Burst* alert appears; **Response** shows a
   ban recommendation for that IP.

---

## Tips

- **RE2, not PCRE/OSSEC**: Go RE2 has no backreferences or lookaround, but is linear-time and
  ReDoS-safe. In RE2, `.` is any char and `\.` is a literal dot (the opposite of OSSEC os_regex).
- **URL-encoded / varied formats**: add alternates in the regex, or keep the decoder simple (just
  set `category` + extract the IP) and let a keyword rule match `event.original`.
- **Precedence**: built-in decoders (sshd/web/fim/windows/suricata) always win; custom decoders
  only run for datasets without a built-in.
- **Reuse existing detections**: setting `category: authentication` + `outcome: failure` reuses
  the brute-force aggregation and ban ladder. Setting `category: web` reuses the web-attack rules.
  Pick a category that matches existing rules and you inherit their detection for free.

See also: [Decoders](features/11-decoders.md) · [Rules](features/06-rules.md) ·
[decoders/README.md](../decoders/README.md).
