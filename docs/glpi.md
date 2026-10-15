# Connect DeusWatch to GLPI (ITSM ticketing)

DeusWatch mirrors its tickets into GLPI so the team works in one queue instead of two.

## What the sync does, and what it refuses to do

| | Direction | Owner |
|---|---|---|
| Ticket title, body, urgency | DeusWatch → GLPI, once at creation | DeusWatch |
| Ticket status | GLPI → DeusWatch, on every cycle | **GLPI** |
| Anything else in GLPI (assignee, follow-ups, SLA, category changes) | not touched | GLPI |
| Tickets created by people in GLPI | not imported | GLPI |

The sync is **one-way for content and read-only for status**. DeusWatch owns what a ticket says;
GLPI owns how far along it is. Nothing DeusWatch writes can overwrite work done in GLPI, which is
why there is no conflict-resolution setting to get wrong — the question never arises.

That is a deliberate limit, not a stage on the way to two-way sync. Editing a ticket's text in
DeusWatch after it has been pushed does **not** update GLPI.

---

## 1. In GLPI: turn on the API and get two tokens

**Setup → General → API**

1. Set *Enable Rest API* to **Yes**.
2. Note the *URL of the API* (usually `https://your-glpi/apirest.php`).
3. Under *API clients*, add a client (or edit the existing "full access from localhost" one so its
   IP range covers the DeusWatch host) and copy its **application token** (`App-Token`).

**The user token:** open the GLPI user DeusWatch should act as, go to the *Settings* tab, and
*Regenerate* the **API token**.

> DeusWatch acts entirely as that user. Its GLPI profile decides what the sync can do, so give it
> a profile that can create tickets and read them, and nothing more. Do not use a super-admin
> account for this.

---

## 2. In DeusWatch: add the connector

**Integrations → Add → GLPI (ITSM ticketing)**

| Field | Value |
|---|---|
| GLPI URL | `https://your-glpi` or `https://your-glpi/apirest.php` — either works |
| App-Token | the API client's application token |
| User API token | the GLPI user's personal API token |
| Category id | *optional* — GLPI ITIL category id for pushed tickets; blank leaves GLPI's default |
| Requester user id | *optional* — GLPI user id recorded as requester; blank leaves it unset |
| Skip TLS verify | `true` only for a self-signed certificate on a trusted internal network |

Both tokens are encrypted at rest and are never shown again after saving.

Enable the connector. The worker picks it up within a minute.

---

## 3. What happens next

Every 60 seconds the worker:

1. **Pushes** DeusWatch tickets that are still open or in progress and have no GLPI counterpart
   (up to 50 per cycle, oldest first).
2. **Reads back** the GLPI status of every linked ticket that is not yet closed (up to 100 per
   cycle) and moves the DeusWatch ticket to match.

### Only live tickets are pushed

Turning the connector on does **not** push your ticket history. Tickets already resolved or closed
stay where they are; pushing them would bury the queue the team actually works with records of
things that are already finished. Only the open queue is mirrored.

### Status mapping

| GLPI | DeusWatch |
|---|---|
| New (1) | `open` |
| Processing — assigned (2) | `in_progress` |
| Processing — planned (3) | `in_progress` |
| **Pending (4)** | `in_progress` |
| Solved (5) | `resolved` |
| Closed (6) | `closed` |

GLPI's **Pending** — waiting on a third party — has no DeusWatch equivalent. It maps to
`in_progress` on purpose: the ticket is still live and still owned, and calling it resolved would
stop the SLA clock on work that has not finished and quietly flatter the scorecard.

A status this version of GLPI has and DeusWatch does not is **left alone** and logged, rather than
guessed at.

### The scorecard

A ticket whose status changes in GLPI is recorded as picked up by `(via GLPI)`. GLPI's status
field says the work started but not who started it, so the scorecard names the channel rather than
inventing a person. Work done entirely inside GLPI still shows up in the response and resolution
times on the Tickets page.

---

## Troubleshooting

Check the worker log (`docker compose logs -f worker | grep -i glpi`).

| Message | Cause |
|---|---|
| `GLPI session: ... ERROR_APP_TOKEN` | wrong App-Token, or the API client's IP range does not cover the DeusWatch host |
| `GLPI session: ... ERROR_LOGIN_PARAMETERS_MISSING` | wrong or regenerated user API token |
| `GLPI session: ... x509: certificate signed by unknown authority` | self-signed GLPI cert — set *Skip TLS verify*, or install the CA |
| `HTTP 404` on `/apirest.php/initSession` | the Rest API is off, or the URL points somewhere else |
| `push ticket ... ERROR_GLPI_ADD` | the GLPI user's profile cannot create tickets, or a mandatory field is enforced by a GLPI rule |
| `created but the link ... was NOT saved` | the GLPI ticket exists but DeusWatch could not record it; the next cycle will create a duplicate, so remove one by hand |
| `unmapped status N` | a GLPI status DeusWatch does not know; the ticket is left untouched |

The sync is inert when no GLPI connector is enabled, and when the secrets cipher is unavailable
(`SECRETS_KEY` unset) the connector's tokens cannot be read, so nothing runs.
