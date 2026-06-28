# Notifications - Telegram & Email setup

DeusWatch can push **alerts** (per event, above a severity you choose) and **scheduled
reports** (a security summary on a cadence) to **Telegram** and **email**. It can also POST
a JSON **webhook export** to an external tool (SIEM, n8n, Slack, etc.) - that is a separate
feature, covered at the end.

There are two layers:

| Layer | Where it lives | What you set |
|---|---|---|
| **Channel credentials** (bot token, SMTP login) | server env (`deploy/.env`) - they are secrets | once, at deploy time |
| **Behaviour** (alert severity threshold, report delivery schedule) | the **UI** | any time, no restart |

> Credentials stay in env on purpose - they're secrets and never touch the database or Git.
> The *threshold* and the *schedule* are stored in the DB and editable live from the UI.

---

## 1. Connect Telegram

### Step 1 - create a bot and get the token
1. In Telegram, open a chat with **[@BotFather](https://t.me/BotFather)**.
2. Send `/newbot` and follow the prompts (give it a name and a username ending in `bot`).
3. BotFather replies with a **token** like `123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxx`. Copy it.

### Step 2 - get your chat id
**Direct messages (to yourself):**
1. Open your new bot and press **Start** (send it any message).
2. Visit `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser (replace `<TOKEN>`).
3. Find `"chat":{"id":123456789,...}` - that number is your **chat id**.
   - Shortcut: message **[@userinfobot](https://t.me/userinfobot)**, it replies with your id.

**A group:**
1. Add your bot to the group.
2. Send a message in the group, then check `getUpdates` as above.
3. The group chat id is usually a **negative** number (e.g. `-1001234567890`).

### Step 3 - put the credentials in `deploy/.env`
```bash
cp deploy/.env.example deploy/.env   # if you don't have one yet
```
Edit `deploy/.env`:
```dotenv
TELEGRAM_BOT_TOKEN=123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_CHAT_ID=123456789
```

### Step 4 - restart the worker so it reads the new env
```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker
```

---

## 2. Connect Email (SMTP)

### Step 1 - get SMTP credentials from your mail provider
You need: host, port, username, password, a "from" address, and one or more "to" addresses.
For Gmail, create an **App Password** (Google Account → Security → App passwords) and use
`smtp.gmail.com` on port `587` - your normal password will not work with 2FA enabled.

### Step 2 - put them in `deploy/.env`
```dotenv
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=you@gmail.com
SMTP_TO=soc-team@example.com,oncall@example.com   # comma-separated
```

### Step 3 - restart the worker
```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker
```

---

## 3. Turn it on in the UI

Once a channel's credentials are set, choose **what** to send:

- **Alerts by severity** - **Settings → Alert notifications → "Notify at or above"**.
  Every event whose severity is at or above your choice (Info / Low / Medium / High / Critical)
  is sent to all configured channels, with per rule+IP dedup so you aren't spammed. The worker
  picks up the new threshold within a minute - no restart.

- **Scheduled report delivery** - **Report → "Scheduled delivery"**.
  Pick `off / 24h / 3 days / 7 days / Custom`. On that cadence the worker builds the report for
  the elapsed period, prepends the AI summary if an LLM integration is configured, and sends it
  to Telegram/email. This is **independent** of the on-page "AI executive summary" schedule.

> If nothing arrives: confirm the channel env vars are set on the **worker** container, that the
> Telegram chat id is correct (a group id is negative), and check `docker compose -f
> deploy/docker-compose.yml logs worker` for `scheduled report delivery failed: …`.

---

## 4. Webhook export (external tools) - not Telegram

The **↗ Webhook** buttons on **Dashboard** and **Report** are a different feature: they POST
the events/alerts or the report as **JSON** to an **export webhook** you register under
**Integrations** (category *Export*). Use it to feed a SIEM, n8n, Zapier, or a custom endpoint.
It is machine-to-machine JSON, **not** a formatted Telegram/email message - to reach Telegram
or email, use the alert threshold and scheduled delivery described above.
