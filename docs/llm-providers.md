# AI / LLM providers - triage and report

DeusWatch uses an LLM for two independent tasks:

- **Triage** - a per-alert verdict (`benign` / `suspicious` / `malicious` / `needs_review`)
  plus a one-line reason, stored on the alert and shown in the UI.
- **Report** - the AI executive summary of the security report (on-demand from the Report
  page, or on a schedule).

You can point **one** model at both, or use **two different models** (for example a small,
free local model for triage and a stronger hosted model for the report). This is controlled by
the **"Use for"** dropdown on the LLM integration.

Any provider that speaks the **OpenAI Chat Completions** API works through a single driver, plus
a native **Anthropic Claude** driver. There is no Python and no per-provider SDK - it is one Go
HTTP client.

---

## 1. Add the integration

**Integrations -> LLM analyzer (AI) -> pick it**, then fill the fields:

| Field | Meaning |
|---|---|
| **Provider** | `ollama` (local), `openai-compatible` (OpenAI / Gemini / Groq / OpenRouter / vLLM / LM Studio), or `anthropic` (Claude). |
| **Use for** | `both` (default), `triage`, or `report`. Decides which task this model powers. |
| **Base URL** | The OpenAI-compatible endpoint (see table below). Leave blank for `anthropic`. |
| **Model** | The model name/tag, e.g. `llama3.1`, `gpt-4o-mini`, `gemini-2.5-flash`, `claude-opus-4-8`. |
| **API key** | Not needed for local Ollama; required for hosted providers and Anthropic. |

Secrets are encrypted at rest. Changing an LLM integration takes effect after the **worker**
restarts (`docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker`).

---

## 2. Base URL per provider

| Provider | Provider field | Base URL | Example model | API key |
|---|---|---|---|---|
| **Ollama** (local, free) | `ollama` | `http://host.docker.internal:11434/v1` (or blank) | `llama3.1`, `qwen2.5`, `mistral` | none |
| **OpenAI** | `openai-compatible` | `https://api.openai.com/v1` | `gpt-4o-mini`, `gpt-4o` | required |
| **Google Gemini** | `openai-compatible` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.5-flash`, `gemini-2.0-flash` | required (Google AI Studio) |
| **Groq** | `openai-compatible` | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | required |
| **OpenRouter** | `openai-compatible` | `https://openrouter.ai/api/v1` | any listed model | required |
| **LM Studio / vLLM / LocalAI** | `openai-compatible` | `http://<host>:<port>/v1` | model you serve | usually none |
| **Anthropic Claude** | `anthropic` | (blank) | `claude-opus-4-8`, `claude-haiku-4-5-20251001` | required |

Gemini works because Google exposes an **OpenAI-compatible** endpoint; DeusWatch calls
`<base_url>/chat/completions` on it. There is no need for Google's native API.

---

## 3. Turn on per-alert triage

Triage runs **only when you enable it**, because with a paid API it would call the model on
every alert:

1. Configure an LLM integration set to **triage** or **both** (or the env vars below).
2. Set `LLM_PER_ALERT=1` in `deploy/.env`.
3. Restart the worker.

The report summary needs **no** flag: as long as a model is set to **report** or **both**, the
Report page's "Generate summary" and the scheduled delivery use it.

> The offline **heuristic** analyzer (`LLM_ENABLED=1`, no model) can produce triage verdicts
> from CTI + severity signals, but it **cannot** write report summaries - those need a
> generative model.

---

## 4. Environment fallback (no UI)

If no LLM integration is configured, the worker/API fall back to env, in order:

```dotenv
# 1) Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-8

# 2) any OpenAI-compatible endpoint (Ollama/OpenAI/Gemini/Groq/...)
LLM_PROVIDER=openai-compatible
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_API_KEY=...
LLM_MODEL=gemini-2.5-flash

# 3) offline heuristic (triage verdicts only, no summaries)
LLM_ENABLED=1

# enable per-alert triage (off by default)
LLM_PER_ALERT=1
```

The env path uses one model for both tasks; use the **Integrations** UI when you want separate
triage and report models.

---

## 5. Notes for production

- **Cost**: with a paid API, keep `LLM_PER_ALERT` off unless alert volume is controlled, or
  point triage at a free local Ollama model and let a hosted model handle only reports.
- **JSON discipline**: triage asks the model for strict JSON
  (`{"verdict":...,"summary":...}`). Large models (gpt-4o, gemini-flash, Claude) follow it
  reliably; very small local models sometimes do not and fall back to `needs_review`.
- **Throughput**: triage processes alerts in batches. A slow local model under heavy alert
  volume will lag behind rather than drop alerts.

See also: [Connect a local LLM (Ollama)](llm-ollama.md).
