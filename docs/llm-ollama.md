# Connect a local LLM (Ollama) for AI report summaries

DeusWatch can turn the security report into a short AI executive summary. It works with any
**OpenAI-compatible** endpoint - the easiest free/offline option is **Ollama**. The LLM is used
for **reports** (on-demand or scheduled), not per alert, so there is no per-alert cost.

## 1. Run Ollama and pull a model

On the host (Docker example):

```bash
docker run -d --name ollama -p 11434:11434 ollama/ollama
docker exec ollama ollama pull llama3        # or a smaller/faster model, see below
docker exec ollama ollama list               # note the exact tag, e.g. llama3:latest
```

## 2. Connect it in DeusWatch

**Integrations -> LLM analyzer (AI triage) -> Enable**, then fill:

| Field | Value |
|---|---|
| Provider | `ollama` |
| Base URL | `http://host.docker.internal:11434/v1` (note the `/v1`) |
| Model | the exact tag from `ollama list`, e.g. `llama3:latest` |
| API key | leave blank (not needed for local Ollama) |

The worker reads the LLM config **at start**, so recreate it after saving:

```bash
docker compose -f deploy/docker-compose.yml up -d worker
```

> `host.docker.internal` lets a container reach a service on the host. DeusWatch adds
> `extra_hosts: host.docker.internal:host-gateway` to the worker so this resolves on Linux -
> make sure your `deploy/docker-compose.yml` has it (pull the latest) and use `up -d`
> (which recreates), not `restart` (which does not apply compose changes).

## 3. Verify the connection

**Config-level (worker log):**

```bash
docker compose -f deploy/docker-compose.yml logs worker | grep -i "LLM analyzer"
```
- `LLM analyzer ready for reports (openai-compat(llama3:latest))` -> configured.
- `LLM analyzer disabled ...` -> not picked up (re-check step 2, then recreate the worker).

**Real test:** open **Report -> AI Executive Summary -> Generate now**. A summary appears when
it truly reached the model. Any error is shown in full so you can act on it (see below).

## Troubleshooting

| Error you see | Cause | Fix |
|---|---|---|
| `dial tcp: lookup host.docker.internal ... no such host` | The worker can't resolve `host.docker.internal` (missing `extra_hosts`, or the worker wasn't recreated). | Pull latest, then `docker compose ... up -d worker` (not `restart`). Verify: `docker inspect deuswatch-worker-1 --format '{{.HostConfig.ExtraHosts}}'` shows `[host.docker.internal:host-gateway]`. |
| `504 Gateway Time-out` (nginx HTML) | A **reverse proxy** sits between the worker and Ollama (via the host) and times out. | **Bypass it - connect containers directly** (see below). |
| `connection refused` | Wrong port / Base URL. | Base URL must be `http://<host>:11434/v1` (include `/v1`); confirm Ollama is published on `11434`. |
| `HTTP 404` / `provider error: model ... not found` | Model name doesn't match. | Use the exact tag from `docker exec ollama ollama list` (e.g. `llama3:latest`). |
| Times out after ~120s (no nginx page) | The model is too slow on CPU for a large report prompt (client timeout is 120s). | Use a smaller model, enable GPU, or pick a shorter report window. |

### Bypass a reverse proxy (fixes the nginx `504`)

If your Ollama is a container and traffic via the host goes through a reverse proxy, talk to
the Ollama container **directly** on the Docker network instead:

```bash
# 1. find the DeusWatch compose network (usually deuswatch_default)
docker network ls | grep deuswatch

# 2. attach the ollama container to it
docker network connect deuswatch_default ollama
```

Then set **Base URL** to the container name and recreate the worker:

```
http://ollama:11434/v1
```
```bash
docker compose -f deploy/docker-compose.yml up -d worker
```

This is a direct container-to-container route (no host, no proxy), so the `504` disappears.

> The `docker network connect` persists until the `ollama` container is recreated. If you
> `docker rm` and re-create Ollama, re-run the connect (or add Ollama as a service in
> `docker-compose.yml` to make it permanent).

## Choosing a model (speed vs quality)

On CPU, large models are slow and may hit the 120s timeout on big reports. Faster options:

```bash
docker exec ollama ollama pull llama3.2:3b     # small, fast
docker exec ollama ollama pull qwen2.5:3b      # small, fast
```

Set the **Model** field to the pulled tag. Larger models (llama3 8B and up) give better prose
but need more time or a GPU. You can also narrow the report window (e.g. 24h) to shorten the
prompt.
