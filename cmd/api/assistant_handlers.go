package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/assistant"
	"deuswatch/internal/auth"
	"deuswatch/internal/integrations"
	"deuswatch/internal/llm"
	"deuswatch/internal/report"
	"deuswatch/internal/secret"
	"deuswatch/internal/store"
)

// ── budget ──────────────────────────────────────────────────────────────────
//
// Every message resends the whole conversation plus the security context, so an idle browser tab
// with a loop in it, or one impatient operator, can run up real cost on a metered provider. The
// cap is per user and deliberately crude: this is a spend guard, not a fairness scheduler.

const (
	assistantDailyMessages = 200
	assistantMinInterval   = 2 * time.Second
)

type assistantBudget struct {
	mu   sync.Mutex
	seen map[string]*budgetEntry
}

type budgetEntry struct {
	day   string // YYYY-MM-DD in UTC; a new day resets the count
	count int
	last  time.Time
}

func newAssistantBudget() *assistantBudget {
	return &assistantBudget{seen: map[string]*budgetEntry{}}
}

// allow reports whether this user may send now, and why not when they may not.
func (b *assistantBudget) allow(user string) (bool, string) {
	now := time.Now()
	day := now.UTC().Format("2006-01-02")
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.seen[user]
	if e == nil || e.day != day {
		e = &budgetEntry{day: day}
		b.seen[user] = e
	}
	if !e.last.IsZero() && now.Sub(e.last) < assistantMinInterval {
		return false, "slow down a moment, one message every couple of seconds"
	}
	if e.count >= assistantDailyMessages {
		return false, fmt.Sprintf("daily assistant limit reached (%d messages); it resets at 00:00 UTC", assistantDailyMessages)
	}
	e.count++
	e.last = now
	return true, ""
}

// ── provider resolution ─────────────────────────────────────────────────────

// resolveAssistantAnalyzer returns the model configured for the assistant, or false when none is.
//
// Unlike the report path this does NOT fall back to AnalyzerFromEnv or to an LLM integration set
// to "both": the assistant is opt-in, so an operator who never asked for it must never find a chat
// panel after an upgrade. Choosing purpose="assistant" is the only way to turn it on.
func resolveAssistantAnalyzer(ctx context.Context, st *store.Store) (llm.Analyzer, bool) {
	cipher, _, err := secret.FromEnv()
	if err != nil {
		return nil, false
	}
	rows, rerr := integrations.NewStore(st.Pool(), cipher).Resolve(ctx, "llm")
	if rerr != nil {
		return nil, false
	}
	for _, row := range rows {
		c := row.Config
		if !integrations.LLMPurposeMatches(c["purpose"], integrations.PurposeAssistant) {
			continue
		}
		if a, aerr := llm.NewAnalyzer(c["provider"], c["base_url"], c["api_key"], c["model"]); aerr == nil {
			return a, true
		}
	}
	return nil, false
}

// assistantStatusHandler tells the UI whether to render the assistant at all, so a deployment that
// has not enabled it shows no dead button.
func assistantStatusHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := resolveAssistantAnalyzer(r.Context(), st)
		out := map[string]any{"enabled": ok, "model": ""}
		if ok {
			out["model"] = a.Name()
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type assistantChatRequest struct {
	Message string         `json:"message"`
	History []llm.ChatTurn `json:"history"`
	Hours   int            `json:"hours"`
	// LocalTime is the operator's wall clock, sent by the browser. The server's clock is UTC in a
	// container and would have the assistant wishing someone good morning at 2am their time.
	LocalTime string `json:"local_time"`
}

// assistantChatHandler answers one message with the current security posture in context.
//
// Read-only by construction: it has no tools and no write path, so the worst a hostile string in
// the ingested data can achieve is a misleading sentence, not a change to the system.
func assistantChatHandler(st *store.Store, budget *assistantBudget) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		username := "unknown"
		if u != nil {
			username = u.Username
		}
		if ok, why := budget.allow(username); !ok {
			http.Error(w, why, http.StatusTooManyRequests)
			return
		}

		var req assistantChatRequest
		// 64 KiB: a conversation, never an upload. Anything larger is a client bug or an attempt
		// to push the bill up by stuffing the prompt.
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.Message = strings.TrimSpace(req.Message)
		if req.Message == "" {
			http.Error(w, "message is empty", http.StatusBadRequest)
			return
		}
		if len(req.History) > assistant.MaxHistoryTurns {
			req.History = req.History[len(req.History)-assistant.MaxHistoryTurns:]
		}

		// A recognised command short-circuits the model entirely (ADR 0003 phase 2). Three reasons,
		// in order of importance: the proposal then provably comes from the operator's own sentence
		// and never from text an attacker wrote into a log; the target cannot be hallucinated; and
		// a model asked to narrate an action it is not performing tends to either claim it did it
		// or deny it can, both of which are wrong. The reply beside the card is written, not
		// generated. Confirming the card calls the ordinary ban/whitelist endpoint under the
		// operator's own session, so this handler still has no write path of its own.
		if p, isCmd := assistant.ParseProposal(req.Message); isCmd {
			writeJSON(w, http.StatusOK, map[string]any{"reply": p.Reply(), "proposal": p, "model": "deuswatch"})
			return
		}

		analyzer, ok := resolveAssistantAnalyzer(r.Context(), st)
		if !ok {
			http.Error(w, "the assistant is not enabled: add an LLM integration with \"Use for\" set to assistant", http.StatusBadRequest)
			return
		}

		// Always loaded: the roster is small and its absence is what made the model invent hosts.
		// A failure to read it is not fatal, but it must not silently look like an empty fleet, so
		// the model is told the list is unavailable rather than being handed nothing.
		roster := "ENROLLED ENDPOINTS: could not be read just now. Say so if asked about agents; do not guess names.\n"
		if rows, rerr := st.AgentRoster(r.Context()); rerr == nil {
			lines := make([]assistant.AgentLine, 0, len(rows))
			for _, a := range rows {
				lines = append(lines, assistant.AgentLine{
					Name: a.Name, OS: a.OS, Status: a.Status,
					Version: a.Version, Detail: a.Detail, Revoked: a.Revoked,
				})
			}
			roster = assistant.Roster(lines)
		}

		var howTo string
		if assistant.NeedsIntegrationsGuide(req.Message) {
			howTo = assistant.IntegrationsGuide()
		}

		hours := req.Hours
		if hours <= 0 || hours > 24*30 {
			hours = 24
		}
		rep, err := st.BuildReport(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// A worker that stopped makes every figure above stale, so the model is told before it is
		// asked anything. Failing to read it is not fatal: an assistant that answers without the
		// health line is better than one that refuses to talk.
		health, herr := st.ServiceHealthFor(r.Context(), store.ServiceWorker, store.WorkerStaleAfter)
		workerAlive := true
		workerDetail := ""
		if herr == nil {
			workerAlive = health.Alive
			// "never reported" and "reported then stopped" need different advice from the operator,
			// so the distinction is passed through rather than flattened into "down".
			switch {
			case health.Alive:
			case !health.EverSeen:
				workerDetail = "it has never reported at all, so it was probably never started"
			default:
				workerDetail = fmt.Sprintf("last heartbeat %.0f seconds ago", health.Age)
			}
		}

		sys := assistant.SystemPrompt(assistantPersona(r.Context(), st), assistant.Context{
			WindowHours:  hours,
			Data:         report.SummaryPrompt(rep),
			WorkerAlive:  workerAlive,
			WorkerDetail: workerDetail,
			Operator:     username,
			// The catalogue rides along only for "how do I set up X" messages. Always sending it
			// would roughly double the prompt and risk silent truncation at Ollama's default
			// context size, for a guide most messages have no use for.
			HowTo:  howTo,
			Roster: roster,
			// Clamped: this lands in a prompt, and a client is free to send anything.
			LocalTime: truncate(strings.TrimSpace(req.LocalTime), 40),
		})

		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		reply, err := analyzer.Chat(ctx, sys, req.History, req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reply": reply, "model": analyzer.Name()})
	}
}

// assistantPersona resolves the persona, "" meaning the built-in default.
//
// Precedence is UI over environment over built-in. The env var predates the UI field and stays as
// the deployment-level default for IaC-managed installs; clearing the field in the UI therefore
// falls back to it rather than to the built-in, which is what "I set this in my compose file"
// should mean. A read failure is not fatal: answering with the default persona beats refusing to
// talk because one settings row could not be read.
func assistantPersona(ctx context.Context, st *store.Store) string {
	if cfg, err := st.LoadAssistantConfig(ctx); err == nil {
		if p := strings.TrimSpace(cfg.Persona); p != "" {
			return p
		}
	}
	return strings.TrimSpace(os.Getenv("ASSISTANT_PERSONA"))
}

// assistantConfigGetHandler returns the saved persona plus the built-in default, so the UI can show
// what it falls back to and offer "restore the default" without hardcoding a copy of the text.
func assistantConfigGetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := st.LoadAssistantConfig(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"persona":         cfg.Persona,
			"default_persona": assistant.DefaultPersona,
			"env_persona_set": strings.TrimSpace(os.Getenv("ASSISTANT_PERSONA")) != "",
			"max_len":         store.MaxPersonaLen,
		})
	}
}

func assistantConfigSetHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg store.AssistantConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := st.SaveAssistantConfig(r.Context(), cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out, _ := st.LoadAssistantConfig(r.Context())
		writeJSON(w, http.StatusOK, out)
	}
}

// truncate caps a client-supplied string before it reaches the prompt.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
