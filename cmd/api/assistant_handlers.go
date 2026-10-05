package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/assistant"
	"deuswatch/internal/auth"
	"deuswatch/internal/detect/sigma"
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
		// A memory instruction is handled here and answered without the model, for the same reason
		// commands are: it comes from the operator's own sentence, the confirmation must say exactly
		// what was stored, and a model paraphrasing "I'll remember that" while nothing was written
		// is the worst possible outcome for a feature whose whole value is being trusted.
		if mem := assistant.ParseMemory(req.Message); u != nil && u.ID != "" && (mem.Remember != "" || mem.Forget != "") {
			var reply string
			switch {
			case mem.Forget != "":
				n, ferr := st.ForgetMatching(r.Context(), u.ID, mem.Forget)
				switch {
				case ferr != nil:
					reply = "I could not reach the memory store, so nothing was forgotten."
				case n == 0:
					reply = fmt.Sprintf("I had nothing remembered about %q, so there was nothing to forget.", mem.Forget)
				default:
					reply = fmt.Sprintf("Forgotten: %d note(s) about %q.", n, mem.Forget)
				}
			default:
				ok, aerr := st.AddMemory(r.Context(), u.ID, mem.Remember)
				switch {
				case aerr != nil:
					reply = "I could not reach the memory store, so that is not saved."
				case !ok:
					reply = fmt.Sprintf("My memory is full (%d notes). Ask me to forget something first, or clear it in the panel.", store.MaxMemories)
				default:
					// Quoted back verbatim: the operator has to be able to see what was stored, not
					// what the model thought they meant.
					reply = fmt.Sprintf("Noted, and I will keep this between sessions: %q", mem.Remember)
				}
			}
			recordChat(r.Context(), st, u, req.Message, reply, "")
			writeJSON(w, http.StatusOK, map[string]any{"reply": reply, "model": "deuswatch"})
			return
		}

		if p, isCmd := assistant.ParseProposal(req.Message); isCmd {
			recordChat(r.Context(), st, u, req.Message, p.Reply(), "")
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

		// Counts, not a rule list: rules.Store.List loads every rule's full YAML, hundreds of
		// kilobytes, which is not something to read on every chat message. A failed read leaves
		// this empty, and an empty block is honest: the model simply has nothing to claim.
		var ruleDigest string
		if d, derr := st.RulesDigest(r.Context()); derr == nil {
			ruleDigest = assistant.Rules(assistant.RuleStats{
				Total: d.Total, Enabled: d.Enabled, Builtin: d.Builtin,
				Custom: d.Custom, Aggregation: d.Aggregation,
				ByCategory: d.ByCategory, CustomNames: d.CustomNames,
				Truncated: d.Custom > len(d.CustomNames),
			})
		}

		// Whether a ban actually reaches a firewall mirrors enforcementHandler: recording a ban and
		// enforcing one are different states, and the assistant must never collapse them.
		enfStats := assistant.EnforcementStats{}
		if ed, ok := st.EnforcementDigestFor(r.Context()); ok {
			enfStats = assistant.EnforcementStats{
				Read: true, ActiveBlocks: ed.ActiveBlocks, ActiveCount: ed.ActiveCount,
				Pending: ed.Pending, Offenders: ed.Offenders,
			}
			live, _ := strconv.ParseBool(os.Getenv("RESPONSE_LIVE"))
			for _, t := range []string{"mikrotik", "crowdsec", "nftables_agent"} {
				if on, herr := integrations.HasEnabled(r.Context(), st.Pool(), t); herr == nil && on {
					enfStats.Backends = append(enfStats.Backends, t)
				}
			}
			enfStats.Enforcing = live && len(enfStats.Backends) > 0
		}
		enforcement := assistant.Enforcement(enfStats)

		// Any address the operator named is looked up directly. This is what makes a question about
		// an arbitrary IP answerable: the offender list is necessarily a slice, and on a busy
		// deployment the address being asked about is usually outside it.
		var remembered string
		if u != nil && u.ID != "" {
			if facts, merr := st.ListMemories(r.Context(), u.ID); merr == nil && len(facts) > 0 {
				lines := make([]string, 0, len(facts))
				for _, f := range facts {
					lines = append(lines, f.Fact)
				}
				remembered = assistant.Memories(lines)
			}
		}

		// A property of the deployment, not of any one address, so it is resolved once.
		mlActive := st.MLAnomalyActive(r.Context())

		var lookups strings.Builder
		for _, ip := range assistant.MentionedIPs(req.Message) {
			lookups.WriteString(addressReport(r.Context(), st, ip, mlActive, true))
		}
		// Addresses carried from earlier turns, otherwise a conversation about one IP loses its
		// subject the moment the operator stops retyping it. Behind a note, and with no live
		// reputation call: a carried address can come from the assistant's own turn, so it may not
		// exist, and a hallucinated IP must not spend an AbuseIPDB request.
		if carried := assistant.CarriedIPs(turnTexts(req.History), req.Message, 2); len(carried) > 0 {
			lookups.WriteString(assistant.CarriedNote)
			for _, ip := range carried {
				lookups.WriteString(addressReport(r.Context(), st, ip, mlActive, false))
			}
		}

		// The roster inherits the caller's RBAC, like every other capability here (ADR 0003
		// decision 2). Knowing which accounts hold admin is reconnaissance, and the Users page
		// requires manage_users for exactly that reason; the assistant must not be a way around it.
		accounts := assistant.Users(nil, false)
		if u != nil && u.Can(auth.PermManageUsers) {
			if list, uerr := st.UserRoster(r.Context()); uerr == nil {
				lines := make([]assistant.UserLine, 0, len(list))
				for _, ur := range list {
					lines = append(lines, assistant.UserLine{Username: ur.Username, Role: ur.Role, Disabled: ur.Disabled})
				}
				accounts = assistant.Users(lines, true)
			}
		}

		// File hashes are looked up only when the operator asked for a check, since a live
		// reputation call spends an API quota and a hash pasted in passing is not a request.
		if assistant.NeedsHashLookup(req.Message) {
			for _, h := range assistant.MentionedHashes(req.Message) {
				lookups.WriteString(assistant.HashReport(hashReportFor(r.Context(), st, h)))
			}
		}

		var howTo string
		if assistant.NeedsIntegrationsGuide(req.Message) {
			howTo = assistant.IntegrationsGuide()
		}
		if assistant.NeedsQuery(req.Message) {
			howTo += "\n" + assistant.SQLGuide()
		}
		if assistant.NeedsPrimer(req.Message) {
			// Conceptual questions answered from generic SIEM knowledge are close enough to sound
			// right and wrong where it counts, such as describing response as automatic when this
			// deployment gates every ban behind an approval.
			howTo += "\n" + assistant.Primer
		}
		draftingRule := assistant.NeedsRuleAuthoring(req.Message)
		if draftingRule {
			// Generic Sigma knowledge produces rules this evaluator rejects, so the supported
			// subset goes in rather than being left to the model's memory.
			howTo += "\n" + assistant.RuleAuthoringGuide
		}

		hours := req.Hours
		if hours <= 0 || hours > assistant.MaxWindowHours {
			hours = 24
		}
		// A window named in the message wins over the client's default: "apa yang terjadi minggu
		// lalu" has to actually look at last week, and resolving it here rather than asking the
		// model for a number keeps the arithmetic off the thing least able to do it. A wrong window
		// is invisible in the answer, which is what makes guessing it unacceptable.
		if h, ok := assistant.ParseWindow(req.Message); ok {
			hours = h
		}
		td := st.ThreatDigestFor(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour))
		threats := assistant.Threats(assistant.ThreatStats{
			Read: td.Read, Malicious: td.Malicious, Suspicious: td.Suspicious,
			RecentNames: td.RecentNames, WindowHours: hours,
		})

		od := st.OpsDigestFor(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour), time.Now())
		ops := assistant.Ops(assistant.OpsStats{
			TicketsByStatus: od.TicketsByStatus, TicketsOpenHigh: od.TicketsOpenHigh,
			FIMRead: od.FIMRead, FileChanges: od.FileChanges, TopFilePaths: od.TopFilePaths,
			VulnAgents: od.VulnAgents, VulnCritical: od.VulnCritical, VulnHigh: od.VulnHigh,
			VulnTot: od.VulnTot, WindowHours: hours,
		})

		rep, err := st.BuildReport(r.Context(), hours)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The baseline. Built only for questions about change, because it doubles the report
		// queries and most messages have no use for it. A failure here is not fatal: the answer
		// loses its comparison, which is better than losing the answer.
		var trend string
		if assistant.NeedsComparison(req.Message) {
			now := time.Now()
			span := time.Duration(hours) * time.Hour
			if prev, perr := st.BuildReportRange(r.Context(), now.Add(-2*span), now.Add(-span)); perr == nil {
				trend = assistant.Trend(asWindow(rep), asWindow(prev), hours)
			}
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
			HowTo:       howTo,
			Roster:      roster,
			Rules:       ruleDigest,
			UI:          assistant.UIMap,
			Ops:         ops,
			Enforcement: enforcement,
			Lookups:     lookups.String(),
			Accounts:    accounts,
			Remembered:  remembered,
			Threats:     threats,
			Trend:       trend,
			// Clamped: this lands in a prompt, and a client is free to send anything.
			LocalTime: truncate(strings.TrimSpace(req.LocalTime), 40),
		})

		ctx, cancel := context.WithTimeout(r.Context(), llm.Timeout())
		defer cancel()
		reply, err := analyzer.Chat(ctx, sys, req.History, req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		out := map[string]any{"reply": reply, "model": analyzer.Name()}
		// A generated query is validated, run and its rows returned for the UI to render. The
		// model never sees the result: it writes the question down as SQL, the operator reads the
		// answer. That keeps one slow model call instead of two, and it means a wrong number cannot
		// be narrated confidently, because the narration never gets the chance.
		if q, ok := assistant.ExtractSQL(reply); ok {
			if verr := assistant.ValidateQuery(q); verr != nil {
				out["query"] = map[string]any{"sql": q, "error": verr.Error()}
			} else if res, qerr := st.RunAssistantQuery(r.Context(), q, assistant.MaxQueryRows, assistant.QueryTimeoutSeconds); qerr != nil {
				out["query"] = map[string]any{"sql": q, "error": qerr.Error()}
			} else {
				out["query"] = map[string]any{
					"sql": q, "columns": res.Columns, "rows": res.Rows,
					"capped": res.Capped, "ms": res.Duration.Milliseconds(),
				}
			}
		}
		// A drafted rule is validated with the engine that will run it, BEFORE the operator is
		// offered a button. Anything that does not parse stays as text in the conversation: the
		// model can be told what was wrong and try again, but it never becomes something that
		// looks approved-and-ready when it would fail on save.
		if draftingRule {
			if y, ok := assistant.ExtractRuleYAML(reply); ok {
				if _, cerr := sigma.Classify([]byte(y)); cerr == nil {
					out["proposal"] = assistant.Proposal{
						Kind:   assistant.KindRule,
						Target: assistant.RuleTitle(y),
						YAML:   y,
					}
				} else {
					out["reply"] = reply + "\n\n(That draft does not parse: " + cerr.Error() +
						". Tell me and I will fix it.)"
				}
			}
		}
		recordChat(r.Context(), st, u, req.Message, asString(out["reply"]), replayContext(out))
		writeJSON(w, http.StatusOK, out)
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
			// The catalogue, so the UI can offer a starting point instead of a blank box. Every
			// entry already carries the safety rules a custom persona would have to reproduce.
			"personas":        assistant.Personas(),
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

// asWindow flattens a report into the shape the comparison works on, keeping internal/assistant
// free of a dependency on the report package.
func asWindow(r report.Report) assistant.Window {
	conv := func(in []report.Count) []assistant.Count {
		out := make([]assistant.Count, 0, len(in))
		for _, c := range in {
			out = append(out, assistant.Count{Label: c.Label, Count: int64(c.Count)})
		}
		return out
	}
	return assistant.Window{
		Events: r.TotalEvents, Alerts: r.TotalAlerts,
		BySeverity: conv(r.BySeverity), TopSourceIPs: conv(r.TopSourceIPs),
		TopRules: conv(r.TopRules), TopAgents: conv(r.TopAgents),
	}
}

// fmtTimePtr renders an optional timestamp for the prompt, empty when absent.
func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// assistantHistoryHandler serves and clears one operator's stored conversation.
//
// Scoped to the caller's own user id, never a parameter. The transcript holds security data and
// whatever they typed, so there is no legitimate reason for one account to read another's, and the
// cheapest way to guarantee that is to make it unaskable.
func assistantHistoryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFrom(r.Context())
		if !ok || u.ID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			msgs, err := st.LoadChat(r.Context(), u.ID, store.MaxStoredMessages)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if msgs == nil {
				msgs = []store.ChatMessage{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
		case http.MethodDelete:
			if err := st.ClearChat(r.Context(), u.ID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// recordChat stores the exchange. Best-effort by design: losing a transcript line is an annoyance,
// losing the answer the operator is waiting for is not, so a failure here is logged and swallowed.
// replyContext is what should be replayed to the model later; empty means "same as reply".
func recordChat(ctx context.Context, st *store.Store, u *auth.User, question, reply, replyContext string) {
	if u == nil || u.ID == "" {
		return
	}
	err := st.AppendChat(ctx, u.ID,
		store.ChatMessage{Role: "user", Content: question},
		store.ChatMessage{Role: "assistant", Content: reply, Context: replyContext},
	)
	if err != nil {
		log.Printf("api: assistant history not saved for %s: %v", u.Username, err)
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// replayContext rebuilds what the client would have sent back as history for this turn, so a
// reloaded conversation carries the same rows the live one did. Without it, reopening the panel
// silently drops the query result and the follow-up question has nothing to reason over.
func replayContext(out map[string]any) string {
	reply := asString(out["reply"])
	q, ok := out["query"].(map[string]any)
	if !ok {
		return ""
	}
	rows, _ := q["rows"].([][]string)
	if len(rows) == 0 {
		return ""
	}
	cols, _ := q["columns"].([]string)
	var b strings.Builder
	b.WriteString(reply)
	fmt.Fprintf(&b, "\n\n[Query result, %d row(s)]\n%s\n", len(rows), strings.Join(cols, " | "))
	for _, r := range rows {
		b.WriteString(strings.Join(r, " | "))
		b.WriteString("\n")
	}
	return b.String()
}

// assistantMessageHandler deletes one stored turn, or that turn and everything after it.
//
// `?after=1` is what an edit is built from: the client rewinds to the message being edited, drops
// it and the rest, then asks again. Done server-side in one statement so a browser that dies
// halfway cannot leave an answer stranded under a question that was rewritten.
func assistantMessageHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		u, ok := auth.UserFrom(r.Context())
		if !ok || u.ID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "bad message id", http.StatusBadRequest)
			return
		}
		after, _ := strconv.ParseBool(r.URL.Query().Get("after"))
		// The user id in the WHERE clause, not just here: an id from another account must match no
		// rows rather than be refused, so nothing can be learned by probing.
		if err := st.DeleteChatMessage(r.Context(), u.ID, id, after); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// assistantMemoryHandler lists and deletes the caller's remembered facts.
//
// Listing is not a convenience. These lines are prepended to every answer the assistant gives, so
// an operator who cannot see them cannot tell why it is behaving the way it is, and cannot take
// something back. Memory that is invisible is memory that has to be trusted blindly, which is not a
// thing to ask for inside a security product.
func assistantMemoryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFrom(r.Context())
		if !ok || u.ID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			facts, err := st.ListMemories(r.Context(), u.ID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if facts == nil {
				facts = []store.Memory{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"memories": facts, "max": store.MaxMemories})
		case http.MethodPost:
			var body struct {
				Fact string `json:"fact"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			added, err := st.AddMemory(r.Context(), u.ID, body.Fact)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !added {
				http.Error(w, fmt.Sprintf("memory is full (%d notes)", store.MaxMemories), http.StatusConflict)
				return
			}
			writeJSON(w, http.StatusCreated, map[string]string{"status": "saved"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// assistantMemoryItemHandler deletes one remembered fact.
func assistantMemoryItemHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFrom(r.Context())
		if !ok || u.ID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "bad memory id", http.StatusBadRequest)
			return
		}
		if err := st.ForgetMemory(r.Context(), u.ID, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "forgotten"})
	}
}
