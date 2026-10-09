package llm

// Context-window detection for Ollama.
//
// This closes the one failure in the assistant that never produces an error anywhere. Ollama
// allocates a context window and silently DROPS THE OLDEST TOKENS when a prompt exceeds it. The
// system prompt is ordered stable-first for cache reuse, so the oldest tokens are the persona: the
// assistant keeps answering questions about the data correctly while its character disappears.
// Nothing is logged, nothing 500s, and the only symptom is a personality that will not stick.
//
// It cost two rounds of guessing on a live deployment before anyone thought to read `n_ctx` out of
// the container logs. A number the product can fetch itself should not be something an operator has
// to know to go looking for.
//
// Ollama-specific on purpose. Hosted providers advertise their window in documentation and do not
// truncate silently; a self-hosted runtime with a 4096 default does.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Window is what the runtime will actually accept, and where the number came from.
type Window struct {
	// Tokens is the effective context window, 0 when it could not be determined.
	Tokens int
	// Source names how Tokens was obtained, for an operator who wants to verify it:
	// "loaded" (the running model, authoritative), "num_ctx" (baked into the model), or "" .
	Source string
	// TrainedMax is the architecture's maximum, which is NOT the runtime window. Reported because
	// a large number here next to a small Tokens is the signature of a server default capping a
	// model that could do much more.
	TrainedMax int
}

// ollamaHost turns an OpenAI-compatible base URL into the Ollama native API root. Ollama serves
// the OpenAI shim under /v1 and its own API at the root, so the suffix is simply dropped.
func ollamaHost(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return strings.TrimSuffix(u, "/v1")
}

var reNumCtx = regexp.MustCompile(`(?m)^\s*num_ctx\s+(\d+)`)

// DetectWindow asks an Ollama server what context window the named model will run with.
//
// Two sources, in order of authority. /api/ps reports the window of a model that is currently
// loaded, which is the real number after the server default, any baked num_ctx and the
// architecture maximum have all been resolved against each other. /api/show reports a num_ctx
// baked into the model, which is what a derived model carries and what beats the server default.
//
// A model that has never been used is not in /api/ps, so the first answer after a restart may come
// from the weaker source or not at all. That is honest: Source says which.
//
// Any failure returns a zero Window and a nil error when the server simply is not Ollama. Callers
// treat an empty Window as "unknown" and must not warn on it: a false alarm about a truncated
// persona is worse than no alarm, because it sends someone to fix a setting that was already right.
func DetectWindow(ctx context.Context, baseURL, model string) (Window, error) {
	host := ollamaHost(baseURL)
	if host == "" || model == "" {
		return Window{}, nil
	}
	hc := &http.Client{Timeout: 5 * time.Second}

	var w Window

	// Authoritative: what the loaded model is actually running with.
	var ps struct {
		Models []struct {
			Name          string `json:"name"`
			Model         string `json:"model"`
			ContextLength int    `json:"context_length"`
		} `json:"models"`
	}
	if err := getJSON(ctx, hc, host+"/api/ps", nil, &ps); err == nil {
		for _, m := range ps.Models {
			if (m.Name == model || m.Model == model) && m.ContextLength > 0 {
				w.Tokens, w.Source = m.ContextLength, "loaded"
				break
			}
		}
	}

	// Either the trained maximum, or the baked num_ctx when nothing is loaded yet.
	var show struct {
		Parameters string         `json:"parameters"`
		ModelInfo  map[string]any `json:"model_info"`
	}
	body, _ := json.Marshal(map[string]string{"model": model})
	if err := getJSON(ctx, hc, host+"/api/show", body, &show); err != nil {
		return w, nil // not an Ollama server, or it does not know this model
	}
	for k, v := range show.ModelInfo {
		if strings.HasSuffix(k, ".context_length") {
			if n, ok := toInt(v); ok {
				w.TrainedMax = n
			}
			break
		}
	}
	if w.Tokens == 0 {
		if m := reNumCtx.FindStringSubmatch(show.Parameters); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				w.Tokens, w.Source = n, "num_ctx"
			}
		}
	}
	return w, nil
}

// Fits reports whether a request of requestTokens (system prompt plus conversation plus the
// operator's message) leaves usable room for the reply, and says plainly what to do when it does
// not.
//
// Three quarters is the line. The last quarter is the reply, and the margin matters because the
// conversation grows while the window does not: a live server reported 5137 tokens on a fresh
// thread and 6331 a few turns later with an identical system prompt. Warning only once the window
// is already full would be warning after the persona had gone.
func (w Window) Fits(requestTokens int) (ok bool, detail string) {
	if w.Tokens == 0 || requestTokens <= 0 {
		return true, "" // unknown: say nothing rather than warn wrongly
	}
	budget := w.Tokens * 3 / 4
	if requestTokens <= budget {
		return true, ""
	}
	d := fmt.Sprintf("This conversation is about %d tokens and this model runs with a %d-token "+
		"context, so Ollama will drop the oldest tokens to make it fit. The persona sits first in "+
		"the prompt, so it goes first: answers stay correct about the data while the character "+
		"disappears, and nothing is logged. Clearing the conversation frees the room the history "+
		"is taking.", requestTokens, w.Tokens)
	if w.TrainedMax > w.Tokens {
		d += fmt.Sprintf(" This model supports up to %d, so the limit is configuration, not the "+
			"model. Recreate the Ollama container with OLLAMA_CONTEXT_LENGTH=16384, and point "+
			"Model at a base model: a num_ctx baked into a derived model beats the server default.",
			w.TrainedMax)
	}
	return false, d
}

func getJSON(ctx context.Context, hc *http.Client, url string, body []byte, out any) error {
	method, rdr := http.MethodGet, (*bytes.Reader)(nil)
	if body != nil {
		method, rdr = http.MethodPost, bytes.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("llm: %s returned HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// toInt accepts the number shapes encoding/json produces for an untyped field.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
}
