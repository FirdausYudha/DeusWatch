package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ollamaStub(t *testing.T, ps, show string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/api/ps":
			body = ps
		case "/api/show":
			body = show
		default:
			http.NotFound(w, r)
			return
		}
		if body == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1" // callers configure the OpenAI-compatible URL
}

// The loaded model is authoritative: it is the number left after the server default, any baked
// num_ctx and the architecture maximum have been resolved against each other.
func TestDetectWindowPrefersTheLoadedModel(t *testing.T) {
	url := ollamaStub(t,
		`{"models":[{"name":"llama3.1:8b","model":"llama3.1:8b","context_length":16384}]}`,
		`{"parameters":"num_ctx  8192\nstop \"<|eot_id|>\"","model_info":{"llama.context_length":131072}}`)

	w, err := DetectWindow(context.Background(), url, "llama3.1:8b")
	if err != nil {
		t.Fatalf("DetectWindow: %v", err)
	}
	if w.Tokens != 16384 || w.Source != "loaded" {
		t.Errorf("got %d from %q, want 16384 from \"loaded\": a baked num_ctx must not win over "+
			"what the running model reports", w.Tokens, w.Source)
	}
	if w.TrainedMax != 131072 {
		t.Errorf("trained max = %d, want 131072", w.TrainedMax)
	}
}

// Nothing loaded yet, which is the state right after a restart. The baked parameter is the only
// evidence available and is better than reporting nothing.
func TestDetectWindowFallsBackToBakedNumCtx(t *testing.T) {
	url := ollamaStub(t, `{"models":[]}`,
		`{"parameters":"num_ctx  8192","model_info":{"llama.context_length":131072}}`)

	w, _ := DetectWindow(context.Background(), url, "deuswatch-llama")
	if w.Tokens != 8192 || w.Source != "num_ctx" {
		t.Errorf("got %d from %q, want 8192 from \"num_ctx\"", w.Tokens, w.Source)
	}
}

// A model loaded under a different name must not lend its window to the one we asked about.
func TestDetectWindowIgnoresAnotherLoadedModel(t *testing.T) {
	url := ollamaStub(t,
		`{"models":[{"name":"gemma4:e4b","model":"gemma4:e4b","context_length":32768}]}`,
		`{"parameters":"","model_info":{"llama.context_length":131072}}`)

	w, _ := DetectWindow(context.Background(), url, "llama3.1:8b")
	if w.Tokens != 0 {
		t.Errorf("got %d from a different model's entry, want 0", w.Tokens)
	}
}

// The most important negative case. A hosted provider has no /api/ps or /api/show, and inventing a
// window for it would warn an operator about a setting that does not exist on their service.
func TestDetectWindowStaysSilentOnNonOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	w, err := DetectWindow(context.Background(), srv.URL+"/v1", "gpt-4o")
	if err != nil {
		t.Fatalf("a non-Ollama endpoint is not an error, it is just unknown: %v", err)
	}
	if w.Tokens != 0 || w.Source != "" {
		t.Errorf("invented a window for a non-Ollama provider: %+v", w)
	}
}

func TestDetectWindowHandlesAnUnreachableHost(t *testing.T) {
	w, err := DetectWindow(context.Background(), "http://127.0.0.1:1/v1", "llama3.1:8b")
	if err != nil || w.Tokens != 0 {
		t.Errorf("an unreachable host should be silent, got %+v err %v", w, err)
	}
}

func TestOllamaHostStripsTheOpenAISuffix(t *testing.T) {
	for in, want := range map[string]string{
		"http://ollama:11434/v1":  "http://ollama:11434",
		"http://ollama:11434/v1/": "http://ollama:11434",
		"http://ollama:11434":     "http://ollama:11434",
		" http://h:1/v1 ":         "http://h:1",
	} {
		if got := ollamaHost(in); got != want {
			t.Errorf("ollamaHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// Fits decides whether anyone is told anything, so its silence matters as much as its warning.
func TestFits(t *testing.T) {
	// Unknown window: never warn. A false alarm sends someone to fix a setting that was right.
	if ok, _ := (Window{}).Fits(5000); !ok {
		t.Error("an unknown window must not warn")
	}
	// Nothing measured yet.
	if ok, _ := (Window{Tokens: 4096}).Fits(0); !ok {
		t.Error("an unmeasured prompt must not warn")
	}
	// Comfortable.
	if ok, _ := (Window{Tokens: 16384}).Fits(4500); !ok {
		t.Error("4500 tokens in a 16384 window must not warn")
	}
	// The real case: our prompt against Ollama's default.
	ok, detail := Window{Tokens: 4096, TrainedMax: 131072}.Fits(4472)
	if ok {
		t.Fatal("4472 tokens in a 4096 window must warn")
	}
	for _, want := range []string{"4472", "4096", "persona", "131072", "OLLAMA_CONTEXT_LENGTH", "Clearing the conversation"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the warning should mention %q so it can be acted on:\n%s", want, detail)
		}
	}
	// Three quarters is the line: the rest of the window belongs to the reply.
	if ok, _ := (Window{Tokens: 8192}).Fits(6500); ok {
		t.Error("a request claiming most of the window leaves no room for the reply")
	}
	// The measurements from a live 16384 server: comfortable on a fresh thread, and still
	// comfortable a few turns in. Neither should warn, or the check cries wolf on a healthy setup.
	for _, tok := range []int{5137, 6331} {
		if ok, d := (Window{Tokens: 16384}).Fits(tok); !ok {
			t.Errorf("%d tokens in a 16384 window must not warn: %s", tok, d)
		}
	}
	// The same conversation against the window it had before the fix.
	if ok, _ := (Window{Tokens: 8192}).Fits(6331); ok {
		t.Error("6331 tokens in an 8192 window must warn: that is the state the operator was in")
	}
}

// json numbers arrive as float64 through an any-typed map.
func TestToInt(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(`{"n":131072}`), &m); err != nil {
		t.Fatal(err)
	}
	if n, ok := toInt(m["n"]); !ok || n != 131072 {
		t.Errorf("toInt = %d, %v", n, ok)
	}
	if _, ok := toInt("131072"); ok {
		t.Error("a string is not a context length")
	}
}
