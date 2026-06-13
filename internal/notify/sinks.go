package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"deuswatch/internal/ingest"
)

func newHTTPClient() *http.Client { return &http.Client{Timeout: 8 * time.Second} }

// ── Telegram ──────────────────────────────────────────────

const defaultTelegramBase = "https://api.telegram.org"

type TelegramNotifier struct {
	token  string
	chatID string
	base   string
	hc     *http.Client
}

func NewTelegramNotifier(token, chatID string) *TelegramNotifier {
	return &TelegramNotifier{token: token, chatID: chatID, base: defaultTelegramBase, hc: newHTTPClient()}
}

func (t *TelegramNotifier) Name() string { return "telegram" }

func (t *TelegramNotifier) Notify(ctx context.Context, n Notification) error {
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", t.base, t.token)
	form := url.Values{"chat_id": {t.chatID}, "text": {n.Text()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Webhook (POST JSON) ───────────────────────────────────

type WebhookNotifier struct {
	url string
	hc  *http.Client
}

func NewWebhookNotifier(rawURL string) *WebhookNotifier {
	return &WebhookNotifier{url: rawURL, hc: newHTTPClient()}
}

func (wn *WebhookNotifier) Name() string { return "webhook" }

func (wn *WebhookNotifier) Notify(ctx context.Context, n Notification) error {
	body, _ := json.Marshal(map[string]any{
		"title":     n.Title,
		"severity":  n.Severity.String(),
		"source_ip": n.SourceIP,
		"rule":      n.Rule,
		"technique": n.Technique,
		"tactic":    n.Tactic,
		"label":     n.Label,
		"time":      n.Time.UTC().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wn.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := wn.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Email (SMTP) ──────────────────────────────────────────

// sendMailFunc memisahkan pengiriman SMTP agar bisa di-stub di test.
type sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

type EmailNotifier struct {
	host string
	port string
	user string
	pass string
	from string
	to   []string
	send sendMailFunc
}

func NewEmailNotifier(host, port, user, pass, from string, to []string) *EmailNotifier {
	return &EmailNotifier{host: host, port: port, user: user, pass: pass, from: from, to: to, send: smtp.SendMail}
}

func (e *EmailNotifier) Name() string { return "email" }

// message membangun pesan RFC 822 sederhana.
func (e *EmailNotifier) message(n Notification) []byte {
	subject := fmt.Sprintf("[DeusWatch][%s] %s", strings.ToUpper(n.Severity.String()), n.Title)
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", e.from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(n.Text())
	return []byte(b.String())
}

func (e *EmailNotifier) Notify(_ context.Context, n Notification) error {
	var auth smtp.Auth
	if e.user != "" {
		auth = smtp.PlainAuth("", e.user, e.pass, e.host)
	}
	addr := e.host + ":" + e.port
	if err := e.send(addr, auth, e.from, e.to, e.message(n)); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}

// ── Konstruksi dari env ───────────────────────────────────

// DispatcherFromEnv membangun Dispatcher dari environment:
//
//	NOTIFY_MIN_SEVERITY  ambang (info|low|medium|high|critical; default high)
//	NOTIFY_THROTTLE       jeda dedup per rule+IP (Go duration; default 10m)
//	TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
//	WEBHOOK_URL
//	SMTP_HOST + SMTP_PORT + SMTP_FROM + SMTP_TO (koma) [+ SMTP_USER + SMTP_PASS]
//
// Mengembalikan (dispatcher, true) bila minimal satu sink aktif.
func DispatcherFromEnv() (*Dispatcher, bool) {
	var sinks []Notifier
	if tok, chat := os.Getenv("TELEGRAM_BOT_TOKEN"), os.Getenv("TELEGRAM_CHAT_ID"); tok != "" && chat != "" {
		sinks = append(sinks, NewTelegramNotifier(tok, chat))
	}
	if u := os.Getenv("WEBHOOK_URL"); u != "" {
		sinks = append(sinks, NewWebhookNotifier(u))
	}
	if host, from := os.Getenv("SMTP_HOST"), os.Getenv("SMTP_FROM"); host != "" && from != "" {
		to := splitCSV(os.Getenv("SMTP_TO"))
		if len(to) > 0 {
			port := os.Getenv("SMTP_PORT")
			if port == "" {
				port = "587"
			}
			sinks = append(sinks, NewEmailNotifier(host, port, os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS"), from, to))
		}
	}
	if len(sinks) == 0 {
		return nil, false
	}
	return NewDispatcher(minSeverityFromEnv(), throttleFromEnv(), sinks...), true
}

func minSeverityFromEnv() ingest.Severity {
	switch strings.ToLower(os.Getenv("NOTIFY_MIN_SEVERITY")) {
	case "info":
		return ingest.SeverityInfo
	case "low":
		return ingest.SeverityLow
	case "medium":
		return ingest.SeverityMedium
	case "critical":
		return ingest.SeverityCritical
	default:
		return ingest.SeverityHigh
	}
}

func throttleFromEnv() time.Duration {
	if v := os.Getenv("NOTIFY_THROTTLE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 10 * time.Minute
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
