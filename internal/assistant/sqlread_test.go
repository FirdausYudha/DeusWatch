package assistant

import (
	"strings"
	"testing"
)

// The allowlist is the only thing standing between a generated query and the password hashes, and
// the prompt that generates it contains text an attacker wrote. So these are written as attacks,
// not as happy paths.
func TestValidateQueryRefusesWhatItMust(t *testing.T) {
	for _, c := range []struct{ sql, why string }{
		{"select * from users", "credential table"},
		{"SELECT * FROM Users", "credential table, different case"},
		{"select * from public.users", "schema-qualified, which a last-segment check would miss"},
		{`select * from "users"`, "quoted identifier"},
		{"select * from integrations", "encrypted API keys"},
		{"select * from sessions", "live session tokens"},
		{"select * from agent_enroll_tokens", "live enrolment credentials"},
		{"select * from audit_log", "deliberately excluded, belongs on its own page"},
		{"select 1; drop table events", "two statements in one batch"},
		{"select 1; select 2", "two statements even when both are reads"},
		{"delete from events", "not a SELECT"},
		{"update agents set revoked = true", "not a SELECT"},
		{"insert into tickets (title) values ('x')", "not a SELECT"},
		{"select * from pg_catalog.pg_tables", "enumerating the tables the allowlist hides"},
		{"select * from information_schema.columns", "same, by another route"},
		{"select pg_sleep(60) from events", "pinning the database"},
		{"select current_setting('deuswatch.superadmin') from events", "reading the tenant-scope GUC"},
		{"select * from events /* sneaky */ join users u on true", "a join past a comment"},
		{"select * from events -- \nunion select * from users", "a union hidden after a line comment"},
		{"", "empty"},
	} {
		if err := ValidateQuery(c.sql); err == nil {
			t.Errorf("ALLOWED but must be refused (%s): %q", c.why, c.sql)
		}
	}
}

func TestValidateQueryAllowsOrdinaryReads(t *testing.T) {
	for _, q := range []string{
		"select host(source_ip), count(*) from events where time >= now() - interval '24 hours' group by 1 order by 2 desc limit 10",
		"SELECT name, status FROM agents WHERE deleted_at IS NULL LIMIT 50",
		"select t.title, t.status from tickets t join ticket_comments c on c.ticket_id = t.id limit 20",
		"with recent as (select * from response_actions where created_at > now() - interval '7 days' limit 50) select status, count(*) from recent group by 1",
		"select * from events where source_ip = '1.2.3.4'::inet limit 5;", // a trailing semicolon is not a second statement
	} {
		if err := ValidateQuery(q); err != nil {
			t.Errorf("refused a legitimate query: %q\n  %v", q, err)
		}
	}
}

// A refusal is shown to the operator, so it has to say which table was the problem and what is
// available, not just "denied".
func TestValidateQueryErrorIsActionable(t *testing.T) {
	err := ValidateQuery("select * from users")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, "users") || !strings.Contains(msg, "events") {
		t.Errorf("refusal should name the offending table and list the readable ones: %q", msg)
	}
}

func TestSQLGuideDescribesOnlyAllowedTables(t *testing.T) {
	g := SQLGuide()
	for name := range AllowedTables {
		if !strings.Contains(g, name) {
			t.Errorf("guide omits the readable table %q", name)
		}
	}
	// The model must be told what it cannot have, or it writes those queries and the operator sees
	// a refusal instead of an answer.
	for _, denied := range []string{"users", "integrations", "sessions", "audit_log"} {
		if !strings.Contains(g, denied) {
			t.Errorf("guide does not warn that %q is refused", denied)
		}
	}
	if !strings.Contains(g, "you will not see the rows, the operator will") {
		t.Error("guide must stop the model inventing a result it never receives")
	}
}

func TestExtractSQL(t *testing.T) {
	got, ok := ExtractSQL("Here you go.\n\n```sql\nselect 1 from events limit 1\n```\ntrailing")
	if !ok || got != "select 1 from events limit 1" {
		t.Errorf("ok=%v got %q", ok, got)
	}
	if _, ok := ExtractSQL("I can look that up, what window do you want?"); ok {
		t.Error("ordinary prose must not be read as a query")
	}
}

func TestNeedsQuery(t *testing.T) {
	for _, m := range []string{"berapa banyak event dari IP itu?", "list all tickets", "run a query for me", "tampilkan semua agent"} {
		if !NeedsQuery(m) {
			t.Errorf("%q should pull in the schema guide", m)
		}
	}
	for _, m := range []string{"hello", "is 1.2.3.4 dangerous?", "what happened today?"} {
		if NeedsQuery(m) {
			t.Errorf("%q should NOT pull in the schema guide", m)
		}
	}
}
