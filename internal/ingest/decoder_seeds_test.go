package ingest

import (
	"testing"
)

// The bundled database decoders, checked against real log lines.
//
// A decoder that does not match is silent: the line still becomes an event, just without the
// category, so the brute-force aggregations skip it and nothing ever fires. There is no error
// anywhere to notice. That is what makes these worth asserting rather than eyeballing, and it is
// how the imported Wazuh drafts sat unused with an empty category.
func TestDatabaseDecoderSeeds(t *testing.T) {
	set, err := LoadDecoderDir("../../decoders")
	if err != nil {
		t.Fatalf("load bundled decoders: %v", err)
	}

	for _, c := range []struct {
		name, dataset, line string
		wantIP, wantUser    string
	}{
		{
			name:    "postgres password failure with %h in the prefix",
			dataset: "postgresql",
			line:    `2026-10-07 10:00:00.123 UTC [12345] postgres@app 203.0.113.9 FATAL:  password authentication failed for user "postgres"`,
			wantIP:  "203.0.113.9", wantUser: "postgres",
		},
		{
			// The default Debian prefix. Still an auth failure, just unbannable.
			name:    "postgres password failure without the address",
			dataset: "postgresql",
			line:    `2026-10-07 10:00:00.123 UTC [12345] FATAL:  password authentication failed for user "admin"`,
			wantIP:  "", wantUser: "admin",
		},
		{
			// Carries the address whatever log_line_prefix says, which is why it is matched apart.
			name:    "postgres pg_hba rejection",
			dataset: "postgresql",
			line:    `2026-10-07 10:00:00.123 UTC [12345] FATAL:  no pg_hba.conf entry for host "203.0.113.9", user "admin", database "app", SSL off`,
			wantIP:  "203.0.113.9", wantUser: "admin",
		},
		{
			name:    "postgres role enumeration",
			dataset: "postgresql",
			line:    `2026-10-07 10:00:00.123 UTC [12345] 203.0.113.9 FATAL:  role "nosuchuser" does not exist`,
			wantIP:  "203.0.113.9", wantUser: "nosuchuser",
		},
		{
			name:    "mysql 8",
			dataset: "mysql",
			line:    `2026-10-07T10:00:00.123456Z 12 [Note] [MY-010926] [Server] Access denied for user 'root'@'203.0.113.9' (using password: YES)`,
			wantIP:  "203.0.113.9", wantUser: "root",
		},
		{
			// "localhost" must not land in source.ip: the ban path reads that field as an address.
			name:    "mysql local connection keeps the address empty",
			dataset: "mysql",
			line:    `2026-10-07T10:00:00.123456Z 12 [Note] [MY-010926] [Server] Access denied for user 'root'@'localhost' (using password: NO)`,
			wantIP:  "", wantUser: "root",
		},
		{
			name:    "mariadb",
			dataset: "mariadb",
			line:    `2026-10-07 10:00:00 12 [Warning] Access denied for user 'app'@'203.0.113.9' (using password: YES)`,
			wantIP:  "203.0.113.9", wantUser: "app",
		},
		{
			name:    "clickhouse without an address, the default shape",
			dataset: "clickhouse",
			line:    `2026.10.07 10:00:00.123456 [ 1234 ] {} <Error> TCPHandler: Code: 516. DB::Exception: admin: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED)`,
			wantIP:  "", wantUser: "admin",
		},
		{
			name:    "clickhouse with an address",
			dataset: "clickhouse",
			line:    `2026.10.07 10:00:00.123456 [ 1234 ] {} <Error> TCPHandler: Code: 516. DB::Exception: admin: Authentication failed. (AUTHENTICATION_FAILED), while receiving query from 203.0.113.9:9000`,
			wantIP:  "203.0.113.9", wantUser: "admin",
		},
		{
			name:    "mongodb structured log",
			dataset: "mongodb",
			line:    `{"t":{"$date":"2026-10-07T10:00:00.123+00:00"},"s":"I","c":"ACCESS","id":20249,"ctx":"conn12","msg":"Authentication failed","attr":{"mechanism":"SCRAM-SHA-256","principalName":"admin","authenticationDatabase":"admin","remote":"203.0.113.9:43210","error":"AuthenticationFailed: SCRAM authentication failed"}}`,
			wantIP:  "203.0.113.9", wantUser: "admin",
		},
		{
			name:    "mssql",
			dataset: "mssql",
			line:    `2026-10-07 10:00:00.12 Logon       Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 203.0.113.9]`,
			wantIP:  "203.0.113.9", wantUser: "sa",
		},
		{
			name:    "mssql local connection",
			dataset: "mssql",
			line:    `2026-10-07 10:00:00.12 Logon       Login failed for user 'app'. Reason: Could not find a login matching the name provided. [CLIENT: <local machine>]`,
			wantIP:  "", wantUser: "app",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			kind := datasetKind(c.dataset)
			e := &Event{Event: EventFields{Dataset: c.dataset, Original: c.line, Severity: SeverityInfo}}
			if !set.apply(kind, c.line, e) {
				t.Fatalf("no decoder matched")
			}
			// These two are what the aggregations select on. Without both, the rule that already
			// exists silently counts nothing.
			if e.Event.Category != "authentication" {
				t.Errorf("category = %q, want authentication", e.Event.Category)
			}
			if e.Event.Outcome != "failure" {
				t.Errorf("outcome = %q, want failure", e.Event.Outcome)
			}

			var gotIP, gotUser string
			if e.Source != nil {
				gotIP = e.Source.IP
			}
			if e.User != nil {
				gotUser = e.User.Name
			}
			if gotIP != c.wantIP {
				t.Errorf("source.ip = %q, want %q", gotIP, c.wantIP)
			}
			if gotUser != c.wantUser {
				t.Errorf("user.name = %q, want %q", gotUser, c.wantUser)
			}
		})
	}
}

// A successful login must not be counted as a failure: the aggregations would then alert on normal
// application traffic, and an operator who sees that once stops trusting the rule.
func TestDatabaseDecodersIgnoreSuccess(t *testing.T) {
	set, err := LoadDecoderDir("../../decoders")
	if err != nil {
		t.Fatalf("load bundled decoders: %v", err)
	}
	for _, c := range []struct{ dataset, line string }{
		{"postgresql", `2026-10-07 10:00:00.123 UTC [12345] postgres@app 203.0.113.9 LOG:  connection authorized: user=postgres database=app`},
		{"postgresql", `2026-10-07 10:00:00.123 UTC [12345] LOG:  connection received: host=203.0.113.9 port=54321`},
		{"mysql", `2026-10-07T10:00:00.123456Z 12 [Note] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections.`},
		{"mariadb", `2026-10-07 10:00:00 0 [Note] mariadbd: ready for connections.`},
		{"clickhouse", `2026.10.07 10:00:00.123456 [ 1234 ] {} <Debug> TCPHandler: Connected ClickHouse client version 24.1.0 from 203.0.113.9:9000`},
		{"mongodb", `{"t":{"$date":"2026-10-07T10:00:00.123+00:00"},"s":"I","c":"ACCESS","id":20250,"ctx":"conn12","msg":"Successful authentication","attr":{"principalName":"admin","remote":"203.0.113.9:43210"}}`},
		{"mssql", `2026-10-07 10:00:00.12 Logon       Login succeeded for user 'sa'. [CLIENT: 203.0.113.9]`},
	} {
		e := &Event{Event: EventFields{Dataset: c.dataset, Original: c.line, Severity: SeverityInfo}}
		if set.apply(datasetKind(c.dataset), c.line, e) {
			t.Errorf("%s: matched a line that is not an auth failure: %s", c.dataset, c.line)
		}
	}
}
