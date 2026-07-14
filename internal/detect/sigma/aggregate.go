package sigma

// The Sigma → SQL AGGREGATION path (Zircolite/pySigma model, see ADR 0001).
//
// Single-event rules (sigma.go) are evaluated per-event in memory. AGGREGATION rules —
// piped conditions like `selection | count() by source.ip > 5` — cannot be answered by
// one event; they need state/correlation. Here we compile an aggregation rule into a
// single SQL query against the TimescaleDB `events` hypertable, and a periodic runner
// executes it (see internal/detect/aggregate.go). This is the generalization of the
// hardcoded brute-force detector to rules written in Sigma.
//
// Supported: pre-pipe = a boolean expression over selections (and/or/not + parens +
// selection names); the pipe `count() [by <field>] <op> <N>` with op > >= < <=;
// `timeframe` (e.g. 5m, 1h) as the time window. Not supported: count(field) distinct,
// sum()/min()/max(), "N of them" on the left of the pipe.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/ingest"
)

// AggRule is an aggregation Sigma rule compiled to SQL.
type AggRule struct {
	ID        string
	Title     string
	Level     string
	Tags      []string
	LogSource map[string]string

	GroupByField string        // ECS field for "by" (empty = global aggregation)
	Op           string        // comparison operator: > >= < <=
	Threshold    int           // count threshold
	Window       time.Duration // timeframe (default 5m if unset)

	whereSQL  string // WHERE fragment compiled from the selection (no time filter)
	whereArgs []any
}

// MITRE & Severity are the same as for a single-event Rule.
func (r *AggRule) MITRE() (techniqueID, tactic string) { return mitreFromTags(r.Tags) }
func (r *AggRule) Severity() ingest.Severity           { return severityFromLevel(r.Level) }

// detectionTimeframe reads detection.timeframe (e.g. "5m"); default 5 minutes.
func detectionTimeframe(detection map[string]any) (time.Duration, error) {
	tf, ok := detection["timeframe"]
	if !ok {
		return 5 * time.Minute, nil
	}
	s := toStr(tf)
	d, err := parseSigmaDuration(s)
	if err != nil {
		return 0, fmt.Errorf("sigma: invalid timeframe %q: %w", s, err)
	}
	return d, nil
}

// parseSigmaDuration accepts the Sigma format "30s","5m","1h","1d" (otherwise tries time.ParseDuration).
func parseSigmaDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

var aggPipeRe = regexp.MustCompile(`^count\(\s*\)\s*(?:by\s+([A-Za-z0-9_.]+)\s+)?(>=|<=|>|<)\s*(\d+)$`)

// isAggregation reports whether the YAML rule has an aggregation condition (contains "|").
func isAggregation(data []byte) bool {
	var raw struct {
		Detection map[string]any `yaml:"detection"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	cond, _ := raw.Detection["condition"].(string)
	return strings.Contains(cond, "|")
}

// ParseAggRule parses + compiles an aggregation Sigma rule from YAML.
func ParseAggRule(data []byte) (*AggRule, error) {
	var raw struct {
		ID        string            `yaml:"id"`
		Title     string            `yaml:"title"`
		Level     string            `yaml:"level"`
		Tags      []string          `yaml:"tags"`
		LogSource map[string]string `yaml:"logsource"`
		Detection map[string]any    `yaml:"detection"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("sigma: parse YAML: %w", err)
	}
	condRaw, ok := raw.Detection["condition"].(string)
	if !ok {
		return nil, fmt.Errorf("sigma: detection.condition must be a string")
	}
	parts := strings.SplitN(condRaw, "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("sigma: not an aggregation rule (no '|')")
	}
	left := strings.TrimSpace(parts[0])
	pipe := strings.TrimSpace(parts[1])

	m := aggPipeRe.FindStringSubmatch(pipe)
	if m == nil {
		return nil, fmt.Errorf("sigma: aggregation %q not supported (only 'count() [by field] <op> N')", pipe)
	}
	threshold, _ := strconv.Atoi(m[3])
	window, err := detectionTimeframe(raw.Detection)
	if err != nil {
		return nil, err
	}

	sels, err := parseSelections(raw.Detection)
	if err != nil {
		return nil, err
	}
	r := &AggRule{
		ID: raw.ID, Title: raw.Title, Level: raw.Level, Tags: raw.Tags,
		LogSource: raw.LogSource, GroupByField: m[1], Op: m[2], Threshold: threshold, Window: window,
	}
	where, args, err := compileCondition(left, sels)
	if err != nil {
		return nil, err
	}
	r.whereSQL, r.whereArgs = where, args
	if r.GroupByField != "" {
		if _, ok := columnFor(r.GroupByField); !ok {
			return nil, fmt.Errorf("sigma: field 'by %s' has no mapped DCS column", r.GroupByField)
		}
	}
	return r, nil
}

// CompileSQL produces the full query + arguments to run against the events table. The
// query returns columns (grp, n, last_seen) for each group that crosses the threshold.
// The time argument (interval) is appended as the last argument.
func (r *AggRule) CompileSQL() (query string, args []any) {
	args = append(args, r.whereArgs...)
	args = append(args, fmt.Sprintf("%d seconds", int(r.Window.Seconds())))
	winPlaceholder := fmt.Sprintf("$%d", len(args))

	grpSelect, groupBy, notNull := "''::text", "", ""
	if r.GroupByField != "" {
		col, _ := columnFor(r.GroupByField)
		groupBy = "\nGROUP BY " + col.expr
		grpSelect = col.selectExpr()
		// A correlation key must exist: rows whose grouping column is NULL (e.g. a
		// failed logon with no source IP - local/loopback) are not a meaningful group,
		// and a NULL group also breaks the string scan in QueryAgg. Exclude them so the
		// rule counts real, attributable events only.
		notNull = " AND " + col.expr + " IS NOT NULL"
	}

	var b strings.Builder
	// max(agent_id)/max(host_name) give a representative endpoint for the group, so a
	// "by source.ip" alert can still show which agent/host was attacked (COALESCE to ''
	// so a group with none scans cleanly into a string).
	fmt.Fprintf(&b, "SELECT %s AS grp, count(*) AS n, max(time) AS last_seen, "+
		"COALESCE(max(agent_id),'') AS agent, COALESCE(max(host_name),'') AS host\nFROM events\n", grpSelect)
	fmt.Fprintf(&b, "WHERE (%s) AND time > now() - %s::interval%s", r.whereSQL, winPlaceholder, notNull)
	b.WriteString(groupBy)
	// op & threshold are safe: op from the regex whitelist, threshold an integer.
	fmt.Fprintf(&b, "\nHAVING count(*) %s %d\nORDER BY n DESC", r.Op, r.Threshold)
	return b.String(), args
}

// ── compile the (boolean selection) condition to SQL ──────

// compileCondition turns the pre-pipe expression (and/or/not/parens + selection names)
// into a WHERE SQL fragment + ordered arguments.
func compileCondition(cond string, sels map[string]selection) (string, []any, error) {
	c := &sqlCond{toks: tokenize(cond), sels: sels}
	sql, err := c.parseOr()
	if err != nil {
		return "", nil, err
	}
	if c.pos != len(c.toks) {
		return "", nil, fmt.Errorf("sigma: leftover condition tokens: %v", c.toks[c.pos:])
	}
	return sql, c.args, nil
}

type sqlCond struct {
	toks []string
	pos  int
	sels map[string]selection
	args []any
}

func (c *sqlCond) peek() string {
	if c.pos < len(c.toks) {
		return c.toks[c.pos]
	}
	return ""
}
func (c *sqlCond) take() string { t := c.peek(); c.pos++; return t }

func (c *sqlCond) parseOr() (string, error) {
	v, err := c.parseAnd()
	if err != nil {
		return "", err
	}
	for c.peek() == "or" {
		c.take()
		rhs, err := c.parseAnd()
		if err != nil {
			return "", err
		}
		v = "(" + v + " OR " + rhs + ")"
	}
	return v, nil
}

func (c *sqlCond) parseAnd() (string, error) {
	v, err := c.parseUnary()
	if err != nil {
		return "", err
	}
	for c.peek() == "and" {
		c.take()
		rhs, err := c.parseUnary()
		if err != nil {
			return "", err
		}
		v = "(" + v + " AND " + rhs + ")"
	}
	return v, nil
}

func (c *sqlCond) parseUnary() (string, error) {
	if c.peek() == "not" {
		c.take()
		v, err := c.parseUnary()
		if err != nil {
			return "", err
		}
		return "(NOT " + v + ")", nil
	}
	return c.parsePrimary()
}

func (c *sqlCond) parsePrimary() (string, error) {
	t := c.take()
	switch {
	case t == "(":
		v, err := c.parseOr()
		if err != nil {
			return "", err
		}
		if c.take() != ")" {
			return "", fmt.Errorf("sigma: missing closing parenthesis")
		}
		return v, nil
	case t == "all" || t == "any" || isNumber(t):
		return "", fmt.Errorf("sigma: '%s of ...' expression is not supported on the left of an aggregation pipe", t)
	case t == "":
		return "", fmt.Errorf("sigma: incomplete condition")
	default:
		sel, ok := c.sels[t]
		if !ok {
			return "", fmt.Errorf("sigma: unknown selection: %q", t)
		}
		return sel.sql(&c.args)
	}
}

// ── selection → SQL fragment ──────────────────────────────

func (s selection) sql(args *[]any) (string, error) {
	if len(s.keywords) > 0 {
		parts := make([]string, 0, len(s.keywords))
		for _, kw := range s.keywords {
			*args = append(*args, "%"+kw+"%")
			parts = append(parts, fmt.Sprintf("event_original ILIKE $%d", len(*args)))
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}
	if len(s.fields) == 0 {
		return "", fmt.Errorf("sigma: empty selection")
	}
	parts := make([]string, 0, len(s.fields))
	for _, fc := range s.fields {
		frag, err := fc.sql(args)
		if err != nil {
			return "", err
		}
		parts = append(parts, frag)
	}
	return "(" + strings.Join(parts, " AND ") + ")", nil
}

func (fc fieldCond) sql(args *[]any) (string, error) {
	col, ok := columnFor(fc.name)
	if !ok {
		return "", fmt.Errorf("sigma: field %q has no mapped DCS column (SQL path)", fc.name)
	}
	mod := ""
	if len(fc.modifiers) > 0 {
		mod = fc.modifiers[0]
	}
	ors := make([]string, 0, len(fc.values))
	for _, v := range fc.values {
		frag, err := col.compare(mod, v, args)
		if err != nil {
			return "", err
		}
		ors = append(ors, frag)
	}
	if len(ors) == 1 {
		return ors[0], nil
	}
	return "(" + strings.Join(ors, " OR ") + ")", nil
}

// ── ECS field → SQL column mapping ────────────────────────

type column struct {
	expr string // SQL column expression (e.g. "source_ip", "event_severity")
	inet bool   // inet-typed column (needs cast / host())
}

// selectExpr returns the expression for the group SELECT clause (inet → host()).
func (c column) selectExpr() string {
	if c.inet {
		return "host(" + c.expr + ")"
	}
	return c.expr
}

// compare produces one SQL predicate for this column against value v with modifier mod
// (contains/startswith/endswith/re/"" = eq). Literal values always go through
// parameterized arguments (never interpolated).
func (c column) compare(mod, v string, args *[]any) (string, error) {
	add := func(val any) string { *args = append(*args, val); return fmt.Sprintf("$%d", len(*args)) }
	lhs := c.expr
	if c.inet && mod != "" {
		lhs = "host(" + c.expr + ")" // pattern match against the IP text
	}
	switch mod {
	case "":
		if c.inet {
			return fmt.Sprintf("%s = %s::inet", c.expr, add(v)), nil
		}
		return fmt.Sprintf("lower(%s::text) = lower(%s)", c.expr, add(v)), nil
	case "contains":
		return fmt.Sprintf("%s ILIKE %s", lhs, add("%"+v+"%")), nil
	case "startswith":
		return fmt.Sprintf("%s ILIKE %s", lhs, add(v+"%")), nil
	case "endswith":
		return fmt.Sprintf("%s ILIKE %s", lhs, add("%"+v)), nil
	case "re":
		return fmt.Sprintf("%s ~ %s", lhs, add(v)), nil
	default:
		return "", fmt.Errorf("sigma: modifier %q outside the SQL-path subset", mod)
	}
}

// fieldColumns maps dotted ECS fields to events-hypertable columns. This is the SQL
// mirror of FlattenEvent (mapping.go) — both MUST stay in sync with schema.go.
var fieldColumns = map[string]column{
	"event.category":       {expr: "event_category"},
	"event.action":         {expr: "event_action"},
	"event.outcome":        {expr: "event_outcome"},
	"event.dataset":        {expr: "event_dataset"},
	"event.severity":       {expr: "event_severity"},
	"event.original":       {expr: "event_original"},
	"source.ip":            {expr: "source_ip", inet: true},
	"source.port":          {expr: "source_port"},
	"destination.ip":       {expr: "destination_ip", inet: true},
	"destination.port":     {expr: "destination_port"},
	"host.name":            {expr: "host_name"},
	"host.os.type":         {expr: "host_os_type"},
	"user.name":            {expr: "user_name"},
	"user.domain":          {expr: "user_domain"},
	"process.name":         {expr: "process_name"},
	"process.command_line": {expr: "process_command_line"},
	"file.path":            {expr: "file_path"},
	"file.hash.sha256":     {expr: "file_hash_sha256"},
	"network.protocol":     {expr: "network_protocol"},
	"network.transport":    {expr: "network_transport"},
}

// columnFor resolves a rule field name (via the taxonomy alias) to a SQL column.
func columnFor(field string) (column, bool) {
	c, ok := fieldColumns[field]
	if ok {
		return c, true
	}
	c, ok = fieldColumns[resolveField(field)]
	return c, ok
}
