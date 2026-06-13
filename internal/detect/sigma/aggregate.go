package sigma

// Jalur AGREGASI Sigma → SQL (model Zircolite/pySigma, lihat ADR 0001).
//
// Rule single-event (sigma.go) dievaluasi per-event di memori. Rule AGREGASI —
// kondisi ber-pipa seperti `selection | count() by source.ip > 5` — tidak bisa
// dijawab satu event; ia butuh state/korelasi. Di sini kita meng-compile rule
// agregasi menjadi satu query SQL terhadap hypertable `events` TimescaleDB, lalu
// runner periodik menjalankannya (lihat internal/detect/aggregate.go). Inilah
// generalisasi detektor brute-force hardcoded ke rule yang ditulis dalam Sigma.
//
// Didukung: pre-pipe = ekspresi boolean atas selection (and/or/not + kurung +
// nama selection); pipa `count() [by <field>] <op> <N>` dengan op > >= < <=;
// `timeframe` (mis. 5m, 1h) sebagai jendela waktu. Tidak didukung: count(field)
// distinct, sum()/min()/max(), "N of them" di sisi kiri pipa.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/ingest"
)

// AggRule adalah rule Sigma agregasi yang sudah di-compile ke SQL.
type AggRule struct {
	ID        string
	Title     string
	Level     string
	Tags      []string
	LogSource map[string]string

	GroupByField string        // field ECS untuk "by" (kosong = agregasi global)
	Op           string        // operator perbandingan: > >= < <=
	Threshold    int           // ambang count
	Window       time.Duration // timeframe (default 5m bila tak diset)

	whereSQL  string // fragmen WHERE hasil compile selection (tanpa filter waktu)
	whereArgs []any
}

// MITRE & Severity sama seperti Rule single-event.
func (r *AggRule) MITRE() (techniqueID, tactic string) { return mitreFromTags(r.Tags) }
func (r *AggRule) Severity() ingest.Severity           { return severityFromLevel(r.Level) }

// detectionTimeframe membaca detection.timeframe (mis. "5m"); default 5 menit.
func detectionTimeframe(detection map[string]any) (time.Duration, error) {
	tf, ok := detection["timeframe"]
	if !ok {
		return 5 * time.Minute, nil
	}
	s := toStr(tf)
	d, err := parseSigmaDuration(s)
	if err != nil {
		return 0, fmt.Errorf("sigma: timeframe %q tidak valid: %w", s, err)
	}
	return d, nil
}

// parseSigmaDuration menerima format Sigma "30s","5m","1h","1d" (selain itu coba time.ParseDuration).
func parseSigmaDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("kosong")
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

// isAggregation melaporkan apakah YAML rule memiliki kondisi agregasi (mengandung "|").
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

// ParseAggRule mem-parse + meng-compile rule Sigma agregasi dari YAML.
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
		return nil, fmt.Errorf("sigma: detection.condition wajib berupa string")
	}
	parts := strings.SplitN(condRaw, "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("sigma: bukan rule agregasi (tak ada '|')")
	}
	left := strings.TrimSpace(parts[0])
	pipe := strings.TrimSpace(parts[1])

	m := aggPipeRe.FindStringSubmatch(pipe)
	if m == nil {
		return nil, fmt.Errorf("sigma: agregasi %q tidak didukung (hanya 'count() [by field] <op> N')", pipe)
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
			return nil, fmt.Errorf("sigma: field 'by %s' tak punya kolom DCS yang dipetakan", r.GroupByField)
		}
	}
	return r, nil
}

// CompileSQL menghasilkan query lengkap + argumen untuk dijalankan terhadap tabel
// events. Hasil query mengembalikan kolom (grp, n, last_seen) untuk tiap grup yang
// melewati ambang. Argumen waktu (interval) ditambahkan sebagai argumen terakhir.
func (r *AggRule) CompileSQL() (query string, args []any) {
	args = append(args, r.whereArgs...)
	args = append(args, fmt.Sprintf("%d seconds", int(r.Window.Seconds())))
	winPlaceholder := fmt.Sprintf("$%d", len(args))

	grpSelect, groupBy := "''::text", ""
	if r.GroupByField != "" {
		col, _ := columnFor(r.GroupByField)
		groupBy = "\nGROUP BY " + col.expr
		grpSelect = col.selectExpr()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "SELECT %s AS grp, count(*) AS n, max(time) AS last_seen\nFROM events\n", grpSelect)
	fmt.Fprintf(&b, "WHERE (%s) AND time > now() - %s::interval", r.whereSQL, winPlaceholder)
	b.WriteString(groupBy)
	// op & threshold aman: op dari whitelist regex, threshold integer.
	fmt.Fprintf(&b, "\nHAVING count(*) %s %d\nORDER BY n DESC", r.Op, r.Threshold)
	return b.String(), args
}

// ── kompilasi kondisi (selection boolean) ke SQL ──────────

// compileCondition mengubah ekspresi pre-pipe (and/or/not/kurung + nama selection)
// menjadi fragmen WHERE SQL + argumen ber-urut.
func compileCondition(cond string, sels map[string]selection) (string, []any, error) {
	c := &sqlCond{toks: tokenize(cond), sels: sels}
	sql, err := c.parseOr()
	if err != nil {
		return "", nil, err
	}
	if c.pos != len(c.toks) {
		return "", nil, fmt.Errorf("sigma: token kondisi tersisa: %v", c.toks[c.pos:])
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
			return "", fmt.Errorf("sigma: tanda kurung tutup hilang")
		}
		return v, nil
	case t == "all" || t == "any" || isNumber(t):
		return "", fmt.Errorf("sigma: ekspresi '%s of ...' tidak didukung di kiri pipa agregasi", t)
	case t == "":
		return "", fmt.Errorf("sigma: kondisi tidak lengkap")
	default:
		sel, ok := c.sels[t]
		if !ok {
			return "", fmt.Errorf("sigma: selection tak dikenal: %q", t)
		}
		return sel.sql(&c.args)
	}
}

// ── selection → fragmen SQL ───────────────────────────────

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
		return "", fmt.Errorf("sigma: selection kosong")
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
		return "", fmt.Errorf("sigma: field %q tak punya kolom DCS yang dipetakan (jalur SQL)", fc.name)
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

// ── pemetaan field ECS → kolom SQL ────────────────────────

type column struct {
	expr string // ekspresi kolom SQL (mis. "source_ip", "event_severity")
	inet bool   // kolom bertipe inet (perlu cast / host())
}

// selectExpr mengembalikan ekspresi untuk klausa SELECT grup (inet → host()).
func (c column) selectExpr() string {
	if c.inet {
		return "host(" + c.expr + ")"
	}
	return c.expr
}

// compare menghasilkan satu predikat SQL untuk kolom ini terhadap nilai v dengan
// modifier mod (contains/startswith/endswith/re/"" = eq). Nilai literal selalu
// lewat argumen ber-parameter (tak pernah di-interpolasi).
func (c column) compare(mod, v string, args *[]any) (string, error) {
	add := func(val any) string { *args = append(*args, val); return fmt.Sprintf("$%d", len(*args)) }
	lhs := c.expr
	if c.inet && mod != "" {
		lhs = "host(" + c.expr + ")" // pattern match di teks IP
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
		return "", fmt.Errorf("sigma: modifier %q di luar subset jalur SQL", mod)
	}
}

// fieldColumns memetakan field ECS dotted ke kolom hypertable events. Ini cermin
// SQL dari FlattenEvent (mapping.go) — keduanya WAJIB selaras dengan schema.go.
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

// columnFor me-resolve nama field rule (lewat alias taksonomi) ke kolom SQL.
func columnFor(field string) (column, bool) {
	c, ok := fieldColumns[field]
	if ok {
		return c, true
	}
	c, ok = fieldColumns[resolveField(field)]
	return c, ok
}
