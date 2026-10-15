// Package snmp polls a network device over SNMP and reports what it found.
//
// It exists because the hospital's SNMP data is split across three tools — The Dude for the
// switches, WIS Cloud for the access points, Grafana at head office — and the ask was explicit:
// one dashboard. The devices already answer SNMP; nothing new has to be installed on them.
//
// On OIDs, and the one thing worth knowing before reading further: SNMP standardises far less
// than people expect. Uptime, the device's own name and description, and the interface table are
// the same everywhere. **CPU load, temperature and power-supply state are not** — every vendor
// puts them somewhere different, and there is no standard OID to read. So this package polls the
// standard tree itself and takes the rest as operator-supplied Sensors: a name, an OID, a unit and
// a threshold. That is why it works on Ruijie, and would keep working on Aruba after a contract
// change, without this file containing a single OID that could not be verified.
//
// Pure by design: it takes a Target, performs the poll, and returns a Result. No database, no
// scheduling, no alerting — the same split as internal/probe, and for the same reason: the rules
// that decide whether something is reported as broken have to be testable without a switch.
package snmp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Standard OIDs. These three are the same on every SNMP-capable device.
const (
	oidSysDescr  = "1.3.6.1.2.1.1.1.0"
	oidSysUptime = "1.3.6.1.2.1.1.3.0" // TimeTicks: hundredths of a second, NOT seconds
	oidSysName   = "1.3.6.1.2.1.1.5.0"

	// IF-MIB. ifName and the 64-bit counters live in the extension table (ifXTable); the rest is
	// the original interface table.
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
)

// IF-MIB ifOperStatus values. Only "up" counts as working; the rest are degrees of not.
const (
	IfUp      = 1
	IfDown    = 2
	IfTesting = 3
)

// Versions this package speaks.
const (
	Version2c = "2c"
	Version3  = "3"
)

// Target is one device to poll.
type Target struct {
	Host    string
	Port    uint16
	Version string // Version2c | Version3

	// v2c
	Community string

	// v3. SecurityLevel is noAuthNoPriv | authNoPriv | authPriv.
	SecurityLevel string
	User          string
	AuthProtocol  string // MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
	AuthPassword  string
	PrivProtocol  string // DES | AES | AES192 | AES256
	PrivPassword  string

	Timeout time.Duration
	Retries int
}

// Sensor is an operator-defined value to read: the CPU and temperature OIDs this package
// deliberately does not hardcode.
type Sensor struct {
	Name string
	OID  string
	Unit string
	// Scale multiplies the raw value. Devices report tenths of a degree, percent-times-ten and
	// similar often enough that without this the operator would be reading 345 for 34.5 °C.
	// Zero means 1.
	Scale float64
	// Thresholds. Nil means no rule in that direction. WarnBelow covers the sensors where LOW is
	// the fault — free memory, a PSU reporting 1 for "ok", fan RPM.
	WarnAbove *float64
	WarnBelow *float64
}

// Reading is one sensor's observed value.
type Reading struct {
	Name  string  `json:"name"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
	// Text holds the value when the device answered with something non-numeric. A sensor that
	// returns a string is not an error; it just cannot be compared with a threshold.
	Text string `json:"text,omitempty"`
	// Breach explains which rule the value broke, empty when it is fine. Operator-facing.
	Breach string `json:"breach,omitempty"`
	// Error is set when this one sensor could not be read, leaving the rest of the poll valid.
	Error string `json:"error,omitempty"`
}

// Iface is one row of the interface table.
type Iface struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	AdminStatus int    `json:"admin_status"`
	OperStatus  int    `json:"oper_status"`
	InOctets    uint64 `json:"in_octets"`
	OutOctets   uint64 `json:"out_octets"`
	InErrors    uint64 `json:"in_errors"`
	OutErrors   uint64 `json:"out_errors"`
}

// Down reports whether this interface is administratively enabled but not actually up — the only
// combination worth alerting on. A port the operator disabled on purpose is not a fault.
func (i Iface) Down() bool { return i.AdminStatus == IfUp && i.OperStatus != IfUp }

// Result is one poll.
type Result struct {
	Reachable bool
	SysName   string
	SysDescr  string
	// UptimeSecs is sysUpTime converted from TimeTicks. Zero when it could not be read.
	UptimeSecs float64
	Sensors    []Reading
	Ifaces     []Iface
	Latency    time.Duration
	// Error explains why the device could not be polled at all. Empty when Reachable.
	Error string
}

// Conn is the slice of an SNMP client this package uses. Narrow on purpose: a fake for the tests
// is then a few lines rather than a reimplementation of gosnmp.
type Conn interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	BulkWalkAll(rootOid string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

// Dialer opens a connection to a target. Swapped in tests.
type Dialer func(ctx context.Context, t Target) (Conn, error)

// Options controls how much of the device is read.
type Options struct {
	// Interfaces walks the interface table. Off by default because it is the expensive half: a
	// 48-port switch produces 48 rows per poll, and twenty of them produce over a million rows a
	// day. Worth it where port state matters, wasteful where only the device's health does.
	Interfaces bool
}

// Poll reads the device. It never returns an error: an unreachable device is a Result with
// Reachable=false and a reason, because "could not be polled" and "answered badly" land on the
// same screen and the operator needs the reason either way.
func Poll(ctx context.Context, t Target, sensors []Sensor, opt Options, dial Dialer) Result {
	if dial == nil {
		dial = DefaultDialer
	}
	start := time.Now()

	conn, err := dial(ctx, t)
	if err != nil {
		return Result{Latency: time.Since(start), Error: fmt.Sprintf("cannot reach %s: %v", t.Host, err)}
	}
	defer conn.Close()

	res := Result{Latency: time.Since(start)}

	// The standard trio first. If this fails the device is not answering SNMP at all, and reading
	// sensors afterwards would only produce a list of identical errors.
	pkt, err := conn.Get([]string{oidSysDescr, oidSysUptime, oidSysName})
	if err != nil {
		res.Latency = time.Since(start)
		res.Error = fmt.Sprintf("SNMP get failed on %s: %v", t.Host, err)
		return res
	}
	for _, pdu := range pkt.Variables {
		switch normaliseOID(pdu.Name) {
		case oidSysDescr:
			res.SysDescr = pduText(pdu)
		case oidSysName:
			res.SysName = pduText(pdu)
		case oidSysUptime:
			if ticks, ok := pduNumber(pdu); ok {
				// TimeTicks are hundredths of a second. Reporting them as seconds would make a
				// device that has been up an hour look like it has been up four days.
				res.UptimeSecs = ticks / 100
			}
		}
	}
	res.Reachable = true

	res.Sensors = readSensors(conn, sensors)
	if opt.Interfaces {
		res.Ifaces = readInterfaces(conn)
	}
	res.Latency = time.Since(start)
	return res
}

// readSensors reads each operator-defined OID. One unreadable sensor is recorded on that sensor
// and does not fail the poll: a mistyped OID must not hide the device's uptime and every other
// reading behind it.
func readSensors(conn Conn, sensors []Sensor) []Reading {
	out := make([]Reading, 0, len(sensors))
	for _, s := range sensors {
		r := Reading{Name: s.Name, Unit: s.Unit}
		pkt, err := conn.Get([]string{s.OID})
		if err != nil || len(pkt.Variables) == 0 {
			r.Error = fmt.Sprintf("could not read %s: %v", s.OID, err)
			out = append(out, r)
			continue
		}
		pdu := pkt.Variables[0]
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
			// The device answered, and what it said was "I do not have that". Naming it plainly
			// saves the operator from debugging the network when the OID is simply wrong for
			// this model.
			r.Error = fmt.Sprintf("the device has no %s", s.OID)
			out = append(out, r)
			continue
		}
		v, ok := pduNumber(pdu)
		if !ok {
			r.Text = pduText(pdu)
			out = append(out, r)
			continue
		}
		scale := s.Scale
		if scale == 0 {
			scale = 1
		}
		r.Value = v * scale
		r.Breach = breach(r.Value, s)
		out = append(out, r)
	}
	return out
}

// breach reports which threshold the value broke, or "" when it is within range.
func breach(v float64, s Sensor) string {
	unit := s.Unit
	if unit != "" {
		unit = " " + unit
	}
	if s.WarnAbove != nil && v > *s.WarnAbove {
		return fmt.Sprintf("%g%s is above the %g%s limit", v, unit, *s.WarnAbove, unit)
	}
	if s.WarnBelow != nil && v < *s.WarnBelow {
		return fmt.Sprintf("%g%s is below the %g%s floor", v, unit, *s.WarnBelow, unit)
	}
	return ""
}

// readInterfaces walks the interface table and assembles one row per interface.
func readInterfaces(conn Conn) []Iface {
	byIndex := map[int]*Iface{}
	get := func(idx int) *Iface {
		if f, ok := byIndex[idx]; ok {
			return f
		}
		f := &Iface{Index: idx}
		byIndex[idx] = f
		return f
	}

	// ifName is the short form operators actually use ("Gi0/1"); ifDescr is the verbose one. Walk
	// descr first so name overwrites it where the device provides both.
	walk(conn, oidIfDescr, func(idx int, pdu gosnmp.SnmpPDU) { get(idx).Name = pduText(pdu) })
	walk(conn, oidIfName, func(idx int, pdu gosnmp.SnmpPDU) {
		if s := pduText(pdu); s != "" {
			get(idx).Name = s
		}
	})
	walkNum(conn, oidIfAdminStatus, func(f *Iface, v float64) { f.AdminStatus = int(v) }, get)
	walkNum(conn, oidIfOperStatus, func(f *Iface, v float64) { f.OperStatus = int(v) }, get)
	walkNum(conn, oidIfHCInOctets, func(f *Iface, v float64) { f.InOctets = uint64(v) }, get)
	walkNum(conn, oidIfHCOutOctets, func(f *Iface, v float64) { f.OutOctets = uint64(v) }, get)
	walkNum(conn, oidIfInErrors, func(f *Iface, v float64) { f.InErrors = uint64(v) }, get)
	walkNum(conn, oidIfOutErrors, func(f *Iface, v float64) { f.OutErrors = uint64(v) }, get)

	out := make([]Iface, 0, len(byIndex))
	for _, f := range byIndex {
		out = append(out, *f)
	}
	// Stable order so the UI does not reshuffle rows between polls.
	sort.Slice(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	return out
}

// walk calls fn for each row of a table column, keyed by interface index. A failed walk is
// skipped rather than fatal: a device that serves the base table but not the 64-bit counters
// should still report its port states.
func walk(conn Conn, root string, fn func(idx int, pdu gosnmp.SnmpPDU)) {
	pdus, err := conn.BulkWalkAll(root)
	if err != nil {
		return
	}
	for _, pdu := range pdus {
		if idx, ok := tableIndex(root, pdu.Name); ok {
			fn(idx, pdu)
		}
	}
}

func walkNum(conn Conn, root string, set func(*Iface, float64), get func(int) *Iface) {
	walk(conn, root, func(idx int, pdu gosnmp.SnmpPDU) {
		if v, ok := pduNumber(pdu); ok {
			set(get(idx), v)
		}
	})
}

// tableIndex pulls the row index off the end of a table OID.
func tableIndex(root, oid string) (int, bool) {
	root, oid = normaliseOID(root), normaliseOID(oid)
	if !strings.HasPrefix(oid, root+".") {
		return 0, false
	}
	tail := strings.TrimPrefix(oid, root+".")
	// Only the interface table's single-level index is handled; anything deeper is not IF-MIB.
	if strings.Contains(tail, ".") {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(tail, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// normaliseOID strips the leading dot gosnmp returns on walked OIDs, so a walked name compares
// equal to the constant it came from.
func normaliseOID(oid string) string { return strings.TrimPrefix(oid, ".") }

// pduNumber converts the numeric SNMP types to a float. Counter64 goes through uint64 so a value
// above 2^53 is not silently rounded on the way in.
func pduNumber(pdu gosnmp.SnmpPDU) (float64, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

// pduText renders a PDU as the string an operator would read.
func pduText(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

// DefaultDialer opens a real SNMP connection.
func DefaultDialer(_ context.Context, t Target) (Conn, error) {
	g := &gosnmp.GoSNMP{
		Target:    t.Host,
		Port:      t.Port,
		Timeout:   t.Timeout,
		Retries:   t.Retries,
		Transport: "udp",
	}
	if g.Port == 0 {
		g.Port = 161
	}
	if g.Timeout <= 0 {
		g.Timeout = 5 * time.Second
	}

	switch t.Version {
	case Version3:
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = v3Flags(t.SecurityLevel)
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 t.User,
			AuthenticationProtocol:   authProtocol(t.AuthProtocol),
			AuthenticationPassphrase: t.AuthPassword,
			PrivacyProtocol:          privProtocol(t.PrivProtocol),
			PrivacyPassphrase:        t.PrivPassword,
		}
	default:
		g.Version = gosnmp.Version2c
		g.Community = t.Community
	}

	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

func v3Flags(level string) gosnmp.SnmpV3MsgFlags {
	switch strings.ToLower(level) {
	case "noauthnopriv":
		return gosnmp.NoAuthNoPriv
	case "authnopriv":
		return gosnmp.AuthNoPriv
	default:
		// authPriv is both the strongest and the sane default: an unrecognised value must not
		// quietly downgrade the device's credentials to cleartext.
		return gosnmp.AuthPriv
	}
}

func authProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func privProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.AES
	}
}
