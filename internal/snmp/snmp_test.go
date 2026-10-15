package snmp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// fakeDevice answers from a table of OID → value, the way a switch would. Walks return every OID
// under the root, with the leading dot gosnmp puts on walked names — which is exactly the detail
// that breaks OID comparison if it is not handled.
type fakeDevice struct {
	values   map[string]any
	getErr   error
	walkErr  error
	noSuch   map[string]bool
	getCalls int
}

func (d *fakeDevice) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	d.getCalls++
	if d.getErr != nil {
		return nil, d.getErr
	}
	pkt := &gosnmp.SnmpPacket{}
	for _, oid := range oids {
		if d.noSuch[oid] {
			pkt.Variables = append(pkt.Variables, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.NoSuchObject})
			continue
		}
		v, ok := d.values[oid]
		if !ok {
			continue
		}
		pkt.Variables = append(pkt.Variables, gosnmp.SnmpPDU{Name: oid, Value: v})
	}
	return pkt, nil
}

func (d *fakeDevice) BulkWalkAll(root string) ([]gosnmp.SnmpPDU, error) {
	if d.walkErr != nil {
		return nil, d.walkErr
	}
	var out []gosnmp.SnmpPDU
	for oid, v := range d.values {
		if strings.HasPrefix(oid, root+".") {
			out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Value: v}) // leading dot, as gosnmp does
		}
	}
	return out, nil
}

func (d *fakeDevice) Close() error { return nil }

func dialer(d *fakeDevice) Dialer {
	return func(context.Context, Target) (Conn, error) { return d, nil }
}

func f(v float64) *float64 { return &v }

func switchDevice() *fakeDevice {
	return &fakeDevice{values: map[string]any{
		oidSysDescr:  "Ruijie RG-S5750 Switch",
		oidSysName:   "sw-lantai3",
		oidSysUptime: uint(360000), // TimeTicks: 3600 s

		oidIfName + ".1":        "Gi0/1",
		oidIfDescr + ".1":       "GigabitEthernet 0/1",
		oidIfAdminStatus + ".1": 1,
		oidIfOperStatus + ".1":  1,
		oidIfHCInOctets + ".1":  uint64(1 << 40),
		oidIfHCOutOctets + ".1": uint64(2 << 40),
		oidIfInErrors + ".1":    uint(3),

		oidIfName + ".2":        "Gi0/2",
		oidIfAdminStatus + ".2": 1,
		oidIfOperStatus + ".2":  2, // admin up, oper down: a real fault
	}}
}

func TestPollReadsStandardTree(t *testing.T) {
	d := switchDevice()
	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, nil, Options{}, dialer(d))

	if !got.Reachable || got.Error != "" {
		t.Fatalf("expected a reachable device, got %+v", got)
	}
	if got.SysName != "sw-lantai3" || !strings.Contains(got.SysDescr, "Ruijie") {
		t.Errorf("identity not read: %+v", got)
	}
	// The TimeTicks trap: 360000 hundredths is one hour, not 360000 seconds.
	if got.UptimeSecs != 3600 {
		t.Errorf("sysUpTime must be converted from hundredths of a second, got %v", got.UptimeSecs)
	}
	// Interfaces are off by default: they are the expensive half.
	if len(got.Ifaces) != 0 {
		t.Errorf("interfaces must not be walked unless asked for, got %d", len(got.Ifaces))
	}
}

func TestPollUnreachableIsAResultNotAnError(t *testing.T) {
	got := Poll(context.Background(), Target{Host: "10.0.0.9"}, nil, Options{},
		func(context.Context, Target) (Conn, error) { return nil, errors.New("i/o timeout") })
	if got.Reachable {
		t.Fatal("a device that cannot be dialled is not reachable")
	}
	if !strings.Contains(got.Error, "10.0.0.9") || !strings.Contains(got.Error, "i/o timeout") {
		t.Fatalf("the error must name the device and the reason, got %q", got.Error)
	}
}

func TestPollDeviceAnswersButNotSNMP(t *testing.T) {
	d := &fakeDevice{getErr: errors.New("request timeout (after 3 retries)")}
	got := Poll(context.Background(), Target{Host: "10.0.0.3"},
		[]Sensor{{Name: "CPU", OID: "1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0"}}, Options{}, dialer(d))

	if got.Reachable || !strings.Contains(got.Error, "retries") {
		t.Fatalf("expected an unreachable result quoting the SNMP error, got %+v", got)
	}
	// One failed Get, not one per sensor: a dead device must not produce a list of identical errors.
	if d.getCalls != 1 {
		t.Errorf("sensors should not be attempted after the base read failed, got %d gets", d.getCalls)
	}
}

// The whole point of the custom-sensor design: CPU and temperature have no standard OID, so the
// operator supplies them and the thresholds are applied to whatever comes back.
func TestCustomSensorsAndThresholds(t *testing.T) {
	d := switchDevice()
	d.values["1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0"] = 91  // CPU %
	d.values["1.3.6.1.4.1.4881.1.1.10.2.36.1.1.2.0"] = 345 // temperature, tenths of a degree
	d.values["1.3.6.1.4.1.4881.1.1.10.2.36.1.1.3.0"] = 4   // free memory, %

	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, []Sensor{
		{Name: "CPU", OID: "1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0", Unit: "%", WarnAbove: f(85)},
		{Name: "Suhu", OID: "1.3.6.1.4.1.4881.1.1.10.2.36.1.1.2.0", Unit: "C", Scale: 0.1, WarnAbove: f(45)},
		{Name: "Memori bebas", OID: "1.3.6.1.4.1.4881.1.1.10.2.36.1.1.3.0", Unit: "%", WarnBelow: f(10)},
	}, Options{}, dialer(d))

	if len(got.Sensors) != 3 {
		t.Fatalf("expected a reading per sensor, got %+v", got.Sensors)
	}
	cpu, temp, mem := got.Sensors[0], got.Sensors[1], got.Sensors[2]

	if cpu.Value != 91 || cpu.Breach == "" {
		t.Errorf("CPU over its limit should breach: %+v", cpu)
	}
	// Scale is what turns a device's 345 into 34.5 °C; without it the reading is nonsense.
	if temp.Value != 34.5 {
		t.Errorf("Scale must be applied, got %v", temp.Value)
	}
	if temp.Breach != "" {
		t.Errorf("34.5C is under the 45C limit and must not breach: %+v", temp)
	}
	// Free memory is the case WarnBelow exists for: here LOW is the fault, and a WarnAbove rule
	// would never fire no matter how close the device came to running out.
	if mem.Breach == "" {
		t.Errorf("4%% free against a 10%% floor should breach: %+v", mem)
	}
	// Readings must stay in the order they were configured, or the UI relabels them.
	if cpu.Name != "CPU" || temp.Name != "Suhu" || mem.Name != "Memori bebas" {
		t.Errorf("sensor order was not preserved: %+v", got.Sensors)
	}
}

// A mistyped OID must not hide the rest of the device behind it.
func TestOneBadSensorDoesNotSpoilThePoll(t *testing.T) {
	d := switchDevice()
	d.values["1.2.3.4.0"] = 7
	d.noSuch = map[string]bool{"9.9.9.9.0": true}

	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, []Sensor{
		{Name: "typo", OID: "9.9.9.9.0"},
		{Name: "good", OID: "1.2.3.4.0"},
	}, Options{}, dialer(d))

	if !got.Reachable || got.UptimeSecs != 3600 {
		t.Fatalf("the device's own readings must survive a bad sensor: %+v", got)
	}
	if got.Sensors[0].Error == "" || !strings.Contains(got.Sensors[0].Error, "9.9.9.9.0") {
		t.Errorf("an absent OID should be reported on that sensor, naming it: %+v", got.Sensors[0])
	}
	if got.Sensors[1].Value != 7 || got.Sensors[1].Error != "" {
		t.Errorf("the good sensor must still be read: %+v", got.Sensors[1])
	}
}

// A sensor that answers with a string is not an error; it just cannot be compared to a threshold.
func TestNonNumericSensorIsKeptAsText(t *testing.T) {
	d := switchDevice()
	d.values["1.2.3.5.0"] = "normal"
	got := Poll(context.Background(), Target{Host: "10.0.0.2"},
		[]Sensor{{Name: "fan", OID: "1.2.3.5.0", WarnAbove: f(1)}}, Options{}, dialer(d))

	r := got.Sensors[0]
	if r.Text != "normal" || r.Error != "" {
		t.Fatalf("a string value should be kept as text, got %+v", r)
	}
	if r.Breach != "" {
		t.Errorf("a non-numeric reading must not be judged against a numeric threshold: %+v", r)
	}
}

func TestInterfaceWalk(t *testing.T) {
	d := switchDevice()
	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, nil, Options{Interfaces: true}, dialer(d))

	if len(got.Ifaces) != 2 {
		t.Fatalf("expected both interfaces, got %+v", got.Ifaces)
	}
	// Stable order, or the UI reshuffles rows between polls.
	if got.Ifaces[0].Index != 1 || got.Ifaces[1].Index != 2 {
		t.Fatalf("interfaces must come back in index order: %+v", got.Ifaces)
	}
	one := got.Ifaces[0]
	// ifName wins over ifDescr: "Gi0/1" is what an operator reads on the switch.
	if one.Name != "Gi0/1" {
		t.Errorf("ifName should win over ifDescr, got %q", one.Name)
	}
	// 64-bit counters must survive as 64-bit.
	if one.InOctets != 1<<40 || one.OutOctets != 2<<40 {
		t.Errorf("high-capacity counters were lost: %+v", one)
	}
	if one.InErrors != 3 {
		t.Errorf("error counters not read: %+v", one)
	}
	if one.Down() {
		t.Error("an up/up port is not down")
	}
	// Admin up, oper down: the combination worth alerting on.
	if !got.Ifaces[1].Down() {
		t.Errorf("admin-up but oper-down is a fault: %+v", got.Ifaces[1])
	}
}

// A port the operator disabled on purpose is not a fault, however loudly it reports down.
func TestAdminDownPortIsNotAFault(t *testing.T) {
	i := Iface{AdminStatus: IfDown, OperStatus: IfDown}
	if i.Down() {
		t.Fatal("a deliberately disabled port must not alert")
	}
}

// A device serving the base table but not the 64-bit counters should still report port state.
func TestPartialInterfaceTableStillReportsState(t *testing.T) {
	d := &fakeDevice{values: map[string]any{
		oidSysUptime:            uint(100),
		oidIfName + ".1":        "Gi0/1",
		oidIfAdminStatus + ".1": 1,
		oidIfOperStatus + ".1":  2,
	}}
	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, nil, Options{Interfaces: true}, dialer(d))
	if len(got.Ifaces) != 1 || !got.Ifaces[0].Down() {
		t.Fatalf("missing counters must not hide a down port: %+v", got.Ifaces)
	}
}

func TestWalkFailureIsNotFatal(t *testing.T) {
	d := switchDevice()
	d.walkErr = errors.New("noSuchName")
	got := Poll(context.Background(), Target{Host: "10.0.0.2"}, nil, Options{Interfaces: true}, dialer(d))
	if !got.Reachable || got.UptimeSecs != 3600 {
		t.Fatalf("a failed interface walk must not fail the poll: %+v", got)
	}
	if len(got.Ifaces) != 0 {
		t.Errorf("expected no interfaces, got %+v", got.Ifaces)
	}
}

// An unrecognised v3 security level must not quietly downgrade the device's credentials.
func TestUnknownV3LevelDefaultsToAuthPriv(t *testing.T) {
	if v3Flags("nonsense") != gosnmp.AuthPriv {
		t.Fatal("an unrecognised security level must default to authPriv, not to cleartext")
	}
	if v3Flags("noAuthNoPriv") != gosnmp.NoAuthNoPriv {
		t.Error("an explicit noAuthNoPriv should be honoured")
	}
}
