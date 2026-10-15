package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/secret"
	"deuswatch/internal/selfhealth"
	"deuswatch/internal/snmp"
	"deuswatch/internal/store"
	"deuswatch/internal/worker"
)

// SNMP polling (gap 7 of the hospital field insight).
//
// Same scheduling shape as the service-health prober: one ticker that scans for devices whose
// interval has elapsed, rather than a goroutine per device. Devices are added and edited live from
// the UI, and a goroutine-per-device design has to chase every change to avoid leaking a poller or
// polling a deleted switch.

const (
	snmpTick = 5 * time.Second
	// Polls run in parallel so one unreachable switch sitting on its UDP timeout does not delay
	// every device behind it — exactly the situation this feature exists to report.
	snmpConcurrency = 8
	// SNMP is UDP: a lost packet is ordinary, so a retry is worth more here than it would be over
	// TCP, and the per-device fail_threshold handles what the retries do not.
	snmpTimeout = 5 * time.Second
	snmpRetries = 1
)

func runSNMPPoll(ctx context.Context, st *store.Store, cipher *secret.Cipher,
	onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	log.Printf("worker: SNMP poller active (scan every %s)", snmpTick)
	t := time.NewTicker(snmpTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pollDueDevices(ctx, st, cipher, onAlert, annotate)
		}
	}
}

func pollDueDevices(ctx context.Context, st *store.Store, cipher *secret.Cipher,
	onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	lc, cancel := context.WithTimeout(ctx, 30*time.Second)
	devices, err := st.EnabledSNMPDevices(lc)
	cancel()
	if err != nil {
		log.Printf("worker: load snmp devices: %v", err)
		return
	}

	now := time.Now()
	due := make([]store.SNMPDevice, 0, len(devices))
	for _, d := range devices {
		if d.LastPolledAt == nil ||
			now.Sub(*d.LastPolledAt) >= time.Duration(d.PollSecs)*time.Second {
			due = append(due, d)
		}
	}
	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, snmpConcurrency)
	var wg sync.WaitGroup
	for _, d := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(d store.SNMPDevice) {
			defer wg.Done()
			defer func() { <-sem }()
			pollOneDevice(ctx, st, cipher, d, onAlert, annotate)
		}(d)
	}
	wg.Wait()
}

// snmpCreds is the sealed JSON holding a device's secrets.
type snmpCreds struct {
	Community    string `json:"community,omitempty"`
	AuthPassword string `json:"auth_password,omitempty"`
	PrivPassword string `json:"priv_password,omitempty"`
}

func pollOneDevice(ctx context.Context, st *store.Store, cipher *secret.Cipher,
	d store.SNMPDevice, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	creds, err := decodeSNMPCreds(cipher, d.CredsEnc)
	if err != nil {
		// Deliberately NOT recorded as a failed poll. Polling without the community string gets a
		// timeout and would report a perfectly healthy switch as down, sending somebody to the
		// rack to debug a device that is fine.
		log.Printf("worker: snmp device %q skipped: %v", d.Name, err)
		return
	}

	sensors := make([]snmp.Sensor, 0, len(d.Sensors))
	for _, s := range d.Sensors {
		sensors = append(sensors, snmp.Sensor{
			Name: s.Name, OID: s.OID, Unit: s.Unit, Scale: s.Scale,
			WarnAbove: s.WarnAbove, WarnBelow: s.WarnBelow,
		})
	}

	res := snmp.Poll(ctx, snmp.Target{
		Host:          d.Host,
		Port:          uint16(d.Port),
		Version:       d.Version,
		Community:     creds.Community,
		SecurityLevel: d.V3Level,
		User:          d.V3User,
		AuthProtocol:  d.V3AuthProto,
		AuthPassword:  creds.AuthPassword,
		PrivProtocol:  d.V3PrivProto,
		PrivPassword:  creds.PrivPassword,
		Timeout:       snmpTimeout,
		Retries:       snmpRetries,
	}, sensors, snmp.Options{Interfaces: d.PollIfaces}, nil)

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	transition, after, err := st.RecordSNMPPoll(rctx, d.ID, buildPollResult(d, res))
	if err != nil {
		log.Printf("worker: record snmp poll for %q: %v", d.Name, err)
		return
	}

	emitSNMPAlerts(rctx, st, d, res, transition, after, onAlert, annotate)
}

// buildPollResult maps the poller's output onto the store's shape, pairing each reading back to
// the sensor row it came from. Poll returns readings in the order the sensors were given, which
// is the order they were loaded in — so the index is the link.
func buildPollResult(d store.SNMPDevice, res snmp.Result) store.SNMPPollResult {
	out := store.SNMPPollResult{
		OK:         res.Reachable,
		Error:      res.Error,
		SysName:    res.SysName,
		SysDescr:   res.SysDescr,
		UptimeSecs: int64(res.UptimeSecs),
	}
	for i, r := range res.Sensors {
		if i >= len(d.Sensors) {
			break
		}
		rd := store.SNMPSensorReading{SensorID: d.Sensors[i].ID, Text: r.Text, Breach: r.Breach}
		// A sensor that could not be read stores no value rather than a zero: a temperature
		// recorded as 0 °C because the OID was wrong is worse than a gap in the chart.
		if r.Error == "" && r.Text == "" {
			v := r.Value
			rd.Value = &v
		} else if r.Error != "" {
			rd.Breach = r.Error
		}
		out.Readings = append(out.Readings, rd)
	}
	for _, f := range res.Ifaces {
		out.Ifaces = append(out.Ifaces, store.SNMPIface{
			Index: f.Index, Name: f.Name,
			AdminStatus: f.AdminStatus, OperStatus: f.OperStatus,
			InOctets:  int64(f.InOctets),
			OutOctets: int64(f.OutOctets),
			InErrors:  int64(f.InErrors),
			OutErrors: int64(f.OutErrors),
		})
	}
	return out
}

// emitSNMPAlerts raises the device up/down alert and, separately, one alert per sensor that has
// just broken its threshold.
func emitSNMPAlerts(ctx context.Context, st *store.Store, d store.SNMPDevice, res snmp.Result,
	transition string, after store.SNMPDevice, onAlert worker.AlertHook, annotate worker.AlertAnnotator) {

	send := func(ev *ingest.Event) {
		if annotate != nil {
			annotate(ev)
		}
		if err := st.InsertEvent(ctx, ev); err != nil {
			log.Printf("worker: store snmp alert: %v", err)
			return
		}
		if onAlert != nil {
			onAlert(ctx, ev)
		}
	}

	if transition != store.TransitionNone {
		send(selfhealth.SNMPDeviceEvent(time.Now(), after.Name, after.Host, after.Location,
			transition == store.TransitionDown, after.LastError, after.ConsecFailures))
		log.Printf("worker: snmp device %q (%s) -> %s", after.Name, after.Host, transition)
	}

	// Sensor breaches only matter when the device answered; on an unreachable device every
	// sensor "fails" and firing one alert each would bury the one that says the switch is down.
	if !res.Reachable {
		return
	}
	for _, r := range res.Sensors {
		if r.Breach == "" {
			continue
		}
		send(selfhealth.SNMPSensorEvent(time.Now(), d.Name, d.Host, d.Location, r.Name, r.Breach))
	}
}

// decodeSNMPCreds unseals a device's secrets. No credentials is an error rather than a silent
// anonymous poll: v2c without a community string reaches nothing, and the resulting timeout would
// be reported as the device being down.
func decodeSNMPCreds(cipher *secret.Cipher, enc string) (snmpCreds, error) {
	var c snmpCreds
	if enc == "" {
		return c, nil
	}
	if cipher == nil {
		return c, fmt.Errorf("credentials are stored but the secrets cipher is unavailable (set SECRETS_KEY)")
	}
	plain, err := cipher.Decrypt(enc)
	if err != nil {
		return c, fmt.Errorf("stored credentials could not be decrypted: %w", err)
	}
	if err := json.Unmarshal([]byte(plain), &c); err != nil {
		return c, fmt.Errorf("stored credentials are not a JSON object: %w", err)
	}
	return c, nil
}
