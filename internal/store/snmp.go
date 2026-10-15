package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SNMP device and sensor storage (gap 7 of the hospital field insight).
//
// The split between columns and rows here is the whole design: what SNMP standardises (uptime,
// identity, the interface table) is columns on the device, and what it does not (CPU, temperature,
// PSU state — no standard OID exists for any of them) is rows in snmp_sensors, supplied by the
// operator. See migrations/000076.

// SNMPDevice is one polled network device.
type SNMPDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Version  string `json:"version"`

	V3User      string `json:"v3_user"`
	V3Level     string `json:"v3_level"`
	V3AuthProto string `json:"v3_auth_proto"`
	V3PrivProto string `json:"v3_priv_proto"`

	// CredsEnc is the sealed JSON holding the community string and the v3 passphrases. Never
	// serialised: a community string is a password with a friendly name.
	CredsEnc string `json:"-"`
	// HasCreds tells the UI that credentials are stored without revealing them.
	HasCreds bool `json:"has_creds"`

	PollSecs      int  `json:"poll_secs"`
	PollIfaces    bool `json:"poll_ifaces"`
	FailThreshold int  `json:"fail_threshold"`
	Enabled       bool `json:"enabled"`

	LastPolledAt   *time.Time `json:"last_polled_at"`
	LastOK         *bool      `json:"last_ok"`
	LastError      string     `json:"last_error"`
	SysName        string     `json:"sys_name"`
	SysDescr       string     `json:"sys_descr"`
	UptimeSecs     int64      `json:"uptime_secs"`
	ConsecFailures int        `json:"consec_failures"`
	Alerting       bool       `json:"alerting"`
	UpdatedAt      time.Time  `json:"updated_at"`

	// Sensors is filled by the list and get paths so one read serves the whole board.
	Sensors []SNMPSensor `json:"sensors"`
}

// SNMPSensor is one operator-defined OID on a device.
type SNMPSensor struct {
	ID        string   `json:"id"`
	DeviceID  string   `json:"device_id"`
	Name      string   `json:"name"`
	OID       string   `json:"oid"`
	Unit      string   `json:"unit"`
	Scale     float64  `json:"scale"`
	WarnAbove *float64 `json:"warn_above"`
	WarnBelow *float64 `json:"warn_below"`
	Position  int      `json:"position"`

	// Latest reading, joined in for the board. Nil when the sensor has never been read.
	LastValue  *float64   `json:"last_value"`
	LastText   string     `json:"last_text"`
	LastBreach string     `json:"last_breach"`
	LastAt     *time.Time `json:"last_at"`
}

// SNMPReading is one historical sample of one sensor.
type SNMPReading struct {
	Time   time.Time `json:"time"`
	Value  *float64  `json:"value"`
	Text   string    `json:"text,omitempty"`
	Breach string    `json:"breach,omitempty"`
}

// SNMPIface is the latest sample of one interface.
type SNMPIface struct {
	Time        time.Time `json:"time"`
	Index       int       `json:"index"`
	Name        string    `json:"name"`
	AdminStatus int       `json:"admin_status"`
	OperStatus  int       `json:"oper_status"`
	InOctets    int64     `json:"in_octets"`
	OutOctets   int64     `json:"out_octets"`
	InErrors    int64     `json:"in_errors"`
	OutErrors   int64     `json:"out_errors"`
}

// SNMPPollResult is what the poller observed, in the shape the store records.
type SNMPPollResult struct {
	OK         bool
	Error      string
	SysName    string
	SysDescr   string
	UptimeSecs int64
	Readings   []SNMPSensorReading
	Ifaces     []SNMPIface
}

// SNMPSensorReading ties one reading to the sensor row it came from.
type SNMPSensorReading struct {
	SensorID string
	Value    *float64
	Text     string
	Breach   string
}

const snmpDeviceCols = `id, name, location, host, port, version,
	v3_user, v3_level, v3_auth_proto, v3_priv_proto, COALESCE(creds_enc,''),
	poll_secs, poll_ifaces, fail_threshold, enabled,
	last_polled_at, last_ok, COALESCE(last_error,''), sys_name, sys_descr, uptime_secs,
	consec_failures, alerting, updated_at`

func scanSNMPDevice(row pgx.Row) (SNMPDevice, error) {
	var d SNMPDevice
	err := row.Scan(&d.ID, &d.Name, &d.Location, &d.Host, &d.Port, &d.Version,
		&d.V3User, &d.V3Level, &d.V3AuthProto, &d.V3PrivProto, &d.CredsEnc,
		&d.PollSecs, &d.PollIfaces, &d.FailThreshold, &d.Enabled,
		&d.LastPolledAt, &d.LastOK, &d.LastError, &d.SysName, &d.SysDescr, &d.UptimeSecs,
		&d.ConsecFailures, &d.Alerting, &d.UpdatedAt)
	d.HasCreds = d.CredsEnc != ""
	return d, err
}

// normalise clamps the values the UI could get wrong before they reach the poller.
func (d *SNMPDevice) normalise() {
	if d.Port <= 0 || d.Port > 65535 {
		d.Port = 161
	}
	if d.Version != "3" {
		d.Version = "2c"
	}
	// A floor of 10s: SNMP polling is the kind of thing somebody sets to 1 while testing and then
	// forgets, and a switch asked 60 times a minute has a real CPU cost of its own.
	if d.PollSecs < 10 {
		d.PollSecs = 10
	}
	if d.PollSecs > 86400 {
		d.PollSecs = 86400
	}
	if d.FailThreshold < 1 {
		d.FailThreshold = 1
	}
	if d.FailThreshold > 100 {
		d.FailThreshold = 100
	}
}

// ListSNMPDevices returns every device with its sensors and their latest readings.
func (s *Store) ListSNMPDevices(ctx context.Context) ([]SNMPDevice, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+snmpDeviceCols+` FROM snmp_devices ORDER BY location, name`)
	if err != nil {
		return nil, fmt.Errorf("store: list snmp devices: %w", err)
	}
	defer rows.Close()
	out := make([]SNMPDevice, 0, 16)
	for rows.Next() {
		d, serr := scanSNMPDevice(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachSensors(ctx, out)
}

// EnabledSNMPDevices returns the devices the poller should visit, with their sensors.
func (s *Store) EnabledSNMPDevices(ctx context.Context) ([]SNMPDevice, error) {
	rows, err := s.q(ctx).Query(ctx,
		`SELECT `+snmpDeviceCols+` FROM snmp_devices WHERE enabled ORDER BY location, name`)
	if err != nil {
		return nil, fmt.Errorf("store: enabled snmp devices: %w", err)
	}
	defer rows.Close()
	out := make([]SNMPDevice, 0, 16)
	for rows.Next() {
		d, serr := scanSNMPDevice(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.attachSensors(ctx, out)
}

// GetSNMPDevice returns one device with its sensors. ok=false (no error) when absent.
func (s *Store) GetSNMPDevice(ctx context.Context, id string) (SNMPDevice, bool, error) {
	d, err := scanSNMPDevice(s.q(ctx).QueryRow(ctx,
		`SELECT `+snmpDeviceCols+` FROM snmp_devices WHERE id = $1`, id))
	if err == pgx.ErrNoRows {
		return SNMPDevice{}, false, nil
	}
	if err != nil {
		return SNMPDevice{}, false, fmt.Errorf("store: get snmp device: %w", err)
	}
	withSensors, err := s.attachSensors(ctx, []SNMPDevice{d})
	if err != nil {
		return SNMPDevice{}, false, err
	}
	return withSensors[0], true, nil
}

// attachSensors fills in each device's sensors and their latest reading in one pass, rather than
// a query per device: twenty switches with six sensors each would otherwise be 120 round trips to
// draw one page.
func (s *Store) attachSensors(ctx context.Context, devices []SNMPDevice) ([]SNMPDevice, error) {
	if len(devices) == 0 {
		return devices, nil
	}
	ids := make([]string, len(devices))
	for i, d := range devices {
		ids[i] = d.ID
	}
	// Scoped to the devices asked for, not the whole table: the poller calls this for ONE device
	// on every poll, and an unscoped scan would mean twenty devices doing twenty full sensor
	// scans every cycle.
	rows, err := s.q(ctx).Query(ctx, `
		SELECT s.id, s.device_id, s.name, s.oid, s.unit, s.scale, s.warn_above, s.warn_below,
		       s.position, r.value, COALESCE(r.text,''), COALESCE(r.breach,''), r.time
		  FROM snmp_sensors s
		  LEFT JOIN LATERAL (
		      SELECT value, text, breach, time FROM snmp_readings
		       WHERE sensor_id = s.id ORDER BY time DESC LIMIT 1
		  ) r ON TRUE
		 WHERE s.device_id = ANY($1)
		 ORDER BY s.device_id, s.position, s.name`, ids)
	if err != nil {
		return nil, fmt.Errorf("store: list snmp sensors: %w", err)
	}
	defer rows.Close()

	byDevice := map[string][]SNMPSensor{}
	for rows.Next() {
		var x SNMPSensor
		if err := rows.Scan(&x.ID, &x.DeviceID, &x.Name, &x.OID, &x.Unit, &x.Scale,
			&x.WarnAbove, &x.WarnBelow, &x.Position,
			&x.LastValue, &x.LastText, &x.LastBreach, &x.LastAt); err != nil {
			return nil, err
		}
		byDevice[x.DeviceID] = append(byDevice[x.DeviceID], x)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range devices {
		devices[i].Sensors = byDevice[devices[i].ID]
		if devices[i].Sensors == nil {
			devices[i].Sensors = []SNMPSensor{}
		}
	}
	return devices, nil
}

// CreateSNMPDevice inserts a device and returns it with its id filled in.
func (s *Store) CreateSNMPDevice(ctx context.Context, d *SNMPDevice) error {
	d.normalise()
	return s.q(ctx).QueryRow(ctx, `
		INSERT INTO snmp_devices
		  (name, location, host, port, version, v3_user, v3_level, v3_auth_proto, v3_priv_proto,
		   creds_enc, poll_secs, poll_ifaces, fail_threshold, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),$11,$12,$13,$14)
		RETURNING id`,
		d.Name, d.Location, d.Host, d.Port, d.Version, d.V3User, d.V3Level, d.V3AuthProto,
		d.V3PrivProto, d.CredsEnc, d.PollSecs, d.PollIfaces, d.FailThreshold, d.Enabled).
		Scan(&d.ID)
}

// UpdateSNMPDevice saves an edit. An empty CredsEnc KEEPS the stored credentials: changing a poll
// interval must not silently wipe the community string, because the next poll would then fail and
// the cause would look like a network problem.
func (s *Store) UpdateSNMPDevice(ctx context.Context, d *SNMPDevice) error {
	d.normalise()
	_, err := s.q(ctx).Exec(ctx, `
		UPDATE snmp_devices SET
		  name=$2, location=$3, host=$4, port=$5, version=$6,
		  v3_user=$7, v3_level=$8, v3_auth_proto=$9, v3_priv_proto=$10,
		  creds_enc=COALESCE(NULLIF($11,''), creds_enc),
		  poll_secs=$12, poll_ifaces=$13, fail_threshold=$14, enabled=$15, updated_at=now()
		WHERE id=$1`,
		d.ID, d.Name, d.Location, d.Host, d.Port, d.Version, d.V3User, d.V3Level,
		d.V3AuthProto, d.V3PrivProto, d.CredsEnc, d.PollSecs, d.PollIfaces,
		d.FailThreshold, d.Enabled)
	if err != nil {
		return fmt.Errorf("store: update snmp device: %w", err)
	}
	return nil
}

func (s *Store) DeleteSNMPDevice(ctx context.Context, id string) error {
	if _, err := s.q(ctx).Exec(ctx, `DELETE FROM snmp_devices WHERE id=$1`, id); err != nil {
		return fmt.Errorf("store: delete snmp device: %w", err)
	}
	return nil
}

// ReplaceSNMPSensors swaps a device's whole sensor list in one transaction.
//
// Replace rather than patch: the UI edits the list as a list, and a diff would have to answer what
// an edited OID means for the history recorded under the old one. Deleting the row takes its
// readings with it (ON DELETE CASCADE is not set on readings, but they are keyed by sensor_id and
// age out), which is the honest outcome — a sensor pointed at a new OID is a new measurement.
func (s *Store) ReplaceSNMPSensors(ctx context.Context, deviceID string, sensors []SNMPSensor) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: replace snmp sensors: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM snmp_sensors WHERE device_id=$1`, deviceID); err != nil {
		return fmt.Errorf("store: clear snmp sensors: %w", err)
	}
	for i, x := range sensors {
		if x.Scale == 0 {
			x.Scale = 1
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO snmp_sensors (device_id, name, oid, unit, scale, warn_above, warn_below, position)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			deviceID, x.Name, x.OID, x.Unit, x.Scale, x.WarnAbove, x.WarnBelow, i); err != nil {
			return fmt.Errorf("store: insert snmp sensor %q: %w", x.Name, err)
		}
	}
	return tx.Commit(ctx)
}

// RecordSNMPPoll stores one poll and advances the device's live state, returning the up/down
// transition. Same latch as the service checks: one outage produces one alert and one recovery,
// not one per poll interval.
func (s *Store) RecordSNMPPoll(ctx context.Context, id string, r SNMPPollResult) (string, SNMPDevice, error) {
	cur, ok, err := s.GetSNMPDevice(ctx, id)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("store: snmp device %s not found", id)
		}
		return TransitionNone, SNMPDevice{}, err
	}

	for _, rd := range r.Readings {
		if _, err := s.q(ctx).Exec(ctx, `
			INSERT INTO snmp_readings (time, device_id, sensor_id, value, text, breach)
			VALUES (now(), $1, $2, $3, NULLIF($4,''), NULLIF($5,''))`,
			id, rd.SensorID, rd.Value, rd.Text, rd.Breach); err != nil {
			return TransitionNone, cur, fmt.Errorf("store: record snmp reading: %w", err)
		}
	}
	for _, f := range r.Ifaces {
		if _, err := s.q(ctx).Exec(ctx, `
			INSERT INTO snmp_iface_samples
			  (time, device_id, if_index, name, admin_status, oper_status,
			   in_octets, out_octets, in_errors, out_errors)
			VALUES (now(),$1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			id, f.Index, f.Name, f.AdminStatus, f.OperStatus,
			f.InOctets, f.OutOctets, f.InErrors, f.OutErrors); err != nil {
			return TransitionNone, cur, fmt.Errorf("store: record snmp interface: %w", err)
		}
	}

	transition := TransitionNone
	consec := cur.ConsecFailures
	alerting := cur.Alerting
	if r.OK {
		consec = 0
		if alerting {
			alerting = false
			transition = TransitionRecovered
		}
	} else {
		consec++
		if !alerting && consec >= cur.FailThreshold {
			alerting = true
			transition = TransitionDown
		}
	}

	// Identity and uptime are only overwritten on a SUCCESSFUL poll. A failed poll knows nothing
	// about the device, and blanking its name because a UDP packet was lost would make the board
	// forget which switch the row is.
	if _, err := s.q(ctx).Exec(ctx, `
		UPDATE snmp_devices SET
		  last_polled_at=now(), last_ok=$2, last_error=NULLIF($3,''),
		  sys_name   = CASE WHEN $2 THEN $4 ELSE sys_name END,
		  sys_descr  = CASE WHEN $2 THEN $5 ELSE sys_descr END,
		  uptime_secs= CASE WHEN $2 THEN $6 ELSE uptime_secs END,
		  consec_failures=$7, alerting=$8
		WHERE id=$1`,
		id, r.OK, r.Error, r.SysName, r.SysDescr, r.UptimeSecs, consec, alerting); err != nil {
		return TransitionNone, cur, fmt.Errorf("store: update snmp device state: %w", err)
	}

	now := time.Now()
	cur.LastPolledAt, cur.LastOK, cur.LastError = &now, &r.OK, r.Error
	if r.OK {
		cur.SysName, cur.SysDescr, cur.UptimeSecs = r.SysName, r.SysDescr, r.UptimeSecs
	}
	cur.ConsecFailures, cur.Alerting = consec, alerting
	return transition, cur, nil
}

// SNMPSensorHistory returns one sensor's samples, oldest first so a chart can plot them directly.
func (s *Store) SNMPSensorHistory(ctx context.Context, sensorID string, since time.Time, limit int) ([]SNMPReading, error) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT time, value, COALESCE(text,''), COALESCE(breach,'')
		  FROM snmp_readings WHERE sensor_id=$1 AND time >= $2
		 ORDER BY time LIMIT $3`, sensorID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("store: snmp sensor history: %w", err)
	}
	defer rows.Close()
	out := make([]SNMPReading, 0, 128)
	for rows.Next() {
		var p SNMPReading
		if err := rows.Scan(&p.Time, &p.Value, &p.Text, &p.Breach); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SNMPLatestIfaces returns the most recent sample of each interface on a device.
func (s *Store) SNMPLatestIfaces(ctx context.Context, deviceID string) ([]SNMPIface, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT DISTINCT ON (if_index)
		       time, if_index, name, admin_status, oper_status,
		       in_octets, out_octets, in_errors, out_errors
		  FROM snmp_iface_samples WHERE device_id=$1
		 ORDER BY if_index, time DESC`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("store: snmp interfaces: %w", err)
	}
	defer rows.Close()
	out := make([]SNMPIface, 0, 48)
	for rows.Next() {
		var f SNMPIface
		if err := rows.Scan(&f.Time, &f.Index, &f.Name, &f.AdminStatus, &f.OperStatus,
			&f.InOctets, &f.OutOctets, &f.InErrors, &f.OutErrors); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
