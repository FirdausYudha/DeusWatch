package store

// Storage for environmental sensors (gap 6). The judgement lives in internal/envsensor; this holds
// the rows and the live state the latch needs between readings.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"deuswatch/internal/envsensor"
)

// EnvSensor is one measurement point, rules and live state together.
type EnvSensor struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Location  string   `json:"location"`
	Kind      string   `json:"kind"`
	Unit      string   `json:"unit"`
	WarnAbove *float64 `json:"warn_above,omitempty"`
	WarnBelow *float64 `json:"warn_below,omitempty"`
	// IngestKey is returned only to callers holding manage_settings: it is the credential a device
	// presents, so it belongs with the other secrets, not on the public board.
	IngestKey      string     `json:"ingest_key,omitempty"`
	StaleAfterSecs int        `json:"stale_after_secs"`
	Enabled        bool       `json:"enabled"`
	LastValue      *float64   `json:"last_value,omitempty"`
	LastText       string     `json:"last_text,omitempty"`
	LastAt         *time.Time `json:"last_at,omitempty"`
	Breach         string     `json:"breach,omitempty"`
	Alerting       bool       `json:"alerting"`
	StaleAlerting  bool       `json:"stale_alerting"`
	// Stale is computed on read, not stored: whether a sensor is late depends on the clock, and a
	// column would be wrong between the moment it goes quiet and the next sweep.
	Stale    bool   `json:"stale"`
	StaleWhy string `json:"stale_why,omitempty"`
}

func (s EnvSensor) rules() envsensor.Sensor {
	return envsensor.Sensor{
		Name: s.Name, Location: s.Location, Unit: s.Unit,
		WarnAbove: s.WarnAbove, WarnBelow: s.WarnBelow,
		StaleAfter: time.Duration(s.StaleAfterSecs) * time.Second,
	}
}

func (s EnvSensor) state() envsensor.State {
	st := envsensor.State{Alerting: s.Alerting}
	if s.LastAt != nil {
		st.LastAt = *s.LastAt
	}
	return st
}

const envSensorCols = `id, name, location, kind, unit, warn_above, warn_below, ingest_key,
	stale_after_secs, enabled, last_value, last_text, last_at, breach, alerting, stale_alerting`

func scanEnvSensor(sc interface{ Scan(...any) error }) (EnvSensor, error) {
	var e EnvSensor
	err := sc.Scan(&e.ID, &e.Name, &e.Location, &e.Kind, &e.Unit, &e.WarnAbove, &e.WarnBelow,
		&e.IngestKey, &e.StaleAfterSecs, &e.Enabled, &e.LastValue, &e.LastText, &e.LastAt,
		&e.Breach, &e.Alerting, &e.StaleAlerting)
	return e, err
}

// ListEnvSensors returns the board, grouped on screen by location.
//
// withKeys is false for the read-only board: the ingest key is a credential, and a page that
// anybody with view_dashboard can open should not carry the token that lets them write readings.
func (s *Store) ListEnvSensors(ctx context.Context, withKeys bool) ([]EnvSensor, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT `+envSensorCols+`
		  FROM env_sensors ORDER BY location, name`)
	if err != nil {
		return nil, fmt.Errorf("store: list env sensors: %w", err)
	}
	defer rows.Close()
	now := time.Now()
	out := make([]EnvSensor, 0, 16)
	for rows.Next() {
		e, err := scanEnvSensor(rows)
		if err != nil {
			return nil, err
		}
		if e.Enabled {
			e.Stale, e.StaleWhy = envsensor.Stale(e.rules(), e.state(), now)
		}
		if !withKeys {
			e.IngestKey = ""
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SaveEnvSensor creates or updates one sensor. A new sensor gets a generated ingest key: asking an
// operator to invent one produces "sensor1" on half the deployments.
func (s *Store) SaveEnvSensor(ctx context.Context, e EnvSensor) (EnvSensor, error) {
	if strings.TrimSpace(e.Name) == "" {
		return EnvSensor{}, fmt.Errorf("store: a sensor needs a name")
	}
	if e.StaleAfterSecs < 0 {
		e.StaleAfterSecs = 0
	}
	if e.ID == "" {
		key, err := newIngestKey()
		if err != nil {
			return EnvSensor{}, err
		}
		row := s.q(ctx).QueryRow(ctx, `
			INSERT INTO env_sensors (name, location, kind, unit, warn_above, warn_below,
			                         ingest_key, stale_after_secs, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+envSensorCols,
			e.Name, e.Location, e.Kind, e.Unit, e.WarnAbove, e.WarnBelow, key, e.StaleAfterSecs, e.Enabled)
		return scanEnvSensor(row)
	}
	// The ingest key is deliberately NOT updatable here. Rotating a credential is its own action
	// with its own consequence (every device using it stops working), not a side effect of
	// correcting a typo in a room name.
	row := s.q(ctx).QueryRow(ctx, `
		UPDATE env_sensors SET name=$2, location=$3, kind=$4, unit=$5, warn_above=$6, warn_below=$7,
		       stale_after_secs=$8, enabled=$9, updated_at=now()
		 WHERE id=$1::uuid RETURNING `+envSensorCols,
		e.ID, e.Name, e.Location, e.Kind, e.Unit, e.WarnAbove, e.WarnBelow, e.StaleAfterSecs, e.Enabled)
	return scanEnvSensor(row)
}

func (s *Store) DeleteEnvSensor(ctx context.Context, id string) error {
	ct, err := s.q(ctx).Exec(ctx, `DELETE FROM env_sensors WHERE id=$1::uuid`, id)
	if err != nil {
		return fmt.Errorf("store: delete env sensor: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("store: sensor not found")
	}
	return nil
}

// EnvTransition is what a reading changed, so the caller can raise exactly one alert.
type EnvTransition struct {
	Sensor    EnvSensor
	Breach    string
	Recovered bool
	Changed   bool
}

// RecordEnvReading stores one pushed reading and reports whether it changed the alerting state.
//
// Looked up by the ingest key rather than by id: the device knows its key and nothing else, and a
// key that matches no sensor is simply refused. That keeps the write path from needing to trust
// anything the caller says about which sensor it is.
func (s *Store) RecordEnvReading(ctx context.Context, ingestKey string, value *float64, text string) (EnvTransition, error) {
	key := strings.TrimSpace(ingestKey)
	if key == "" {
		return EnvTransition{}, fmt.Errorf("store: an ingest key is required")
	}
	row := s.q(ctx).QueryRow(ctx, `SELECT `+envSensorCols+` FROM env_sensors WHERE ingest_key=$1`, key)
	e, err := scanEnvSensor(row)
	if err != nil {
		return EnvTransition{}, fmt.Errorf("store: unknown ingest key")
	}
	if !e.Enabled {
		return EnvTransition{}, fmt.Errorf("store: sensor %q is disabled", e.Name)
	}

	now := time.Now()
	out := EnvTransition{Sensor: e}
	if value != nil {
		v := envsensor.Evaluate(e.rules(), e.state(), *value)
		out.Breach, out.Recovered, out.Changed = v.Breach, v.Recovered, v.Transition
		e.Alerting, e.Breach = v.Alerting, v.Breach
	}

	if _, err := s.q(ctx).Exec(ctx, `
		INSERT INTO env_readings (time, sensor_id, value, text, breach)
		VALUES ($1, $2::uuid, $3, NULLIF($4,''), NULLIF($5,''))`,
		now, e.ID, value, text, out.Breach); err != nil {
		return EnvTransition{}, fmt.Errorf("store: record reading: %w", err)
	}
	// stale_alerting is cleared here: a reading arriving IS the recovery from silence, and leaving
	// it set would keep a sensor flagged as quiet while it is plainly reporting.
	if _, err := s.q(ctx).Exec(ctx, `
		UPDATE env_sensors SET last_value=$2, last_text=$3, last_at=$4, breach=$5,
		       alerting=$6, stale_alerting=false, updated_at=now()
		 WHERE id=$1::uuid`, e.ID, value, text, now, e.Breach, e.Alerting); err != nil {
		return EnvTransition{}, fmt.Errorf("store: update sensor state: %w", err)
	}
	out.Sensor = e
	return out, nil
}

// StaleEnvSensors returns the sensors that have gone quiet and have not been reported as quiet yet,
// latching them so the sweep raises one alert each rather than one per pass.
func (s *Store) StaleEnvSensors(ctx context.Context) ([]EnvSensor, error) {
	all, err := s.ListEnvSensors(ctx, false)
	if err != nil {
		return nil, err
	}
	out := make([]EnvSensor, 0, 4)
	for _, e := range all {
		if !e.Enabled || !e.Stale || e.StaleAlerting {
			continue
		}
		if _, err := s.q(ctx).Exec(ctx,
			`UPDATE env_sensors SET stale_alerting=true, updated_at=now() WHERE id=$1::uuid`, e.ID); err != nil {
			return nil, fmt.Errorf("store: latch stale sensor: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

// newIngestKey makes a per-sensor credential. 32 bytes, URL-safe, so it survives being pasted into
// a shell script or a vendor's webhook field.
func newIngestKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generate ingest key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
