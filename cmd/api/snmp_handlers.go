package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/secret"
	"deuswatch/internal/store"
)

// SNMP device CRUD.
//
// Credentials are sealed at THIS boundary, like the service checks: the community string and the
// v3 passphrases exist in plaintext only inside the request that carried them. A community string
// is a password that happens to have a friendly name — read it and you can read the whole device.

type snmpSensorBody struct {
	Name      string   `json:"name"`
	OID       string   `json:"oid"`
	Unit      string   `json:"unit"`
	Scale     float64  `json:"scale"`
	WarnAbove *float64 `json:"warn_above"`
	WarnBelow *float64 `json:"warn_below"`
}

type snmpDeviceBody struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Version  string `json:"version"`

	V3User      string `json:"v3_user"`
	V3Level     string `json:"v3_level"`
	V3AuthProto string `json:"v3_auth_proto"`
	V3PrivProto string `json:"v3_priv_proto"`

	// Write-only. Omitted on an edit means "keep what is stored".
	Community    string `json:"community"`
	AuthPassword string `json:"auth_password"`
	PrivPassword string `json:"priv_password"`

	PollSecs      int   `json:"poll_secs"`
	PollIfaces    bool  `json:"poll_ifaces"`
	FailThreshold int   `json:"fail_threshold"`
	Enabled       *bool `json:"enabled"`

	Sensors []snmpSensorBody `json:"sensors"`
}

// snmpCredsPayload is the sealed JSON shape; it must match the worker's snmpCreds.
type snmpCredsPayload struct {
	Community    string `json:"community,omitempty"`
	AuthPassword string `json:"auth_password,omitempty"`
	PrivPassword string `json:"priv_password,omitempty"`
}

func (b snmpDeviceBody) toDevice(cipher *secret.Cipher) (store.SNMPDevice, error) {
	d := store.SNMPDevice{
		Name:          strings.TrimSpace(b.Name),
		Location:      strings.TrimSpace(b.Location),
		Host:          strings.TrimSpace(b.Host),
		Port:          b.Port,
		Version:       strings.TrimSpace(b.Version),
		V3User:        strings.TrimSpace(b.V3User),
		V3Level:       strings.TrimSpace(b.V3Level),
		V3AuthProto:   strings.ToUpper(strings.TrimSpace(b.V3AuthProto)),
		V3PrivProto:   strings.ToUpper(strings.TrimSpace(b.V3PrivProto)),
		PollSecs:      b.PollSecs,
		PollIfaces:    b.PollIfaces,
		FailThreshold: b.FailThreshold,
		Enabled:       b.Enabled == nil || *b.Enabled,
	}
	if d.Name == "" {
		return d, errors.New("name is required")
	}
	if err := validateSNMPHost(d.Host); err != nil {
		return d, err
	}
	if d.Version == "3" && d.V3User == "" {
		return d, errors.New("SNMPv3 needs a username")
	}

	creds := snmpCredsPayload{
		Community:    b.Community,
		AuthPassword: b.AuthPassword,
		PrivPassword: b.PrivPassword,
	}
	if creds != (snmpCredsPayload{}) {
		if cipher == nil {
			// Refuse rather than store a community string in the clear. The operator asked for
			// credentials to be kept; keeping them readable is the worse of the two failures.
			return d, errors.New("cannot store credentials: the secrets cipher is unavailable (set SECRETS_KEY)")
		}
		raw, err := json.Marshal(creds)
		if err != nil {
			return d, errors.New("credentials could not be encoded")
		}
		enc, err := cipher.Encrypt(string(raw))
		if err != nil {
			return d, errors.New("credentials could not be encrypted")
		}
		d.CredsEnc = enc
	}
	return d, nil
}

// validateSNMPHost rejects a target the poller could not use, while the operator is still looking
// at the form. A device saved broken only announces itself later as a fake outage.
func validateSNMPHost(host string) error {
	if host == "" {
		return errors.New("host is required")
	}
	// IP first, and IPv6 before anything rejects a colon: fd00::1 is a perfectly good target and
	// an address full of colons is not a host:port pair.
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.ContainsAny(host, " /:") {
		return errors.New("host must be a bare IP or hostname, with no scheme or port")
	}
	// Not an IP, so it has to look like a hostname the resolver could take.
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return errors.New("host is not a valid hostname")
	}
	return nil
}

func (b snmpDeviceBody) sensors() []store.SNMPSensor {
	out := make([]store.SNMPSensor, 0, len(b.Sensors))
	for _, s := range b.Sensors {
		name, oid := strings.TrimSpace(s.Name), strings.TrimSpace(s.OID)
		if name == "" || oid == "" {
			continue // a half-filled row in the form is not a sensor
		}
		out = append(out, store.SNMPSensor{
			Name: name, OID: oid, Unit: strings.TrimSpace(s.Unit),
			Scale: s.Scale, WarnAbove: s.WarnAbove, WarnBelow: s.WarnBelow,
		})
	}
	return out
}

func snmpDevicesListHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := st.ListSNMPDevices(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func snmpDeviceCreateHandler(st *store.Store, cipher *secret.Cipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b snmpDeviceBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		d, err := b.toDevice(cipher)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := st.CreateSNMPDevice(r.Context(), &d); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := st.ReplaceSNMPSensors(r.Context(), d.ID, b.sensors()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeSNMPDevice(w, st, r, d.ID)
	}
}

func snmpDeviceUpdateHandler(st *store.Store, cipher *secret.Cipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b snmpDeviceBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		d, err := b.toDevice(cipher)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.ID = r.PathValue("id")
		// An edit that does not resend the credentials keeps the stored ones, so changing a poll
		// interval does not silently wipe the community string.
		if err := st.UpdateSNMPDevice(r.Context(), &d); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := st.ReplaceSNMPSensors(r.Context(), d.ID, b.sensors()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeSNMPDevice(w, st, r, d.ID)
	}
}

func snmpDeviceDeleteHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.DeleteSNMPDevice(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// snmpSensorHistoryHandler: GET /api/snmp/sensors/{id}/history?hours=
func snmpSensorHistoryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if v := r.URL.Query().Get("hours"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
				hours = n
			}
		}
		pts, err := st.SNMPSensorHistory(r.Context(), r.PathValue("id"),
			time.Now().Add(-time.Duration(hours)*time.Hour), 2000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, pts)
	}
}

// snmpDeviceIfacesHandler: GET /api/snmp/devices/{id}/interfaces
func snmpDeviceIfacesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := st.SNMPLatestIfaces(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

// writeSNMPDevice answers with the device as STORED, not as submitted: the store clamps the poll
// interval, and an edit that omitted the credentials kept the stored ones, so echoing the request
// would tell the UI the community string had just been dropped.
func writeSNMPDevice(w http.ResponseWriter, st *store.Store, r *http.Request, id string) {
	d, ok, err := st.GetSNMPDevice(r.Context(), id)
	if err != nil || !ok {
		http.Error(w, "saved, but could not be read back", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
