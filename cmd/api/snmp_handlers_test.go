package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A community string is a password with a friendly name: read it and you can read the whole
// device. It must not reach the store in the clear.
func TestSNMPCredentialsAreSealed(t *testing.T) {
	cipher := testCipher(t)
	b := snmpDeviceBody{
		Name: "sw-lantai3", Host: "10.0.0.2", Version: "2c", Community: "r4h4s14-sekali",
	}
	d, err := b.toDevice(cipher)
	if err != nil {
		t.Fatalf("toDevice: %v", err)
	}
	if d.CredsEnc == "" {
		t.Fatal("credentials were not stored at all")
	}
	if strings.Contains(d.CredsEnc, "r4h4s14-sekali") {
		t.Fatalf("the community string survived in the clear: %q", d.CredsEnc)
	}

	plain, err := cipher.Decrypt(d.CredsEnc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var got snmpCredsPayload
	if err := json.Unmarshal([]byte(plain), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Community != "r4h4s14-sekali" {
		t.Fatalf("round-trip lost the community string: %+v", got)
	}
}

func TestSNMPCredentialsRefusedWithoutCipher(t *testing.T) {
	b := snmpDeviceBody{Name: "sw", Host: "10.0.0.2", Community: "public"}
	if _, err := b.toDevice(nil); err == nil {
		t.Fatal("expected a refusal when credentials cannot be encrypted")
	}
	// A device with no credentials still saves fine without a cipher.
	if _, err := (snmpDeviceBody{Name: "sw", Host: "10.0.0.2"}).toDevice(nil); err != nil {
		t.Fatalf("a device without credentials should not need the cipher: %v", err)
	}
}

// A device saved broken does not fail loudly — it shows up later as a fake outage.
func TestSNMPHostValidation(t *testing.T) {
	cases := []struct {
		name, host string
		ok         bool
	}{
		{"ipv4", "10.0.0.2", true},
		{"ipv6", "fd00::1", true},
		{"hostname", "sw-lantai3.rs.local", true},
		{"empty", "", false},
		{"with scheme", "http://10.0.0.2", false},
		{"with port", "10.0.0.2:161", false},
		{"with space", "10.0.0.2 ", false},
		{"trailing dot", "sw.rs.local.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSNMPHost(tc.host)
			if tc.ok && err != nil {
				t.Fatalf("expected %q to be accepted, got %v", tc.host, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected %q to be rejected", tc.host)
			}
		})
	}
}

// v3 without a username cannot authenticate; catching it in the form beats a timeout later.
func TestSNMPv3NeedsAUser(t *testing.T) {
	if _, err := (snmpDeviceBody{Name: "ap", Host: "10.0.1.5", Version: "3"}).toDevice(nil); err == nil {
		t.Fatal("SNMPv3 without a username should be rejected")
	}
	if _, err := (snmpDeviceBody{
		Name: "ap", Host: "10.0.1.5", Version: "3", V3User: "monitor",
	}).toDevice(nil); err != nil {
		t.Fatalf("v3 with a username should be accepted: %v", err)
	}
}

// Half-filled rows are what an empty form row looks like; they are not sensors.
func TestSNMPSensorsDropIncompleteRows(t *testing.T) {
	b := snmpDeviceBody{Sensors: []snmpSensorBody{
		{Name: "CPU", OID: "1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0", Unit: "%"},
		{Name: "", OID: "1.2.3"},  // no name
		{Name: "Suhu", OID: "  "}, // no OID
		{Name: " Fan ", OID: " 1.2.3.4 "},
	}}
	got := b.sensors()
	if len(got) != 2 {
		t.Fatalf("expected the two complete rows, got %+v", got)
	}
	// Whitespace from a pasted OID must not become part of the OID.
	if got[1].Name != "Fan" || got[1].OID != "1.2.3.4" {
		t.Errorf("name and OID should be trimmed: %+v", got[1])
	}
}

// A new device is polled unless the form says otherwise; an explicit false must survive.
func TestSNMPEnabledDefault(t *testing.T) {
	var on snmpDeviceBody
	if err := json.Unmarshal([]byte(`{"name":"sw","host":"10.0.0.2"}`), &on); err != nil {
		t.Fatal(err)
	}
	d, err := on.toDevice(nil)
	if err != nil || !d.Enabled {
		t.Fatalf("omitted enabled should default to on, got %v (%v)", d.Enabled, err)
	}

	var off snmpDeviceBody
	if err := json.Unmarshal([]byte(`{"name":"sw","host":"10.0.0.2","enabled":false}`), &off); err != nil {
		t.Fatal(err)
	}
	if d2, _ := off.toDevice(nil); d2.Enabled {
		t.Fatal("an explicit enabled:false was ignored")
	}
}
