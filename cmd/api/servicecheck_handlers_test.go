package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"deuswatch/internal/secret"
)

func testCipher(t *testing.T) *secret.Cipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("SECRETS_KEY", base64.StdEncoding.EncodeToString(key))
	c, _, err := secret.FromEnv()
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return c
}

// The whole point of sealing at this boundary: the token the operator typed must not be readable
// in what gets handed to the store.
func TestServiceCheckHeadersAreSealed(t *testing.T) {
	cipher := testCipher(t)
	b := serviceCheckBody{
		Name: "BPJS pendaftaran", Kind: "http", Target: "https://api.example.test/peserta",
		Headers: map[string]string{"X-Signature": "sangat-rahasia"},
	}
	c, err := b.toCheck(cipher)
	if err != nil {
		t.Fatalf("toCheck: %v", err)
	}
	if c.HeadersEnc == "" {
		t.Fatal("headers were not stored at all")
	}
	if strings.Contains(c.HeadersEnc, "sangat-rahasia") {
		t.Fatalf("the token survived in the clear: %q", c.HeadersEnc)
	}

	plain, err := cipher.Decrypt(c.HeadersEnc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(plain), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["X-Signature"] != "sangat-rahasia" {
		t.Fatalf("round-trip lost the header: %+v", got)
	}
}

// Storing the credentials readable would be the worse failure, so the save is refused instead.
func TestServiceCheckHeadersRefusedWithoutCipher(t *testing.T) {
	b := serviceCheckBody{
		Name: "x", Kind: "http", Target: "https://a.test/",
		Headers: map[string]string{"Authorization": "Bearer t"},
	}
	if _, err := b.toCheck(nil); err == nil {
		t.Fatal("expected a refusal when credentials cannot be encrypted")
	}
	// A check with no credentials still saves fine without a cipher.
	if _, err := (serviceCheckBody{Name: "x", Kind: "http", Target: "https://a.test/"}).toCheck(nil); err != nil {
		t.Fatalf("a check without credentials should not need the cipher: %v", err)
	}
}

// A check saved broken does not fail loudly — it announces itself later as a fake outage.
func TestServiceCheckTargetValidation(t *testing.T) {
	cases := []struct {
		name, kind, target string
		ok                 bool
	}{
		{"http url", "http", "https://api.test/ping", true},
		{"bare host for http", "http", "api.test", false},
		{"empty", "http", "", false},
		{"tcp host:port", "tcp", "10.0.0.5:5432", true},
		{"tcp without port", "tcp", "10.0.0.5", false},
		{"unknown kind", "icmp", "10.0.0.5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTarget(tc.kind, tc.target)
			if tc.ok && err != nil {
				t.Fatalf("expected %q to be accepted, got %v", tc.target, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected %q to be rejected", tc.target)
			}
		})
	}
}

// A new check is enabled unless the client says otherwise; an explicit false must survive.
func TestServiceCheckEnabledDefault(t *testing.T) {
	base := `{"name":"x","kind":"http","target":"https://a.test/"}`
	var b serviceCheckBody
	if err := json.Unmarshal([]byte(base), &b); err != nil {
		t.Fatal(err)
	}
	c, err := b.toCheck(nil)
	if err != nil || !c.Enabled {
		t.Fatalf("omitted enabled should default to on, got %v (%v)", c.Enabled, err)
	}

	var off serviceCheckBody
	if err := json.Unmarshal([]byte(`{"name":"x","kind":"http","target":"https://a.test/","enabled":false}`), &off); err != nil {
		t.Fatal(err)
	}
	if c2, _ := off.toCheck(nil); c2.Enabled {
		t.Fatal("an explicit enabled:false was ignored")
	}
}
