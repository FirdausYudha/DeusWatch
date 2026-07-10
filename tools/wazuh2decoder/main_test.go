package main

import (
	"regexp"
	"testing"
)

func TestOS2RE2InvertedDot(t *testing.T) {
	cases := map[string]string{
		`\.+$`:             `.+$`, // os "any char" -> RE2 .
		`aborted:\s(\.+)$`: `aborted:\s(.+)$`,
		`192.168.0.1`:      `192\.168\.0\.1`, // os literal dot -> RE2 \.
		`\p`:               `[[:punct:]]`,
		`(\d\d\d)\s(\S+)`:  `(\d\d\d)\s(\S+)`,
		`User (\.+) not`:   `User (.+) not`,
	}
	for in, want := range cases {
		if got := os2re2(in); got != want {
			t.Fatalf("os2re2(%q) = %q, want %q", in, got, want)
		}
		if _, err := regexp.Compile(os2re2(in)); err != nil {
			t.Fatalf("os2re2(%q) does not compile: %v", in, err)
		}
	}
}

func TestNameGroups(t *testing.T) {
	got, err := nameGroups(`for (\S+) from (\S+) port`, []string{"user", "srcip"})
	if err != nil {
		t.Fatal(err)
	}
	want := `for (?P<user_name>\S+) from (?P<source_ip>\S+) port`
	if got != want {
		t.Fatalf("nameGroups = %q, want %q", got, want)
	}
	// A real Wazuh sshd 'Accepted' regex round-trips into a working DeusWatch decoder.
	re2, ok := toRE2(`^ \S+ for (\S+) from (\S+) port `, "")
	if !ok {
		t.Fatal("toRE2 failed")
	}
	named, err := nameGroups(re2, []string{"user", "srcip"})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(named)
	m := re.FindStringSubmatch(` password for root from 1.2.3.4 port `)
	if m == nil {
		t.Fatal("converted sshd regex did not match a real line")
	}
}
