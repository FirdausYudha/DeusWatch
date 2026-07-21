package agent

import "testing"

func TestParseOSRelease(t *testing.T) {
	content := `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian`
	id, ver, codename := parseOSRelease(content)
	if id != "ubuntu" || ver != "22.04" || codename != "jammy" {
		t.Fatalf("got id=%q ver=%q codename=%q", id, ver, codename)
	}
}

// TestParseDpkg pins the exact field layout the collector requests, including that the SOURCE
// package (what phase-2 OVAL matching joins on) is captured only when it differs from the binary
// name.
func TestParseDpkg(t *testing.T) {
	// name \t version \t arch \t source
	out := "nginx-core\t1.18.0-6ubuntu14.4\tamd64\tnginx\n" +
		"bash\t5.1-6ubuntu1\tamd64\tbash\n" + // source == name → Source should be empty
		"libssl3\t3.0.2-0ubuntu1.15\tamd64\topenssl\n" +
		"\t\t\t\n" + // junk line, must be skipped
		"linux-image-generic\t5.15.0.101.98\tamd64\tlinux-meta\n"
	pkgs := parseDpkg(out)
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d: %+v", len(pkgs), pkgs)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if p := byName["libssl3"]; p.Version != "3.0.2-0ubuntu1.15" || p.Source != "openssl" || p.Arch != "amd64" {
		t.Fatalf("libssl3 parsed wrong: %+v", p)
	}
	if p := byName["bash"]; p.Source != "" {
		t.Fatalf("when source == binary name, Source must be empty; got %q", p.Source)
	}
	if p := byName["nginx-core"]; p.Source != "nginx" {
		t.Fatalf("nginx-core source should be nginx, got %q", p.Source)
	}
}

func TestParseRPM(t *testing.T) {
	out := "nginx\t1.20.1-14.el9\tx86_64\tnginx-1.20.1-14.el9.src.rpm\n" +
		"openssl-libs\t3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n"
	pkgs := parseRPM(out)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "nginx" || pkgs[0].Version != "1.20.1-14.el9" {
		t.Fatalf("nginx parsed wrong: %+v", pkgs[0])
	}
	// source rpm reduces to the package name; when it equals the binary name it is left empty.
	if pkgs[0].Source != "" {
		t.Fatalf("nginx source == name should be empty, got %q", pkgs[0].Source)
	}
	if pkgs[1].Source != "openssl" {
		t.Fatalf("openssl-libs should map to source 'openssl', got %q", pkgs[1].Source)
	}
}

func TestSrcRPMName(t *testing.T) {
	cases := map[string]string{
		"nginx-1.20.1-14.el9.src.rpm":       "nginx",
		"openssl-3.0.7-27.el9.src.rpm":      "openssl",
		"glibc-common-2.34-100.el9.src.rpm": "glibc-common",
	}
	for in, want := range cases {
		if got := srcRPMName(in); got != want {
			t.Fatalf("srcRPMName(%q) = %q, want %q", in, got, want)
		}
	}
}
