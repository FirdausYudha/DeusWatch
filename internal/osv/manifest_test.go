package osv

import (
	"strings"
	"testing"
)

func has(t *testing.T, deps []Dep, want Dep) {
	t.Helper()
	for _, d := range deps {
		if d == want {
			return
		}
	}
	t.Errorf("missing %+v in %+v", want, deps)
}

func TestParsePackageLockV3(t *testing.T) {
	deps := ParseManifest("package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name":"myapp","version":"1.0.0"},
	    "node_modules/lodash": {"version":"4.17.20"},
	    "node_modules/a/node_modules/minimist": {"version":"1.2.5"}
	  }
	}`)
	has(t, deps, Dep{PURLType: "npm", Name: "lodash", Version: "4.17.20"})
	// Nested dependency: the real name is after the LAST node_modules segment.
	has(t, deps, Dep{PURLType: "npm", Name: "minimist", Version: "1.2.5"})
	for _, d := range deps {
		if d.Name == "myapp" {
			t.Error("the root project itself must not be reported as a dependency")
		}
	}
}

func TestParseGoSum(t *testing.T) {
	deps := ParseManifest("go.sum", strings.Join([]string{
		"github.com/pkg/errors v0.9.1 h1:abc=",
		"github.com/pkg/errors v0.9.1/go.mod h1:def=",
		"golang.org/x/net v0.17.0 h1:ghi=",
	}, "\n"))
	has(t, deps, Dep{PURLType: "golang", Name: "github.com/pkg/errors", Version: "0.9.1"})
	has(t, deps, Dep{PURLType: "golang", Name: "golang.org/x/net", Version: "0.17.0"})
	if len(deps) != 2 {
		t.Errorf("the /go.mod line must not add a duplicate: %+v", deps)
	}
}

func TestParseRequirements(t *testing.T) {
	deps := ParseManifest("requirements.txt", strings.Join([]string{
		"# comment",
		"Django==4.2.1",
		"requests[security]==2.31.0",
		"urllib3>=1.0", // unpinned: no exact version to match on
		"-r other.txt",
		"flask==2.0.1 ; python_version < '3.9'",
	}, "\n"))
	has(t, deps, Dep{PURLType: "pypi", Name: "Django", Version: "4.2.1"})
	has(t, deps, Dep{PURLType: "pypi", Name: "requests", Version: "2.31.0"})
	has(t, deps, Dep{PURLType: "pypi", Name: "flask", Version: "2.0.1"})
	for _, d := range deps {
		if d.Name == "urllib3" {
			t.Error("unpinned requirement must be skipped")
		}
	}
}

func TestParseCargoAndGemfile(t *testing.T) {
	cargo := ParseManifest("Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.188\"\n\n[[package]]\nname = \"libc\"\nversion = \"0.2.147\"\n")
	has(t, cargo, Dep{PURLType: "cargo", Name: "serde", Version: "1.0.188"})
	has(t, cargo, Dep{PURLType: "cargo", Name: "libc", Version: "0.2.147"})

	gem := ParseManifest("Gemfile.lock", strings.Join([]string{
		"GEM",
		"  remote: https://rubygems.org/",
		"  specs:",
		"    rack (2.2.4)",
		"    rails (7.0.4)",
		"      actionpack (= 7.0.4)", // transitive constraint, not a resolved version
	}, "\n"))
	has(t, gem, Dep{PURLType: "gem", Name: "rack", Version: "2.2.4"})
	has(t, gem, Dep{PURLType: "gem", Name: "rails", Version: "7.0.4"})
	for _, d := range gem {
		if d.Name == "actionpack" {
			t.Error("indented constraint line must not be treated as a resolved gem")
		}
	}
}

func TestDepPURL(t *testing.T) {
	if got := (Dep{PURLType: "npm", Name: "lodash", Version: "4.17.20"}).PURL(); got != "pkg:npm/lodash@4.17.20" {
		t.Errorf("purl = %q", got)
	}
	if ParseManifest("pom.xml", "<project/>") != nil {
		t.Error("unsupported manifest should yield nil, not an error")
	}
}
