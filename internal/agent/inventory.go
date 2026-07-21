package agent

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Software inventory (Vulnerability Assessment, phase 1). The agent enumerates installed packages
// and the OS/kernel release and ships them to the manager, which later (phase 2) matches them
// against vendor OVAL/USN vulnerability data. Nothing here evaluates vulnerabilities — this is
// purely the "what is installed" collection, the equivalent of Wazuh's syscollector.
//
// The data model captures exactly what OVAL matching needs: the SOURCE package (advisories are
// keyed by source, not binary), the exact version (Debian epoch:upstream-revision), the arch, and
// the OS release + codename (advisories are scoped to a distro release).

// Package is one installed package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	// Source is the source-package name the binary was built from (dpkg ${source:Package}).
	// Vendor advisories are keyed by source package, so this is what phase-2 matching joins on;
	// empty means "same as Name".
	Source string `json:"source,omitempty"`
}

// Inventory is one agent's full software picture at a point in time.
type Inventory struct {
	OSID        string    `json:"os_id"`       // os-release ID: ubuntu | debian | rhel | ...
	OSVersion   string    `json:"os_version"`  // os-release VERSION_ID: 22.04
	OSCodename  string    `json:"os_codename"` // os-release VERSION_CODENAME: jammy | bookworm
	Kernel      string    `json:"kernel"`      // uname -r
	Arch        string    `json:"arch"`        // GOARCH of the agent
	PkgManager  string    `json:"pkg_manager"` // dpkg | rpm | (empty)
	Packages    []Package `json:"packages"`
	CollectedAt time.Time `json:"collected_at"`
}

// CollectInventory gathers the OS release and installed-package list for the host. It is
// best-effort: a missing tool or file yields an empty field rather than an error, so partial data
// is still shipped (the OS release alone is useful, and better than nothing). Currently populates
// packages on Debian/RPM Linux; other platforms still report OS/kernel/arch with no package list.
func CollectInventory(ctx context.Context) Inventory {
	inv := Inventory{Arch: runtime.GOARCH, CollectedAt: time.Now()}

	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			inv.OSID, inv.OSVersion, inv.OSCodename = parseOSRelease(string(b))
		}
		inv.Kernel = invFirstLine(runCmd(ctx, "uname", "-r"))

		// Debian/Ubuntu first (dpkg), then RPM. Whichever tool is present wins.
		if out, ok := tryCmd(ctx, "dpkg-query", "-W",
			"-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\n"); ok {
			inv.PkgManager = "dpkg"
			inv.Packages = parseDpkg(out)
		} else if out, ok := tryCmd(ctx, "rpm", "-qa",
			"--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"); ok {
			inv.PkgManager = "rpm"
			inv.Packages = parseRPM(out)
		}
	} else {
		inv.OSID = runtime.GOOS // windows/darwin: OS is known; package collection is a later phase
	}
	return inv
}

// parseOSRelease extracts ID, VERSION_ID and VERSION_CODENAME from /etc/os-release content. Values
// may be quoted (ID="ubuntu") or bare (ID=debian); both are handled.
func parseOSRelease(content string) (id, version, codename string) {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			version = v
		case "VERSION_CODENAME":
			codename = strings.ToLower(v)
		}
	}
	return id, version, codename
}

// parseDpkg turns `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}'`
// output into packages. A blank source column means the binary IS the source package.
func parseDpkg(out string) []Package {
	var pkgs []Package
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 || f[0] == "" || f[1] == "" {
			continue
		}
		p := Package{Name: f[0], Version: f[1]}
		if len(f) >= 3 {
			p.Arch = f[2]
		}
		if len(f) >= 4 && f[3] != "" && f[3] != f[0] {
			// dpkg prints "source (version)" when the source version differs; keep just the name.
			p.Source = strings.Fields(f[3])[0]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// parseRPM turns `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}'` output into
// packages. The source RPM (e.g. "nginx-1.20.1-14.el9.src.rpm") is reduced to its package name.
func parseRPM(out string) []Package {
	var pkgs []Package
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 || f[0] == "" || f[1] == "" {
			continue
		}
		p := Package{Name: f[0], Version: f[1]}
		if len(f) >= 3 {
			p.Arch = f[2]
		}
		if len(f) >= 4 {
			if src := srcRPMName(f[3]); src != "" && src != f[0] {
				p.Source = src
			}
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// srcRPMName reduces "nginx-1.20.1-14.el9.src.rpm" to "nginx" (strip the trailing -version-release
// and the .src.rpm suffix). An unparseable value is returned as-is.
func srcRPMName(s string) string {
	s = strings.TrimSuffix(s, ".src.rpm")
	// Drop the last two dash-separated fields (version, release).
	parts := strings.Split(s, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return s
}

// --- small exec/file helpers, isolated so the parsers above stay pure & testable ---

func runCmd(ctx context.Context, name string, args ...string) string {
	out, _ := tryCmd(ctx, name, args...)
	return out
}

func tryCmd(ctx context.Context, name string, args ...string) (string, bool) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func invFirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
