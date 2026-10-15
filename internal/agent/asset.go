package agent

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Hardware asset facts: the ITIL "asset management" half of an inventory.
//
// A hospital IT team runs its asset register out of the same tool as its tickets, and the fields
// that register wants are not the software ones. They are the computer's name, its brand and
// model, and above all the SERIAL NUMBER, which is what a warranty claim, an audit and a physical
// stock-take are all keyed on. The existing inventory collected installed packages for
// vulnerability matching and none of this, so an asset register still had to be typed by hand.
//
// It rides the inventory transport that already exists (agent -> POST /v1/inventory ->
// ReplaceInventory) rather than adding a second report: the data is collected at the same moment,
// changes at the same (slow) rate, and belongs to the same row.
//
// Best-effort, like the rest of the inventory. Every field is independent, so a missing tool or an
// unreadable DMI file leaves that one field empty instead of failing the report. On Linux the DMI
// serial is root-only, so an agent running unprivileged reports everything else and leaves the
// serial blank, which is honest; the alternative, a hard error, would cost the fields it could read.

// collectAsset fills the hardware-asset fields in place.
func (inv *Inventory) collectAsset(ctx context.Context) {
	inv.Hostname, _ = os.Hostname()
	inv.CPUCores = runtime.NumCPU()
	inv.PrimaryIP, inv.PrimaryMAC = primaryInterface()

	switch runtime.GOOS {
	case "linux":
		inv.Manufacturer = dmiValue("sys_vendor")
		inv.Model = dmiValue("product_name")
		inv.SerialNumber = dmiValue("product_serial")
		// dmidecode is the fallback where /sys/class/dmi is absent (some containers, older kernels).
		if inv.SerialNumber == "" {
			inv.SerialNumber = cleanAssetField(invFirstLine(runCmd(ctx, "dmidecode", "-s", "system-serial-number")))
		}
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			inv.MemoryMB = parseMemTotalMB(string(b))
		}

	case "windows":
		// The technique the hospital's own engineer named: PowerShell against the CIM classes
		// (WMIC is deprecated and already absent from recent Windows builds). One invocation emits
		// all four values as lines, because starting PowerShell is the expensive part, not the query.
		if out, ok := tryCmd(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"$c=Get-CimInstance Win32_ComputerSystem; $c.Manufacturer; $c.Model; "+
				"(Get-CimInstance Win32_BIOS).SerialNumber; $c.TotalPhysicalMemory"); ok {
			man, model, serial, memBytes := parseWindowsAsset(out)
			inv.Manufacturer, inv.Model, inv.SerialNumber = man, model, serial
			inv.MemoryMB = memBytes / (1024 * 1024)
		}
	}
}

// parseWindowsAsset reads the four lines the PowerShell one-liner above emits. Split out so the
// parsing is testable without Windows.
func parseWindowsAsset(out string) (manufacturer, model, serial string, memBytes int64) {
	fields := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	at := func(i int) string {
		if i < len(fields) {
			return cleanAssetField(fields[i])
		}
		return ""
	}
	manufacturer, model, serial = at(0), at(1), at(2)
	if n, err := strconv.ParseInt(at(3), 10, 64); err == nil && n > 0 {
		memBytes = n
	}
	return manufacturer, model, serial, memBytes
}

// dmiValue reads one field out of /sys/class/dmi/id.
func dmiValue(name string) string {
	b, err := os.ReadFile("/sys/class/dmi/id/" + name)
	if err != nil {
		return ""
	}
	return cleanAssetField(string(b))
}

// cleanAssetField trims the value and drops the placeholder strings firmware ships when a field
// was never programmed at the factory. Keeping them would be worse than keeping nothing: "To Be
// Filled By O.E.M." looks like real data in an asset register, and every machine from that batch
// reports the identical string, so a register keyed on serial number silently collapses them into
// one asset.
func cleanAssetField(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "0", "na", "n/a", "none", "null", "oem", "o.e.m.",
		"default string", "not specified", "not applicable", "unknown",
		"to be filled by o.e.m.", "to be filled by oem",
		"system serial number", "system manufacturer", "system product name",
		"chassis serial number", "invalid":
		return ""
	}
	return s
}

// parseMemTotalMB reads MemTotal (reported in kB) out of /proc/meminfo contents.
func parseMemTotalMB(meminfo string) int64 {
	for _, line := range strings.Split(meminfo, "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || kb < 0 {
			return 0
		}
		return kb / 1024
	}
	return 0
}

// primaryInterface returns the IPv4 address and MAC of the first non-loopback interface that is up
// and carries a routable address. Which interface is "primary" is genuinely ambiguous on a
// multi-homed host; an asset register only needs something stable to recognise the machine by, so
// first-up-with-an-address is enough, and link-local is skipped because it identifies nothing.
func primaryInterface() (ip, mac string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, in := range ifaces {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aerr := in.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := n.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			return v4.String(), in.HardwareAddr.String()
		}
	}
	return "", ""
}
