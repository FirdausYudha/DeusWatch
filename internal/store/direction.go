package store

import (
	"net"
)

// rfc1918Nets are the private + loopback CIDRs that always count as "our side" when classifying event
// direction, so a fresh install (empty whitelist) still gets useful LATERAL/OUTBOUND labels for
// internal traffic instead of tagging every internal-to-internal packet as "unknown".
var rfc1918Nets = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"::1/128",
	"fc00::/7",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inNets(ipStr string, nets []*net.IPNet) bool {
	if ipStr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// AttachDirection labels each row's Direction using the internal-tagged whitelist ∪ RFC1918/loopback:
//
//   - "lateral"  — source AND destination are internal (attacker moving inside our network)
//   - "outbound" — source internal, destination external (our host reaching out — possible C2/exfil)
//   - "inbound"  — source external, destination internal OR the event is destined for one of our
//                  agents (which is always internal by definition)
//   - ""         — can't be classified (no source_ip, or external→external and no agent context)
//
// LATERAL is the highest-value signal for a SOAR: it says the attacker is already past the perimeter.
// INBOUND is the common attack pattern (the SSH-brute-force alerts the operator sees). OUTBOUND is
// the beaconing/exfil signal. When destination_ip is missing we still infer INBOUND from an external
// source hitting one of our agents — most log-based alerts are shaped that way.
func AttachDirection(rows []EventRow, internalNets []*net.IPNet) {
	// Union with the always-internal defaults so an empty whitelist still classifies correctly.
	nets := append([]*net.IPNet(nil), internalNets...)
	nets = append(nets, rfc1918Nets...)
	for i := range rows {
		r := &rows[i]
		if r.SourceIP == "" {
			continue
		}
		srcInternal := inNets(r.SourceIP, nets)
		dstInternal := inNets(r.DestinationIP, nets)
		hasDst := r.DestinationIP != ""
		hasAgent := r.AgentID != "" // an agent report is an event landing on one of our hosts

		switch {
		case srcInternal && dstInternal:
			r.Direction = "lateral"
		case srcInternal && hasDst && !dstInternal:
			r.Direction = "outbound"
		case !srcInternal && (dstInternal || hasAgent):
			r.Direction = "inbound"
		case srcInternal && !hasDst && hasAgent:
			// Internal source, no explicit destination, but the event was reported by one of our
			// agents — treat as LATERAL (an internal host talking to another internal host we watch).
			r.Direction = "lateral"
		}
	}
}
