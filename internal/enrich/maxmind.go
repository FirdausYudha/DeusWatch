package enrich

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// MaxMindClient looks up a country ISO code from a locally mounted MaxMind GeoLite2 .mmdb file.
// Offline (no external API, no rate limit) so it's the preferred first-choice source when the
// operator can obtain the free GeoLite2 database from MaxMind. When the database file is missing
// or unreadable, Open returns an error and the composite provider falls through to the online
// sources (AbuseIPDB/OTX country → ip-api.com).
//
// Only the Country database is used — City accuracy needs the paid GeoIP2-City DB. City data still
// comes from ip-api.com or a paid provider if wired.
type MaxMindClient struct {
	reader *maxminddb.Reader
	path   string
	mu     sync.RWMutex
}

// NewMaxMindClient opens the .mmdb file at path. Returns (nil, nil) when path is empty (feature
// disabled), (nil, error) when the file exists but is not a valid mmdb, and a working client on
// success.
func NewMaxMindClient(path string) (*MaxMindClient, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("maxmind: db file %q does not exist", path)
	}
	rdr, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("maxmind: open %q: %w", path, err)
	}
	return &MaxMindClient{reader: rdr, path: path}, nil
}

// Close releases the underlying mmap. Safe to call on a nil client.
func (c *MaxMindClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reader != nil {
		err := c.reader.Close()
		c.reader = nil
		return err
	}
	return nil
}

// Country returns the ISO-3166-1 alpha-2 country code for ip. Empty when the IP isn't in the
// database (unallocated / bogon / anycast that MaxMind chose not to attribute).
func (c *MaxMindClient) Country(_ context.Context, ip string) (string, error) {
	if c == nil {
		return "", nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("maxmind: parse ip: %w", err)
	}
	c.mu.RLock()
	rdr := c.reader
	c.mu.RUnlock()
	if rdr == nil {
		return "", errors.New("maxmind: reader closed")
	}
	// The Country database schema — we only need ISO code, so decode into a minimal struct rather
	// than the library's full City record. This keeps allocs bounded per event.
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	res := rdr.Lookup(addr)
	if !res.Found() {
		return "", nil
	}
	if err := res.Decode(&rec); err != nil {
		return "", fmt.Errorf("maxmind: decode: %w", err)
	}
	return rec.Country.ISOCode, nil
}

// MaxMindASNClient reads MaxMind's GeoLite2-ASN.mmdb. Distinct file from the Country DB
// (they're maintained separately by MaxMind), same mmap-once startup pattern. Wired into
// the CompositeProvider so an operator with both DBs mounted gets country AND ASN offline.
type MaxMindASNClient struct {
	reader *maxminddb.Reader
	path   string
	mu     sync.RWMutex
}

// NewMaxMindASNClient opens the GeoLite2-ASN .mmdb at path. Same nil/error semantics as
// NewMaxMindClient: (nil, nil) when path empty, (nil, error) when path present but invalid.
func NewMaxMindASNClient(path string) (*MaxMindASNClient, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("maxmind: asn db file %q does not exist", path)
	}
	rdr, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("maxmind: open asn %q: %w", path, err)
	}
	return &MaxMindASNClient{reader: rdr, path: path}, nil
}

// Close releases the underlying mmap. Safe to call on a nil client.
func (c *MaxMindASNClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reader != nil {
		err := c.reader.Close()
		c.reader = nil
		return err
	}
	return nil
}

// ASN returns the AS number + organisation string for ip. (0, "") when the IP isn't in the
// DB (unallocated / private / MaxMind chose not to attribute).
func (c *MaxMindASNClient) ASN(_ context.Context, ip string) (uint, string, error) {
	if c == nil {
		return 0, "", nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, "", fmt.Errorf("maxmind: parse ip: %w", err)
	}
	c.mu.RLock()
	rdr := c.reader
	c.mu.RUnlock()
	if rdr == nil {
		return 0, "", errors.New("maxmind: asn reader closed")
	}
	var rec struct {
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	}
	res := rdr.Lookup(addr)
	if !res.Found() {
		return 0, "", nil
	}
	if err := res.Decode(&rec); err != nil {
		return 0, "", fmt.Errorf("maxmind: decode asn: %w", err)
	}
	return rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization, nil
}
