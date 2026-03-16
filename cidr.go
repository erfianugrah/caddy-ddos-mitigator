// Package ddosmitigator — CIDR aggregation.
//
// When multiple IPs from the same subnet are jailed, promote the entire
// prefix. This catches distributed attacks from contiguous IP blocks
// (e.g., a botnet operating from a single /24 allocation).
//
// IPv4: /24 aggregation (256 IPs). Threshold: 5 jailed IPs from same /24.
// IPv6: /64 aggregation. Threshold: 5 jailed IPs from same /64.
package ddosmitigator

import (
	"net/netip"
	"sync"
	"time"
)

// ─── CIDR Aggregator ────────────────────────────────────────────────

const (
	cidrPrefixV4 = 24
	cidrPrefixV6 = 64
)

// cidrAggregator tracks per-prefix jail counts and promotes prefixes.
type cidrAggregator struct {
	mu          sync.Mutex
	promoted    map[netip.Prefix]time.Time // promoted prefixes → expiry
	thresholdV4 int
	thresholdV6 int
}

func newCIDRAggregatorWithThresholds(v4, v6 int) *cidrAggregator {
	return &cidrAggregator{
		promoted:    make(map[netip.Prefix]time.Time),
		thresholdV4: v4,
		thresholdV6: v6,
	}
}

func newCIDRAggregator() *cidrAggregator {
	return &cidrAggregator{
		promoted: make(map[netip.Prefix]time.Time),
	}
}

// Check evaluates whether a newly jailed IP should trigger prefix promotion.
// Called after an IP is added to the jail. Returns the prefix to promote, if any.
func (c *cidrAggregator) Check(jail *ipJail, addr netip.Addr, ttl time.Duration) *netip.Prefix {
	var prefixLen int
	if addr.Is4() {
		prefixLen = cidrPrefixV4
	} else {
		prefixLen = cidrPrefixV6
	}

	prefix, err := addr.Prefix(prefixLen)
	if err != nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Already promoted?
	if exp, ok := c.promoted[prefix]; ok && time.Now().Before(exp) {
		return nil
	}

	// Count jailed IPs in this prefix
	snap := jail.Snapshot()
	count := 0
	for ip := range snap {
		p, err := ip.Prefix(prefixLen)
		if err != nil {
			continue
		}
		if p == prefix {
			count++
		}
	}

	threshold := c.thresholdV4
	if !addr.Is4() {
		threshold = c.thresholdV6
	}

	if count >= threshold {
		c.promoted[prefix] = time.Now().Add(ttl)
		return &prefix
	}
	return nil
}

// IsPromoted returns true if the given IP falls within a promoted prefix.
func (c *cidrAggregator) IsPromoted(addr netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for prefix, exp := range c.promoted {
		if now.After(exp) {
			delete(c.promoted, prefix)
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Sweep removes expired promoted prefixes. Returns count removed.
func (c *cidrAggregator) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for prefix, exp := range c.promoted {
		if now.After(exp) {
			delete(c.promoted, prefix)
			removed++
		}
	}
	return removed
}

// Count returns the number of active promoted prefixes.
func (c *cidrAggregator) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.promoted)
}
