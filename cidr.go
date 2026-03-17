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
	"sync/atomic"
	"time"
)

// ─── CIDR Aggregator ────────────────────────────────────────────────

const (
	cidrPrefixV4 = 24
	cidrPrefixV6 = 64
)

// cidrAggregator tracks per-prefix jail counts and promotes prefixes.
// Uses per-prefix atomic counters (O(1)) instead of O(N) snapshot scanning.
type cidrAggregator struct {
	mu          sync.RWMutex
	promoted    map[netip.Prefix]time.Time // promoted prefixes → expiry
	counters    map[netip.Prefix]*atomic.Int32
	thresholdV4 int
	thresholdV6 int
}

func newCIDRAggregatorWithThresholds(v4, v6 int) *cidrAggregator {
	return &cidrAggregator{
		promoted:    make(map[netip.Prefix]time.Time),
		counters:    make(map[netip.Prefix]*atomic.Int32),
		thresholdV4: v4,
		thresholdV6: v6,
	}
}

// prefixFor returns the aggregation prefix for an address.
func prefixFor(addr netip.Addr) (netip.Prefix, bool) {
	var prefixLen int
	if addr.Is4() {
		prefixLen = cidrPrefixV4
	} else {
		prefixLen = cidrPrefixV6
	}
	prefix, err := addr.Prefix(prefixLen)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// IncrementPrefix atomically increments the counter for the IP's prefix.
// Called after an IP is added to the jail.
func (c *cidrAggregator) IncrementPrefix(addr netip.Addr) {
	prefix, ok := prefixFor(addr)
	if !ok {
		return
	}

	c.mu.Lock()
	cnt, exists := c.counters[prefix]
	if !exists {
		cnt = &atomic.Int32{}
		c.counters[prefix] = cnt
	}
	c.mu.Unlock()

	cnt.Add(1)
}

// DecrementPrefix atomically decrements the counter for the IP's prefix.
// Called when a jailed IP expires or is removed.
func (c *cidrAggregator) DecrementPrefix(addr netip.Addr) {
	prefix, ok := prefixFor(addr)
	if !ok {
		return
	}

	c.mu.Lock()
	cnt, exists := c.counters[prefix]
	c.mu.Unlock()

	if exists {
		if cnt.Add(-1) <= 0 {
			// Clean up zero/negative counters to prevent map growth.
			c.mu.Lock()
			if cnt.Load() <= 0 {
				delete(c.counters, prefix)
			}
			c.mu.Unlock()
		}
	}
}

// Check evaluates whether a newly jailed IP should trigger prefix promotion.
// Called after an IP is added to the jail. Returns the prefix to promote, if any.
// Uses per-prefix atomic counters for O(1) lookup instead of O(N) snapshot scan.
func (c *cidrAggregator) Check(addr netip.Addr, ttl time.Duration) *netip.Prefix {
	prefix, ok := prefixFor(addr)
	if !ok {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Already promoted?
	if exp, ok := c.promoted[prefix]; ok && time.Now().Before(exp) {
		return nil
	}

	// Read the counter for this prefix.
	cnt, exists := c.counters[prefix]
	count := int32(0)
	if exists {
		count = cnt.Load()
	}

	threshold := int32(c.thresholdV4)
	if !addr.Is4() {
		threshold = int32(c.thresholdV6)
	}

	if count >= threshold {
		c.promoted[prefix] = time.Now().Add(ttl)
		return &prefix
	}
	return nil
}

// IsPromoted returns true if the given IP falls within a promoted prefix.
// Uses RLock — no mutation on the read path. Expired entries are cleaned
// by the background Sweep() goroutine instead of lazy deletion here.
func (c *cidrAggregator) IsPromoted(addr netip.Addr) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	for prefix, exp := range c.promoted {
		if now.After(exp) {
			continue // skip expired, don't delete — Sweep() handles it
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
