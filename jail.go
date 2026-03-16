// Package ddosmitigator — IP jail subsystem.
//
// Sharded concurrent map with TTL-based expiry. Uses netip.Addr as key
// (24-byte value type, zero heap allocation, directly comparable).
// 64 shards with per-shard sync.RWMutex for minimal lock contention
// under high-concurrency read-heavy workloads.
package ddosmitigator

import (
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Constants ──────────────────────────────────────────────────────

const jailShards = 64

// ─── Types ──────────────────────────────────────────────────────────

// jailEntry represents a single jailed IP with metadata.
type jailEntry struct {
	ExpiresAt       int64  // unix nanoseconds
	InfractionCount int32  // drives exponential backoff
	Reason          string // "auto:z-score", "auto:threshold", "manual", "file:wafctl"
	JailedAt        int64  // unix nanoseconds
}

// ipJail is a sharded, concurrent IP jail with TTL-based expiry.
type ipJail struct {
	shards [jailShards]jailShard
	count  atomic.Int64
}

type jailShard struct {
	mu      sync.RWMutex
	entries map[netip.Addr]*jailEntry
}

// ─── Constructor ────────────────────────────────────────────────────

func newIPJail() *ipJail {
	j := &ipJail{}
	for i := range j.shards {
		j.shards[i].entries = make(map[netip.Addr]*jailEntry)
	}
	return j
}

// ─── Shard Selection ────────────────────────────────────────────────

func (j *ipJail) shard(addr netip.Addr) *jailShard {
	b := addr.As16()
	h := fnv.New32a()
	h.Write(b[:])
	return &j.shards[h.Sum32()%jailShards]
}

// ─── Public API ─────────────────────────────────────────────────────

// Add inserts or updates a jail entry for the given IP address.
// If the IP already exists, the entry is updated (not duplicated).
func (j *ipJail) Add(addr netip.Addr, ttl time.Duration, reason string, infractions int32) {
	s := j.shard(addr)
	now := time.Now().UnixNano()

	s.mu.Lock()
	_, exists := s.entries[addr]
	s.entries[addr] = &jailEntry{
		ExpiresAt:       now + int64(ttl),
		InfractionCount: infractions,
		Reason:          reason,
		JailedAt:        now,
	}
	s.mu.Unlock()

	if !exists {
		j.count.Add(1)
	}
}

// IsJailed returns true if the IP is in the jail and has not expired.
// Expired entries are treated as not jailed (lazy expiry).
func (j *ipJail) IsJailed(addr netip.Addr) bool {
	s := j.shard(addr)
	s.mu.RLock()
	e, ok := s.entries[addr]
	s.mu.RUnlock()

	if !ok {
		return false
	}
	return time.Now().UnixNano() < e.ExpiresAt
}

// Get returns a copy of the jail entry for the given IP, or nil if not found
// or expired.
func (j *ipJail) Get(addr netip.Addr) *jailEntry {
	s := j.shard(addr)
	s.mu.RLock()
	e, ok := s.entries[addr]
	s.mu.RUnlock()

	if !ok {
		return nil
	}
	if time.Now().UnixNano() >= e.ExpiresAt {
		return nil
	}
	// Return a copy to prevent concurrent modification.
	cp := *e
	return &cp
}

// Remove explicitly removes an IP from the jail.
func (j *ipJail) Remove(addr netip.Addr) {
	s := j.shard(addr)
	s.mu.Lock()
	_, exists := s.entries[addr]
	if exists {
		delete(s.entries, addr)
	}
	s.mu.Unlock()

	if exists {
		j.count.Add(-1)
	}
}

// Count returns the total number of entries across all shards.
// Note: includes expired entries that haven't been swept yet.
func (j *ipJail) Count() int64 {
	return j.count.Load()
}

// Sweep removes all expired entries from the jail. Returns the number removed.
func (j *ipJail) Sweep() int {
	now := time.Now().UnixNano()
	total := 0

	for i := range j.shards {
		s := &j.shards[i]
		s.mu.Lock()
		for addr, e := range s.entries {
			if now >= e.ExpiresAt {
				delete(s.entries, addr)
				total++
			}
		}
		s.mu.Unlock()
	}

	if total > 0 {
		j.count.Add(-int64(total))
	}
	return total
}

// Snapshot returns a copy of all non-expired jail entries.
// Used for file serialization and API responses.
func (j *ipJail) Snapshot() map[netip.Addr]jailEntry {
	now := time.Now().UnixNano()
	result := make(map[netip.Addr]jailEntry)

	for i := range j.shards {
		s := &j.shards[i]
		s.mu.RLock()
		for addr, e := range s.entries {
			if now < e.ExpiresAt {
				result[addr] = *e
			}
		}
		s.mu.RUnlock()
	}
	return result
}
