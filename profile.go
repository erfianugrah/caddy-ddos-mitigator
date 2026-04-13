// Package ddosmitigator — per-IP behavioral profiling.
//
// Three-layer detection architecture:
//
//   - L1 (global rate gate): sustained req/s per IP above GlobalRateThreshold →
//     jail immediately, regardless of path diversity. Protects server capacity.
//     Uses a 64-slot ring buffer tracking the last 64 request timestamps for a
//     sliding 60s window rate — immune to the dilution effect of long profile lifetimes.
//
//   - L2 (per-service path diversity): ipTracker is keyed on (IP, host) so each
//     service gets its own behavioral profile. A flood on one service does not
//     inflate the score for other services from the same IP.
//
//   - L3 (host diversity exculpation): a separate global host-count tracker counts
//     how many distinct hosts an IP has been seen on. At jail decision time,
//     effectiveScore = perHostScore / log2(uniqueHosts + 1). A real user hitting
//     8 services gets a 3.17× score reduction; a DDoS on 1 service gets none.
//
// Inspired by Cloudflare's anomaly detection research: variables that follow
// normal distributions, are uncorrelated with volume, and deviate during attacks.
// See: https://blog.cloudflare.com/training-a-million-models-per-day/
//
// The composite anomaly score ranges 0.0 (normal) to 1.0 (definite anomaly).
// Only IPs with score > threshold AND request count > minimum are jailed.
package ddosmitigator

import (
	"container/list"
	"math"
	"net/netip"
	"sync"
	"time"
)

// ─── IP Host Key ─────────────────────────────────────────────────────

// ipHostKey is the composite key for the per-service tracker.
// Each (IP, host) pair gets its own behavioral profile.
type ipHostKey struct {
	addr netip.Addr
	host string
}

// ─── IP Profile ─────────────────────────────────────────────────────

// ipProfile tracks behavioral features for a single (IP, host) pair.
// All fields are updated atomically on each request — no per-request allocation.
type ipProfile struct {
	Requests    int64
	FirstSeen   int64 // unix nano
	LastSeen    int64 // unix nano
	UniquePaths int
	Methods     map[string]int

	// HyperLogLog-like path tracking: use a small set for exact counting
	// up to a limit, then switch to approximate. For simplicity, we use
	// a bounded map (max 256 unique paths tracked).
	paths map[string]struct{}

	// Sliding window rate: ring buffer of the last rateWindowSize request
	// timestamps (unix nano). Gives accurate req/s over the last 60s without
	// being diluted by long profile lifetimes.
	recentTimes [rateWindowSize]int64
	recentHead  int // next write index (mod rateWindowSize)

	// LRU eviction support: element in the per-shard LRU list.
	lruElem *list.Element
}

const (
	maxTrackedPaths = 256
	rateWindowSize  = 64                      // ring buffer slots — covers ~60s at 1 req/s, ~6s at 10 req/s
	rateWindowNs    = int64(60 * time.Second) // 60s sliding window
)

func newIPProfile() *ipProfile {
	return &ipProfile{
		Methods: make(map[string]int, 4),
		paths:   make(map[string]struct{}, 32),
	}
}

func (p *ipProfile) record(method, path string) {
	now := time.Now().UnixNano()
	if p.FirstSeen == 0 {
		p.FirstSeen = now
	}
	p.LastSeen = now
	p.Requests++

	p.Methods[method]++

	if len(p.paths) < maxTrackedPaths {
		if _, exists := p.paths[path]; !exists {
			p.paths[path] = struct{}{}
			p.UniquePaths++
		}
	}

	// Update ring buffer for sliding window rate.
	p.recentTimes[p.recentHead%rateWindowSize] = now
	p.recentHead++
}

// PathDiversity returns unique paths / total requests.
// Range: 0.0 (all same path) to 1.0 (every request different path).
// Normal users: 0.1–0.8. Floods: <0.01.
func (p *ipProfile) PathDiversity() float64 {
	if p.Requests == 0 {
		return 1.0
	}
	return float64(p.UniquePaths) / float64(p.Requests)
}

// MethodDiversity returns unique methods / total requests.
// Normal users: ~0.01–0.1 (mostly GET, occasional POST).
// Single-method floods: exactly 1/requests ≈ 0.
func (p *ipProfile) MethodDiversity() float64 {
	if p.Requests == 0 {
		return 1.0
	}
	return float64(len(p.Methods)) / float64(p.Requests)
}

// RequestRate returns requests per second since first seen (lifetime average).
// Used for the rateBoost component of AnomalyScore.
func (p *ipProfile) RequestRate() float64 {
	if p.Requests <= 1 || p.LastSeen <= p.FirstSeen {
		return 0
	}
	duration := float64(p.LastSeen-p.FirstSeen) / 1e9
	if duration < 0.001 {
		return 0
	}
	return float64(p.Requests) / duration
}

// RecentRate returns requests per second over the last 60s sliding window.
// Uses the ring buffer of recent timestamps. This is the L1 gate signal —
// immune to dilution from long profile lifetimes, catches bursts accurately.
func (p *ipProfile) RecentRate() float64 {
	if p.Requests == 0 {
		return 0
	}
	now := time.Now().UnixNano()
	cutoff := now - rateWindowNs

	// Count timestamps within the 60s window.
	count := 0
	oldest := now
	for _, ts := range p.recentTimes {
		if ts == 0 {
			continue
		}
		if ts >= cutoff {
			count++
			if ts < oldest {
				oldest = ts
			}
		}
	}
	if count < 2 {
		return 0
	}
	// Compute rate over actual observed window span (not full 60s).
	windowSpan := float64(now-oldest) / 1e9
	if windowSpan < 0.001 {
		return 0
	}
	return float64(count) / windowSpan
}

// AnomalyScore computes a composite behavioral anomaly score.
// Range: 0.0 (normal) to 1.0 (definite anomaly).
//
// uniqueHosts is the number of distinct hosts this IP has been profiled
// against (from the global host-count tracker). Used for L3 exculpation:
// effectiveScore = rawScore / log2(uniqueHosts + 1).
// A legitimate user hitting 8 services gets a 3.17× score reduction.
// A DDoS targeting 1 service gets no reduction.
//
// recentRate is the 60s sliding-window rate from the global hostTracker ring
// buffer (all hosts combined). Passed in to avoid a second lock acquisition
// and to use the accurate per-window rate for the rateBoost signal.
//
// The score combines multiple signals:
// - Low path diversity (flood indicator) — heaviest weight
// - High recent request rate with low diversity (amplified flood indicator)
// - Low method diversity is a weak signal (most users use mostly GET)
//
// A user browsing 50 pages at 2 req/s scores ~0.1.
// A bot hitting one page at 100 req/s scores ~0.95.
func (p *ipProfile) AnomalyScore(uniqueHosts int, recentRate float64) float64 {
	if p.Requests < 5 {
		return 0 // not enough data
	}

	pathDiv := p.PathDiversity()

	// Path diversity is the primary signal, using an exponential curve.
	// pathDiv ≥ 0.05 → normal (score ≈ 0), most users browse 5%+ unique paths
	// pathDiv 0.01–0.05 → suspicious zone (score 0.3–0.5)
	// pathDiv < 0.005 → definite flood (score → 1.0)
	//
	// Using: pathScore = exp(-pathDiv * k) where k controls sensitivity.
	// k=80: pathDiv=0.05→0.02, pathDiv=0.02→0.20, pathDiv=0.005→0.67, pathDiv=0.002→0.85
	pathScore := math.Exp(-pathDiv * 80.0)

	// Volume confidence: very low request count reduces score (not enough data).
	// Below 10 requests: dampened. Above 30: full confidence.
	volumeConf := math.Min(float64(p.Requests)/30.0, 1.0)

	// Rate boost: uses the 60s sliding-window rate (global across all hosts).
	// This avoids lifetime-dilution and reflects the actual current burst rate.
	// Only amplifies when both rate is high AND path diversity is low.
	rateBoost := 1.0
	if recentRate > 5.0 && pathDiv < 0.05 {
		rateBoost = math.Min(1.0+(recentRate-5.0)/20.0, 1.5) // up to 50% boost
	}

	rawScore := math.Min(pathScore*volumeConf*rateBoost, 1.0)

	// L3: host diversity exculpation.
	// Divide by log2(uniqueHosts + 1) to dampen score for IPs hitting many services.
	// uniqueHosts=1 → factor=1.0 (no reduction)
	// uniqueHosts=3 → factor=2.0 (score halved)
	// uniqueHosts=8 → factor=3.17 (score divided by 3.17)
	if uniqueHosts > 1 {
		hostFactor := math.Log2(float64(uniqueHosts) + 1.0)
		rawScore = rawScore / hostFactor
	}

	return math.Min(rawScore, 1.0)
}

// ─── IP Tracker (per-service, keyed on (IP, host)) ──────────────────

const trackerShards = 64

// trackerShard holds a subset of (IP, host) profiles with its own lock and LRU list.
type trackerShard struct {
	mu       sync.RWMutex
	profiles map[ipHostKey]*ipProfile
	lru      *list.List
	maxIPs   int // per-shard capacity: global maxIPs / trackerShards
}

// lruEntry is stored as list.Element.Value for LRU eviction.
type lruEntry struct {
	key ipHostKey
}

// ipTracker manages per-(IP, host) behavioral profiles with bounded memory.
// Uses 64 shards for reduced lock contention and per-shard LRU eviction.
type ipTracker struct {
	shards [trackerShards]trackerShard
	ttl    time.Duration
}

func newIPTracker(maxIPs int, ttl time.Duration) *ipTracker {
	perShard := maxIPs / trackerShards
	if perShard < 1 {
		perShard = 1
	}
	t := &ipTracker{ttl: ttl}
	for i := range t.shards {
		t.shards[i] = trackerShard{
			profiles: make(map[ipHostKey]*ipProfile, 64),
			lru:      list.New(),
			maxIPs:   perShard,
		}
	}
	return t
}

func (t *ipTracker) shard(key ipHostKey) *trackerShard {
	b := key.addr.As16()
	// Mix host into the hash by XOR-ing with a simple hash of the host string.
	h := fnv32a(b[:])
	for i := 0; i < len(key.host); i++ {
		h ^= uint32(key.host[i])
		h *= 16777619
	}
	return &t.shards[h%trackerShards]
}

// Record adds a request observation to the (IP, host) behavioral profile.
func (t *ipTracker) Record(addr netip.Addr, host, method, path, ua string) {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.profiles[key]
	if !exists {
		if len(s.profiles) >= s.maxIPs {
			s.evictOldestLocked()
		}
		p = newIPProfile()
		s.profiles[key] = p
		p.lruElem = s.lru.PushBack(&lruEntry{key: key})
	} else {
		s.lru.MoveToBack(p.lruElem)
	}
	p.record(method, path)
}

// RecordAndScore records a request and returns the anomaly score in a single
// lock acquisition. uniqueHosts and recentRate are passed in from the global
// host tracker — both are already updated before this call.
func (t *ipTracker) RecordAndScore(addr netip.Addr, host, method, path, ua string, uniqueHosts int, recentRate float64) float64 {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.profiles[key]
	if !exists {
		if len(s.profiles) >= s.maxIPs {
			s.evictOldestLocked()
		}
		p = newIPProfile()
		s.profiles[key] = p
		p.lruElem = s.lru.PushBack(&lruEntry{key: key})
	} else {
		s.lru.MoveToBack(p.lruElem)
	}
	p.record(method, path)
	return p.AnomalyScore(uniqueHosts, recentRate)
}

// RecentRate returns the 60s sliding window rate for the given (IP, host) pair.
func (t *ipTracker) RecentRate(addr netip.Addr, host string) float64 {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[key]
	if !ok {
		return 0
	}
	return p.RecentRate()
}

// Profile returns the behavioral profile for an (IP, host) pair, or nil.
func (t *ipTracker) Profile(addr netip.Addr, host string) *ipProfile {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.profiles[key]
	if !exists {
		return nil
	}
	if time.Since(time.Unix(0, p.LastSeen)) > t.ttl {
		return nil
	}
	return p
}

// Score returns the anomaly score for an (IP, host) pair. Returns 0 if not tracked.
// recentRate should be from hostTracker.GlobalRecentRate for accurate rateBoost.
func (t *ipTracker) Score(addr netip.Addr, host string, uniqueHosts int, recentRate float64) float64 {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.profiles[key]
	if !exists {
		return 0
	}
	if time.Since(time.Unix(0, p.LastSeen)) > t.ttl {
		return 0
	}
	return p.AnomalyScore(uniqueHosts, recentRate)
}

// Reset removes the behavioral profile for an (IP, host) pair.
// Called when an IP is manually unjailed to prevent immediate re-jail.
func (t *ipTracker) Reset(addr netip.Addr, host string) {
	key := ipHostKey{addr: addr, host: host}
	s := t.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.profiles[key]
	if exists {
		s.lru.Remove(p.lruElem)
		delete(s.profiles, key)
	}
}

// ResetAll removes all behavioral profiles for an IP across all hosts.
// Called when an IP is unjailed — sweeps all (IP, *) entries.
func (t *ipTracker) ResetAll(addr netip.Addr) {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for key, p := range s.profiles {
			if key.addr == addr {
				s.lru.Remove(p.lruElem)
				delete(s.profiles, key)
			}
		}
		s.mu.Unlock()
	}
}

// Count returns the total number of tracked (IP, host) profiles across all shards.
func (t *ipTracker) Count() int {
	total := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		total += len(s.profiles)
		s.mu.RUnlock()
	}
	return total
}

// Sweep removes expired profiles across all shards. Returns count removed.
func (t *ipTracker) Sweep() int {
	now := time.Now().UnixNano()
	cutoff := now - int64(t.ttl)
	total := 0

	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for key, p := range s.profiles {
			if p.LastSeen < cutoff {
				s.lru.Remove(p.lruElem)
				delete(s.profiles, key)
				total++
			}
		}
		s.mu.Unlock()
	}
	return total
}

// Snapshot returns a copy of all non-expired profiles for API/debug use.
// Returns a map of ipHostKey → profile snapshot.
func (t *ipTracker) Snapshot() []ProfileSnapshot {
	now := time.Now().UnixNano()
	cutoff := now - int64(t.ttl)
	var result []ProfileSnapshot

	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, p := range s.profiles {
			if p.LastSeen < cutoff {
				continue
			}
			result = append(result, ProfileSnapshot{
				Addr:         key.addr,
				Host:         key.host,
				Requests:     p.Requests,
				UniquePaths:  p.UniquePaths,
				PathDiv:      p.PathDiversity(),
				Rate:         p.RecentRate(),
				LifetimeRate: p.RequestRate(),
			})
		}
		s.mu.RUnlock()
	}
	return result
}

// ProfileSnapshot is a point-in-time copy of a profile for API responses.
type ProfileSnapshot struct {
	Addr         netip.Addr
	Host         string
	Requests     int64
	UniquePaths  int
	PathDiv      float64
	Rate         float64 // recent 60s rate
	LifetimeRate float64 // full lifetime rate
}

// evictOldestLocked removes the LRU-front entry from this shard.
// Caller must hold s.mu write lock.
func (s *trackerShard) evictOldestLocked() {
	front := s.lru.Front()
	if front == nil {
		return
	}
	entry := front.Value.(*lruEntry)
	p := s.profiles[entry.key]
	if p != nil {
		s.lru.Remove(p.lruElem)
	}
	delete(s.profiles, entry.key)
}

// ─── Global Host Tracker ─────────────────────────────────────────────

// hostTracker counts the number of distinct hosts each IP has been seen on.
// This is the L3 exculpation signal: more unique hosts → lower effective score.
// Keyed by IP only (not per-service), bounded per-shard with LRU eviction.
type hostTracker struct {
	shards [trackerShards]hostShard
	ttl    time.Duration
}

type hostShard struct {
	mu      sync.RWMutex
	entries map[netip.Addr]*hostEntry
	lru     *list.List
	maxIPs  int
}

type hostEntry struct {
	hosts    map[string]struct{}
	LastSeen int64 // unix nano
	lruElem  *list.Element
	// Global rate ring buffer: all requests from this IP across all hosts.
	// Sized identically to ipProfile.recentTimes for consistency.
	recentTimes [rateWindowSize]int64
	recentHead  int
}

type hostLRUEntry struct {
	addr netip.Addr
}

func newHostTracker(maxIPs int, ttl time.Duration) *hostTracker {
	perShard := maxIPs / trackerShards
	if perShard < 1 {
		perShard = 1
	}
	ht := &hostTracker{ttl: ttl}
	for i := range ht.shards {
		ht.shards[i] = hostShard{
			entries: make(map[netip.Addr]*hostEntry, 64),
			lru:     list.New(),
			maxIPs:  perShard,
		}
	}
	return ht
}

func (ht *hostTracker) shard(addr netip.Addr) *hostShard {
	b := addr.As16()
	return &ht.shards[fnv32a(b[:])%trackerShards]
}

// Record records that addr was seen hitting host. Returns the updated unique host count.
// Also updates the global rate ring buffer (all hosts combined) for L1 rate gate use.
func (ht *hostTracker) Record(addr netip.Addr, host string) int {
	s := ht.shard(addr)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixNano()

	e, exists := s.entries[addr]
	if !exists {
		if len(s.entries) >= s.maxIPs {
			ht.evictOldestLocked(s)
		}
		e = &hostEntry{
			hosts:   make(map[string]struct{}, 4),
			lruElem: s.lru.PushBack(&hostLRUEntry{addr: addr}),
		}
		s.entries[addr] = e
	} else {
		s.lru.MoveToBack(e.lruElem)
	}
	e.hosts[host] = struct{}{}
	e.LastSeen = now
	// Write to global rate ring buffer — counts ALL requests from this IP.
	e.recentTimes[e.recentHead%rateWindowSize] = now
	e.recentHead++
	return len(e.hosts)
}

// GlobalRecentRate returns the global request rate (all hosts combined) for an IP
// over the last 60s sliding window. Used for the L1 rate gate.
// Called AFTER Record() so the current request is included in the count.
func (ht *hostTracker) GlobalRecentRate(addr netip.Addr) float64 {
	s := ht.shard(addr)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[addr]
	if !ok {
		return 0
	}
	now := time.Now().UnixNano()
	cutoff := now - rateWindowNs
	count := 0
	oldest := now
	for _, ts := range e.recentTimes {
		if ts == 0 {
			continue
		}
		if ts >= cutoff {
			count++
			if ts < oldest {
				oldest = ts
			}
		}
	}
	if count < 2 {
		return 0
	}
	windowSpan := float64(now-oldest) / 1e9
	if windowSpan < 0.001 {
		return 0
	}
	return float64(count) / windowSpan
}

// UniqueHosts returns the number of distinct hosts seen for addr.
func (ht *hostTracker) UniqueHosts(addr netip.Addr) int {
	s := ht.shard(addr)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[addr]
	if !ok {
		return 1 // default: assume 1 host (no dampening)
	}
	if time.Since(time.Unix(0, e.LastSeen)) > ht.ttl {
		return 1
	}
	return len(e.hosts)
}

// Hosts returns the set of hosts seen for addr (for API responses).
func (ht *hostTracker) Hosts(addr netip.Addr) []string {
	s := ht.shard(addr)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[addr]
	if !ok {
		return nil
	}
	hosts := make([]string, 0, len(e.hosts))
	for h := range e.hosts {
		hosts = append(hosts, h)
	}
	return hosts
}

// Reset removes the host entry for addr (called on unjail).
func (ht *hostTracker) Reset(addr netip.Addr) {
	s := ht.shard(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[addr]; ok {
		s.lru.Remove(e.lruElem)
		delete(s.entries, addr)
	}
}

// Sweep removes expired entries. Returns count removed.
func (ht *hostTracker) Sweep() int {
	cutoff := time.Now().Add(-ht.ttl).UnixNano()
	total := 0
	for i := range ht.shards {
		s := &ht.shards[i]
		s.mu.Lock()
		for addr, e := range s.entries {
			if e.LastSeen < cutoff {
				s.lru.Remove(e.lruElem)
				delete(s.entries, addr)
				total++
			}
		}
		s.mu.Unlock()
	}
	return total
}

func (ht *hostTracker) evictOldestLocked(s *hostShard) {
	front := s.lru.Front()
	if front == nil {
		return
	}
	entry := front.Value.(*hostLRUEntry)
	if e, ok := s.entries[entry.addr]; ok {
		s.lru.Remove(e.lruElem)
	}
	delete(s.entries, entry.addr)
}
