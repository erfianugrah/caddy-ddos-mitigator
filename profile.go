// Package ddosmitigator — per-IP behavioral profiling.
//
// Instead of raw frequency z-scores (which flag power users as anomalous),
// this tracks distributional features per IP that distinguish real users
// from bots/floods:
//
//   - Path diversity: unique paths / total requests (users browse many pages, bots hit one)
//   - Method diversity: unique methods / total requests
//   - Status entropy: response status code diversity
//   - Request rate: requests per second (high rate alone isn't sufficient, combined with low diversity it is)
//
// Inspired by Cloudflare's anomaly detection research: variables that follow
// normal distributions, are uncorrelated with volume, and deviate during attacks.
// See: https://blog.cloudflare.com/training-a-million-models-per-day/
//
// The composite anomaly score ranges 0.0 (normal) to 1.0 (definite anomaly).
// Only IPs with score > threshold AND request count > minimum are jailed.
package ddosmitigator

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// ─── IP Profile ─────────────────────────────────────────────────────

// ipProfile tracks behavioral features for a single client IP.
// All fields are updated atomically on each request — no per-request allocation.
type ipProfile struct {
	Requests    int64
	FirstSeen   int64 // unix nano
	LastSeen    int64 // unix nano
	UniquePaths int
	Methods     map[string]int
	StatusCodes map[int]int

	// HyperLogLog-like path tracking: use a small set for exact counting
	// up to a limit, then switch to approximate. For simplicity, we use
	// a bounded map (max 256 unique paths tracked).
	paths map[string]struct{}
}

const maxTrackedPaths = 256

func newIPProfile() *ipProfile {
	return &ipProfile{
		Methods:     make(map[string]int, 4),
		StatusCodes: make(map[int]int, 8),
		paths:       make(map[string]struct{}, 32),
	}
}

func (p *ipProfile) record(method, path string, status int) {
	now := time.Now().UnixNano()
	if p.FirstSeen == 0 {
		p.FirstSeen = now
	}
	p.LastSeen = now
	p.Requests++

	p.Methods[method]++
	p.StatusCodes[status]++

	if len(p.paths) < maxTrackedPaths {
		if _, exists := p.paths[path]; !exists {
			p.paths[path] = struct{}{}
			p.UniquePaths++
		}
	}
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

// StatusEntropy measures the diversity of response status codes.
// Uses normalized Shannon entropy. Range: 0.0 (all same) to 1.0 (uniform).
func (p *ipProfile) StatusEntropy() float64 {
	if p.Requests == 0 || len(p.StatusCodes) <= 1 {
		return 0.0
	}
	total := float64(p.Requests)
	entropy := 0.0
	for _, count := range p.StatusCodes {
		prob := float64(count) / total
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}
	// Normalize by max possible entropy
	maxEntropy := math.Log2(float64(len(p.StatusCodes)))
	if maxEntropy == 0 {
		return 0
	}
	return entropy / maxEntropy
}

// RequestRate returns requests per second since first seen.
func (p *ipProfile) RequestRate() float64 {
	if p.Requests <= 1 || p.LastSeen <= p.FirstSeen {
		return 0
	}
	duration := float64(p.LastSeen-p.FirstSeen) / 1e9 // nanoseconds to seconds
	if duration < 0.001 {
		return 0
	}
	return float64(p.Requests) / duration
}

// AnomalyScore computes a composite behavioral anomaly score.
// Range: 0.0 (normal) to 1.0 (definite anomaly).
//
// The score combines multiple signals:
// - Low path diversity (flood indicator) — heaviest weight
// - High request rate with low diversity (amplified flood indicator)
// - Low method diversity is a weak signal (most users use mostly GET)
//
// A user browsing 50 pages at 2 req/s scores ~0.1.
// A bot hitting one page at 100 req/s scores ~0.95.
func (p *ipProfile) AnomalyScore() float64 {
	if p.Requests < 5 {
		return 0 // not enough data
	}

	pathDiv := p.PathDiversity()
	rate := p.RequestRate()

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

	// Rate boost: if rate > 5 req/s AND diversity is low, amplify.
	rateBoost := 1.0
	if rate > 5.0 && pathDiv < 0.05 {
		rateBoost = math.Min(1.0+(rate-5.0)/20.0, 1.5) // up to 50% boost
	}

	score := math.Min(pathScore*volumeConf*rateBoost, 1.0)

	return math.Min(score, 1.0)
}

// ─── IP Tracker ─────────────────────────────────────────────────────

// ipTracker manages per-IP behavioral profiles with bounded memory.
type ipTracker struct {
	mu       sync.RWMutex
	profiles map[netip.Addr]*ipProfile
	maxIPs   int
	ttl      time.Duration
}

func newIPTracker(maxIPs int, ttl time.Duration) *ipTracker {
	return &ipTracker{
		profiles: make(map[netip.Addr]*ipProfile, 256),
		maxIPs:   maxIPs,
		ttl:      ttl,
	}
}

// Record adds a request observation to the IP's behavioral profile.
func (t *ipTracker) Record(ip netip.Addr, method, path, ua string, status int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	p, exists := t.profiles[ip]
	if !exists {
		// Evict if at capacity (simple: drop oldest entry)
		if len(t.profiles) >= t.maxIPs {
			t.evictOldestLocked()
		}
		p = newIPProfile()
		t.profiles[ip] = p
	}
	p.record(method, path, status)
}

// Profile returns the behavioral profile for an IP, or nil if not tracked.
func (t *ipTracker) Profile(ip netip.Addr) *ipProfile {
	t.mu.RLock()
	defer t.mu.RUnlock()

	p, exists := t.profiles[ip]
	if !exists {
		return nil
	}
	// Check TTL
	if time.Since(time.Unix(0, p.LastSeen)) > t.ttl {
		return nil
	}
	return p
}

// Score returns the anomaly score for an IP. Returns 0 if not tracked.
func (t *ipTracker) Score(ip netip.Addr) float64 {
	p := t.Profile(ip)
	if p == nil {
		return 0
	}
	return p.AnomalyScore()
}

// Reset removes the behavioral profile for an IP, allowing it to be
// re-evaluated from scratch. Called when an IP is manually unjailed via
// the wafctl API to prevent immediate re-jail from stale profile data.
func (t *ipTracker) Reset(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.profiles, ip)
}

// Count returns the number of tracked IPs.
func (t *ipTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.profiles)
}

// Sweep removes expired profiles.
func (t *ipTracker) Sweep() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UnixNano()
	cutoff := now - int64(t.ttl)
	removed := 0
	for ip, p := range t.profiles {
		if p.LastSeen < cutoff {
			delete(t.profiles, ip)
			removed++
		}
	}
	return removed
}

func (t *ipTracker) evictOldestLocked() {
	var oldestIP netip.Addr
	var oldestTime int64 = math.MaxInt64
	for ip, p := range t.profiles {
		if p.LastSeen < oldestTime {
			oldestTime = p.LastSeen
			oldestIP = ip
		}
	}
	if oldestIP.IsValid() {
		delete(t.profiles, oldestIP)
	}
}
