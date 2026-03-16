// Package ddosmitigator — adaptive statistics subsystem.
//
// Implements Welford's online algorithm for numerically stable single-pass
// mean + variance computation, combined with dual-rate EWMA for spike detection.
//
// All operations are O(1) time and O(1) memory (three float64 variables for
// Welford, two for EWMA). Thread-safe via sync.Mutex.
//
// References:
//   - B.P. Welford, "Note on a method for calculating corrected sums of
//     squares and products", Technometrics 4(3), 1962
//   - Cloudflare dosd: dual-rate EWMA for fast spike vs slow baseline comparison
package ddosmitigator

import (
	"math"
	"sync"
)

// ─── EWMA Decay Constants ───────────────────────────────────────────

const (
	ewmaAlphaFast = 0.3  // half-life ≈ 2 samples — reacts quickly to spikes
	ewmaAlphaSlow = 0.05 // half-life ≈ 14 samples — long-term baseline

	// Spike mode threshold: ewmaFast > spikeRatio * ewmaSlow
	spikeRatio = 3.0

	// Minimum stddev to avoid division by zero in z-score.
	// When stddev is below this, deviations from mean get a high z-score.
	minStdDev = 1e-9

	// Default minimum observations before z-score becomes actionable.
	// Configurable via DDOSMitigator.WarmupRequests.
	defaultMinObservationsForZScore = 1000
)

// ─── Types ──────────────────────────────────────────────────────────

// adaptiveStats tracks global traffic statistics using Welford's algorithm
// for numerically stable mean/variance and dual-rate EWMA for spike detection.
type adaptiveStats struct {
	mu sync.Mutex

	// Welford's online algorithm
	count int64
	mean  float64
	m2    float64 // running sum of squared differences from mean

	// Dual EWMA
	ewmaFast    float64
	ewmaSlow    float64
	ewmaStarted bool

	// Configurable warmup threshold
	minObservations int64
}

// ─── Constructor ────────────────────────────────────────────────────

func newAdaptiveStats() *adaptiveStats {
	return &adaptiveStats{minObservations: defaultMinObservationsForZScore}
}

func newAdaptiveStatsWithWarmup(minObs int) *adaptiveStats {
	return &adaptiveStats{minObservations: int64(minObs)}
}

// ─── Observe ────────────────────────────────────────────────────────

// Observe feeds a new value into both Welford's algorithm and the dual EWMA.
// Called once per request/event with the current frequency or rate metric.
func (s *adaptiveStats) Observe(x float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Welford's online update
	s.count++
	delta := x - s.mean
	s.mean += delta / float64(s.count)
	delta2 := x - s.mean
	s.m2 += delta * delta2

	// Dual EWMA update
	if !s.ewmaStarted {
		s.ewmaFast = x
		s.ewmaSlow = x
		s.ewmaStarted = true
	} else {
		s.ewmaFast = ewmaAlphaFast*x + (1-ewmaAlphaFast)*s.ewmaFast
		s.ewmaSlow = ewmaAlphaSlow*x + (1-ewmaAlphaSlow)*s.ewmaSlow
	}
}

// ─── Queries ────────────────────────────────────────────────────────

// Mean returns the running mean of all observed values.
func (s *adaptiveStats) Mean() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mean
}

// Variance returns the unbiased sample variance (Bessel's correction).
// Returns 0 if fewer than 2 observations.
func (s *adaptiveStats) Variance() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.count < 2 {
		return 0
	}
	return s.m2 / float64(s.count-1)
}

// StdDev returns the sample standard deviation.
func (s *adaptiveStats) StdDev() float64 {
	return math.Sqrt(s.Variance())
}

// ZScore computes how many standard deviations the value x is from the mean.
// Returns 0 if insufficient data (< 2 observations).
// When stddev is effectively zero (constant input), returns a very high z-score
// for any value that differs from the mean, and 0 for the mean itself.
func (s *adaptiveStats) ZScore(x float64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Don't produce actionable z-scores until we have a real baseline.
	// With too few observations, the mean and variance are meaningless —
	// a single user browsing normally looks anomalous against near-zero stats.
	if s.count < s.minObservations {
		return 0
	}

	variance := s.m2 / float64(s.count-1)
	sd := math.Sqrt(variance)

	diff := math.Abs(x - s.mean)

	if sd < minStdDev {
		if diff < minStdDev {
			return 0
		}
		// Stddev is ~0 but value differs: return a large z-score.
		return diff / minStdDev
	}

	return diff / sd
}

// EWMA returns the current fast and slow exponentially weighted moving averages.
func (s *adaptiveStats) EWMA() (fast, slow float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ewmaFast, s.ewmaSlow
}

// IsSpikeMode returns true when the fast EWMA significantly exceeds the slow
// EWMA, indicating a sudden traffic surge (potential DDoS).
func (s *adaptiveStats) IsSpikeMode() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ewmaStarted {
		return false
	}
	// Avoid false positives when baseline is near zero.
	if s.ewmaSlow < 1.0 {
		return s.ewmaFast > spikeRatio
	}
	return s.ewmaFast > spikeRatio*s.ewmaSlow
}
