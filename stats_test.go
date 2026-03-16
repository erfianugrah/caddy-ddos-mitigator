package ddosmitigator

import (
	"math"
	"testing"
)

const floatEpsilon = 0.0001

func almostEqual(a, b, eps float64) bool {
	return math.Abs(a-b) < eps
}

// --- Welford Tests ---

func TestStats_SingleObservation(t *testing.T) {
	s := newAdaptiveStats()
	s.Observe(42.0)

	if s.Mean() != 42.0 {
		t.Fatalf("mean: got %f, want 42.0", s.Mean())
	}
	// Variance undefined for n=1, StdDev should return 0
	if s.StdDev() != 0 {
		t.Fatalf("stddev for n=1: got %f, want 0", s.StdDev())
	}
}

func TestStats_KnownSequence(t *testing.T) {
	s := newAdaptiveStats()
	// Sequence: 2, 4, 4, 4, 5, 5, 7, 9
	// Mean = 5.0, Variance = 4.0, StdDev = 2.0
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	for _, v := range vals {
		s.Observe(v)
	}

	if !almostEqual(s.Mean(), 5.0, floatEpsilon) {
		t.Fatalf("mean: got %f, want 5.0", s.Mean())
	}
	// Sample variance (Bessel's correction, N-1): 32/7 ≈ 4.5714
	if !almostEqual(s.Variance(), 32.0/7.0, floatEpsilon) {
		t.Fatalf("variance: got %f, want %f (sample variance)", s.Variance(), 32.0/7.0)
	}
	if !almostEqual(s.StdDev(), math.Sqrt(32.0/7.0), floatEpsilon) {
		t.Fatalf("stddev: got %f, want %f", s.StdDev(), math.Sqrt(32.0/7.0))
	}
}

func TestStats_NumericalStability(t *testing.T) {
	// Welford's algorithm should handle large values without catastrophic cancellation.
	// The naive formula E[X²] - (E[X])² fails here.
	s := newAdaptiveStats()
	base := 1e9
	for i := range 1000 {
		s.Observe(base + float64(i))
	}

	// Expected: mean ≈ 1e9 + 499.5, variance ≈ 83416.67 (sample var of 0..999)
	expectedMean := base + 499.5
	if !almostEqual(s.Mean(), expectedMean, 0.1) {
		t.Fatalf("mean: got %f, want %f", s.Mean(), expectedMean)
	}

	// Sample variance of 0..999 = (1000^2 - 1) / 12 = 83333.25
	// But we're computing variance of base+0..base+999, same relative variance.
	v := s.Variance()
	if v < 80000 || v > 90000 {
		t.Fatalf("variance: got %f, expected ~83333", v)
	}
	if v < 0 {
		t.Fatal("variance should never be negative (catastrophic cancellation)")
	}
}

func TestStats_ZeroVariance(t *testing.T) {
	s := newAdaptiveStats()
	for range 100 {
		s.Observe(5.0)
	}

	if !almostEqual(s.Variance(), 0.0, floatEpsilon) {
		t.Fatalf("constant input variance: got %f, want 0.0", s.Variance())
	}
	if !almostEqual(s.StdDev(), 0.0, floatEpsilon) {
		t.Fatalf("constant input stddev: got %f, want 0.0", s.StdDev())
	}
}

// --- Z-Score Tests ---

func TestStats_ZScore(t *testing.T) {
	s := newAdaptiveStats()
	// Build a baseline: mean=50, stddev≈10
	// Use N(50, 10²) approximation: feed values 30..70 uniformly
	for i := range 1000 {
		v := 30.0 + 40.0*float64(i)/999.0 // 30 to 70
		s.Observe(v)
	}

	mean := s.Mean()
	sd := s.StdDev()

	// A value at the mean should have z≈0
	z0 := s.ZScore(mean)
	if !almostEqual(z0, 0.0, 0.1) {
		t.Fatalf("z-score at mean: got %f, want ≈0", z0)
	}

	// A value 2 stddevs above should have z≈2
	z2 := s.ZScore(mean + 2*sd)
	if !almostEqual(z2, 2.0, 0.1) {
		t.Fatalf("z-score at mean+2σ: got %f, want ≈2", z2)
	}

	// A value 4 stddevs above
	z4 := s.ZScore(mean + 4*sd)
	if !almostEqual(z4, 4.0, 0.1) {
		t.Fatalf("z-score at mean+4σ: got %f, want ≈4", z4)
	}
}

func TestStats_ZScoreWithZeroStdDev(t *testing.T) {
	s := newAdaptiveStats()
	for range 100 {
		s.Observe(5.0)
	}

	// When stddev=0, any deviation should return a high z-score (or 0 if at mean).
	z := s.ZScore(5.0)
	if z != 0 {
		t.Fatalf("z-score at mean with zero stddev: got %f, want 0", z)
	}

	zHigh := s.ZScore(10.0)
	if zHigh < 100 {
		t.Fatalf("z-score away from mean with zero stddev: got %f, want very high", zHigh)
	}
}

func TestStats_ZScoreInsufficientData(t *testing.T) {
	s := newAdaptiveStats()
	// No observations: z-score should be 0 (can't compute)
	z := s.ZScore(100.0)
	if z != 0 {
		t.Fatalf("z-score with no data: got %f, want 0", z)
	}

	s.Observe(10.0)
	// Single observation: still can't compute variance
	z = s.ZScore(100.0)
	if z != 0 {
		t.Fatalf("z-score with 1 datum: got %f, want 0", z)
	}
}

// --- EWMA Tests ---

func TestStats_EWMA(t *testing.T) {
	s := newAdaptiveStats()

	// Feed constant value — EWMA should converge
	for range 100 {
		s.Observe(50.0)
	}

	fast, slow := s.EWMA()
	if !almostEqual(fast, 50.0, 1.0) {
		t.Fatalf("ewmaFast: got %f, want ≈50", fast)
	}
	if !almostEqual(slow, 50.0, 2.0) {
		t.Fatalf("ewmaSlow: got %f, want ≈50", slow)
	}
}

func TestStats_EWMASpike(t *testing.T) {
	s := newAdaptiveStats()

	// Build baseline at 10
	for range 100 {
		s.Observe(10.0)
	}

	// Sudden spike to 100
	for range 10 {
		s.Observe(100.0)
	}

	fast, slow := s.EWMA()
	// Fast EWMA should react quickly (closer to 100)
	// Slow EWMA should lag (still closer to 10)
	if fast <= slow {
		t.Fatalf("fast EWMA (%f) should exceed slow EWMA (%f) during spike", fast, slow)
	}
}

func TestStats_IsSpikeMode(t *testing.T) {
	s := newAdaptiveStats()

	// Build baseline at 10 — enough for EWMA to stabilize but not so many
	// that the slow EWMA can't be outpaced by a short spike.
	for range 100 {
		s.Observe(10.0)
	}

	if s.IsSpikeMode() {
		t.Fatal("should not be in spike mode during stable traffic")
	}

	// Sudden spike: fast EWMA (α=0.3) reacts in ~3 samples, slow (α=0.05)
	// barely moves. Just a few observations at a high value suffice.
	for range 5 {
		s.Observe(1000.0)
	}

	if !s.IsSpikeMode() {
		fast, slow := s.EWMA()
		t.Fatalf("should be in spike mode after 100x spike (fast=%f, slow=%f, ratio=%f)",
			fast, slow, fast/slow)
	}
}
