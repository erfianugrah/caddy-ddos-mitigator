package ddosmitigator

import (
	"sync"
	"testing"
)

func TestCMS_IncrementAndEstimate(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	key := []byte("test-fingerprint")

	count := cms.Increment(key)
	if count != 1 {
		t.Fatalf("first increment: got %d, want 1", count)
	}

	count = cms.Increment(key)
	if count != 2 {
		t.Fatalf("second increment: got %d, want 2", count)
	}

	est := cms.Estimate(key)
	if est != 2 {
		t.Fatalf("estimate: got %d, want 2", est)
	}
}

func TestCMS_DifferentKeys(t *testing.T) {
	cms := newCountMinSketch(4, 8192)

	for range 100 {
		cms.Increment([]byte("key-a"))
	}
	for range 50 {
		cms.Increment([]byte("key-b"))
	}

	estA := cms.Estimate([]byte("key-a"))
	estB := cms.Estimate([]byte("key-b"))

	// CMS guarantee: estimate >= true count
	if estA < 100 {
		t.Fatalf("key-a estimate %d < true count 100", estA)
	}
	if estB < 50 {
		t.Fatalf("key-b estimate %d < true count 50", estB)
	}

	// With width=8192 and depth=4, collision should be rare for 2 keys.
	// Allow small overestimate (up to 5%).
	if estA > 105 {
		t.Fatalf("key-a estimate %d too high (expected ≤105)", estA)
	}
	if estB > 55 {
		t.Fatalf("key-b estimate %d too high (expected ≤55)", estB)
	}
}

func TestCMS_NeverUnderestimates(t *testing.T) {
	cms := newCountMinSketch(4, 4096)

	// Insert many different keys and verify CMS never underestimates.
	trueCounts := make(map[string]int64)
	for i := range 10000 {
		key := []byte{byte(i >> 8), byte(i), byte(i >> 16)}
		count := int64(i%10 + 1)
		for range count {
			cms.Increment(key)
		}
		trueCounts[string(key)] = count
	}

	for keyStr, trueCount := range trueCounts {
		est := cms.Estimate([]byte(keyStr))
		if est < trueCount {
			t.Fatalf("CMS underestimated: key %x, true=%d, est=%d", keyStr, trueCount, est)
		}
	}
}

func TestCMS_Decay(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	key := []byte("decay-test")

	for range 100 {
		cms.Increment(key)
	}

	before := cms.Estimate(key)
	if before != 100 {
		t.Fatalf("before decay: got %d, want 100", before)
	}

	cms.Decay(0.5)
	after := cms.Estimate(key)

	// After halving, should be approximately 50.
	// Atomic integer division means some cells might round to 50 or 49.
	if after < 45 || after > 55 {
		t.Fatalf("after decay(0.5): got %d, want ~50", after)
	}
}

func TestCMS_DecayMultipleRounds(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	key := []byte("multi-decay")

	for range 1000 {
		cms.Increment(key)
	}

	// 5 rounds of 0.5 decay: 1000 → 500 → 250 → 125 → 62 → 31
	for range 5 {
		cms.Decay(0.5)
	}

	est := cms.Estimate(key)
	// Allow ±5 for rounding
	if est < 26 || est > 36 {
		t.Fatalf("after 5 decay rounds: got %d, want ~31", est)
	}
}

func TestCMS_Reset(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	key := []byte("reset-test")

	for range 100 {
		cms.Increment(key)
	}

	cms.Reset()

	est := cms.Estimate(key)
	if est != 0 {
		t.Fatalf("after reset: got %d, want 0", est)
	}
}

func TestCMS_ZeroEstimateForUnknown(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	est := cms.Estimate([]byte("never-inserted"))
	if est != 0 {
		t.Fatalf("unknown key estimate: got %d, want 0", est)
	}
}

// --- Concurrency ---

func TestCMS_ConcurrentIncrement(t *testing.T) {
	cms := newCountMinSketch(4, 8192)
	key := []byte("concurrent-key")
	const goroutines = 100
	const incrementsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range incrementsPerGoroutine {
				cms.Increment(key)
			}
		}()
	}
	wg.Wait()

	est := cms.Estimate(key)
	expected := int64(goroutines * incrementsPerGoroutine)
	if est != expected {
		t.Fatalf("concurrent estimate: got %d, want %d", est, expected)
	}
}

// --- Benchmark ---

func BenchmarkCMS_Increment(b *testing.B) {
	cms := newCountMinSketch(4, 8192)
	keys := make([][]byte, 1000)
	for i := range keys {
		keys[i] = []byte{byte(i >> 8), byte(i), byte(i >> 16), byte(i >> 24)}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cms.Increment(keys[i%len(keys)])
			i++
		}
	})
}
