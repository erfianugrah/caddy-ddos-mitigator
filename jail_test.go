package ddosmitigator

import (
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// --- Unit Tests ---

func TestJail_AddAndCheck(t *testing.T) {
	j := newIPJail()
	addr := netip.MustParseAddr("192.0.2.1")

	if j.IsJailed(addr) {
		t.Fatal("fresh jail should not contain any IP")
	}

	j.Add(addr, 1*time.Hour, "test", 0)

	if !j.IsJailed(addr) {
		t.Fatal("IP should be jailed after Add")
	}
	if j.Count() != 1 {
		t.Fatalf("count: got %d, want 1", j.Count())
	}
}

func TestJail_Get(t *testing.T) {
	j := newIPJail()
	addr := netip.MustParseAddr("10.0.0.1")

	if e := j.Get(addr); e != nil {
		t.Fatal("Get on missing IP should return nil")
	}

	j.Add(addr, 1*time.Hour, "auto:z-score", 3)

	e := j.Get(addr)
	if e == nil {
		t.Fatal("Get should return entry after Add")
	}
	if e.Reason != "auto:z-score" {
		t.Fatalf("reason: got %q, want %q", e.Reason, "auto:z-score")
	}
	if e.InfractionCount != 3 {
		t.Fatalf("infractions: got %d, want 3", e.InfractionCount)
	}
}

func TestJail_TTLExpiry(t *testing.T) {
	j := newIPJail()
	addr := netip.MustParseAddr("192.0.2.2")

	j.Add(addr, 10*time.Millisecond, "test", 0)

	if !j.IsJailed(addr) {
		t.Fatal("should be jailed immediately after add")
	}

	time.Sleep(20 * time.Millisecond)

	if j.IsJailed(addr) {
		t.Fatal("should NOT be jailed after TTL expiry")
	}
}

func TestJail_Remove(t *testing.T) {
	j := newIPJail()
	addr := netip.MustParseAddr("192.0.2.3")

	j.Add(addr, 1*time.Hour, "test", 0)
	if !j.IsJailed(addr) {
		t.Fatal("should be jailed")
	}

	j.Remove(addr)
	if j.IsJailed(addr) {
		t.Fatal("should NOT be jailed after Remove")
	}
	if j.Count() != 0 {
		t.Fatalf("count: got %d, want 0", j.Count())
	}
}

func TestJail_Sweep(t *testing.T) {
	j := newIPJail()

	alive := netip.MustParseAddr("10.0.0.1")
	expired1 := netip.MustParseAddr("10.0.0.2")
	expired2 := netip.MustParseAddr("10.0.0.3")

	j.Add(alive, 1*time.Hour, "test", 0)
	j.Add(expired1, 5*time.Millisecond, "test", 0)
	j.Add(expired2, 5*time.Millisecond, "test", 0)

	if j.Count() != 3 {
		t.Fatalf("count before sweep: got %d, want 3", j.Count())
	}

	time.Sleep(10 * time.Millisecond)
	swept := j.Sweep()

	if swept != 2 {
		t.Fatalf("swept: got %d, want 2", swept)
	}
	if j.Count() != 1 {
		t.Fatalf("count after sweep: got %d, want 1", j.Count())
	}
	if !j.IsJailed(alive) {
		t.Fatal("alive entry should survive sweep")
	}
	if j.IsJailed(expired1) || j.IsJailed(expired2) {
		t.Fatal("expired entries should be swept")
	}
}

func TestJail_AddUpdatesExisting(t *testing.T) {
	j := newIPJail()
	addr := netip.MustParseAddr("192.0.2.1")

	j.Add(addr, 1*time.Minute, "first", 1)
	j.Add(addr, 2*time.Hour, "second", 5)

	e := j.Get(addr)
	if e == nil {
		t.Fatal("entry should exist")
	}
	if e.Reason != "second" {
		t.Fatalf("reason should be updated: got %q", e.Reason)
	}
	if e.InfractionCount != 5 {
		t.Fatalf("infractions should be updated: got %d", e.InfractionCount)
	}
	// Count should not double
	if j.Count() != 1 {
		t.Fatalf("count: got %d, want 1 (update, not insert)", j.Count())
	}
}

func TestJail_IPv6(t *testing.T) {
	j := newIPJail()
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")

	j.Add(v4, 1*time.Hour, "v4", 0)
	j.Add(v6, 1*time.Hour, "v6", 0)

	if !j.IsJailed(v4) {
		t.Fatal("v4 should be jailed")
	}
	if !j.IsJailed(v6) {
		t.Fatal("v6 should be jailed")
	}
	if j.Count() != 2 {
		t.Fatalf("count: got %d, want 2", j.Count())
	}
}

func TestJail_Snapshot(t *testing.T) {
	j := newIPJail()
	j.Add(netip.MustParseAddr("10.0.0.1"), 1*time.Hour, "a", 1)
	j.Add(netip.MustParseAddr("10.0.0.2"), 1*time.Hour, "b", 2)
	j.Add(netip.MustParseAddr("10.0.0.3"), 5*time.Millisecond, "c", 0)

	time.Sleep(10 * time.Millisecond)

	snap := j.Snapshot()
	// Snapshot should only include non-expired entries
	if len(snap) != 2 {
		t.Fatalf("snapshot length: got %d, want 2 (expired entry excluded)", len(snap))
	}
	if _, ok := snap[netip.MustParseAddr("10.0.0.1")]; !ok {
		t.Fatal("snapshot missing 10.0.0.1")
	}
	if _, ok := snap[netip.MustParseAddr("10.0.0.2")]; !ok {
		t.Fatal("snapshot missing 10.0.0.2")
	}
}

// --- Concurrency Tests ---

func TestJail_ConcurrentAddAndCheck(t *testing.T) {
	j := newIPJail()
	const goroutines = 100
	const ipsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range ipsPerGoroutine {
				// Use deterministic IPs derived from goroutine ID + index
				b3 := byte(id)
				b4 := byte(i)
				addr := netip.AddrFrom4([4]byte{10, 0, b3, b4})
				j.Add(addr, 1*time.Hour, "concurrent", 0)
				if !j.IsJailed(addr) {
					t.Errorf("IP %s should be jailed right after Add", addr)
				}
			}
		}(g)
	}
	wg.Wait()

	if j.Count() != goroutines*ipsPerGoroutine {
		t.Fatalf("count: got %d, want %d", j.Count(), goroutines*ipsPerGoroutine)
	}
}

func TestJail_ConcurrentSweep(t *testing.T) {
	j := newIPJail()

	// Add 1000 IPs with short TTL
	for i := range 1000 {
		addr := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		j.Add(addr, 5*time.Millisecond, "test", 0)
	}
	time.Sleep(10 * time.Millisecond)

	// Sweep concurrently with adds
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		j.Sweep()
	}()
	go func() {
		defer wg.Done()
		for i := range 100 {
			addr := netip.AddrFrom4([4]byte{172, 16, 0, byte(i)})
			j.Add(addr, 1*time.Hour, "new", 0)
		}
	}()
	wg.Wait()

	// All short-TTL should be swept, all new should survive
	for i := range 100 {
		addr := netip.AddrFrom4([4]byte{172, 16, 0, byte(i)})
		if !j.IsJailed(addr) {
			t.Fatalf("new IP %s should survive concurrent sweep", addr)
		}
	}
}

// --- Benchmark ---

func BenchmarkJail_IsJailed(b *testing.B) {
	j := newIPJail()
	// Pre-populate with 10K entries
	for i := range 10000 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		j.Add(addr, 1*time.Hour, "bench", 0)
	}

	// Benchmark lookups against a mix of jailed and non-jailed IPs
	addrs := make([]netip.Addr, 1000)
	for i := range addrs {
		if i%2 == 0 {
			addrs[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		} else {
			addrs[i] = netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)})
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := rand.Intn(len(addrs))
		for pb.Next() {
			j.IsJailed(addrs[i%len(addrs)])
			i++
		}
	})
}
