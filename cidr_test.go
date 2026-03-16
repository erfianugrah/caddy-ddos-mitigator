package ddosmitigator

import (
	"net/netip"
	"testing"
	"time"
)

func TestCIDR_NoPromotionBelowThreshold(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	// Jail 4 IPs from same /24 (below threshold of 5)
	for i := range 4 {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	addr := netip.MustParseAddr("192.0.2.4")
	prefix := agg.Check(jail, addr, 1*time.Hour)
	if prefix != nil {
		t.Fatalf("should not promote with only 4 IPs, got %s", prefix)
	}
}

func TestCIDR_PromotionAtThreshold(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	// Jail 5 IPs from same /24 (at threshold)
	for i := range 5 {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	addr := netip.MustParseAddr("192.0.2.5")
	prefix := agg.Check(jail, addr, 1*time.Hour)
	if prefix == nil {
		t.Fatal("should promote /24 when 5 IPs are jailed")
	}

	expected := netip.MustParsePrefix("192.0.2.0/24")
	if *prefix != expected {
		t.Fatalf("prefix: got %s, want %s", prefix, expected)
	}
}

func TestCIDR_IsPromoted(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	for i := range 5 {
		addr := netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	addr := netip.MustParseAddr("10.0.1.5")
	agg.Check(jail, addr, 1*time.Hour)

	// Any IP in 10.0.1.0/24 should be promoted
	if !agg.IsPromoted(netip.MustParseAddr("10.0.1.100")) {
		t.Fatal("10.0.1.100 should be in promoted /24")
	}
	if !agg.IsPromoted(netip.MustParseAddr("10.0.1.255")) {
		t.Fatal("10.0.1.255 should be in promoted /24")
	}

	// Different /24 should not be promoted
	if agg.IsPromoted(netip.MustParseAddr("10.0.2.1")) {
		t.Fatal("10.0.2.1 should NOT be in promoted prefix")
	}
}

func TestCIDR_PromotionExpires(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	for i := range 5 {
		addr := netip.AddrFrom4([4]byte{172, 16, 0, byte(i + 1)})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	agg.Check(jail, netip.MustParseAddr("172.16.0.5"), 50*time.Millisecond)
	if !agg.IsPromoted(netip.MustParseAddr("172.16.0.100")) {
		t.Fatal("should be promoted immediately after check")
	}

	time.Sleep(100 * time.Millisecond)

	if agg.IsPromoted(netip.MustParseAddr("172.16.0.100")) {
		t.Fatal("promotion should have expired")
	}
}

func TestCIDR_SweepExpired(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	for i := range 5 {
		addr := netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}
	agg.Check(jail, netip.MustParseAddr("10.0.1.5"), 50*time.Millisecond)

	if agg.Count() != 1 {
		t.Fatalf("count: got %d, want 1", agg.Count())
	}

	time.Sleep(100 * time.Millisecond)
	swept := agg.Sweep()
	if swept != 1 {
		t.Fatalf("swept: got %d, want 1", swept)
	}
	if agg.Count() != 0 {
		t.Fatalf("count after sweep: got %d, want 0", agg.Count())
	}
}

func TestCIDR_IPv6(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	// Jail 5 IPs from same /64
	for i := range 5 {
		addr := netip.MustParseAddr("2001:db8::1")
		// Vary the interface ID part
		a := addr.As16()
		a[15] = byte(i + 1)
		addr = netip.AddrFrom16(a)
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	a16 := netip.MustParseAddr("2001:db8::5").As16()
	a16[15] = 5
	addr := netip.AddrFrom16(a16)
	prefix := agg.Check(jail, addr, 1*time.Hour)
	if prefix == nil {
		t.Fatal("should promote /64 when 5 IPv6 IPs from same prefix are jailed")
	}
}

func TestCIDR_DifferentSubnetsNotPromoted(t *testing.T) {
	jail := newIPJail()
	agg := newCIDRAggregatorWithThresholds(5, 5)

	// Jail 5 IPs from DIFFERENT /24s — no single /24 should be promoted
	for i := range 5 {
		addr := netip.AddrFrom4([4]byte{10, 0, byte(i), 1})
		jail.Add(addr, 1*time.Hour, "test", 0)
	}

	addr := netip.MustParseAddr("10.0.4.1")
	prefix := agg.Check(jail, addr, 1*time.Hour)
	if prefix != nil {
		t.Fatalf("should NOT promote when IPs span different /24s, got %s", prefix)
	}
}
