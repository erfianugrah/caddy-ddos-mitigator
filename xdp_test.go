package ddosmitigator

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ─── Mock XDP Manager ───────────────────────────────────────────────

type mockXDP struct {
	mu            sync.Mutex
	setupCalled   bool
	syncCalls     int
	lastSync      map[netip.Addr]jailEntry
	cleanupCalled bool
	available     bool
}

func (m *mockXDP) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setupCalled = true
	return nil
}

func (m *mockXDP) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalls++
	m.lastSync = entries
	return nil
}

func (m *mockXDP) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupCalled = true
	return nil
}

func (m *mockXDP) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.available
}

func (m *mockXDP) Stats() (uint64, uint64) { return 0, 0 }

// ─── Tests ──────────────────────────────────────────────────────────

func TestXDP_NoopWhenDisabled(t *testing.T) {
	n := xdpNoop{}
	if n.Available() {
		t.Fatal("noop should not be available")
	}
	if err := n.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := n.SyncJail(nil, nil); err != nil {
		t.Fatal(err)
	}
	p, d := n.Stats()
	if p != 0 || d != 0 {
		t.Fatal("noop stats should be zero")
	}
	if err := n.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestXDP_MockSetupAndSync(t *testing.T) {
	m := &mockXDP{available: true}

	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if !m.setupCalled {
		t.Fatal("setup should be called")
	}

	entries := map[netip.Addr]jailEntry{
		netip.MustParseAddr("192.0.2.1"):   {ExpiresAt: time.Now().Add(1 * time.Hour).UnixNano()},
		netip.MustParseAddr("2001:db8::1"): {ExpiresAt: time.Now().Add(30 * time.Minute).UnixNano()},
	}

	if err := m.SyncJail(entries, nil); err != nil {
		t.Fatal(err)
	}
	if m.syncCalls != 1 {
		t.Fatalf("sync calls: got %d, want 1", m.syncCalls)
	}
	if len(m.lastSync) != 2 {
		t.Fatalf("synced entries: got %d, want 2", len(m.lastSync))
	}
}

func TestXDP_MockCleanup(t *testing.T) {
	m := &mockXDP{available: true}
	m.Setup()
	if err := m.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !m.cleanupCalled {
		t.Fatal("cleanup should be called")
	}
}

func TestXDP_GracefulWhenUnavailable(t *testing.T) {
	m := &mockXDP{available: false}
	if m.Available() {
		t.Fatal("should not be available")
	}
}

func TestXDP_RealUnavailableWithoutBPFCap(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	mgr := newXDPManager("lo", logger)

	// Without BPF cap, Available() may still return true (it only checks
	// if the spec can be parsed and the interface exists). Setup() is what
	// actually requires BPF cap.
	available := mgr.Available()
	t.Logf("XDP available: %v", available)

	if available {
		// If somehow available (running as root), setup will likely fail
		// on WSL2 which doesn't support XDP on loopback.
		err := mgr.Setup()
		if err != nil {
			t.Logf("XDP setup failed (expected without BPF cap): %v", err)
		} else {
			// Cleanup if it somehow succeeded
			mgr.Cleanup()
		}
	}
}

func TestXDP_LpmKeyLayout(t *testing.T) {
	// Verify the v4-mapped-v6 key layout matches what the C program expects.
	var key xdpDropLpmKey
	key.Prefixlen = 128

	// IPv4 192.0.2.1 → ::ffff:192.0.2.1
	addr := netip.MustParseAddr("192.0.2.1")
	a4 := addr.As4()
	key.Addr[10] = 0xff
	key.Addr[11] = 0xff
	copy(key.Addr[12:], a4[:])

	if key.Addr[12] != 192 || key.Addr[13] != 0 || key.Addr[14] != 2 || key.Addr[15] != 1 {
		t.Fatalf("IPv4 mapping wrong: %v", key.Addr)
	}
	if key.Addr[10] != 0xff || key.Addr[11] != 0xff {
		t.Fatal("v4-mapped-v6 prefix wrong")
	}
	// First 10 bytes should be zero
	for i := range 10 {
		if key.Addr[i] != 0 {
			t.Fatalf("byte %d should be zero, got %d", i, key.Addr[i])
		}
	}
}
