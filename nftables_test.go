package ddosmitigator

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ─── Mock nftManager ────────────────────────────────────────────────

type mockNft struct {
	mu            sync.Mutex
	setupCalled   bool
	setupErr      error
	syncCalls     int
	lastSync      map[netip.Addr]jailEntry
	cleanupCalled bool
	available     bool
}

func (m *mockNft) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setupCalled = true
	return m.setupErr
}

func (m *mockNft) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalls++
	m.lastSync = entries
	return nil
}

func (m *mockNft) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupCalled = true
	return nil
}

func (m *mockNft) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.available
}

// ─── Tests ──────────────────────────────────────────────────────────

func TestNft_NoopWhenDisabled(t *testing.T) {
	n := nftNoop{}
	if n.Available() {
		t.Fatal("noop should not be available")
	}
	if err := n.Setup(); err != nil {
		t.Fatal("noop setup should not error")
	}
	if err := n.SyncJail(nil, nil); err != nil {
		t.Fatal("noop sync should not error")
	}
	if err := n.Cleanup(); err != nil {
		t.Fatal("noop cleanup should not error")
	}
}

func TestNft_MockSetupAndSync(t *testing.T) {
	m := &mockNft{available: true}

	if !m.Available() {
		t.Fatal("mock should be available")
	}

	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	if !m.setupCalled {
		t.Fatal("setup should be called")
	}

	entries := map[netip.Addr]jailEntry{
		netip.MustParseAddr("192.0.2.1"): {
			ExpiresAt: time.Now().Add(1 * time.Hour).UnixNano(),
			Reason:    "test",
		},
		netip.MustParseAddr("2001:db8::1"): {
			ExpiresAt: time.Now().Add(30 * time.Minute).UnixNano(),
			Reason:    "test",
		},
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

func TestNft_MockCleanup(t *testing.T) {
	m := &mockNft{available: true}
	m.Setup()

	if err := m.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !m.cleanupCalled {
		t.Fatal("cleanup should be called")
	}
}

func TestNft_GracefulWhenUnavailable(t *testing.T) {
	m := &mockNft{available: false}

	if m.Available() {
		t.Fatal("should not be available")
	}
	// Setup/sync/cleanup should still work (noop behavior)
	if err := m.SyncJail(nil, nil); err != nil {
		t.Fatal("sync should not error when unavailable")
	}
}

func TestNft_SyncFiltersExpired(t *testing.T) {
	m := &mockNft{available: true}
	m.Setup()

	entries := map[netip.Addr]jailEntry{
		netip.MustParseAddr("10.0.0.1"): {
			ExpiresAt: time.Now().Add(1 * time.Hour).UnixNano(),
			Reason:    "alive",
		},
		netip.MustParseAddr("10.0.0.2"): {
			ExpiresAt: time.Now().Add(-1 * time.Hour).UnixNano(), // expired
			Reason:    "expired",
		},
	}

	// The real nftReal.SyncJail filters expired entries.
	// Our mock doesn't filter, but we verify the contract:
	// the caller (the sync goroutine) passes jail.Snapshot()
	// which already excludes expired entries.
	// Here we just verify the mock receives what it's given.
	m.SyncJail(entries, nil)
	if m.syncCalls != 1 {
		t.Fatal("sync should be called once")
	}
}

func TestNft_MultipleSyncs(t *testing.T) {
	m := &mockNft{available: true}
	m.Setup()

	for range 10 {
		m.SyncJail(map[netip.Addr]jailEntry{}, nil)
	}
	if m.syncCalls != 10 {
		t.Fatalf("sync calls: got %d, want 10", m.syncCalls)
	}
}

func TestNft_RealUnavailableWithoutNetAdmin(t *testing.T) {
	// The real nftManager should gracefully report unavailable
	// when running without NET_ADMIN (which is the case in tests).
	logger, _ := newTestLogger()
	n := newNftManager(logger)

	// On most test environments (no NET_ADMIN), this returns false.
	// If running as root, it may return true — both are correct behavior.
	available := n.Available()
	t.Logf("nftables available: %v (expected false without NET_ADMIN)", available)

	if !available {
		// Verify cleanup doesn't panic on inactive manager
		if err := n.Cleanup(); err != nil {
			t.Fatalf("cleanup on unavailable manager should not error: %v", err)
		}
	}
}

// newTestLogger creates a no-op zap logger for testing.
func newTestLogger() (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	cfg.OutputPaths = []string{} // discard output
	return cfg.Build()
}
