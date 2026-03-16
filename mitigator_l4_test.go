package ddosmitigator

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// ─── Mock Connection ────────────────────────────────────────────────

// mockTCPConn simulates a net.TCPConn for testing forceDrop behavior.
type mockTCPConn struct {
	net.TCPConn // embed for interface satisfaction
	remoteAddr  net.Addr
	closed      bool
	lingerSet   bool
	lingerSecs  int
	readClosed  bool
	writeClosed bool
}

func (c *mockTCPConn) RemoteAddr() net.Addr        { return c.remoteAddr }
func (c *mockTCPConn) Close() error                { c.closed = true; return nil }
func (c *mockTCPConn) Read(b []byte) (int, error)  { return 0, nil }
func (c *mockTCPConn) Write(b []byte) (int, error) { return len(b), nil }

// mockConn wraps mockTCPConn with the interfaces layer4.Connection expects.
type mockConn struct {
	tcp        *mockTCPConn
	remoteAddr net.Addr
	closed     bool
}

func (c *mockConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (c *mockConn) Close() error                       { c.closed = true; return nil }
func (c *mockConn) Read(b []byte) (int, error)         { return 0, nil }
func (c *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// ─── Jail Registry Tests ────────────────────────────────────────────

func TestJailRegistry_SharedInstance(t *testing.T) {
	// Clean registry state
	jailRegistryMu.Lock()
	delete(jailRegistry, "/test/shared.json")
	jailRegistryMu.Unlock()

	j1 := getOrCreateJail("/test/shared.json")
	j2 := getOrCreateJail("/test/shared.json")

	if j1 != j2 {
		t.Fatal("same jail file path should return same jail instance")
	}

	// Different path = different jail
	j3 := getOrCreateJail("/test/other.json")
	if j1 == j3 {
		t.Fatal("different jail file path should return different jail instance")
	}
}

func TestJailRegistry_L7AndL4ShareState(t *testing.T) {
	// Clean registry
	jailRegistryMu.Lock()
	delete(jailRegistry, "/test/l7l4.json")
	jailRegistryMu.Unlock()

	// Simulate L7 provisioning
	l7Jail := getOrCreateJail("/test/l7l4.json")
	addr := netip.MustParseAddr("198.51.100.1")
	l7Jail.Add(addr, 1*time.Hour, "auto:z-score", 0)

	// Simulate L4 looking up the same jail
	l4Jail := getJail("/test/l7l4.json")
	if l4Jail == nil {
		t.Fatal("L4 should find jail registered by L7")
	}

	if !l4Jail.IsJailed(addr) {
		t.Fatal("L4 jail should see entry added by L7")
	}
}

func TestJailRegistry_GetMissing(t *testing.T) {
	j := getJail("/nonexistent/jail.json")
	if j != nil {
		t.Fatal("getJail for unregistered path should return nil")
	}
}

// ─── L4 Module Tests ────────────────────────────────────────────────

func TestL4_CaddyModule_ID(t *testing.T) {
	m := DDOSMitigatorL4{}
	info := m.CaddyModule()
	if info.ID != "layer4.handlers.ddos_mitigator" {
		t.Fatalf("L4 module ID: got %q, want %q", info.ID, "layer4.handlers.ddos_mitigator")
	}
}

func TestL4_Provision_WithSharedJail(t *testing.T) {
	// Clean registry
	jailRegistryMu.Lock()
	delete(jailRegistry, "/test/l4-provision.json")
	jailRegistryMu.Unlock()

	// First register a jail (simulates L7 Provision running first)
	l7Jail := getOrCreateJail("/test/l4-provision.json")
	l7Jail.Add(netip.MustParseAddr("10.0.0.1"), 1*time.Hour, "test", 0)

	// Provision L4 with same path
	m := &DDOSMitigatorL4{
		JailFile: "/test/l4-provision.json",
	}
	ctx, cancel := testContext()
	defer cancel()

	if err := m.Provision(ctx); err != nil {
		t.Fatalf("L4 Provision: %v", err)
	}

	if m.jail == nil {
		t.Fatal("L4 jail should be initialized after Provision")
	}
	if !m.jail.IsJailed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("L4 should share L7's jail state")
	}
}

func TestL4_Provision_WithoutJailFile(t *testing.T) {
	m := &DDOSMitigatorL4{}
	ctx, cancel := testContext()
	defer cancel()

	if err := m.Provision(ctx); err != nil {
		t.Fatalf("L4 Provision without jail_file: %v", err)
	}
	if m.jail == nil {
		t.Fatal("L4 should create a standalone jail when no jail_file specified")
	}
}

// ─── Force Drop Tests ───────────────────────────────────────────────

func TestForceDropTCP(t *testing.T) {
	// We can't test actual SO_LINGER without real sockets, but we can
	// verify the connection unwrap + close logic by testing with a net.Conn
	// that isn't a *net.TCPConn (fallback path).
	conn := &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 12345},
	}

	err := forceDropConn(conn)
	if err == nil {
		t.Fatal("forceDrop should return an error to halt the handler chain")
	}
	if !conn.closed {
		t.Fatal("connection should be closed")
	}
}

// ─── Extract Remote IP Tests ────────────────────────────────────────

func TestExtractRemoteIP_TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345}
	got, ok := extractRemoteIP(addr)
	if !ok {
		t.Fatal("should parse TCPAddr")
	}
	if got != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("got %s, want 192.0.2.1", got)
	}
}

func TestExtractRemoteIP_IPv6(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	got, ok := extractRemoteIP(addr)
	if !ok {
		t.Fatal("should parse IPv6 TCPAddr")
	}
	if got != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("got %s, want 2001:db8::1", got)
	}
}

func TestExtractRemoteIP_StringAddr(t *testing.T) {
	// Some connection wrappers return non-TCPAddr with String() = "1.2.3.4:567"
	addr := stringAddr("203.0.113.50:9999")
	got, ok := extractRemoteIP(addr)
	if !ok {
		t.Fatal("should parse string addr with host:port")
	}
	if got != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("got %s, want 203.0.113.50", got)
	}
}

// stringAddr implements net.Addr with just a string.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

// ─── Integration: Jail Check Logic ──────────────────────────────────

func TestL4_JailCheckLogic(t *testing.T) {
	// Clean registry
	jailRegistryMu.Lock()
	delete(jailRegistry, "/test/l4-check.json")
	jailRegistryMu.Unlock()

	jail := getOrCreateJail("/test/l4-check.json")

	// Jail an IP
	jailedAddr := netip.MustParseAddr("198.51.100.99")
	jail.Add(jailedAddr, 1*time.Hour, "test", 0)

	// Clean IP should not be jailed
	cleanAddr := netip.MustParseAddr("203.0.113.1")
	if jail.IsJailed(cleanAddr) {
		t.Fatal("clean IP should not be jailed")
	}

	// Jailed IP should be caught
	if !jail.IsJailed(jailedAddr) {
		t.Fatal("jailed IP should be detected")
	}
}

// ─── Benchmark ──────────────────────────────────────────────────────

func BenchmarkExtractRemoteIP(b *testing.B) {
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12345}
	b.ResetTimer()
	for b.Loop() {
		extractRemoteIP(addr)
	}
}

// Verify unused imports don't cause issues
var _ = bytes.NewBuffer
