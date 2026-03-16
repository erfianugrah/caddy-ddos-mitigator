package ddosmitigator

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- Whitelist Tests ---

func TestWhitelist_Contains(t *testing.T) {
	wl, err := newWhitelist([]string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"::1/128",
	})
	if err != nil {
		t.Fatalf("newWhitelist: %v", err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"192.168.255.255", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"172.16.0.1", false},
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		addr := netip.MustParseAddr(tt.ip)
		got := wl.Contains(addr)
		if got != tt.want {
			t.Errorf("whitelist.Contains(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestWhitelist_Empty(t *testing.T) {
	wl, err := newWhitelist(nil)
	if err != nil {
		t.Fatalf("newWhitelist(nil): %v", err)
	}
	if wl.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("empty whitelist should not contain anything")
	}
}

func TestWhitelist_InvalidCIDR(t *testing.T) {
	// Invalid CIDRs should now return an error
	_, err := newWhitelist([]string{"not-a-cidr", "10.0.0.0/8", "also-bad"})
	if err == nil {
		t.Fatal("newWhitelist with invalid CIDR should return error")
	}

	// Valid-only list should succeed
	wl, err := newWhitelist([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("newWhitelist with valid CIDR: %v", err)
	}
	if !wl.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("valid CIDR should match")
	}
	if wl.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("non-matching CIDR should not match")
	}
}

// --- Atomic Write Tests ---

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"hello":"world"}`)

	if err := atomicWriteFile(path, data, 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch: got %q, want %q", got, data)
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	if err := atomicWriteFile(path, []byte("first"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("second"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("overwrite failed: got %q", got)
	}
}

func TestAtomicWriteFile_ConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.json")

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			data := []byte(`{"n":` + string(rune('0'+n%10)) + `}`)
			_ = atomicWriteFile(path, data, 0644)
		}(i)
	}
	wg.Wait()

	// File should exist and contain valid JSON (no partial writes)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("file should contain valid JSON after concurrent writes: %v (content: %q)", err, got)
	}
}

// --- Jail File Serialization Tests ---

func TestJailFile_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	j := newIPJail()
	j.Add(netip.MustParseAddr("192.0.2.1"), 1*time.Hour, "auto:z-score", 3)
	j.Add(netip.MustParseAddr("2001:db8::1"), 30*time.Minute, "manual", 1)

	if err := writeJailFile(path, j); err != nil {
		t.Fatalf("writeJailFile: %v", err)
	}

	// Read back into a fresh jail
	j2 := newIPJail()
	if err := readJailFile(path, j2); err != nil {
		t.Fatalf("readJailFile: %v", err)
	}

	if j2.Count() != 2 {
		t.Fatalf("count after read: got %d, want 2", j2.Count())
	}
	if !j2.IsJailed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("192.0.2.1 should be jailed after read")
	}
	if !j2.IsJailed(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("2001:db8::1 should be jailed after read")
	}

	e := j2.Get(netip.MustParseAddr("192.0.2.1"))
	if e == nil {
		t.Fatal("entry should exist")
	}
	if e.Reason != "auto:z-score" {
		t.Fatalf("reason: got %q, want %q", e.Reason, "auto:z-score")
	}
	if e.InfractionCount != 3 {
		t.Fatalf("infractions: got %d, want 3", e.InfractionCount)
	}
}

func TestJailFile_SkipsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	j := newIPJail()
	j.Add(netip.MustParseAddr("10.0.0.1"), 1*time.Hour, "alive", 0)
	j.Add(netip.MustParseAddr("10.0.0.2"), 5*time.Millisecond, "expired", 0)

	time.Sleep(10 * time.Millisecond)

	if err := writeJailFile(path, j); err != nil {
		t.Fatal(err)
	}

	j2 := newIPJail()
	if err := readJailFile(path, j2); err != nil {
		t.Fatal(err)
	}

	// Only the alive entry should be loaded
	if j2.Count() != 1 {
		t.Fatalf("count: got %d, want 1 (expired should be excluded)", j2.Count())
	}
	if !j2.IsJailed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("alive entry should survive")
	}
}

func TestJailFile_MergePreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	// Write a file with one entry (simulating wafctl writing)
	j1 := newIPJail()
	j1.Add(netip.MustParseAddr("192.0.2.1"), 1*time.Hour, "manual", 0)
	if err := writeJailFile(path, j1); err != nil {
		t.Fatal(err)
	}

	// Plugin has its own entry
	j2 := newIPJail()
	j2.Add(netip.MustParseAddr("192.0.2.2"), 1*time.Hour, "auto:z-score", 1)

	// Read file into j2 (merge)
	if err := readJailFile(path, j2); err != nil {
		t.Fatal(err)
	}

	// Should have both entries
	if j2.Count() != 2 {
		t.Fatalf("count after merge: got %d, want 2", j2.Count())
	}
	if !j2.IsJailed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("file entry should be merged in")
	}
	if !j2.IsJailed(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("existing entry should be preserved")
	}
}

func TestJailFile_ReadMissing(t *testing.T) {
	j := newIPJail()
	err := readJailFile("/nonexistent/jail.json", j)
	if err != nil {
		t.Fatalf("reading missing file should not error (no-op): %v", err)
	}
}

func TestJailFile_ReadCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")
	os.WriteFile(path, []byte("not json{{{"), 0644)

	j := newIPJail()
	err := readJailFile(path, j)
	if err == nil {
		t.Fatal("reading corrupt file should return error")
	}
}
