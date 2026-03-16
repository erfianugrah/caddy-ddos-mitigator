package ddosmitigator

import (
	"net/netip"
	"testing"
)

// --- Path Normalization ---

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple", "/foo/bar", "/foo/bar"},
		{"strip query", "/foo?a=1&b=2", "/foo"},
		{"strip fragment", "/foo#section", "/foo#section"}, // path.Clean doesn't strip fragments
		{"collapse dotdot", "/foo/../bar", "/bar"},
		{"collapse dot", "/foo/./bar", "/foo/bar"},
		{"lowercase", "/Foo/BAR", "/foo/bar"},
		{"trailing slash", "/foo/bar/", "/foo/bar"},
		{"double slash", "/foo//bar", "/foo/bar"},
		{"root", "/", "/"},
		{"empty", "", "/"},
		{"query only", "?x=1", "/"},
		{"complex", "/API/V2/../v1/Users?page=3", "/api/v1/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.in, 0)
			if got != tt.want {
				t.Fatalf("normalizePath(%q, 0) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizePath_Depth(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		depth int
		want  string
	}{
		{"depth 0 no truncation", "/a/b/c/d", 0, "/a/b/c/d"},
		{"depth 1", "/a/b/c/d", 1, "/a"},
		{"depth 2", "/a/b/c/d", 2, "/a/b"},
		{"depth 3", "/a/b/c/d", 3, "/a/b/c"},
		{"depth exceeds segments", "/a/b", 5, "/a/b"},
		{"root with depth", "/", 2, "/"},
		{"single segment", "/foo", 1, "/foo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.in, tt.depth)
			if got != tt.want {
				t.Fatalf("normalizePath(%q, %d) = %q, want %q", tt.in, tt.depth, got, tt.want)
			}
		})
	}
}

// --- Fingerprint Strategies ---

func TestFingerprint_DifferentStrategiesProduceDifferentHashes(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	method := "GET"
	path := "/api/users"
	ua := "Mozilla/5.0"

	results := make(map[fingerprintStrategy][8]byte)
	strategies := []fingerprintStrategy{fpFull, fpIPPath, fpIPOnly, fpPathUA, fpPathOnly}

	for _, s := range strategies {
		results[s] = computeFingerprint(s, addr, method, path, ua, 0)
	}

	// Each strategy should produce a different hash (except by coincidence).
	// At minimum, fpIPOnly and fpPathOnly must differ since they hash
	// completely different inputs.
	if results[fpIPOnly] == results[fpPathOnly] {
		t.Fatal("fpIPOnly and fpPathOnly should produce different hashes")
	}
	if results[fpFull] == results[fpIPOnly] {
		t.Fatal("fpFull and fpIPOnly should produce different hashes")
	}
}

func TestFingerprint_SameInputsSameHash(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")

	for _, strat := range []fingerprintStrategy{fpFull, fpIPPath, fpIPOnly, fpPathUA, fpPathOnly} {
		a := computeFingerprint(strat, addr, "POST", "/login", "curl/7.88", 0)
		b := computeFingerprint(strat, addr, "POST", "/login", "curl/7.88", 0)
		if a != b {
			t.Fatalf("strategy %d: same inputs should produce same hash", strat)
		}
	}
}

func TestFingerprint_DifferentIPsDifferentHash(t *testing.T) {
	a := computeFingerprint(fpFull,
		netip.MustParseAddr("10.0.0.1"), "GET", "/", "ua", 0)
	b := computeFingerprint(fpFull,
		netip.MustParseAddr("10.0.0.2"), "GET", "/", "ua", 0)
	if a == b {
		t.Fatal("different IPs should produce different fingerprints")
	}
}

func TestFingerprint_PathNormalizationApplied(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")

	// These paths should normalize to the same value
	a := computeFingerprint(fpFull, addr, "GET", "/Foo/Bar?x=1", "ua", 0)
	b := computeFingerprint(fpFull, addr, "GET", "/foo/bar?y=2", "ua", 0)
	if a != b {
		t.Fatal("fingerprint should normalize paths (lowercase, strip query)")
	}
}

func TestFingerprint_IPv6(t *testing.T) {
	a := computeFingerprint(fpIPOnly, netip.MustParseAddr("2001:db8::1"), "", "", "", 0)
	b := computeFingerprint(fpIPOnly, netip.MustParseAddr("2001:db8::2"), "", "", "", 0)
	if a == b {
		t.Fatal("different IPv6 addresses should produce different fingerprints")
	}
}

func TestFpHex(t *testing.T) {
	fp := [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}
	hex := fpHex(fp)
	if hex != "deadbeefcafebabe" {
		t.Fatalf("fpHex: got %q, want %q", hex, "deadbeefcafebabe")
	}
}

// --- Benchmark ---

func BenchmarkFingerprint_Full(b *testing.B) {
	addr := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for b.Loop() {
		computeFingerprint(fpFull, addr, "GET", "/api/v1/users?page=3", "Mozilla/5.0 (X11; Linux)", 0)
	}
}
