// Package ddosmitigator — request fingerprinting subsystem.
//
// Produces an 8-byte (64-bit) FNV-64a hash from a configurable combination
// of request attributes. Multiple fingerprint strategies allow the system to
// select the most discriminating signature during spike mode (dosd-inspired).
//
// Path normalization strips query parameters, collapses traversal sequences,
// and lowercases — matching the policy engine's uri_path extraction.
package ddosmitigator

import (
	"encoding/hex"
	"hash/fnv"
	"net/netip"
	"net/url"
	"path"
	"strings"
)

// ─── Fingerprint Strategies ─────────────────────────────────────────

type fingerprintStrategy int32

const (
	fpFull     fingerprintStrategy = iota // hash(ip, method, path, ua)
	fpIPPath                              // hash(ip, method, path)
	fpIPOnly                              // hash(ip)
	fpPathUA                              // hash(method, path, ua)
	fpPathOnly                            // hash(method, path)
)

// ─── Compute ────────────────────────────────────────────────────────

// computeFingerprint hashes request attributes according to the given strategy.
// Returns an 8-byte hash suitable as a CMS key.
func computeFingerprint(strat fingerprintStrategy, addr netip.Addr, method, rawPath, ua string, pathDepth int) [8]byte {
	h := fnv.New64a()
	ip16 := addr.As16()
	normPath := normalizePath(rawPath, pathDepth)

	switch strat {
	case fpFull:
		h.Write(ip16[:])
		h.Write([]byte(method))
		h.Write([]byte(normPath))
		h.Write([]byte(ua))
	case fpIPPath:
		h.Write(ip16[:])
		h.Write([]byte(method))
		h.Write([]byte(normPath))
	case fpIPOnly:
		h.Write(ip16[:])
	case fpPathUA:
		h.Write([]byte(method))
		h.Write([]byte(normPath))
		h.Write([]byte(ua))
	case fpPathOnly:
		h.Write([]byte(method))
		h.Write([]byte(normPath))
	default:
		// Fallback to full
		h.Write(ip16[:])
		h.Write([]byte(method))
		h.Write([]byte(normPath))
		h.Write([]byte(ua))
	}

	var out [8]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ─── Path Normalization ─────────────────────────────────────────────

// normalizePath strips query strings, collapses traversal (/../, /./),
// removes trailing slashes, and lowercases the path. If maxDepth > 0,
// only the first maxDepth path segments are kept.
func normalizePath(p string, maxDepth int) string {
	// URL-decode first to normalize encoded characters
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}

	// Strip query string
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}

	// path.Clean handles: collapse //, /../, /./, trailing slash.
	// Returns "." for empty input — normalize to "/".
	p = path.Clean(p)
	if p == "." {
		p = "/"
	}

	// Truncate to maxDepth segments if configured.
	if maxDepth > 0 {
		segments := strings.Split(p, "/")
		if len(segments) > maxDepth+1 { // +1 for leading empty string from "/"
			p = strings.Join(segments[:maxDepth+1], "/")
		}
	}

	// Lowercase
	return strings.ToLower(p)
}

// ─── Hex Encoding ───────────────────────────────────────────────────

// fpHex returns the hex-encoded string representation of a fingerprint.
func fpHex(fp [8]byte) string {
	return hex.EncodeToString(fp[:])
}
