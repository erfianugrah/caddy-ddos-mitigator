// Package ddosmitigator — shared utilities.
//
// Whitelist for CIDR prefix matching, atomic file writes, and jail file
// serialization (JSON format shared with wafctl sidecar).
package ddosmitigator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// ─── Inline FNV-1a (Zero Allocation) ────────────────────────────────

const (
	fnv1aOffset32 = uint32(2166136261)
	fnv1aPrime32  = uint32(16777619)
	fnv1aOffset64 = uint64(14695981039346656037)
	fnv1aPrime64  = uint64(1099511628211)
)

// fnv32a computes FNV-1a 32-bit hash of a byte slice with zero allocation.
func fnv32a(data []byte) uint32 {
	h := fnv1aOffset32
	for _, b := range data {
		h ^= uint32(b)
		h *= fnv1aPrime32
	}
	return h
}

// fnv64a computes FNV-1a 64-bit hash of byte slices with zero allocation.
// Accepts variadic slices to hash multiple inputs without concatenation.
func fnv64a(parts ...[]byte) uint64 {
	h := fnv1aOffset64
	for _, data := range parts {
		for _, b := range data {
			h ^= uint64(b)
			h *= fnv1aPrime64
		}
	}
	return h
}

// fnv64aSeeded computes FNV-1a 64-bit hash with a seed XOR'd into the offset.
func fnv64aSeeded(seed uint64, data []byte) uint64 {
	h := fnv1aOffset64 ^ seed
	for _, b := range data {
		h ^= uint64(b)
		h *= fnv1aPrime64
	}
	return h
}

// ─── Jail Path Validation ───────────────────────────────────────────

// validateJailPath checks that the jail file path is absolute and not a symlink.
func validateJailPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("jail_file must be an absolute path, got %q", path)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("jail_file %q is a symlink, refusing", path)
		}
	}
	return nil
}

// ─── File Locking ───────────────────────────────────────────────────

// withFileLock acquires an exclusive flock on path+".lock" for the duration
// of fn. This coordinates jail file access between the plugin and wafctl.
func withFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire file lock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// ─── Whitelist ──────────────────────────────────────────────────────

// whitelist holds a static set of CIDR prefixes that bypass jail checks.
// whitelist holds an atomically-swappable set of CIDR prefixes.
// The inner whitelistData is immutable — updates create a new instance
// and swap the pointer atomically, so Contains() is lock-free.
type whitelist struct {
	data atomic.Pointer[whitelistData]
}

type whitelistData struct {
	prefixes []netip.Prefix
}

// newWhitelist parses CIDR strings and returns a whitelist.
// Returns an error if any CIDR is invalid.
func newWhitelist(cidrs []string) (*whitelist, error) {
	d := &whitelistData{}
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist CIDR %q: %w", s, err)
		}
		d.prefixes = append(d.prefixes, p)
	}
	w := &whitelist{}
	w.data.Store(d)
	return w, nil
}

// Update atomically replaces the whitelist with new CIDRs.
// Invalid CIDRs are silently skipped (logged by caller).
func (w *whitelist) Update(cidrs []string) error {
	d := &whitelistData{}
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid whitelist CIDR %q: %w", s, err)
		}
		d.prefixes = append(d.prefixes, p)
	}
	w.data.Store(d)
	return nil
}

// Contains returns true if the address falls within any whitelisted prefix.
// Lock-free — reads the atomic pointer.
func (w *whitelist) Contains(addr netip.Addr) bool {
	d := w.data.Load()
	if d == nil {
		return false
	}
	for _, p := range d.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// CIDRs returns the current whitelist CIDRs as strings.
func (w *whitelist) CIDRs() []string {
	d := w.data.Load()
	if d == nil {
		return nil
	}
	result := make([]string, len(d.prefixes))
	for i, p := range d.prefixes {
		result[i] = p.String()
	}
	return result
}

// ─── Atomic File Write ──────────────────────────────────────────────

// atomicWriteFile writes data to a temporary file in the same directory,
// fsyncs, then renames to the target path. This ensures the file is never
// partially written — readers always see either the old or new content.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		// Clean up temp file on error
		tmp.Close()
		os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp to target: %w", err)
	}
	return nil
}

// ─── Jail File I/O ──────────────────────────────────────────────────

// jailFileFormat is the JSON structure shared between the plugin and wafctl.
type jailFileFormat struct {
	Version   int                      `json:"version"`
	Entries   map[string]jailFileEntry `json:"entries"`
	Whitelist []string                 `json:"whitelist,omitempty"` // CIDR prefixes, updated by wafctl
	UpdatedAt string                   `json:"updated_at"`
}

// jailFileEntry is the per-IP data in the jail file.
type jailFileEntry struct {
	ExpiresAt   string `json:"expires_at"`
	Infractions int32  `json:"infractions"`
	Reason      string `json:"reason"`
	JailedAt    string `json:"jailed_at"`
}

// writeJailFile serializes the jail's non-expired entries to a JSON file.
// Includes the current whitelist CIDRs so wafctl can read/update them.
// Uses atomic write to prevent partial reads by wafctl.
func writeJailFile(path string, j *ipJail, wl *whitelist) error {
	snap := j.Snapshot()
	f := jailFileFormat{
		Version:   1,
		Entries:   make(map[string]jailFileEntry, len(snap)),
		Whitelist: wl.CIDRs(),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for addr, e := range snap {
		f.Entries[addr.String()] = jailFileEntry{
			ExpiresAt:   time.Unix(0, e.ExpiresAt).UTC().Format(time.RFC3339),
			Infractions: e.InfractionCount,
			Reason:      e.Reason,
			JailedAt:    time.Unix(0, e.JailedAt).UTC().Format(time.RFC3339),
		}
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal jail file: %w", err)
	}
	return atomicWriteFile(path, data, 0644)
}

// readJailFile reads a jail file and merges its entries into the jail.
// Wrapper around readJailFileIPs that discards the result.
func readJailFile(path string, j *ipJail) error {
	_, err := readJailFileIPs(path, j)
	return err
}

// readJailFileIPs reads a jail file, merges new entries into the jail, and
// returns the set of non-expired IPs present in the file plus a count of
// entries that were skipped due to parse errors. This allows callers to
// detect IPs that were removed from the file (e.g., unjailed via wafctl).
// Returns nil map if the file does not exist.
// jailFileResult holds the parsed contents of a jail file.
type jailFileResult struct {
	IPs       map[netip.Addr]bool // non-expired IPs present in the file
	Whitelist []string            // CIDR prefixes from the file (may be nil)
	Skipped   int                 // entries that failed to parse
}

func readJailFileIPs(path string, j *ipJail) (*jailFileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read jail file: %w", err)
	}

	var f jailFileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("unmarshal jail file: %w", err)
	}

	now := time.Now()
	result := &jailFileResult{
		IPs:       make(map[netip.Addr]bool, len(f.Entries)),
		Whitelist: f.Whitelist,
	}
	for ipStr, entry := range f.Entries {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			result.Skipped++
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
		if err != nil {
			result.Skipped++
			continue
		}

		// Skip expired
		if now.After(expiresAt) {
			continue
		}

		result.IPs[addr] = true

		// Don't overwrite existing entries (plugin state takes precedence)
		if j.IsJailed(addr) {
			continue
		}

		ttl := time.Until(expiresAt)
		j.Add(addr, ttl, entry.Reason, entry.Infractions)
	}

	return result, nil
}
