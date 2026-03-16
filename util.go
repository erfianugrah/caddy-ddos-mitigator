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
	"syscall"
	"time"
)

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
type whitelist struct {
	prefixes []netip.Prefix
}

// newWhitelist parses CIDR strings and returns a whitelist.
// Returns an error if any CIDR is invalid.
func newWhitelist(cidrs []string) (*whitelist, error) {
	w := &whitelist{}
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist CIDR %q: %w", s, err)
		}
		w.prefixes = append(w.prefixes, p)
	}
	return w, nil
}

// Contains returns true if the address falls within any whitelisted prefix.
func (w *whitelist) Contains(addr netip.Addr) bool {
	for _, p := range w.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
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
// Uses atomic write to prevent partial reads by wafctl.
func writeJailFile(path string, j *ipJail) error {
	snap := j.Snapshot()
	f := jailFileFormat{
		Version:   1,
		Entries:   make(map[string]jailFileEntry, len(snap)),
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
	return atomicWriteFile(path, data, 0664)
}

// readJailFile reads a jail file and merges its entries into the jail.
// Entries already in the jail are not overwritten (plugin entries take precedence).
// Missing file is a no-op. Expired entries in the file are skipped.
func readJailFile(path string, j *ipJail) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read jail file: %w", err)
	}

	var f jailFileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("unmarshal jail file: %w", err)
	}

	now := time.Now()
	for ipStr, entry := range f.Entries {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue // skip invalid IPs
		}

		expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAt)
		if err != nil {
			continue
		}

		// Skip expired
		if now.After(expiresAt) {
			continue
		}

		// Don't overwrite existing entries (plugin state takes precedence)
		if j.IsJailed(addr) {
			continue
		}

		ttl := time.Until(expiresAt)
		j.Add(addr, ttl, entry.Reason, entry.Infractions)
	}

	return nil
}
