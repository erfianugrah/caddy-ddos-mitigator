// Package ddosmitigator — nftables kernel-level drop subsystem.
//
// Manages an nftables ipset (inet family) that mirrors the IP jail.
// Packets from jailed IPs are dropped in the kernel before reaching
// Caddy's socket, at ~1.5M pps per CPU.
//
// Feature-flagged: disabled by default. Enable via Caddyfile:
//
//	ddos_mitigator {
//	    kernel_drop true
//	}
//
// Requires NET_ADMIN capability on the Caddy container. If the capability
// is missing, the module logs a warning and falls back to userspace-only
// mitigation (L7 403 + L4 RST).
//
// On cleanup (Caddy shutdown/reload), all nftables rules, chains, and
// tables created by this module are removed — no stale kernel state.
package ddosmitigator

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

// ─── Constants ──────────────────────────────────────────────────────

const (
	nftTableName = "ddos_mitigator"
	nftChainName = "input_filter"
	nftSetV4Name = "jail_v4"
	nftSetV6Name = "jail_v6"
)

// ─── Interface (for testing) ────────────────────────────────────────

// nftManager abstracts nftables operations for testability.
type nftManager interface {
	// Setup creates the nftables table, chain, sets, and drop rules.
	Setup() error
	// SyncJail updates the nftables sets to match the current jail state
	// and promoted CIDR prefixes.
	SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error
	// Cleanup removes all nftables resources created by this module.
	Cleanup() error
	// Available returns true if nftables is accessible (NET_ADMIN cap present).
	Available() bool
}

// ─── Real Implementation ────────────────────────────────────────────

type nftReal struct {
	mu                sync.Mutex
	conn              *nftables.Conn
	table             *nftables.Table
	chain             *nftables.Chain
	setV4             *nftables.Set
	setV6             *nftables.Set
	logger            *zap.Logger
	active            bool
	consecutiveErrors int
}

func newNftManager(logger *zap.Logger) nftManager {
	return &nftReal{logger: logger}
}

func (n *nftReal) Available() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Try to open a netlink connection — fails without NET_ADMIN.
	conn, err := nftables.New()
	if err != nil {
		n.logger.Debug("nftables not available", zap.Error(err))
		return false
	}
	// Verify we can list tables (actual netlink operation).
	if _, err := conn.ListTables(); err != nil {
		n.logger.Debug("nftables not available (list tables failed)", zap.Error(err))
		return false
	}
	n.conn = conn
	return true
}

func (n *nftReal) Setup() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.setupLocked()
}

// setupLocked performs the actual nftables setup. Caller must hold n.mu.
func (n *nftReal) setupLocked() error {
	if n.conn == nil {
		return fmt.Errorf("nftables connection not initialized")
	}

	// Delete existing table if present (prevents duplicate rules on hot-reload).
	n.conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   nftTableName,
	})
	n.conn.Flush() // ignore error — table may not exist yet

	// Create table: inet ddos_mitigator
	n.table = n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   nftTableName,
	})

	// Create chain: input filter with hook input, priority -200 (before conntrack).
	n.chain = n.conn.AddChain(&nftables.Chain{
		Name:     nftChainName,
		Table:    n.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(-200),
	})

	// Create IPv4 set with interval mode (supports both /32 IPs and CIDR ranges).
	n.setV4 = &nftables.Set{
		Table:    n.table,
		Name:     nftSetV4Name,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := n.conn.AddSet(n.setV4, nil); err != nil {
		return fmt.Errorf("create IPv4 set: %w", err)
	}

	// Create IPv6 set with interval mode.
	n.setV6 = &nftables.Set{
		Table:    n.table,
		Name:     nftSetV6Name,
		KeyType:  nftables.TypeIP6Addr,
		Interval: true,
	}
	if err := n.conn.AddSet(n.setV6, nil); err != nil {
		return fmt.Errorf("create IPv6 set: %w", err)
	}

	// Rule: ip saddr @jail_v4 counter drop
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: []expr.Any{
			// Load IPv4 source address
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv4)}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // IPv4 src addr offset
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        nftSetV4Name,
				SetID:          n.setV4.ID,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule: ip6 saddr @jail_v6 counter drop
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(nftables.TableFamilyIPv6)}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8, // IPv6 src addr offset
				Len:          16,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        nftSetV6Name,
				SetID:          n.setV6.ID,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	n.active = true
	n.consecutiveErrors = 0
	n.logger.Info("nftables kernel drop enabled",
		zap.String("table", nftTableName),
		zap.String("chain", nftChainName))
	return nil
}

func (n *nftReal) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active || n.conn == nil {
		return nil
	}

	if err := n.syncJailLocked(entries, promoted); err != nil {
		n.consecutiveErrors++
		n.logger.Warn("nftables sync failed, attempting reconnect",
			zap.Error(err),
			zap.Int("consecutive_errors", n.consecutiveErrors))

		// Attempt to create a new nftables connection and re-setup.
		conn, connErr := nftables.New()
		if connErr != nil {
			n.logger.Error("nftables reconnect failed",
				zap.Error(connErr),
				zap.Int("consecutive_errors", n.consecutiveErrors))
			return fmt.Errorf("nftables reconnect: %w", connErr)
		}
		n.conn = conn

		if setupErr := n.setupLocked(); setupErr != nil {
			n.logger.Error("nftables re-setup failed after reconnect",
				zap.Error(setupErr),
				zap.Int("consecutive_errors", n.consecutiveErrors))
			return fmt.Errorf("nftables re-setup: %w", setupErr)
		}

		// Retry sync after successful reconnect.
		if retryErr := n.syncJailLocked(entries, promoted); retryErr != nil {
			n.consecutiveErrors++
			n.logger.Error("nftables sync failed after reconnect",
				zap.Error(retryErr),
				zap.Int("consecutive_errors", n.consecutiveErrors))
			return fmt.Errorf("nftables sync after reconnect: %w", retryErr)
		}

		n.logger.Info("nftables reconnected and synced successfully")
	}

	n.consecutiveErrors = 0
	return nil
}

// syncJailLocked performs the actual nftables set sync. Caller must hold n.mu.
// Includes both individually-jailed IPs (as /32 or /128) and promoted CIDR prefixes.
// Interval sets require [start, end) pairs where end is the first address NOT in the range.
func (n *nftReal) syncJailLocked(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	now := time.Now().UnixNano()
	nowTime := time.Now()

	// Rebuild sets from scratch: flush in one transaction, add in another.
	// Interval sets require this two-step approach — flushing and adding
	// in the same netlink batch can cause EEXIST on overlapping elements
	// that haven't been flushed from the kernel yet.
	n.conn.FlushSet(n.setV4)
	n.conn.FlushSet(n.setV6)
	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush sets: %w", err)
	}

	var v4Elements, v6Elements []nftables.SetElement

	// Build a set of promoted prefixes for containment checks.
	// Individual IPs that fall within a promoted prefix are skipped
	// to avoid overlapping intervals (nftables rejects overlaps with EEXIST).
	activePrefixes := make([]netip.Prefix, 0, len(promoted))
	for prefix, exp := range promoted {
		if !nowTime.After(exp) {
			activePrefixes = append(activePrefixes, prefix)
		}
	}

	// Add individually-jailed IPs as /32 or /128 intervals.
	// Skip IPs already covered by a promoted CIDR prefix.
	for addr, e := range entries {
		if now >= e.ExpiresAt {
			continue
		}
		covered := false
		for _, prefix := range activePrefixes {
			if prefix.Contains(addr) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		start, end := ipToInterval(addr)
		if start == nil {
			continue
		}
		elem := []nftables.SetElement{
			{Key: start},
			{Key: end, IntervalEnd: true},
		}
		if addr.Is4() {
			v4Elements = append(v4Elements, elem...)
		} else {
			v6Elements = append(v6Elements, elem...)
		}
	}

	// Add promoted CIDR prefixes as native interval ranges.
	for prefix, exp := range promoted {
		if nowTime.After(exp) {
			continue
		}
		start, end := prefixToInterval(prefix)
		if start == nil {
			continue
		}
		elem := []nftables.SetElement{
			{Key: start},
			{Key: end, IntervalEnd: true},
		}
		if prefix.Addr().Is4() {
			v4Elements = append(v4Elements, elem...)
		} else {
			v6Elements = append(v6Elements, elem...)
		}
	}

	if len(v4Elements) > 0 {
		if err := n.conn.SetAddElements(n.setV4, v4Elements); err != nil {
			return fmt.Errorf("add IPv4 elements: %w", err)
		}
	}
	if len(v6Elements) > 0 {
		if err := n.conn.SetAddElements(n.setV6, v6Elements); err != nil {
			return fmt.Errorf("add IPv6 elements: %w", err)
		}
	}

	return n.conn.Flush()
}

// ipToInterval converts a single IP to an nftables interval [IP, IP+1).
func ipToInterval(addr netip.Addr) (start, end []byte) {
	if addr.Is4() {
		ip := addr.As4()
		next := addr.Next()
		if !next.IsValid() {
			return nil, nil
		}
		n := next.As4()
		return ip[:], n[:]
	}
	ip := addr.As16()
	next := addr.Next()
	if !next.IsValid() {
		return nil, nil
	}
	n := next.As16()
	return ip[:], n[:]
}

// prefixToInterval converts a CIDR prefix to an nftables interval [first, last+1).
// For example, 192.168.1.0/24 → [192.168.1.0, 192.168.2.0).
func prefixToInterval(prefix netip.Prefix) (start, end []byte) {
	rng := netip.PrefixFrom(prefix.Masked().Addr(), prefix.Bits())
	first := rng.Addr()

	// Compute the first address AFTER the prefix range.
	// For a /24: 256 addresses, so end = first + 256.
	bits := first.BitLen() - rng.Bits()
	count := uint64(1) << bits

	if first.Is4() {
		s := first.As4()
		// Convert to uint32, add count, convert back.
		v := uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
		v += uint32(count)
		e := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		return s[:], e[:]
	}

	// IPv6: use As16, add count to the lower 64 bits.
	s := first.As16()
	lo := uint64(s[8])<<56 | uint64(s[9])<<48 | uint64(s[10])<<40 | uint64(s[11])<<32 |
		uint64(s[12])<<24 | uint64(s[13])<<16 | uint64(s[14])<<8 | uint64(s[15])
	lo += count
	e := s
	e[8] = byte(lo >> 56)
	e[9] = byte(lo >> 48)
	e[10] = byte(lo >> 40)
	e[11] = byte(lo >> 32)
	e[12] = byte(lo >> 24)
	e[13] = byte(lo >> 16)
	e[14] = byte(lo >> 8)
	e[15] = byte(lo)
	return s[:], e[:]
}

func (n *nftReal) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active || n.conn == nil {
		return nil
	}

	// Delete the entire table — removes all chains, sets, rules.
	n.conn.DelTable(n.table)
	if err := n.conn.Flush(); err != nil {
		return err
	}

	n.active = false
	n.logger.Info("nftables kernel drop cleaned up")
	return nil
}

// ─── No-op Implementation (when kernel_drop is disabled) ────────────

type nftNoop struct{}

func (nftNoop) Setup() error { return nil }
func (nftNoop) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	return nil
}
func (nftNoop) Cleanup() error  { return nil }
func (nftNoop) Available() bool { return false }
