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
	// SyncJail updates the nftables sets to match the current jail state.
	SyncJail(entries map[netip.Addr]jailEntry) error
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

	// Create IPv4 set
	n.setV4 = &nftables.Set{
		Table:   n.table,
		Name:    nftSetV4Name,
		KeyType: nftables.TypeIPAddr,
	}
	if err := n.conn.AddSet(n.setV4, nil); err != nil {
		return fmt.Errorf("create IPv4 set: %w", err)
	}

	// Create IPv6 set
	n.setV6 = &nftables.Set{
		Table:   n.table,
		Name:    nftSetV6Name,
		KeyType: nftables.TypeIP6Addr,
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

func (n *nftReal) SyncJail(entries map[netip.Addr]jailEntry) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active || n.conn == nil {
		return nil
	}

	if err := n.syncJailLocked(entries); err != nil {
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
		if retryErr := n.syncJailLocked(entries); retryErr != nil {
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
func (n *nftReal) syncJailLocked(entries map[netip.Addr]jailEntry) error {
	now := time.Now().UnixNano()

	// Rebuild sets from scratch (flush + re-add).
	// For small jail populations (<100K) this is simpler and safer than
	// computing diffs. At 100K entries this takes <1ms.
	n.conn.FlushSet(n.setV4)
	n.conn.FlushSet(n.setV6)

	var v4Elements, v6Elements []nftables.SetElement
	for addr, e := range entries {
		if now >= e.ExpiresAt {
			continue
		}
		if addr.Is4() {
			ip := addr.As4()
			v4Elements = append(v4Elements, nftables.SetElement{
				Key: ip[:],
			})
		} else {
			ip := addr.As16()
			v6Elements = append(v6Elements, nftables.SetElement{
				Key: ip[:],
			})
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

func (nftNoop) Setup() error                                    { return nil }
func (nftNoop) SyncJail(entries map[netip.Addr]jailEntry) error { return nil }
func (nftNoop) Cleanup() error                                  { return nil }
func (nftNoop) Available() bool                                 { return false }
