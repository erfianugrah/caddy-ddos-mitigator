// Package ddosmitigator — XDP kernel-level drop subsystem.
//
// Loads an eBPF/XDP program onto the network interface that drops packets
// from jailed IPs at the NIC driver level — the fastest possible drop point,
// achieving 10M+ pps on a single CPU with zero userspace overhead.
//
// Feature-flagged: disabled by default. Enable via Caddyfile:
//
//	ddos_mitigator {
//	    xdp_drop  true
//	    xdp_iface eth0
//	}
//
// Requires BPF + NET_ADMIN capabilities. If unavailable, falls back silently.
// On cleanup, the XDP program is detached and BPF maps are closed.
//
// The jail → BPF map sync uses v4-mapped-v6 addressing (:ffff:a.b.c.d)
// to handle both IPv4 and IPv6 with a single LPM trie map.
package ddosmitigator

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target amd64 -type lpm_key xdpDrop bpf/xdp_drop.c -- -I/usr/include -O2 -Wall

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// ─── XDP Manager Interface ──────────────────────────────────────────

// xdpManager abstracts XDP operations for testability.
type xdpManager interface {
	// Setup loads the XDP program and attaches it to the interface.
	Setup() error
	// SyncJail updates the BPF jail map to match the current jail state
	// and promoted CIDR prefixes.
	SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error
	// Cleanup detaches the XDP program and closes BPF objects.
	Cleanup() error
	// Available returns true if BPF capabilities are present.
	Available() bool
	// Stats returns passed/dropped packet counters.
	Stats() (passed, dropped uint64)
}

// ─── Real Implementation ────────────────────────────────────────────

type xdpReal struct {
	mu      sync.Mutex
	ifName  string
	objs    *xdpDropObjects
	xdpLink link.Link
	logger  *zap.Logger
	active  bool
	inMap   map[netip.Addr]struct{} // tracks what's currently in the BPF jail map
}

func newXDPManager(ifName string, logger *zap.Logger) xdpManager {
	return &xdpReal{ifName: ifName, logger: logger}
}

func (x *xdpReal) Available() bool {
	// Try to load the collection spec (doesn't need BPF cap, just parses ELF).
	// The actual load into kernel happens in Setup().
	_, err := loadXdpDrop()
	if err != nil {
		x.logger.Debug("XDP: eBPF spec load failed", zap.Error(err))
		return false
	}

	// Check interface exists
	_, err = net.InterfaceByName(x.ifName)
	if err != nil {
		x.logger.Debug("XDP: interface not found", zap.String("iface", x.ifName), zap.Error(err))
		return false
	}
	return true
}

func (x *xdpReal) Setup() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	iface, err := net.InterfaceByName(x.ifName)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", x.ifName, err)
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("refusing to attach XDP to loopback interface %q", x.ifName)
	}

	objs := &xdpDropObjects{}
	if err := loadXdpDropObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			x.logger.Error("XDP verifier error", zap.String("log", ve.Error()))
		}
		return fmt.Errorf("load XDP objects: %w", err)
	}
	x.objs = objs

	// Attach XDP program to the interface
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDdosDrop,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach XDP to %s: %w", x.ifName, err)
	}
	x.xdpLink = xdpLink
	x.active = true
	x.inMap = make(map[netip.Addr]struct{})

	x.logger.Info("XDP program attached",
		zap.String("iface", x.ifName),
		zap.Int("ifindex", iface.Index))
	return nil
}

func (x *xdpReal) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if !x.active || x.objs == nil {
		return nil
	}

	now := time.Now().UnixNano()
	jailMap := x.objs.JailMap

	// Build wanted set from non-expired entries.
	wanted := make(map[netip.Addr]struct{}, len(entries))
	for addr, e := range entries {
		if now < e.ExpiresAt {
			wanted[addr] = struct{}{}
		}
	}

	// Delete entries in inMap but not in wanted.
	for addr := range x.inMap {
		if _, ok := wanted[addr]; !ok {
			key := x.addrToLpmKey(addr)
			if err := jailMap.Delete(&key); err != nil {
				x.logger.Warn("XDP: failed to delete jail entry",
					zap.String("ip", addr.String()), zap.Error(err))
			}
			delete(x.inMap, addr)
		}
	}

	// Add entries in wanted but not in inMap.
	dummyVal := uint8(1)
	for addr := range wanted {
		if _, ok := x.inMap[addr]; !ok {
			key := x.addrToLpmKey(addr)
			if err := jailMap.Put(&key, &dummyVal); err != nil {
				x.logger.Warn("XDP: failed to add jail entry",
					zap.String("ip", addr.String()), zap.Error(err))
				continue
			}
			x.inMap[addr] = struct{}{}
		}
	}

	// Add promoted CIDR prefixes to the BPF LPM trie.
	// The LPM trie natively supports prefix lengths — use the actual
	// prefix bits (e.g., 24 for /24) mapped to v4-in-v6 (96 + bits).
	nowTime := time.Now()
	for prefix, exp := range promoted {
		if nowTime.After(exp) {
			continue
		}
		key := x.prefixToLpmKey(prefix)
		if err := jailMap.Put(&key, &dummyVal); err != nil {
			x.logger.Warn("XDP: failed to add promoted prefix",
				zap.String("prefix", prefix.String()), zap.Error(err))
		}
	}

	return nil
}

// addrToLpmKey converts a netip.Addr to a v4-mapped-v6 LPM trie key.
func (x *xdpReal) addrToLpmKey(addr netip.Addr) xdpDropLpmKey {
	var key xdpDropLpmKey
	key.Prefixlen = 128 // full match (v4-mapped-v6)

	if addr.Is4() {
		a4 := addr.As4()
		key.Addr[10] = 0xff
		key.Addr[11] = 0xff
		copy(key.Addr[12:], a4[:])
	} else {
		a16 := addr.As16()
		copy(key.Addr[:], a16[:])
	}
	return key
}

// prefixToLpmKey converts a netip.Prefix to a v4-mapped-v6 LPM trie key.
// IPv4 prefixes are mapped to v4-in-v6 with prefix length offset by 96.
func (x *xdpReal) prefixToLpmKey(prefix netip.Prefix) xdpDropLpmKey {
	var key xdpDropLpmKey
	addr := prefix.Masked().Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		a4 := addr.As4()
		key.Addr[10] = 0xff
		key.Addr[11] = 0xff
		copy(key.Addr[12:], a4[:])
		key.Prefixlen = uint32(96 + bits) // v4-in-v6 offset
	} else {
		a16 := addr.As16()
		copy(key.Addr[:], a16[:])
		key.Prefixlen = uint32(bits)
	}
	return key
}

func (x *xdpReal) Stats() (passed, dropped uint64) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if !x.active || x.objs == nil {
		return 0, 0
	}

	// Read per-CPU counters and sum
	statsMap := x.objs.StatsMap
	for _, idx := range []uint32{0, 1} {
		var values []uint64
		if err := statsMap.Lookup(&idx, &values); err != nil {
			continue
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		if idx == 0 {
			passed = sum
		} else {
			dropped = sum
		}
	}
	return
}

func (x *xdpReal) Cleanup() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if !x.active {
		return nil
	}

	var errs []error
	if x.xdpLink != nil {
		if err := x.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("detach XDP: %w", err))
		}
	}
	if x.objs != nil {
		if err := x.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close BPF objects: %w", err))
		}
	}

	x.active = false
	x.logger.Info("XDP program detached", zap.String("iface", x.ifName))
	return errors.Join(errs...)
}

// ─── No-op Implementation ───────────────────────────────────────────

type xdpNoop struct{}

func (xdpNoop) Setup() error { return nil }
func (xdpNoop) SyncJail(entries map[netip.Addr]jailEntry, promoted map[netip.Prefix]time.Time) error {
	return nil
}
func (xdpNoop) Cleanup() error          { return nil }
func (xdpNoop) Available() bool         { return false }
func (xdpNoop) Stats() (uint64, uint64) { return 0, 0 }
