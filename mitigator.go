// Package ddosmitigator implements an adaptive DDoS/DoS mitigation plugin
// for Caddy. It registers as an L7 HTTP middleware handler that evaluates
// request fingerprints against adaptive statistical thresholds, auto-jails
// offending IPs, and blocks subsequent requests.
//
// Handler ordering: log_append runs first (outermost), then ddos_mitigator,
// then policy_engine. Blocked traffic never reaches the WAF, saving all
// downstream CPU.
//
// Module ID: http.handlers.ddos_mitigator
package ddosmitigator

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(DDOSMitigator))
	httpcaddyfile.RegisterHandlerDirective("ddos_mitigator", parseCaddyfileDDOSMitigator)
}

// ─── Module Struct ──────────────────────────────────────────────────

// DDOSMitigator is the L7 HTTP middleware handler for DDoS mitigation.
type DDOSMitigator struct {
	// --- Configuration (from Caddyfile/JSON) ---

	// JailFile is the path to the shared jail JSON file (bidirectional with wafctl).
	JailFile string `json:"jail_file,omitempty"`

	// Threshold is the behavioral anomaly score (0.0-1.0) above which an IP triggers auto-jail.
	Threshold float64 `json:"threshold,omitempty"`

	// BasePenalty is the initial jail duration for the first offense.
	BasePenalty caddy.Duration `json:"base_penalty,omitempty"`

	// MaxPenalty caps the exponential backoff jail duration.
	MaxPenalty caddy.Duration `json:"max_penalty,omitempty"`

	// SweepInterval is how often expired jail entries are removed.
	SweepInterval caddy.Duration `json:"sweep_interval,omitempty"`

	// DecayInterval is how often CMS counters are halved.
	DecayInterval caddy.Duration `json:"decay_interval,omitempty"`

	// SyncInterval is how often the jail file is read/written.
	SyncInterval caddy.Duration `json:"sync_interval,omitempty"`

	// CMSWidth is the width of the Count-Min Sketch matrix.
	CMSWidth int `json:"cms_width,omitempty"`

	// CMSDepth is the depth (number of hash functions) of the CMS.
	CMSDepth int `json:"cms_depth,omitempty"`

	// WhitelistCIDRs are CIDR prefixes that bypass all jail checks.
	WhitelistCIDRs []string `json:"whitelist,omitempty"`

	// KernelDrop enables nftables ipset-based kernel-level packet dropping.
	// Requires NET_ADMIN capability. Disabled by default.
	KernelDrop bool `json:"kernel_drop,omitempty"`

	// NftSyncInterval is how often the nftables ipset is synced with the jail.
	NftSyncInterval caddy.Duration `json:"nft_sync_interval,omitempty"`

	// XDPDrop enables eBPF/XDP packet dropping at the NIC driver level.
	// Requires BPF + NET_ADMIN capabilities. Disabled by default.
	XDPDrop bool `json:"xdp_drop,omitempty"`

	// XDPIface is the network interface to attach the XDP program to.
	// Required when xdp_drop is enabled. Example: "eth0".
	XDPIface string `json:"xdp_iface,omitempty"`

	// XDPSyncInterval is how often the BPF jail map is synced.
	XDPSyncInterval caddy.Duration `json:"xdp_sync_interval,omitempty"`

	// CIDRThresholdV4 is the number of jailed IPs from the same /24 needed
	// to promote the entire prefix. Default: 5.
	CIDRThresholdV4 int `json:"cidr_threshold_v4,omitempty"`

	// CIDRThresholdV6 is the same for IPv6 /64 prefixes. Default: 5.
	CIDRThresholdV6 int `json:"cidr_threshold_v6,omitempty"`

	// ProfileTTL is how long IP behavioral profiles are retained. Default: 10m.
	ProfileTTL caddy.Duration `json:"profile_ttl,omitempty"`

	// ProfileMaxIPs is the maximum number of IP profiles tracked. Default: 100000.
	ProfileMaxIPs int `json:"profile_max_ips,omitempty"`

	// WarmupRequests is the minimum number of observations before the stats
	// engine produces actionable z-scores. Prevents false positives during
	// startup and low-traffic periods. Default: 1000.
	WarmupRequests int `json:"warmup_requests,omitempty"`

	// PathDepth is the maximum number of path segments used for fingerprinting.
	// If > 0, paths are truncated: /a/b/c/d with depth=2 → /a/b.
	// Default: 0 (no truncation — backward compatible).
	PathDepth int `json:"path_depth,omitempty"`

	// --- Internal state ---

	jail      *ipJail
	cms       *countMinSketch
	stats     *adaptiveStats
	tracker   *ipTracker
	cidr      *cidrAggregator
	whitelist *whitelist
	nft       nftManager
	xdp       xdpManager
	strategy  atomic.Int32 // current fingerprintStrategy
	logger    *zap.Logger
	cancel    context.CancelFunc
}

// ─── Caddy Module Interface ─────────────────────────────────────────

func (*DDOSMitigator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ddos_mitigator",
		New: func() caddy.Module { return new(DDOSMitigator) },
	}
}

// ─── Provision ──────────────────────────────────────────────────────

func (m *DDOSMitigator) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Apply defaults
	if m.Threshold == 0 {
		m.Threshold = 0.65 // behavioral anomaly score: 0.0 (normal) to 1.0 (flood)
	}
	if m.BasePenalty == 0 {
		m.BasePenalty = caddy.Duration(60 * time.Second)
	}
	if m.MaxPenalty == 0 {
		m.MaxPenalty = caddy.Duration(24 * time.Hour)
	}
	if m.SweepInterval == 0 {
		m.SweepInterval = caddy.Duration(10 * time.Second)
	}
	if m.DecayInterval == 0 {
		m.DecayInterval = caddy.Duration(30 * time.Second)
	}
	if m.SyncInterval == 0 {
		m.SyncInterval = caddy.Duration(5 * time.Second)
	}
	if m.CMSWidth == 0 {
		m.CMSWidth = 8192
	}
	if m.CMSDepth == 0 {
		m.CMSDepth = 4
	}

	// Initialize domain objects.
	// Use the jail registry so L4 handlers can share the same jail.
	if m.JailFile != "" {
		if err := validateJailPath(m.JailFile); err != nil {
			return err
		}
		m.jail = getOrCreateJail(m.JailFile)
	} else {
		m.jail = newIPJail()
	}
	m.cms = newCountMinSketch(m.CMSDepth, m.CMSWidth)
	m.stats = newAdaptiveStatsWithWarmup(m.WarmupRequests)
	if m.ProfileTTL == 0 {
		m.ProfileTTL = caddy.Duration(10 * time.Minute)
	}
	if m.ProfileMaxIPs == 0 {
		m.ProfileMaxIPs = 100000
	}
	if m.WarmupRequests == 0 {
		m.WarmupRequests = 1000
	}
	if m.CIDRThresholdV4 == 0 {
		m.CIDRThresholdV4 = 5
	}
	if m.CIDRThresholdV6 == 0 {
		m.CIDRThresholdV6 = 5
	}
	m.tracker = newIPTracker(m.ProfileMaxIPs, time.Duration(m.ProfileTTL))
	m.cidr = newCIDRAggregatorWithThresholds(m.CIDRThresholdV4, m.CIDRThresholdV6)
	wl, err := newWhitelist(m.WhitelistCIDRs)
	if err != nil {
		return fmt.Errorf("whitelist: %w", err)
	}
	m.whitelist = wl
	m.strategy.Store(int32(fpFull))

	if m.NftSyncInterval == 0 {
		m.NftSyncInterval = caddy.Duration(2 * time.Second)
	}

	// Initialize nftables if kernel_drop is enabled.
	if m.KernelDrop {
		mgr := newNftManager(m.logger)
		if mgr.Available() {
			if err := mgr.Setup(); err != nil {
				m.logger.Error("nftables setup failed, falling back to userspace-only",
					zap.Error(err))
				m.nft = nftNoop{}
			} else {
				m.nft = mgr
			}
		} else {
			m.logger.Warn("kernel_drop enabled but NET_ADMIN not available, falling back to userspace-only")
			m.nft = nftNoop{}
		}
	} else {
		m.nft = nftNoop{}
	}

	// Initialize XDP if enabled.
	if m.XDPSyncInterval == 0 {
		m.XDPSyncInterval = caddy.Duration(2 * time.Second)
	}
	if m.XDPDrop {
		if m.XDPIface == "" {
			m.logger.Warn("xdp_drop enabled but xdp_iface not set, disabling XDP")
			m.xdp = xdpNoop{}
		} else {
			mgr := newXDPManager(m.XDPIface, m.logger)
			if mgr.Available() {
				if err := mgr.Setup(); err != nil {
					m.logger.Error("XDP setup failed, falling back",
						zap.Error(err))
					m.xdp = xdpNoop{}
				} else {
					m.xdp = mgr
				}
			} else {
				m.logger.Warn("xdp_drop enabled but BPF not available, falling back")
				m.xdp = xdpNoop{}
			}
		}
	} else {
		m.xdp = xdpNoop{}
	}

	// Load jail file if configured
	if m.JailFile != "" {
		if err := readJailFile(m.JailFile, m.jail); err != nil {
			m.logger.Warn("failed to load jail file",
				zap.String("path", m.JailFile), zap.Error(err))
		} else {
			m.logger.Info("loaded jail file",
				zap.String("path", m.JailFile),
				zap.Int64("entries", m.jail.Count()))
		}
	}

	// Start background goroutines
	bgCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go m.runSweeper(bgCtx)
	go m.runDecay(bgCtx)
	if m.JailFile != "" {
		go m.runFileSync(bgCtx)
	}
	if m.KernelDrop {
		go m.runNftSync(bgCtx)
	}
	if m.XDPDrop {
		go m.runXDPSync(bgCtx)
	}

	m.logger.Info("ddos_mitigator provisioned",
		zap.Float64("threshold", m.Threshold),
		zap.Duration("base_penalty", time.Duration(m.BasePenalty)),
		zap.Int("cms_width", m.CMSWidth),
		zap.Int("cms_depth", m.CMSDepth),
		zap.Int("whitelist_prefixes", len(m.whitelist.prefixes)),
		zap.Bool("kernel_drop", m.KernelDrop),
		zap.Bool("xdp_drop", m.XDPDrop))

	return nil
}

// ─── Validate ───────────────────────────────────────────────────────

func (m *DDOSMitigator) Validate() error {
	if m.Threshold <= 0 {
		return fmt.Errorf("threshold must be positive, got %f", m.Threshold)
	}
	if m.BasePenalty <= 0 {
		return fmt.Errorf("base_penalty must be positive")
	}
	if m.MaxPenalty <= 0 {
		return fmt.Errorf("max_penalty must be positive")
	}
	if m.MaxPenalty < m.BasePenalty {
		return fmt.Errorf("max_penalty (%s) must be >= base_penalty (%s)",
			time.Duration(m.MaxPenalty), time.Duration(m.BasePenalty))
	}
	if m.CMSWidth <= 0 {
		return fmt.Errorf("cms_width must be positive, got %d", m.CMSWidth)
	}
	if m.CMSDepth <= 0 {
		return fmt.Errorf("cms_depth must be positive, got %d", m.CMSDepth)
	}
	if m.CIDRThresholdV4 <= 0 {
		return fmt.Errorf("cidr_threshold_v4 must be positive, got %d", m.CIDRThresholdV4)
	}
	if m.CIDRThresholdV6 <= 0 {
		return fmt.Errorf("cidr_threshold_v6 must be positive, got %d", m.CIDRThresholdV6)
	}
	if m.ProfileMaxIPs <= 0 {
		return fmt.Errorf("profile_max_ips must be positive, got %d", m.ProfileMaxIPs)
	}
	if m.WarmupRequests < 0 {
		return fmt.Errorf("warmup_requests must be non-negative, got %d", m.WarmupRequests)
	}
	if m.PathDepth < 0 {
		return fmt.Errorf("path_depth must be non-negative, got %d", m.PathDepth)
	}
	return nil
}

// ─── Cleanup ────────────────────────────────────────────────────────

func (m *DDOSMitigator) Cleanup() error {
	if m.cancel != nil {
		m.cancel()
	}
	// Clean up kernel state (no stale rules/programs)
	if m.xdp != nil {
		if err := m.xdp.Cleanup(); err != nil {
			m.logger.Error("XDP cleanup error", zap.Error(err))
		}
	}
	if m.nft != nil {
		if err := m.nft.Cleanup(); err != nil {
			m.logger.Error("nftables cleanup error", zap.Error(err))
		}
	}
	// Write final jail state
	if m.JailFile != "" && m.jail != nil {
		if err := writeJailFile(m.JailFile, m.jail); err != nil {
			m.logger.Error("failed to write jail file on cleanup",
				zap.String("path", m.JailFile), zap.Error(err))
		}
		releaseJail(m.JailFile)
	}
	return nil
}

// ─── ServeHTTP (Hot Path) ───────────────────────────────────────────

func (m *DDOSMitigator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	addr, ok := clientAddr(r)
	if !ok {
		m.logger.Debug("could not extract client IP, passing through",
			zap.String("remote_addr", r.RemoteAddr))
		return next.ServeHTTP(w, r)
	}

	// 1. Whitelist check
	if m.whitelist.Contains(addr) {
		m.setVars(r, "pass", addr, 0, "")
		return next.ServeHTTP(w, r)
	}

	// 2. Jail check — RLock on one of 64 shards
	if m.jail.IsJailed(addr) || m.cidr.IsPromoted(addr) {
		m.setVars(r, "blocked", addr, 0, "")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// 3. Record behavioral profile + update CMS for EPS tracking
	m.tracker.Record(addr, r.Method, r.URL.Path, r.UserAgent())
	strat := fingerprintStrategy(m.strategy.Load())
	fp := computeFingerprint(strat, addr, r.Method, r.URL.Path, r.UserAgent(), m.PathDepth)
	m.cms.Increment(fp[:])
	m.stats.Observe(1.0) // observation count for EWMA/spike detection

	// 4. Behavioral anomaly check — score based on path diversity, not raw volume.
	// Normal users browsing diverse pages score ~0. Floods hitting one endpoint score ~0.8+.
	score := m.tracker.Score(addr)
	if score > m.Threshold {
		ttl := m.calcTTL(addr)
		m.jail.Add(addr, ttl, "auto:behavioral", m.infractionCount(addr))
		m.cidr.IncrementPrefix(addr)
		m.setVars(r, "jailed", addr, score, fpHex(fp))
		m.logger.Info("auto-jailed IP (behavioral)",
			zap.String("ip", addr.String()),
			zap.Float64("anomaly_score", score),
			zap.Float64("threshold", m.Threshold),
			zap.Duration("ttl", ttl),
			zap.String("fingerprint", fpHex(fp)))

		// Check CIDR aggregation — promote /24 or /64 if enough IPs from same subnet
		if prefix := m.cidr.Check(addr, ttl); prefix != nil {
			m.logger.Warn("CIDR prefix promoted",
				zap.String("prefix", prefix.String()),
				zap.Duration("ttl", ttl))
		}

		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// 5. Pass through
	m.setVars(r, "pass", addr, score, fpHex(fp))
	return next.ServeHTTP(w, r)
}

// ─── TTL Calculation ────────────────────────────────────────────────

// calcTTL computes the jail duration using exponential backoff with jitter.
func (m *DDOSMitigator) calcTTL(addr netip.Addr) time.Duration {
	infractions := m.infractionCount(addr)

	// Exponential backoff: base * 2^infractions
	shift := min(infractions, 16) // prevent overflow
	ttl := time.Duration(m.BasePenalty) << shift
	maxP := time.Duration(m.MaxPenalty)
	if ttl > maxP {
		ttl = maxP
	}

	// ±25% jitter to prevent synchronized retry storms
	if ttl > 0 {
		jitter := time.Duration(rand.Int64N(int64(ttl)/2)) - ttl/4
		ttl += jitter
	}

	return ttl
}

func (m *DDOSMitigator) infractionCount(addr netip.Addr) int32 {
	if e := m.jail.Get(addr); e != nil {
		return e.InfractionCount + 1
	}
	return 0
}

// ─── Log Variables ──────────────────────────────────────────────────

func (m *DDOSMitigator) setVars(r *http.Request, action string, addr netip.Addr, score float64, fingerprint string) {
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.action", action)
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.ip", addr.String())
	// NOTE: the variable key is kept as "z_score" for backward compatibility
	// with existing log templates, but the value is the behavioral anomaly score (0.0-1.0).
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.z_score", fmt.Sprintf("%.2f", score))
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.spike_mode", fmt.Sprintf("%t", m.stats.IsSpikeMode()))
	if fingerprint != "" {
		caddyhttp.SetVar(r.Context(), "ddos_mitigator.fingerprint", fingerprint)
	}
}

// ─── Client IP Extraction ───────────────────────────────────────────

// clientAddr extracts the client IP from the request, respecting Caddy's
// trusted_proxies configuration via the standard client_ip variable.
func clientAddr(r *http.Request) (netip.Addr, bool) {
	// Try Caddy's client_ip variable first (set by trusted_proxies)
	if val := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); val != nil {
		if ipStr, ok := val.(string); ok {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				return addr.Unmap(), true
			}
		}
	}

	// Fallback: parse RemoteAddr directly
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ─── Background Goroutines ──────────────────────────────────────────

func (m *DDOSMitigator) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.SweepInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n := m.jail.SweepWithCallback(func(addr netip.Addr) {
				m.cidr.DecrementPrefix(addr)
			})
			if n > 0 {
				m.logger.Debug("jail sweep", zap.Int("removed", n),
					zap.Int64("remaining", m.jail.Count()))
			}
		}
	}
}

func (m *DDOSMitigator) runDecay(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.DecayInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cms.Decay(0.5)
		}
	}
}

func (m *DDOSMitigator) runFileSync(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.SyncInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := withFileLock(m.JailFile, func() error {
				// Snapshot current jail before reading file
				beforeSync := m.jail.Snapshot()

				// Read file to learn which IPs wafctl currently has.
				// readJailFile merges new entries; it does NOT remove stale ones.
				fileIPs, skipped, err := readJailFileIPs(m.JailFile, m.jail)
				if err != nil {
					m.logger.Warn("jail file read error", zap.Error(err))
				}
				if skipped > 0 {
					m.logger.Warn("jail file contained invalid entries",
						zap.Int("skipped", skipped),
						zap.String("path", m.JailFile))
				}

				// Detect IPs that wafctl explicitly unjailed:
				// an IP was jailed before sync, is still jailed now (not expired),
				// but is absent from the file → wafctl removed it.
				for addr := range beforeSync {
					if !m.jail.IsJailed(addr) {
						// Expired naturally between cycles — reset profile.
						m.tracker.Reset(addr)
						m.logger.Info("cleared behavioral profile for expired IP",
							zap.String("ip", addr.String()))
						continue
					}
					if fileIPs != nil && !fileIPs[addr] {
						// Still jailed in memory but removed from file by wafctl.
						m.jail.Remove(addr)
						m.cidr.DecrementPrefix(addr)
						m.tracker.Reset(addr)
						m.logger.Info("unjailed IP removed by wafctl",
							zap.String("ip", addr.String()))
					}
				}

				// Write current jail state to file (for wafctl to read),
				// but only if the jail has been modified since the last write.
				if m.jail.dirty.CompareAndSwap(true, false) {
					if err := writeJailFile(m.JailFile, m.jail); err != nil {
						m.logger.Warn("jail file write error", zap.Error(err))
						m.jail.dirty.Store(true) // restore flag on failure
					}
				}
				return nil
			}); err != nil {
				m.logger.Warn("jail file sync lock error", zap.Error(err))
			}
		}
	}
}

func (m *DDOSMitigator) runNftSync(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.NftSyncInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := m.jail.Snapshot()
			if err := m.nft.SyncJail(snap); err != nil {
				m.logger.Warn("nftables sync error", zap.Error(err))
			}
		}
	}
}

func (m *DDOSMitigator) runXDPSync(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.XDPSyncInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := m.jail.Snapshot()
			if err := m.xdp.SyncJail(snap); err != nil {
				m.logger.Warn("XDP sync error", zap.Error(err))
			}
		}
	}
}

// ─── Caddyfile Parsing ──────────────────────────────────────────────

func (m *DDOSMitigator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "jail_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.JailFile = d.Val()
		case "threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v float64
			if _, err := fmt.Sscanf(d.Val(), "%f", &v); err != nil {
				return d.Errf("invalid threshold: %v", err)
			}
			m.Threshold = v
		case "base_penalty":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid base_penalty: %v", err)
			}
			m.BasePenalty = caddy.Duration(dur)
		case "max_penalty":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid max_penalty: %v", err)
			}
			m.MaxPenalty = caddy.Duration(dur)
		case "sweep_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid sweep_interval: %v", err)
			}
			m.SweepInterval = caddy.Duration(dur)
		case "decay_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid decay_interval: %v", err)
			}
			m.DecayInterval = caddy.Duration(dur)
		case "sync_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid sync_interval: %v", err)
			}
			m.SyncInterval = caddy.Duration(dur)
		case "cms_width":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid cms_width: %v", err)
			}
			m.CMSWidth = v
		case "cms_depth":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid cms_depth: %v", err)
			}
			m.CMSDepth = v
		case "whitelist":
			m.WhitelistCIDRs = d.RemainingArgs()
			if len(m.WhitelistCIDRs) == 0 {
				return d.ArgErr()
			}
		case "kernel_drop":
			if d.NextArg() {
				m.KernelDrop = d.Val() == "true" || d.Val() == "on"
			} else {
				m.KernelDrop = true
			}
		case "nft_sync_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid nft_sync_interval: %v", err)
			}
			m.NftSyncInterval = caddy.Duration(dur)
		case "xdp_drop":
			if d.NextArg() {
				m.XDPDrop = d.Val() == "true" || d.Val() == "on"
			} else {
				m.XDPDrop = true
			}
		case "xdp_iface":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.XDPIface = d.Val()
		case "xdp_sync_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid xdp_sync_interval: %v", err)
			}
			m.XDPSyncInterval = caddy.Duration(dur)
		case "cidr_threshold_v4":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid cidr_threshold_v4: %v", err)
			}
			m.CIDRThresholdV4 = v
		case "cidr_threshold_v6":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid cidr_threshold_v6: %v", err)
			}
			m.CIDRThresholdV6 = v
		case "profile_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid profile_ttl: %v", err)
			}
			m.ProfileTTL = caddy.Duration(dur)
		case "profile_max_ips":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid profile_max_ips: %v", err)
			}
			m.ProfileMaxIPs = v
		case "warmup_requests":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid warmup_requests: %v", err)
			}
			m.WarmupRequests = v
		case "path_depth":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var v int
			if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil {
				return d.Errf("invalid path_depth: %v", err)
			}
			m.PathDepth = v
		default:
			return d.Errf("unknown ddos_mitigator directive: %s", d.Val())
		}
	}
	return nil
}

func parseCaddyfileDDOSMitigator(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(DDOSMitigator)
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

// ─── Interface Guards ───────────────────────────────────────────────

var (
	_ caddy.Module                = (*DDOSMitigator)(nil)
	_ caddy.Provisioner           = (*DDOSMitigator)(nil)
	_ caddy.Validator             = (*DDOSMitigator)(nil)
	_ caddy.CleanerUpper          = (*DDOSMitigator)(nil)
	_ caddyhttp.MiddlewareHandler = (*DDOSMitigator)(nil)
	_ caddyfile.Unmarshaler       = (*DDOSMitigator)(nil)
)
