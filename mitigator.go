// Package ddosmitigator implements an adaptive DDoS/DoS mitigation plugin
// for Caddy. It registers as an L7 HTTP middleware handler that evaluates
// request fingerprints against adaptive statistical thresholds, auto-jails
// offending IPs, and blocks subsequent requests.
//
// Handler ordering: ddos_mitigator runs before log_append and policy_engine.
// Blocked traffic never reaches the WAF, saving all downstream CPU.
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
	caddy.RegisterModule(DDOSMitigator{})
	httpcaddyfile.RegisterHandlerDirective("ddos_mitigator", parseCaddyfileDDOSMitigator)
}

// ─── Module Struct ──────────────────────────────────────────────────

// DDOSMitigator is the L7 HTTP middleware handler for DDoS mitigation.
type DDOSMitigator struct {
	// --- Configuration (from Caddyfile/JSON) ---

	// JailFile is the path to the shared jail JSON file (bidirectional with wafctl).
	JailFile string `json:"jail_file,omitempty"`

	// Threshold is the z-score above which a fingerprint triggers auto-jail.
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

	// --- Internal state ---

	jail      *ipJail
	cms       *countMinSketch
	stats     *adaptiveStats
	whitelist *whitelist
	nft       nftManager
	strategy  atomic.Int32 // current fingerprintStrategy
	logger    *zap.Logger
	cancel    context.CancelFunc
}

// ─── Caddy Module Interface ─────────────────────────────────────────

func (DDOSMitigator) CaddyModule() caddy.ModuleInfo {
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
		m.Threshold = 4.0
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
		m.jail = getOrCreateJail(m.JailFile)
	} else {
		m.jail = newIPJail()
	}
	m.cms = newCountMinSketch(m.CMSDepth, m.CMSWidth)
	m.stats = newAdaptiveStats()
	m.whitelist = newWhitelist(m.WhitelistCIDRs)
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

	m.logger.Info("ddos_mitigator provisioned",
		zap.Float64("threshold", m.Threshold),
		zap.Duration("base_penalty", time.Duration(m.BasePenalty)),
		zap.Int("cms_width", m.CMSWidth),
		zap.Int("cms_depth", m.CMSDepth),
		zap.Int("whitelist_prefixes", len(m.whitelist.prefixes)),
		zap.Bool("kernel_drop", m.KernelDrop))

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
	return nil
}

// ─── Cleanup ────────────────────────────────────────────────────────

func (m *DDOSMitigator) Cleanup() error {
	if m.cancel != nil {
		m.cancel()
	}
	// Clean up nftables rules/sets (no stale kernel state)
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
	}
	return nil
}

// ─── ServeHTTP (Hot Path) ───────────────────────────────────────────

func (m *DDOSMitigator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	addr, ok := clientAddr(r)
	if !ok {
		// Can't determine client IP — pass through
		return next.ServeHTTP(w, r)
	}

	// 1. Whitelist check
	if m.whitelist.Contains(addr) {
		return next.ServeHTTP(w, r)
	}

	// 2. Jail check — RLock on one of 64 shards
	if m.jail.IsJailed(addr) {
		m.setVars(r, "blocked", addr, 0)
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	// 3. Fingerprint + adaptive threshold
	strat := fingerprintStrategy(m.strategy.Load())
	fp := computeFingerprint(strat, addr, r.Method, r.URL.Path, r.UserAgent())
	freq := m.cms.Increment(fp[:])
	m.stats.Observe(float64(freq))
	z := m.stats.ZScore(float64(freq))

	if z > m.Threshold {
		ttl := m.calcTTL(addr)
		m.jail.Add(addr, ttl, "auto:z-score", m.infractionCount(addr))
		m.setVars(r, "jailed", addr, z)
		m.logger.Info("auto-jailed IP",
			zap.String("ip", addr.String()),
			zap.Float64("z_score", z),
			zap.Duration("ttl", ttl),
			zap.String("fingerprint", fpHex(fp)))
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	// 4. Pass through
	m.setVars(r, "pass", addr, z)
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

func (m *DDOSMitigator) setVars(r *http.Request, action string, addr netip.Addr, zScore float64) {
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.action", action)
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.ip", addr.String())
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.z_score", fmt.Sprintf("%.2f", zScore))
	caddyhttp.SetVar(r.Context(), "ddos_mitigator.spike_mode", fmt.Sprintf("%t", m.stats.IsSpikeMode()))
}

// ─── Client IP Extraction ───────────────────────────────────────────

// clientAddr extracts the client IP from the request, respecting Caddy's
// trusted_proxies configuration via the standard client_ip variable.
func clientAddr(r *http.Request) (netip.Addr, bool) {
	// Try Caddy's client_ip variable first (set by trusted_proxies)
	if val := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); val != nil {
		if ipStr, ok := val.(string); ok {
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				return addr, true
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
	return addr, true
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
			n := m.jail.Sweep()
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
			// Read new entries from file (written by wafctl)
			if err := readJailFile(m.JailFile, m.jail); err != nil {
				m.logger.Warn("jail file read error", zap.Error(err))
			}
			// Write current jail state to file (for wafctl to read)
			if err := writeJailFile(m.JailFile, m.jail); err != nil {
				m.logger.Warn("jail file write error", zap.Error(err))
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
