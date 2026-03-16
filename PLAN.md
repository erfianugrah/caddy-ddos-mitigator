# caddy-ddos-mitigator — Design Plan

Caddy plugin for adaptive DDoS/DoS mitigation, compiled into the Caddy binary
via xcaddy alongside the existing plugins. Registers three module types in one package:

- **L7 HTTP middleware** (`http.handlers.ddos_mitigator`) — fingerprint + z-score + jail
- **L4 connection handler** (`layer4.handlers.ddos_mitigator`) — TCP RST pre-TLS
- **Kernel drop manager** — nftables ipset + eBPF/XDP from within the Caddy process

Everything runs inside one Caddy image, one container, one process. No sidecars.
The Caddy container gains `NET_ADMIN` (and later `BPF`) capabilities to manage
kernel-level packet filtering directly.

This is the **first and only line of automated defense** — there is no upstream
CDN/WAF (Cloudflare is being removed from the stack). Caddy sits directly behind
the router, exposed to the internet.

**Repository:** `github.com/erfianugrah/caddy-ddos-mitigator`
**Package:** `ddosmitigator`
**Go version:** 1.24+ (stdlib + `caddy-l4` + `google/nftables` + `cilium/ebpf`)
**Sibling plugins:** `caddy-policy-engine`, `caddy-body-matcher`

---

## Problem

### Why Cloudflare is Being Removed

Moving to a fully self-hosted edge. Caddy + policy engine + DDoS mitigator replaces
the Cloudflare CDN, WAF, and DDoS protection layers. This means:

- No L3/L4 DDoS shield upstream — volumetric floods hit the origin directly
- No Cloudflare WAF — `caddy-policy-engine` is the sole WAF (already operational)
- No CDN caching — Caddy's `cache` directive + static file serving
- TLS termination at Caddy — no Cloudflare edge TLS
- DNS managed directly (no CF proxy, A records point to origin IP)

### Network Topology

```
Internet
  │
  ▼
Router (NAT, port forward 80/443 → Caddy host)
  │
  ▼ WAN link (residential/colo bandwidth)
  │
Caddy host (network_mode: host in Docker, +NET_ADMIN, +BPF)
  ├─ NIC driver ──── [eBPF/XDP: phase 5, managed by plugin]
  ├─ nftables ────── [kernel drop: phase 4, managed by plugin]
  ├─ Caddy L4 ────── [TCP RST: phase 3, caddy-l4 handler]
  ├─ Caddy L7 ────── [HTTP 403: phase 1-2, HTTP middleware]
  │   ├─ ddos_mitigator (this plugin, ordered first)
  │   ├─ log_append
  │   ├─ policy_engine (WAF)
  │   └─ reverse_proxy → upstream services
  │
  └─ wafctl sidecar (analytics, jail mgmt, dashboard)
      (reads jail.json + access logs, serves API + dashboard)
```

### What This Plugin Must Handle (Without Cloudflare)

1. **HTTP floods** — application-layer attacks that complete TCP+TLS. The main
   threat for a self-hosted origin. Policy engine rate limiting catches simple
   floods, but fingerprint-based adaptive detection catches distributed patterns
   where each IP stays below per-IP thresholds.

2. **TLS exhaustion** — botnets that connect, complete TLS handshake, then
   disconnect. Each TLS handshake costs ~1ms CPU. At 10K/s that's 10 CPU cores.
   L4 drop (TCP RST pre-TLS) eliminates this for jailed IPs.

3. **TCP state exhaustion** — SYN floods, connection floods. Kernel SYN cookies
   help, but repeated connections from jailed IPs should be RST'd immediately.
   `SetLinger(0)` bypasses TIME_WAIT, reclaiming fd in O(1).

4. **Bandwidth saturation** — UDP/ICMP volumetric floods that saturate the WAN
   link. **The router is the bottleneck here, not the server.** No amount of
   server-side filtering helps if the ISP pipe is full. This is the one attack
   vector we cannot fully mitigate without upstream protection. However:
   - nftables/XDP can keep the server alive even if the link is degraded
   - The router may support basic rate limiting (check per-model)
   - ISP-level null routing is the last resort (manual)

5. **Slowloris / slow-read** — Caddy handles these natively (timeouts, max
   header size). Not in scope for this plugin.

### Observations From Production (With Cloudflare)

Under a sustained bombardment (791K events in hours):
- WAF logged every blocked event individually → 2GB JSONL, 3-minute startup
- Health endpoint timeouts, dashboard unreachable
- Even returning 403 costs: TLS handshake + HTTP parse + header write + log
- At 10K req/s: ~8 CPU cores just to reject traffic
- Policy engine's 6-pass evaluation is too expensive for the DDoS check path

---

## Prior Art: Cloudflare's dosd Model

### Architecture

Cloudflare runs three complementary DDoS systems:

| System | Location | Speed | Scale |
|--------|----------|-------|-------|
| **Gatebot** | Core DCs (centralized) | Seconds-minutes | Large distributed attacks |
| **dosd** | Every edge server (decentralized) | 0-3 seconds | Small + large, localized |
| **flowtrackd** | Edge | Real-time | TCP state tracking |

**dosd** is the closest analog to what we're building:
- Runs on every server, no centralized dependency
- XDP samples packets at 81x Gatebot's rate → dosd analyzes with streaming algorithms
- Generates **multiple fingerprint permutations**, picks the most discriminating one
- Pushes mitigation rules as eBPF programs inline at the NIC level
- Mitigated 281K L3/4 attacks per month (55x more than Gatebot)
- **Gossips** mitigation instructions between servers in a DC and globally

### IP Jails

When HTTP floods exceed a rate threshold, Gatebot pushes mitigation from L7 to L4:
- Instead of responding with 403/challenge, **drop the TCP connection**
- Response bandwidth slashed by 10x, CPU returned to normal
- This is exactly the tiered escalation pattern we implement

### Dynamic Fingerprinting

dosd doesn't use a single fixed fingerprint. It:
1. Samples traffic attributes (src IP, port, dst IP, port, protocol, TCP flags, etc.)
2. Generates multiple permutations of these attributes as candidate fingerprints
3. Uses a streaming algorithm to identify which permutation best separates attack
   from legitimate traffic (highest discrimination)
4. Pushes the optimal fingerprint as an eBPF match rule

For example: if an attack randomizes User-Agent but uses a fixed path, the
`(method, path)` fingerprint is more useful than `(ip, method, path, ua)`.

### Packet Drop Hierarchy (Cloudflare benchmarks, single CPU)

| Layer | Technique | Throughput |
|-------|-----------|-----------|
| Userspace | `recvmmsg()` loop | 175K pps |
| Kernel | iptables INPUT | 608K pps |
| Kernel | iptables raw PREROUTING | 1.69M pps |
| Kernel | nftables ingress hook | 1.53M pps |
| Kernel | tc ingress | 1.8M pps |
| Driver | XDP (`XDP_DROP`) | **10M pps** |

Source: [How to drop 10 million packets/s](https://blog.cloudflare.com/how-to-drop-10-million-packets/)

---

## Dependency Decision: Stdlib + Targeted Imports

### What stdlib provides (sufficient)

| Need | Stdlib solution | Notes |
|------|----------------|-------|
| IP type | `net/netip.Addr` (Go 1.18+) | Value type, 24 bytes, no heap alloc, map key compatible |
| Hash | `hash/fnv` (FNV-64a) | ~50ns/hash. At our scale (1K-10K rps), not a bottleneck |
| Atomics | `sync/atomic.Int64` | Lock-free CMS increments |
| Concurrency | `sync.RWMutex` | 64-shard jail, reads dominate writes 100:1 |
| CMS | Hand-rolled ~100 lines | d=4, w=8192, 256KB fixed. Trivial to implement. |
| Welford/EWMA | Hand-rolled ~80 lines | Three float64 variables. No library needed. |
| JSON | `encoding/json` | Jail file serialization |
| Atomic write | `os.CreateTemp` + `os.Rename` | Matches wafctl's `atomicWriteFile` pattern |

### What we import

All compiled into one Caddy binary via xcaddy:

| Dep | Why | When |
|-----|-----|------|
| `github.com/caddyserver/caddy/v2` | Required for Caddy plugin | Phase 1 |
| `go.uber.org/zap` | Structured logging (implicit via caddy) | Phase 1 |
| `github.com/mholt/caddy-l4` | `layer4.Handler` interface for L4 handler | Phase 3 |
| `github.com/google/nftables` | nftables ipset management from within Caddy process | Phase 4 |
| `github.com/cilium/ebpf` | eBPF map/program loader for XDP from within Caddy process | Phase 5 |

### What we don't import (and why)

| Library | Why not |
|---------|---------|
| `go-immutable-radix` | External dep for a feature (CIDR aggregation) we don't need until phase 6. `[]netip.Prefix` from stdlib suffices. |
| `xxhash` | 2-3x faster than FNV-64a, irrelevant at 1K-10K rps. Matters at 1M+ pps (Cloudflare scale). |
| CMS libraries | ~100 lines to implement. Not worth a dep. |

### Key type change from v1 plan

**`netip.Addr`** replaces `[16]byte` as the jail key. It's stdlib (Go 1.18+), a
24-byte value type (no heap allocation), directly usable as a map key, and has
`Is4()`, `Is6()`, `Prefix()` built in. Eliminates manual `To16()` normalization.

---

## Architecture

### Full Defense Stack (All Phases)

```
Internet → Router → NIC
                      │
              ┌───────┴───────────────────────────────────┐
              │  Phase 5: eBPF/XDP (NIC driver level)     │
              │  BPF map lookup → XDP_DROP                │
              │  10M pps/CPU, ~0 cost                     │
              ├───────────────────────────────────────────┤
              │  Phase 4: nftables (kernel, pre-routing)  │
              │  ipset lookup → drop                      │
              │  1.5M pps/CPU, ~0.01ms/pkt                │
              ├───────────────────────────────────────────┤
              │  Phase 3: Caddy L4 (userspace, pre-TLS)   │
              │  Jail lookup → SetLinger(0) + RST          │
              │  ~0.1ms/conn                              │
              ├───────────────────────────────────────────┤
              │  Phase 1-2: Caddy L7 (HTTP layer)         │
              │  Jail check + fingerprint + z-score → 403  │
              │  ~0.2ms/req                               │
              ├───────────────────────────────────────────┤
              │  Policy Engine (WAF, 6-pass)              │
              │  Allow/block/detect/rate_limit             │
              │  ~1-2ms/req                               │
              ├───────────────────────────────────────────┤
              │  reverse_proxy → upstream services         │
              └───────────────────────────────────────────┘
```

### Tiered Escalation

| Tier | Trigger | Action | Layer | Cost | Phase |
|------|---------|--------|-------|------|-------|
| 1 | First offense | Rate limit 429 | L7 (policy engine) | ~2ms | existing |
| 2 | Repeat offender | Block 403 | L7 (policy engine) | ~1ms | existing |
| 3 | Z-score breach | Auto-jail + 403 | L7 (ddos_mitigator) | ~0.2ms | 1 |
| 4 | Jailed IP, new conn | TCP RST | L4 (ddos_mitigator) | ~0.1ms | 3 |
| 5 | Jailed IP, kernel | nftables drop | Kernel | ~0.01ms | 4 |
| 6 | Jailed IP, XDP | XDP_DROP | NIC driver | ~0.001ms | 5 |
| 7 | Known bad actor | Permanent list | All layers | varies | 2 |

### Request Flow (Caddyfile)

```
# Handler ordering — ddos_mitigator runs before everything
order ddos_mitigator before log_append
order log_append before policy_engine

# Per-site usage (inside site block):
ddos_mitigator {
    jail_file       /data/waf/jail.json
    threshold       4.0
    base_penalty    60s
    max_penalty     24h
    whitelist       192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 127.0.0.0/8 ::1/128
}
import site_log myservice
import waf
reverse_proxy upstream:8080
```

```
request
  → ddos_mitigator   ← one shard RLock + one CMS atomic increment (~200ns)
    ├─ jailed?        → 403, stop chain (no TLS handshake cost saved at L7,
    │                    but saves WAF + proxy + upstream CPU)
    ├─ over threshold → jail + 403, stop chain
    └─ pass
      → log_append    ← captures ddos_* vars for access log
        → policy_engine ← 6-pass WAF evaluation
          → reverse_proxy → upstream
```

---

## Data Structures

### 1. IP Jail — Sharded Concurrent Map with TTL

```go
const jailShards = 64

type jailEntry struct {
    ExpiresAt       int64  // unix nano
    InfractionCount int32  // drives exponential backoff
    Reason          string // "auto:z-score", "auto:threshold", "manual", "file:wafctl"
    JailedAt        int64  // unix nano
}

type ipJail struct {
    shards [jailShards]jailShard
    count  atomic.Int64
}

type jailShard struct {
    mu      sync.RWMutex
    entries map[netip.Addr]*jailEntry  // netip.Addr: value type, comparable, zero alloc
}
```

**Shard selection:** `fnv32a(addr.As16()) % jailShards`

**Why `netip.Addr`:** stdlib since Go 1.18. A 24-byte value type (no heap alloc),
directly usable as a map key, supports `Is4()`, `Is6()`, `Prefix()`. Eliminates
all the manual `IP.To16()` normalization code from v1 plan.

### 2. Count-Min Sketch — Probabilistic Frequency Tracker

```go
const (
    cmsDepth = 4
    cmsWidth = 8192
)

type countMinSketch struct {
    matrix [cmsDepth][cmsWidth]atomic.Int64
    seeds  [cmsDepth]uint64  // per-row FNV seeds, set at init
}
```

**Memory:** 4 × 8192 × 8 = 256KB fixed. Tracks millions of unique fingerprints.
**Error bound:** ε ≈ 1/8192 ≈ 0.00012, confidence ≈ 0.9999.
**Decay:** background goroutine halves all counters every `decay_interval` (30s).

### 3. Adaptive Statistics — Welford + Dual EWMA

```go
type adaptiveStats struct {
    mu sync.Mutex

    // Welford's online algorithm (numerically stable single-pass variance)
    count int64
    mean  float64
    m2    float64  // running sum of squared differences

    // Dual EWMA
    ewmaFast float64  // α=0.3, half-life ≈2 samples — spike detection
    ewmaSlow float64  // α=0.05, half-life ≈14 samples — baseline

    // EPS tracking
    windowStart int64
    windowCount int64
    prevEPS     float64
    currEPS     float64
}
```

**Spike mode detection:** `ewmaFast > 3 × ewmaSlow` → system is under volumetric
attack. Communicated to wafctl via log fields, triggering observation-layer dedup.

### 4. Dynamic Fingerprint Strategies (dosd-inspired)

Instead of one fixed fingerprint, maintain multiple strategies and pick the most
discriminating one during spike mode:

```go
type fingerprintStrategy int

const (
    fpFull    fingerprintStrategy = iota  // hash(ip, method, path, ua)
    fpIPPath                              // hash(ip, path)
    fpIPOnly                              // hash(ip)
    fpPathUA                              // hash(method, path, ua)
    fpPathOnly                            // hash(method, path)
)
```

**Normal mode:** use `fpFull` (most specific, fewest false positives).
**Spike mode:** evaluate all strategies against recent traffic, pick the one where
the top-N fingerprints capture the most attack volume. This catches:
- Randomized UA attacks → `fpIPPath` or `fpPathOnly` captures better
- Distributed botnets hitting same endpoint → `fpPathOnly` captures better
- Single-IP floods → `fpIPOnly` captures immediately

Strategy selection runs in the CMS decay goroutine (every 30s), not on the hot path.

### 5. Whitelist — Static Prefix Set

```go
type whitelist struct {
    prefixes []netip.Prefix  // parsed at Provision time
}

func (w *whitelist) Contains(addr netip.Addr) bool {
    for _, p := range w.prefixes {
        if p.Contains(addr) { return true }
    }
    return false
}
```

Small set (<20 entries), linear scan is fine.

---

## Kernel-Level Drop Pipeline (In-Process)

The plugin manages nftables and eBPF/XDP **directly from within the Caddy process**.
No sidecar needed — the Caddy container gains the necessary capabilities.

### compose.yaml Changes

```yaml
caddy:
    cap_add:
      - NET_BIND_SERVICE
      - DAC_OVERRIDE
      - NET_ADMIN          # nftables ipset management (phase 4)
      - BPF                # eBPF program loading (phase 5, Linux 5.8+)
      - PERFMON            # perf event sampling (phase 5)
```

### Phase 4: nftables (In-Process)

The plugin's `Provision()` method creates nftables rules and ipsets directly
using `github.com/google/nftables`. A background goroutine syncs the jail
state to the kernel ipset.

```go
// Spawned in Provision(), stopped in Cleanup()
func (m *DDOSMitigator) runNftablesSync(ctx context.Context) {
    // Create nftables table + chain + ipset on startup
    // inet filter input: ip saddr @ddos_jail_v4 counter drop
    // inet filter input: ip6 saddr @ddos_jail_v6 counter drop
    ticker := time.NewTicker(m.nftSyncInterval) // default 2s
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            // Clean up: remove nftables rules + sets
            return
        case <-ticker.C:
            m.syncJailToNftables()
        }
    }
}
```

This drops packets in the kernel **before they reach Caddy's socket**, at
1.5M pps per CPU. The `Cleanup()` method removes the nftables rules/sets
on shutdown so the plugin doesn't leave stale kernel state.

### Phase 5: eBPF/XDP (In-Process)

XDP requires `BPF` + `NET_ADMIN` capabilities. The host kernel (6.6+) has
`CONFIG_BPF=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_BPF_JIT=y`.

The plugin loads an XDP program onto the host NIC during `Provision()` and
manages a BPF hashmap that mirrors the jail state:

```go
func (m *DDOSMitigator) startXDP() error {
    // Load pre-compiled eBPF bytecode (generated by bpf2go at build time)
    objs := &xdpObjects{}
    if err := loadXdpObjects(objs, nil); err != nil {
        return err
    }
    // Attach XDP program to the NIC
    link, err := netlink.AttachXDP(objs.XdpDdosDrop, m.ifIndex, nil)
    // ...
    m.xdpLink = link
    m.jailMap = objs.JailMap
    return nil
}

// Background goroutine syncs jail → BPF map
func (m *DDOSMitigator) syncJailToXDP() {
    // For each jailed IP: put in BPF LPM trie map
    // For expired: delete from map
    // BPF map updates are atomic from kernel's perspective
}
```

The XDP C program:

```c
struct bpf_map_def SEC("maps") jail_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,  // supports CIDR prefix matching
    .key_size = sizeof(struct lpm_key),
    .value_size = sizeof(__u64),     // expiry timestamp
    .max_entries = 100000,
};

SEC("xdp")
int xdp_ddos_drop(struct xdp_md *ctx) {
    // Parse ethernet + IP headers
    // Lookup src IP in jail_map
    // If found and not expired: return XDP_DROP
    // Else: return XDP_PASS
}
```

**`cilium/ebpf`** handles: C → eBPF bytecode compilation (via `bpf2go`),
program loading, BPF map CRUD, pinning to bpffs for persistence.

`Cleanup()` detaches the XDP program and closes BPF maps on shutdown.

### Bandwidth Saturation Caveat

XDP drops packets at the NIC driver level, but packets have **already traversed
the WAN link**. If the ISP pipe (e.g., 1 Gbps) is saturated with 5 Gbps of
attack traffic, the router drops 80% before it reaches the server. XDP keeps
the server alive (CPU not wasted processing attack traffic), but doesn't solve
bandwidth exhaustion. Only upstream filtering (ISP null routing, VPS/colo with
scrubbing capacity) solves that.

---

## Caddy Plugin: Module Registration

Two modules in one package:

```go
func init() {
    caddy.RegisterModule(DDOSMitigator{})
    caddy.RegisterModule(DDOSMitigatorL4{})
    httpcaddyfile.RegisterHandlerDirective("ddos_mitigator", parseCaddyfile)
}
```

### L7 Module: `http.handlers.ddos_mitigator`

```go
type DDOSMitigator struct {
    // Config (from Caddyfile/JSON)
    JailFile      string         `json:"jail_file,omitempty"`
    Threshold     float64        `json:"threshold,omitempty"`       // z-score, default 4.0
    BasePenalty   caddy.Duration `json:"base_penalty,omitempty"`    // default 60s
    MaxPenalty    caddy.Duration `json:"max_penalty,omitempty"`     // default 24h
    SweepInterval caddy.Duration `json:"sweep_interval,omitempty"` // default 10s
    DecayInterval caddy.Duration `json:"decay_interval,omitempty"` // default 30s
    SyncInterval  caddy.Duration `json:"sync_interval,omitempty"`  // default 5s
    CMSWidth      int            `json:"cms_width,omitempty"`      // default 8192
    CMSDepth      int            `json:"cms_depth,omitempty"`      // default 4
    WhitelistCIDRs []string      `json:"whitelist,omitempty"`

    // Internal state
    jail      *ipJail
    cms       *countMinSketch
    stats     *adaptiveStats
    whitelist *whitelist
    strategy  atomic.Int32  // current fingerprintStrategy
    logger    *zap.Logger
    cancel    context.CancelFunc
}
```

Implements: `caddy.Module`, `caddy.Provisioner`, `caddy.Validator`,
`caddy.CleanerUpper`, `caddyhttp.MiddlewareHandler`, `caddyfile.Unmarshaler`

### L4 Module: `layer4.handlers.ddos_mitigator`

```go
type DDOSMitigatorL4 struct {
    JailFile string `json:"jail_file,omitempty"`

    jail   *ipJail
    logger *zap.Logger
}
```

Implements: `caddy.Module`, `caddy.Provisioner`, `layer4.Handler`

Shared jail via package-level singleton (`sync.Once`).

---

## Connection Termination

### L4 Force Drop

```go
func forceDrop(cx *layer4.Connection) error {
    conn := cx.Conn
    for {
        if u, ok := conn.(interface{ NetConn() net.Conn }); ok {
            conn = u.NetConn()
        } else {
            break
        }
    }
    if tcp, ok := conn.(*net.TCPConn); ok {
        _ = tcp.SetLinger(0)  // SO_LINGER=0 → RST, skip TIME_WAIT
        _ = tcp.Close()       // fd reclaimed immediately, O(1)
    } else {
        _ = cx.Conn.Close()
    }
    return errors.New("ddos_mitigator: dropped")
}
```

### L7 ServeHTTP (Hot Path)

```go
func (m *DDOSMitigator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    addr := clientAddr(r)

    // 1. Whitelist
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
    freq := m.cms.Increment(fp)
    m.stats.Observe(float64(freq))
    z := m.stats.ZScore(float64(freq))

    if z > m.Threshold {
        ttl := m.calcTTL(addr)
        m.jail.Add(addr, ttl, "auto:z-score")
        m.setVars(r, "jailed", addr, z)
        w.WriteHeader(http.StatusForbidden)
        return nil
    }

    // 4. Pass
    m.setVars(r, "pass", addr, z)
    return next.ServeHTTP(w, r)
}
```

---

## Penalty Escalation

```go
func (m *DDOSMitigator) calcTTL(addr netip.Addr) time.Duration {
    infractions := int32(0)
    if entry := m.jail.Get(addr); entry != nil {
        infractions = entry.InfractionCount + 1
    }
    shift := min(infractions, 16)
    ttl := time.Duration(m.BasePenalty) << shift
    if ttl > time.Duration(m.MaxPenalty) {
        ttl = time.Duration(m.MaxPenalty)
    }
    // ±25% jitter
    jitter := time.Duration(rand.Int64N(int64(ttl)/2)) - ttl/4
    return ttl + jitter
}
```

| Infraction | Base=60s | TTL (± jitter) |
|------------|----------|----------------|
| 0 | 60s × 2⁰ | 60s ± 15s |
| 1 | 60s × 2¹ | 2m ± 30s |
| 3 | 60s × 2³ | 8m ± 2m |
| 5 | 60s × 2⁵ | 32m ± 8m |
| 10 | capped | 24h ± 6h |

---

## Background Goroutines

Spawned in `Provision`, stopped via `context.CancelFunc` in `Cleanup`:

1. **Jail sweeper** (every `sweep_interval`, default 10s) — removes expired entries
2. **CMS decay** (every `decay_interval`, default 30s) — halves all counters
3. **Jail file sync** (every `sync_interval`, default 5s) — bidirectional merge
   with `jail.json` (read wafctl entries, write plugin entries)
4. **Strategy selector** (every 30s, only during spike mode) — evaluates
   fingerprint strategies, picks most discriminating one

---

## Log Fields

The L7 handler sets Caddy variables via `caddyhttp.SetVar()`:

| Variable | Values | Description |
|----------|--------|-------------|
| `ddos_mitigator.action` | `pass`, `blocked`, `jailed` | What happened |
| `ddos_mitigator.fingerprint` | hex string | FNV-64a hash |
| `ddos_mitigator.ip` | IP address | Client IP evaluated |
| `ddos_mitigator.z_score` | float | Statistical deviation |
| `ddos_mitigator.spike_mode` | `true`/`false` | ewmaFast > 3×ewmaSlow |
| `ddos_mitigator.strategy` | `full`/`ip_path`/etc | Active fingerprint strategy |

Caddyfile `log_append` additions:
```
log_append ddos_action {http.vars.ddos_mitigator.action}
log_append ddos_fingerprint {http.vars.ddos_mitigator.fingerprint}
log_append ddos_z_score {http.vars.ddos_mitigator.z_score}
log_append ddos_spike_mode {http.vars.ddos_mitigator.spike_mode}
```

wafctl tails these from the combined access log for spike detection and forensics.

---

## Jail File Format

```json
{
  "version": 1,
  "entries": {
    "192.0.2.1": {
      "expires_at": "2026-03-16T12:00:00Z",
      "infractions": 3,
      "reason": "auto:z-score",
      "jailed_at": "2026-03-16T11:00:00Z"
    },
    "2001:db8::1": {
      "expires_at": "2026-03-16T13:00:00Z",
      "infractions": 1,
      "reason": "manual",
      "jailed_at": "2026-03-16T12:30:00Z"
    }
  },
  "updated_at": "2026-03-16T11:00:05Z"
}
```

Atomic write (temp + fsync + rename). Shared volume: `/data/waf/jail.json`.

---

## wafctl Integration

### New Files

| File | Purpose |
|------|---------|
| `wafctl/dos_mitigation.go` | JailStore, SpikeDetector, SpikeReporter, FingerprintAnalyzer |
| `wafctl/handlers_dos.go` | All `/api/dos/*` HTTP handlers (closure pattern) |
| `wafctl/dos_mitigation_test.go` | Tests |
| `wafctl/handlers_dos_test.go` | Handler tests |

### JailStore

```go
type JailStore struct {
    mu       sync.RWMutex
    file     string            // /data/waf/jail.json
    entries  map[string]JailFileEntry
    lastMod  time.Time
}
```

Reads `jail.json` on interval (5s mtime poll, matching policy engine pattern).
Provides CRUD for manual jail/unjail via API.

### SpikeDetector

Tails the combined access log, reads `ddos_action`/`ddos_spike_mode` fields:

```go
type SpikeDetector struct {
    mu           sync.RWMutex
    mode         string    // "normal" or "spike"
    currentEPS   float64
    peakEPS      float64
    spikeStart   time.Time
    triggerEPS   float64   // from WAF_DOS_EPS_TRIGGER env (default 50)
    cooldownEPS  float64   // from WAF_DOS_EPS_COOLDOWN env (default 10)
    cooldownDelay time.Duration // WAF_DOS_COOLDOWN_DELAY (default 30s)
}
```

### SpikeReporter

On cooldown transition, generates forensic reports:

```go
type SpikeReport struct {
    ID              string            `json:"id"`
    StartTime       time.Time         `json:"start_time"`
    EndTime         time.Time         `json:"end_time"`
    Duration        string            `json:"duration"`
    TotalEvents     int64             `json:"total_events"`
    PeakEPS         float64           `json:"peak_eps"`
    UniqueIPs       int               `json:"unique_ips"`
    UniqueFingerprints int            `json:"unique_fingerprints"`
    TopIPs          []CountEntry      `json:"top_ips"`
    TopPaths        []CountEntry      `json:"top_paths"`
    TopFingerprints []CountEntry      `json:"top_fingerprints"`
    TopCountries    []CountEntry      `json:"top_countries"`
    JailedIPs       int               `json:"jailed_ips"`
    Strategy        string            `json:"strategy"`
}
```

Persisted to `/data/spike-reports/{id}.json`. Keeps last 100 (configurable).

### New API Endpoints

Registered in `main.go` `runServe()`:

```go
// DDoS Mitigation
mux.HandleFunc("GET /api/dos/status", handleDosStatus(jailStore, spikeDetector))
mux.HandleFunc("GET /api/dos/jail", handleListJail(jailStore))
mux.HandleFunc("POST /api/dos/jail", handleAddJail(jailStore))
mux.HandleFunc("DELETE /api/dos/jail/{ip}", handleRemoveJail(jailStore))
mux.HandleFunc("GET /api/dos/reports", handleListSpikeReports(spikeReporter))
mux.HandleFunc("GET /api/dos/reports/{id}", handleGetSpikeReport(spikeReporter))
mux.HandleFunc("GET /api/dos/config", handleGetDosConfig(dosConfigStore))
mux.HandleFunc("PUT /api/dos/config", handleUpdateDosConfig(dosConfigStore))
```

### DDoS Config Store

```go
type DosConfig struct {
    Enabled       bool    `json:"enabled"`
    Threshold     float64 `json:"threshold"`       // z-score, default 4.0
    BasePenalty   string  `json:"base_penalty"`     // "60s"
    MaxPenalty    string  `json:"max_penalty"`      // "24h"
    EPSTrigger    float64 `json:"eps_trigger"`      // spike mode entry, default 50
    EPSCooldown   float64 `json:"eps_cooldown"`     // spike mode exit, default 10
    CooldownDelay string  `json:"cooldown_delay"`   // sustain below cooldown, default "30s"
    MaxBuckets    int     `json:"max_buckets"`      // fingerprint buckets per spike, default 10000
    MaxReports    int     `json:"max_reports"`      // keep last N reports, default 100
    Whitelist     []string `json:"whitelist"`       // CIDR strings
    KernelDrop    bool    `json:"kernel_drop"`      // enable nftables sidecar sync
    Strategy      string  `json:"strategy"`         // "auto", "full", "ip_path", etc.
}
```

Persisted to `/data/dos-config.json`. The plugin reads `jail.json` for runtime
state; the config store is for dashboard-editable settings that wafctl pushes
to the plugin via the jail file's config section or environment reload.

### New Environment Variables

```yaml
# compose.yaml additions for wafctl
- WAF_DOS_CONFIG_FILE=/data/dos-config.json
- WAF_DOS_JAIL_FILE=/data/waf/jail.json
- WAF_DOS_SPIKE_REPORTS_DIR=/data/spike-reports
- WAF_DOS_EPS_TRIGGER=50
- WAF_DOS_EPS_COOLDOWN=10
- WAF_DOS_COOLDOWN_DELAY=30s
- WAF_DOS_MAX_BUCKETS=10000
- WAF_DOS_MAX_REPORTS=100
```

### Health Check Addition

`handleHealth()` gains a `dos` section:

```json
{
  "status": "ok",
  "stores": {
    "dos": {
      "mode": "normal",
      "eps": 12.5,
      "jail_count": 3,
      "spike_reports": 2,
      "kernel_drop": true,
      "strategy": "full"
    }
  }
}
```

---

## Dashboard Integration

### New Page: `/dos` — DDoS Protection

**Nav entry** in `DashboardLayout.astro` `navLinks`:
```js
{ id: "dos", label: "DDoS Protection", href: "/dos", icon: "shield-alert", section: "Security" }
```

### Page Structure

```
/dos
├─ Status Banner
│  ├─ Mode indicator: "MONITORING" (green) / "SPIKE: 150 EPS" (amber pulsing)
│  ├─ Current EPS sparkline (last 5 minutes)
│  ├─ Jail count badge
│  └─ Active strategy label
│
├─ Configuration Panel (collapsible, calls GET/PUT /api/dos/config)
│  ├─ Z-score threshold slider (1.0 - 10.0, default 4.0)
│  ├─ Base penalty duration input
│  ├─ Max penalty duration input
│  ├─ EPS trigger/cooldown inputs
│  ├─ Whitelist CIDR editor (tag input)
│  ├─ Kernel drop toggle (nftables sidecar)
│  ├─ Fingerprint strategy selector (auto/full/ip_path/path_only/etc.)
│  └─ Save + Deploy buttons
│
├─ IP Jail Table (calls GET /api/dos/jail)
│  ├─ Columns: IP, Reason, Infractions, Jailed At, Expires At, TTL remaining
│  ├─ Manual jail button (POST /api/dos/jail, modal: IP + TTL + reason)
│  ├─ Unjail button per row (DELETE /api/dos/jail/{ip})
│  ├─ Bulk unjail
│  ├─ Search/filter
│  └─ Auto-refresh (5s during spike mode, 30s normal)
│
├─ Spike Reports (calls GET /api/dos/reports)
│  ├─ Table: ID, Start, Duration, Peak EPS, Total Events, Jailed IPs
│  ├─ Click → drill-down (GET /api/dos/reports/{id})
│  │   ├─ Timeline chart (EPS over spike duration)
│  │   ├─ Top IPs table
│  │   ├─ Top paths table
│  │   ├─ Top fingerprints table
│  │   ├─ Top countries table
│  │   └─ Strategy used
│  └─ Pagination
│
└─ Enforcement Layers (status cards)
   ├─ L7 Plugin: ✓ Active, threshold 4.0, strategy: full
   ├─ L4 Plugin: ✓ Active / ✗ Not configured
   ├─ nftables: ✓ Active (N IPs in ipset) / ✗ Sidecar not running
   └─ XDP: ✓ Active / ✗ Not configured
```

### New Files

| File | Purpose |
|------|---------|
| `waf-dashboard/src/pages/dos.astro` | Astro page, renders `DDoSPanel` |
| `waf-dashboard/src/components/DDoSPanel.tsx` | Main React component (~600 lines) |
| `waf-dashboard/src/components/dos/StatusBanner.tsx` | EPS sparkline, mode indicator |
| `waf-dashboard/src/components/dos/JailTable.tsx` | IP jail CRUD table |
| `waf-dashboard/src/components/dos/SpikeReports.tsx` | Reports list + drill-down |
| `waf-dashboard/src/components/dos/ConfigPanel.tsx` | Settings editor |
| `waf-dashboard/src/components/dos/EnforcementLayers.tsx` | Layer status cards |
| `waf-dashboard/src/lib/api/dos.ts` | API module (types + fetch wrappers) |

### API Module: `dos.ts`

```typescript
const API_BASE = "/api";

export interface DosStatus {
  mode: "normal" | "spike";
  eps: number;
  jail_count: number;
  peak_eps: number;
  spike_start?: string;
  strategy: string;
  kernel_drop: boolean;
}

export interface JailEntry {
  ip: string;
  expires_at: string;
  infractions: number;
  reason: string;
  jailed_at: string;
}

export interface SpikeReport { /* ... */ }
export interface DosConfig { /* ... */ }

export async function fetchDosStatus(): Promise<DosStatus> { ... }
export async function fetchJail(): Promise<JailEntry[]> { ... }
export async function addJail(ip: string, ttl: string, reason: string): Promise<void> { ... }
export async function removeJail(ip: string): Promise<void> { ... }
export async function fetchSpikeReports(): Promise<SpikeReport[]> { ... }
export async function fetchSpikeReport(id: string): Promise<SpikeReport> { ... }
export async function getDosConfig(): Promise<DosConfig> { ... }
export async function updateDosConfig(config: DosConfig): Promise<void> { ... }
```

### Health Indicator Enhancement

In `DashboardLayout.astro`, the existing green/red health dot gains a third state:

```
● MONITORING          — green (normal mode, DDoS plugin active)
● SPIKE: 150 EPS      — amber pulsing (spike mode detected)
● UNHEALTHY            — red (wafctl unreachable)
```

The health check already polls `/api/health` every 30s. Add `dos.mode` and
`dos.eps` to the response, check in the health indicator logic.

---

## File Layout

### Plugin Repository

```
caddy-ddos-mitigator/
├── .gitignore
├── go.mod
├── go.sum
├── PLAN.md
├── README.md
│
├── mitigator.go             ← DDOSMitigator L7 handler, Provision, ServeHTTP, Caddyfile
├── mitigator_l4.go          ← DDOSMitigatorL4 L4 handler, Handle, forceDrop
├── jail.go                  ← ipJail: sharded map[netip.Addr], CRUD, sweep, file sync
├── cms.go                   ← countMinSketch: Increment/Estimate/Decay
├── stats.go                 ← adaptiveStats: Welford + dual EWMA, ZScore
├── fingerprint.go           ← strategies, computeFingerprint, normalizePath
├── nftables.go              ← nftables ipset create/sync/cleanup (phase 4)
├── xdp.go                   ← XDP program loader + BPF map sync (phase 5)
├── xdp_drop.c               ← XDP eBPF C source (compiled via bpf2go)
├── util.go                  ← clientAddr, atomicWriteFile
│
├── mitigator_test.go
├── mitigator_l4_test.go
├── jail_test.go
├── cms_test.go
├── stats_test.go
├── fingerprint_test.go
├── nftables_test.go
├── xdp_test.go
└── testhelpers_test.go
```

### wafctl Additions (in caddy-compose repo)

```
wafctl/
├── dos_mitigation.go         ← JailStore, SpikeDetector, SpikeReporter
├── handlers_dos.go           ← /api/dos/* handlers
├── dos_mitigation_test.go
└── handlers_dos_test.go

waf-dashboard/src/
├── pages/dos.astro
├── components/
│   └── dos/
│       ├── DDoSPanel.tsx
│       ├── StatusBanner.tsx
│       ├── JailTable.tsx
│       ├── SpikeReports.tsx
│       ├── ConfigPanel.tsx
│       └── EnforcementLayers.tsx
└── lib/api/dos.ts
```

---

## Dockerfile & Compose Integration

### Dockerfile

```dockerfile
FROM caddy:${VERSION}-builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@v0.2.3 \
    --with github.com/mholt/caddy-dynamicdns \
    --with github.com/erfianugrah/caddy-body-matcher@v0.1.1 \
    --with github.com/erfianugrah/caddy-policy-engine@v0.19.0 \
    --with github.com/erfianugrah/caddy-ddos-mitigator@v0.1.0 \
    --with github.com/mholt/caddy-l4
```

Note: `caddy-dns/cloudflare` will be replaced with another DNS provider plugin
once CF is fully removed from the stack.

### compose.yaml Changes

```yaml
caddy:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # existing: bind to 80/443
      - DAC_OVERRIDE        # existing: file access
      - NET_ADMIN            # NEW: nftables ipset management (phase 4)
      # Phase 5 additions (uncomment when implementing XDP):
      # - BPF               # eBPF program loading
      # - PERFMON            # perf event access for XDP sampling
```

Everything runs in one container. No sidecars. The jail file (`/data/waf/jail.json`)
is shared with wafctl via the existing `/data/waf` volume mount.

---

## Implementation Phases

### Phase 1: Core L7 Plugin (~4 days)

Adaptive auto-jail with fingerprint-based detection. No external deps beyond caddy.

| Task | File | Est. |
|------|------|------|
| Scaffold repo, `go.mod`, module registration | `mitigator.go` | 2h |
| IP jail: sharded map, Add/IsJailed/Get/Remove/Sweep | `jail.go` | 4h |
| Count-Min Sketch: atomic increments, decay | `cms.go` | 3h |
| Welford + dual EWMA, ZScore | `stats.go` | 3h |
| Fingerprint strategies, normalizePath | `fingerprint.go` | 3h |
| L7 handler: Provision, Validate, Cleanup, ServeHTTP | `mitigator.go` | 4h |
| Caddyfile parsing (UnmarshalCaddyfile) | `mitigator.go` | 2h |
| Util: clientAddr (trusted_proxies aware), atomicWriteFile | `util.go` | 2h |
| Tests: jail (concurrency, TTL, sweep) | `jail_test.go` | 3h |
| Tests: CMS (accuracy, decay, concurrent) | `cms_test.go` | 2h |
| Tests: stats (Welford stability, EWMA convergence) | `stats_test.go` | 2h |
| Tests: fingerprint (normalization, distribution) | `fingerprint_test.go` | 2h |
| Tests: L7 handler (httptest) | `mitigator_test.go` | 3h |
| Integration: xcaddy build + traffic test | - | 2h |

### Phase 2: Jail File Sync + wafctl Backend (~3 days)

Bidirectional jail state, DDoS API, spike detection.

| Task | File | Est. |
|------|------|------|
| Jail file sync goroutine (read/merge/write) | `jail.go` | 4h |
| Log field integration (caddyhttp.SetVar) | `mitigator.go` | 2h |
| Caddyfile `log_append` additions | Caddyfile | 1h |
| JailStore (reads/writes jail.json) | `wafctl/dos_mitigation.go` | 3h |
| SpikeDetector (EPS from access log) | `wafctl/dos_mitigation.go` | 4h |
| SpikeReporter (forensic snapshots) | `wafctl/dos_mitigation.go` | 3h |
| DosConfigStore (dos-config.json) | `wafctl/dos_mitigation.go` | 2h |
| API handlers: status, jail CRUD, reports, config | `wafctl/handlers_dos.go` | 4h |
| Health check addition (dos section) | `wafctl/handlers_events.go` | 1h |
| Env vars + main.go wiring | `wafctl/main.go` | 1h |
| compose.yaml additions (env vars, volumes) | `compose.yaml` | 1h |
| Tests: jail file sync races | `jail_test.go` | 2h |
| Tests: wafctl API handlers | `wafctl/handlers_dos_test.go` | 3h |

### Phase 3: L4 Handler (~2 days)

TCP RST for jailed IPs, pre-TLS. Requires `caddy-l4` dep.

| Task | File | Est. |
|------|------|------|
| DDOSMitigatorL4: Handle, forceDrop, unwrap | `mitigator_l4.go` | 4h |
| Shared jail via package singleton | `jail.go` | 2h |
| L4 JSON config + Caddy admin integration | `mitigator_l4.go` | 2h |
| Dockerfile: add `--with caddy-l4` | `Dockerfile` | 1h |
| Tests: mock TCP conn, verify RST | `mitigator_l4_test.go` | 3h |

### Phase 4: nftables Kernel Drop (~3 days)

In-process nftables management. Caddy container gains `NET_ADMIN`.

| Task | File | Est. |
|------|------|------|
| nftables table/chain/ipset creation in Provision() | `nftables.go` | 4h |
| Jail → nftables sync goroutine | `nftables.go` | 3h |
| Cleanup: remove rules/sets on shutdown | `nftables.go` | 2h |
| Caddyfile config: `kernel_drop` toggle | `mitigator.go` | 1h |
| compose.yaml: add NET_ADMIN cap | `compose.yaml` | 1h |
| Dashboard: enforcement layer status cards | `dos/EnforcementLayers.tsx` | 3h |
| Tests: nftables sync logic | `nftables_test.go` | 3h |
| Integration test: verify kernel drop | - | 3h |

### Phase 5: eBPF/XDP (~4 days)

In-process XDP management. Caddy container gains `BPF` + `PERFMON`.

| Task | File | Est. |
|------|------|------|
| XDP C program (packet parse + BPF map lookup) | `xdp_drop.c` | 4h |
| bpf2go codegen + Go loader (cilium/ebpf) | `xdp.go` | 4h |
| Jail → BPF map sync goroutine | `xdp.go` | 3h |
| Cleanup: detach XDP + close maps on shutdown | `xdp.go` | 2h |
| compose.yaml: add BPF + PERFMON caps | `compose.yaml` | 1h |
| Verify on target kernel (6.6+) | - | 3h |
| Dashboard: XDP status card | `dos/EnforcementLayers.tsx` | 2h |
| Benchmarks: pps throughput with XDP | - | 3h |

### Phase 6: Dashboard UI (~3 days)

Full DDoS Protection page.

| Task | File | Est. |
|------|------|------|
| API module (types, fetch wrappers) | `waf-dashboard/src/lib/api/dos.ts` | 2h |
| Astro page + DDoSPanel shell | `dos.astro`, `DDoSPanel.tsx` | 2h |
| StatusBanner (EPS sparkline, mode) | `dos/StatusBanner.tsx` | 3h |
| ConfigPanel (settings editor) | `dos/ConfigPanel.tsx` | 3h |
| JailTable (CRUD, search, bulk) | `dos/JailTable.tsx` | 4h |
| SpikeReports (list + drill-down) | `dos/SpikeReports.tsx` | 4h |
| EnforcementLayers (L4/nft/XDP cards) | `dos/EnforcementLayers.tsx` | 2h |
| Nav entry + health indicator update | `DashboardLayout.astro` | 1h |
| Tests: component tests | - | 3h |

### Phase 7: CIDR Aggregation + Advanced (future)

| Task | Notes |
|------|-------|
| Promote /24 (v4) or /64 (v6) when N IPs from same prefix jailed | `[]netip.Prefix` in jail |
| Origin error feedback (5xx rate → lower threshold) | Tail upstream errors |
| Multi-strategy evaluation with entropy scoring | Better attack discrimination |
| BPF_MAP_TYPE_LPM_TRIE for CIDR in XDP | Kernel-level prefix match |

---

## Removing Cloudflare: Migration Checklist

When CF is removed, these Caddyfile/config changes are needed:

| Current (with CF) | After (no CF) |
|---|---|
| `trusted_proxies_strict` + CF IP ranges | Remove trusted_proxies or set to local LB |
| `acme_dns cloudflare` | Switch to `acme_dns` with new provider, or HTTP-01 challenge |
| `dns cloudflare` for ECH | ECH via alternative or disable |
| `dynamic_dns` with CF provider | Use alternative DDNS provider |
| CF trusted proxies seeding in entrypoint | Remove entrypoint seeding |
| `X-Forwarded-For` trust chain via CF | Direct client IP from socket |
| `import /data/waf/cf_trusted_proxies.caddy` | Remove import |

The DDoS mitigator plugin's `clientAddr()` function must handle both scenarios:
- With CF: trust `X-Forwarded-For` / `CF-Connecting-IP` (current)
- Without CF: use `r.RemoteAddr` directly (future)

This is handled by Caddy's `trusted_proxies` config — when no proxies are trusted,
`r.RemoteAddr` is the real client IP. The plugin just calls
`caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey)` and gets the right answer.

---

## Design Decisions Log

### Why separate plugin, not in policy engine?
1. Handler ordering: runs before logging and WAF
2. Hot path: one shard RLock + one CMS atomic increment vs 6-pass rule evaluation
3. L4 capability: HTTP handlers cannot register as L4 connection handlers
4. Kernel integration: manages nftables/XDP via jail file (policy engine has no such need)
5. Single responsibility: ~1500 lines vs policy engine's 5748 lines

### Why file-based sync, not Unix socket?
Matches existing architecture (policy-rules.json). Battle-tested, debuggable,
survives restarts, works with Docker volumes. 5s sync interval is acceptable —
jail is checked in-memory on hot path, file sync adds entries from wafctl.

### Why add NET_ADMIN/BPF to the Caddy container instead of a sidecar?
One container, one process, zero coordination overhead. The sidecar approach adds
a second container that must read jail.json on a polling interval, introducing
latency between jail → kernel drop. In-process, the plugin writes to the nftables
ipset and BPF map immediately when an IP is jailed — zero delay. The tradeoff
(wider attack surface on the web-facing container) is acceptable because:
- `NET_ADMIN` only grants network config, not filesystem/process control
- `BPF` only grants eBPF program loading, scoped by the kernel verifier
- The container is still `read_only: true`, `no-new-privileges: true`
- `Cleanup()` removes all kernel state on shutdown (no stale rules)

### Why not solve bandwidth saturation?
The router's WAN link is the bottleneck. Even XDP at 10M pps can't help if the
ISP pipe is full. Solutions: ISP null routing, VPS/colo with scrubbing capacity,
or eventually re-adding a CDN (self-hosted or commercial, not necessarily CF).
The plugin protects the **server** (CPU, memory, file descriptors) — the **link**
requires upstream intervention.

### Why `netip.Addr` over `[16]byte`?
Stdlib (Go 1.18+), 24-byte value type, no heap alloc, comparable (map key),
has `Is4()`/`Is6()`/`Prefix()`. Eliminates manual normalization code.

### Why dynamic fingerprint strategies (dosd-inspired)?
A fixed fingerprint `hash(ip, method, path, ua)` fails when attackers randomize
one field. Multiple strategies with automatic selection during spike mode catches
attacks that any single fingerprint would miss.
