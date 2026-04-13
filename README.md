# caddy-ddos-mitigator

Adaptive DDoS/DoS mitigation plugin for [Caddy](https://caddyserver.com/). Behavioral IP profiling with multi-layer enforcement: L7 HTTP block, L4 TCP RST, kernel nftables drop, and eBPF/XDP NIC-level drop.

## How It Works

Three-layer detection architecture (v0.17.0+) eliminates false positives from legitimate
multi-service clients while catching floods:

**Layer 1 — Global rate gate:** Per-IP sustained req/s across ALL services (60s sliding window
via ring buffer). Catches server-saturating floods regardless of path diversity. Configurable
threshold; 0 = disabled. Uses `hostTracker.GlobalRecentRate()`.

**Layer 2 — Per-service behavioral profiling:** Tracker keyed on `(IP, host)` so each service
gets its own profile. Path diversity scoring detects targeted low-rate attacks that don't
trigger L1. A flood on one service does not inflate another service's score.

**Layer 3 — Host diversity exculpation:** Global per-IP host count. At jail-decision time:
`effectiveScore = rawScore / log2(uniqueHosts + 1)`. A real user hitting 8 services gets
3.17× score reduction; a DDoS targeting 1 service gets none.

**Detection signals (L2):**
- **Path diversity** — unique paths / total requests per (IP, host). Users browse many pages; bots hammer one.
- **Volume confidence** — low request counts are dampened (not enough data to judge).
- **Rate amplification** — high 60s-window req/s with low diversity is more suspicious than slow monotone traffic.

**Enforcement layers (fastest to slowest):**

| Layer | Mechanism | Throughput | Config |
|-------|-----------|-----------|--------|
| eBPF/XDP | `XDP_DROP` at NIC driver | ~10M pps | `xdp_drop`, `xdp_iface` |
| nftables | Kernel ipset drop | ~1.5M pps | `kernel_drop` |
| L4 TCP | `SetLinger(0)` → RST | ~100K conn/s | L4 handler (caddy-l4) |
| L7 HTTP | 403 Forbidden | ~50K req/s | L7 handler (default) |

All layers share the same IP jail. When a request triggers the behavioral threshold, the IP is jailed and immediately blocked at all active layers.

## Installation

```bash
xcaddy build \
    --with github.com/erfianugrah/caddy-ddos-mitigator@latest \
    --with github.com/mholt/caddy-l4  # optional, for L4 TCP RST
```

## Caddyfile

```caddyfile
{
    order ddos_mitigator first
}

example.com {
    ddos_mitigator {
        # Core detection
        jail_file         /data/waf/jail.json
        threshold         0.65          # L2 behavioral anomaly score (0.0–1.0)
        base_penalty      60s           # first offense jail duration
        max_penalty       24h           # cap for exponential backoff
        warmup_requests   1000          # min observations before adaptive stats activate

        # Three-layer detection (v0.17.0+)
        global_rate_threshold 0         # L1: sustained req/s to jail (0=disabled)
        min_host_exculpation  2         # L3: unique hosts needed for dampening

        # Behavioral profiling
        profile_ttl       10m           # how long per-(IP,host) profiles are retained
        profile_max_ips   100000        # max tracked (IP,host) pairs (LRU eviction)

        # CIDR aggregation
        cidr_threshold_v4 5             # jail /24 when 5+ IPs from same subnet
        cidr_threshold_v6 5             # jail /64 when 5+ IPv6 from same prefix

        # Count-Min Sketch (fingerprint frequency tracking)
        cms_width         8192          # matrix width (memory: depth × width × 8 bytes)
        cms_depth         4             # hash functions (higher = fewer collisions)

        # Background intervals
        sweep_interval    10s           # expired jail entry cleanup
        decay_interval    30s           # CMS counter halving
        sync_interval     5s            # jail file read/write with wafctl

        # Kernel-level drop (requires NET_ADMIN capability)
        kernel_drop       true
        nft_sync_interval 2s

        # eBPF/XDP (requires BPF + NET_ADMIN capabilities)
        # xdp_drop        true
        # xdp_iface       eth0
        # xdp_sync_interval 2s

        # Whitelist (never jail these CIDRs)
        whitelist         192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 127.0.0.0/8 ::1/128
    }

    reverse_proxy upstream:8080
}
```

## JSON Configuration

All Caddyfile directives map to JSON fields on the `http.handlers.ddos_mitigator` module:

```json
{
    "handler": "ddos_mitigator",
    "jail_file": "/data/waf/jail.json",
    "threshold": 0.65,
    "base_penalty": "60s",
    "max_penalty": "24h",
    "warmup_requests": 1000,
    "global_rate_threshold": 0,
    "min_host_exculpation": 2,
    "profile_ttl": "10m",
    "profile_max_ips": 100000,
    "cidr_threshold_v4": 5,
    "cidr_threshold_v6": 5,
    "cms_width": 8192,
    "cms_depth": 4,
    "sweep_interval": "10s",
    "decay_interval": "30s",
    "sync_interval": "5s",
    "kernel_drop": true,
    "nft_sync_interval": "2s",
    "whitelist": ["192.168.0.0/16", "10.0.0.0/8"]
}
```

## L4 Handler (TCP RST)

Requires [caddy-l4](https://github.com/mholt/caddy-l4). Drops jailed IPs at the TCP level before TLS handshake, via `SetLinger(0)` which sends a RST and bypasses TIME_WAIT state accumulation.

```json
{
    "apps": {
        "layer4": {
            "servers": {
                "tcp_guard": {
                    "listen": [":443"],
                    "routes": [{
                        "handle": [
                            {"handler": "ddos_mitigator", "jail_file": "/data/waf/jail.json"},
                            {"handler": "tls"},
                            {"handler": "proxy", "upstreams": [{"dial": ["127.0.0.1:8443"]}]}
                        ]
                    }]
                }
            }
        }
    }
}
```

The L4 and L7 modules share the same jail via a package-level registry keyed by `jail_file` path.

## Architecture

```
                   ┌─────────────────────────────────────────────────┐
                   │             caddy-ddos-mitigator                │
 TCP connection ──►│                                                 │
                   │  eBPF/XDP: BPF map lookup → XDP_DROP            │
                   │  nftables: ipset lookup → kernel drop           │
                   │  L4 handler: jail check → SetLinger(0) + RST    │
                    │  L7 handler:                                    │
                    │    ├─ whitelist? → pass                         │
                    │    ├─ jailed or CIDR promoted? → 403            │
                    │    ├─ hosts.Record(ip, host) → uniqueHosts      │
                    │    ├─ hosts.GlobalRecentRate(ip) → globalRate    │
                    │    ├─ L1: globalRate > threshold? → jail (rate)  │
                    │    ├─ L2: tracker.RecordAndScore(ip, host, ...) │
                    │    ├─ L3: score / log2(uniqueHosts+1)           │
                    │    ├─ effectiveScore > threshold? → jail (behav) │
                    │    └─ pass → next handler (WAF, proxy)          │
                   └─────────────────────────────────────────────────┘
                              │
                   jail.json  │  Caddy log fields
                   (file)     │  (ddos_action, ddos_fingerprint, ...)
                              ▼
                          wafctl sidecar
                   (spike detection, forensics, dashboard, jail API)
```

## Behavioral Scoring

The `AnomalyScore(uniqueHosts, recentRate)` function computes a 0.0–1.0 score per (IP, host):

| Scenario | Path Div | Volume | Hosts | Raw Score | Effective |
|----------|----------|--------|-------|-----------|-----------|
| Normal browsing (16 pages) | 1.00 | 16 | 1 | 0.00 | 0.00 |
| Power user (200 reqs, 20 pages) | 0.10 | 200 | 1 | 0.00 | 0.00 |
| Crawler (100 unique pages) | 1.00 | 100 | 1 | 0.00 | 0.00 |
| Slow flood (50 reqs, 1 page) | 0.02 | 50 | 1 | 0.20 | 0.20 |
| Flood (500 reqs, 1 page) | 0.002 | 500 | 1 | 0.85 | 0.85 |
| Composer SSE (8k reqs, 22 paths) | 0.003 | 8101 | 8 | 1.00 | **0.32** |
| DDoS targeting 1 service | 0.002 | 500 | 1 | 0.85 | 0.85 |

Scoring uses exponential decay on path diversity (`exp(-pathDiv × 80)`) modulated by volume confidence, rate amplification (60s sliding window), and L3 host diversity dampening (`/ log2(uniqueHosts + 1)`). The Composer SSE scenario shows how a legitimate multi-service client with bot-like per-service patterns is exculpated by L3.

## Penalty Escalation

Jailed IPs receive exponential backoff with ±25% jitter:

```
TTL = base_penalty × 2^infractions + random_jitter
```

| Infraction | Base=60s | TTL (± jitter) |
|------------|----------|----------------|
| 0 | 60s × 2⁰ | 60s ± 15s |
| 1 | 60s × 2¹ | 2m ± 30s |
| 3 | 60s × 2³ | 8m ± 2m |
| 5 | 60s × 2⁵ | 32m ± 8m |
| 10+ | capped | 24h ± 6h |

Jitter prevents synchronized retry storms when a botnet emerges from jail simultaneously.

## CIDR Aggregation

When `cidr_threshold_v4` (default 5) IPs from the same /24 subnet are jailed, the entire /24 prefix is promoted. Any subsequent connection from that prefix is instantly blocked without per-IP lookup. Same logic for IPv6 /64 prefixes.

## Log Fields

The L7 handler sets Caddy variables consumable by `log_append`:

```caddyfile
log_append ddos_action      {http.vars.ddos_mitigator.action}
log_append ddos_fingerprint  {http.vars.ddos_mitigator.fingerprint}
log_append ddos_z_score      {http.vars.ddos_mitigator.z_score}
log_append ddos_spike_mode   {http.vars.ddos_mitigator.spike_mode}
```

| Field | Values | Description |
|-------|--------|-------------|
| `ddos_action` | `pass`, `blocked`, `jailed` | What the mitigator decided. Jail reason in jail.json: `auto:rate` (L1) or `auto:behavioral` (L2) |
| `ddos_fingerprint` | hex string | FNV-64a hash of request signature |
| `ddos_z_score` | float | Behavioral anomaly score (0.0-1.0, not a statistical z-score; name kept for backward compatibility) |
| `ddos_spike_mode` | `true`/`false` | Whether EWMA spike detection is active |

## Jail File Format

Shared bidirectionally with [wafctl](https://github.com/erfianugrah/caddy-compose) sidecar:

```json
{
    "version": 1,
    "entries": {
        "198.51.100.1": {
            "expires_at": "2026-03-16T12:00:00Z",
            "infractions": 3,
            "reason": "auto:behavioral",
            "jailed_at": "2026-03-16T11:00:00Z"
        }
    },
    "updated_at": "2026-03-16T11:00:05Z"
}
```

## Container Capabilities

| Feature | Required Cap | Docker Compose |
|---------|-------------|----------------|
| L7 + L4 (default) | `NET_BIND_SERVICE` | Already present |
| nftables kernel drop | `NET_ADMIN` | `cap_add: [NET_ADMIN]` |
| eBPF/XDP | `BPF`, `NET_ADMIN` | `cap_add: [BPF, NET_ADMIN]` |

## Performance

Benchmarks on AMD Ryzen 7 7800X3D (single-threaded, zero allocation):

| Operation | Time | Allocs |
|-----------|------|--------|
| Jail IsJailed | 9 ns/op | 0 B/op |
| CMS Increment | 8 ns/op | 0 B/op |
| Fingerprint (full) | 70 ns/op | 0 B/op |
| ExtractRemoteIP | 2.5 ns/op | 0 B/op |

Total hot path (whitelist + jail + profile + CMS): ~90 ns per request with zero GC pressure.

## Testing

```bash
# Unit tests
go test -count=1 -timeout 60s ./...

# Benchmarks
go test -bench=. -benchmem ./...

# Regenerate eBPF bytecode (requires clang + kernel headers)
go generate ./...
```

## File Structure

| File | Lines | Purpose |
|------|-------|---------|
| `mitigator.go` | 1021 | L7 handler, 3-layer detection, Caddy lifecycle, Caddyfile parsing |
| `nftables.go` | 434 | Kernel ipset management via google/nftables |
| `jail.go` | 347 | 64-shard concurrent map, TTL, sweep, registry |
| `util.go` | 338 | Whitelist, atomicWriteFile, jail file I/O |
| `profile.go` | 688 | Per-(IP,host) profiling, hostTracker (L3), anomaly scoring, ring buffer rate |
| `xdp.go` | 292 | eBPF/XDP loader via cilium/ebpf |
| `cidr.go` | 205 | CIDR prefix aggregation |
| `mitigator_l4.go` | 204 | L4 TCP RST handler, forceDrop |
| `stats.go` | 190 | Welford + dual EWMA, spike detection |
| `xdpdrop_x86_bpfel.go` | 143 | Generated eBPF Go bindings |
| `cms.go` | 120 | Count-Min Sketch, atomic, decay |
| `fingerprint.go` | 107 | 5 strategies, path normalization |
| `bpf/xdp_drop.c` | 106 | XDP eBPF C program |

## Security

v0.8.2 includes a comprehensive security audit (March 2026) with 21 fixes:
- IPv4-mapped IPv6 jail bypass fixed (Unmap on all paths)
- 64-shard IP tracker with per-shard LRU eviction (O(1) instead of O(N))
- CIDR prefix counters (O(1) check instead of O(N) snapshot)
- CMS seeds from crypto/rand (not deterministic)
- Jail file: symlink validation, absolute path check, flock coordination
- XDP: loopback interface rejection, diff-based sync (O(delta) not O(N))
- nftables: auto-reconnection on failure
- Path normalization: URL decode + configurable depth truncation
- Whitelist validation rejects invalid CIDRs at Provision time
- Numeric config validation prevents panics on bad values
- Proper error pages via caddyhttp.Error (not bare WriteHeader)

## License

[MIT](LICENSE)
