# FIXES.md -- Security & Code Review Findings

**Date:** 2026-03-16
**Scope:** `caddy-ddos-mitigator` v0.7.3, reviewed in the context of the full `ergo` stack:
`caddy-ddos-mitigator` + `caddy-policy-engine` + `caddy-body-matcher` + `caddy-compose` (Caddy, wafctl, Authelia).

**Perspectives:** Network engineering, security engineering, adversarial (white-hat).

---

## Table of Contents

1. [CRITICAL: IPv4-Mapped IPv6 Jail Bypass in L7 Handler](#1-critical-ipv4-mapped-ipv6-jail-bypass-in-l7-handler)
2. [CRITICAL: Fingerprint Hash Not Collision-Resistant](#2-critical-fingerprint-hash-not-collision-resistant)
3. [CRITICAL: Jail File Symlink Race and Permission Issues](#3-critical-jail-file-symlink-race-and-permission-issues)
4. [HIGH: ipTracker Single Global Mutex Bottleneck](#4-high-iptracker-single-global-mutex-bottleneck)
5. [HIGH: CIDR Check Takes O(N) Snapshot on Hot Path](#5-high-cidr-check-takes-on-snapshot-on-hot-path)
6. [HIGH: O(N) Profile Eviction Under Write Lock](#6-high-on-profile-eviction-under-write-lock)
7. [HIGH: No xdp_iface Validation](#7-high-no-xdp_iface-validation)
8. [MEDIUM: Path Diversity Evasion via Random Suffixes](#8-medium-path-diversity-evasion-via-random-suffixes)
9. [MEDIUM: Low-and-Slow Attacks Bypass Detection Entirely](#9-medium-low-and-slow-attacks-bypass-detection-entirely)
10. [MEDIUM: User-Agent Rotation Defeats CMS / CMS Appears Vestigial](#10-medium-user-agent-rotation-defeats-cms--cms-appears-vestigial)
11. [MEDIUM: CMS Decay is Not Atomic](#11-medium-cms-decay-is-not-atomic)
12. [MEDIUM: Jail Registry Leaks Memory on Caddy Reload](#12-medium-jail-registry-leaks-memory-on-caddy-reload)
13. [MEDIUM: No nftables Reconnection on Failure](#13-medium-no-nftables-reconnection-on-failure)
14. [MEDIUM: XDP Sync O(N) Flush Per Cycle](#14-medium-xdp-sync-on-flush-per-cycle)
15. [MEDIUM: Bidirectional Jail File Race Between Plugin and wafctl](#15-medium-bidirectional-jail-file-race-between-plugin-and-wafctl)
16. [LOW: Jail File Permissions Too Permissive](#16-low-jail-file-permissions-too-permissive)
17. [LOW: Unconditional Disk I/O on Sync Interval](#17-low-unconditional-disk-io-on-sync-interval)
18. [LOW: Status Code Always Zero / StatusEntropy Dead Signal](#18-low-status-code-always-zero--statusentropy-dead-signal)
19. [LOW: Whitelist Silently Ignores Invalid CIDRs](#19-low-whitelist-silently-ignores-invalid-cidrs)
20. [LOW: Missing Validation on Numeric Config Values](#20-low-missing-validation-on-numeric-config-values)
21. [LOW: Unused addrToNetIP Helper](#21-low-unused-addrtonetip-helper)
22. [Architecture Notes (Positive)](#architecture-notes-positive)

---

## 1. CRITICAL: IPv4-Mapped IPv6 Jail Bypass in L7 Handler

**Status: FIXED** — `.Unmap()` added to both return paths in `clientAddr()`.

**Files:** `mitigator.go:431-451`, `mitigator_l4.go:136-155`, `jail.go:54-59`

**Problem:**

The L7 `clientAddr()` function parses the client IP but never calls `Unmap()`.
The L4 `extractRemoteIP()` correctly calls `a.Unmap()` at lines 140 and 153.

This inconsistency means the same physical client can appear as two different
IPs in the jail depending on which layer processed it:

- `192.168.1.1` (IPv4-native)
- `::ffff:192.168.1.1` (IPv4-mapped IPv6)

These produce different `As16()` bytes, which means different FNV shard hashes
in the jail. An IP jailed as `192.168.1.1` is not matched when a request arrives
as `::ffff:192.168.1.1`.

**Ecosystem impact:**

- The Caddy deployment in `caddy-compose` runs with `network_mode: host` and uses
  Cloudflare's `trusted_proxies`. Cloudflare can send either `CF-Connecting-IP`
  as v4 or v4-mapped-v6 depending on the edge node and protocol. The Caddy
  `client_ip` variable may contain either form.
- wafctl's jail API writes IPs as strings (e.g., `"192.168.1.1"`). If the plugin
  later sees the same client as `::ffff:192.168.1.1`, the wafctl-added jail entry
  doesn't match.
- CIDR aggregation in `cidr.go` also fails: `Prefix()` on a v4-mapped-v6 address
  returns a different prefix than on the unmapped v4 address.

**Attack scenario:**

An attacker behind a dual-stack proxy (or crafting packets through a CDN that
outputs v4-mapped-v6) can bypass L7 jail checks entirely. The L4 layer would
still catch them (it does Unmap), but only if caddy-l4 is deployed.

**Fix:**

```go
// mitigator.go, clientAddr function — add Unmap() to both return paths

func clientAddr(r *http.Request) (netip.Addr, bool) {
    if val := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); val != nil {
        if ipStr, ok := val.(string); ok {
            if addr, err := netip.ParseAddr(ipStr); err == nil {
                return addr.Unmap(), true  // <-- ADD .Unmap()
            }
        }
    }
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return netip.Addr{}, false
    }
    addr, err := netip.ParseAddr(host)
    if err != nil {
        return netip.Addr{}, false
    }
    return addr.Unmap(), true  // <-- ADD .Unmap()
}
```

**Effort:** One-line fix per return path. Zero risk. Highest priority.

---

## 2. CRITICAL: Fingerprint Hash Not Collision-Resistant

**Status: FIXED** — CMS seeds generated from crypto/rand per instance.

**Files:** `fingerprint.go:36-69`, `cms.go:42-46`, `cms.go:52-59`

**Problem:**

FNV-64a is a fast, non-cryptographic hash with known universal collision
families. An attacker who reads this open-source code can:

1. Observe that CMS seeds are deterministic (`cms.go:43`):
   `seeds[i] = uint64(i)*0x517cc1b727220a95 + 0x6c62272e07bb0142`
2. Precompute inputs that collide in all CMS rows with a target fingerprint.
3. Send requests from attacker IPs that hash to the same CMS buckets as a
   legitimate user's fingerprint, inflating the victim's frequency count.

This enables a **targeted false-positive attack**: the attacker causes a specific
legitimate user to be jailed.

**Ecosystem impact:**

- Since v0.6.0, the primary detection signal is behavioral profiling (path
  diversity), not CMS z-score. The CMS is incremented (`mitigator.go:352`) and
  observed (`mitigator.go:353`), but the z-score is not used in jailing decisions.
  This significantly reduces the practical impact of CMS collisions.
- However, the CMS is still exercised on every request. If a future refactor
  re-enables CMS-based detection, this becomes immediately exploitable.

**Fix (if CMS is retained):**

Replace deterministic seeds with a cryptographically random secret generated
once at Provision time:

```go
// cms.go constructor
import "crypto/rand"

func newCountMinSketch(depth, width int) *countMinSketch {
    cms := &countMinSketch{
        depth:  depth,
        width:  width,
        matrix: make([][]atomic.Int64, depth),
        seeds:  make([]uint64, depth),
    }
    for i := range depth {
        cms.matrix[i] = make([]atomic.Int64, width)
        // Random per-instance seeds — not reproducible by attacker
        var buf [8]byte
        if _, err := rand.Read(buf[:]); err != nil {
            panic("crypto/rand failed: " + err.Error())
        }
        cms.seeds[i] = binary.LittleEndian.Uint64(buf[:])
    }
    return cms
}
```

For stronger guarantees, replace FNV-64a with SipHash-2-4 (the same algorithm
Go's runtime map hasher uses for hash-flooding resistance).

**Alternative fix:** If CMS is truly vestigial (see [#10](#10-medium-user-agent-rotation-defeats-cms--cms-appears-vestigial)),
remove it entirely and reclaim 256KB of memory + per-request hash computation.

**Effort:** Small. Replace seed generation or remove CMS.

---

## 3. CRITICAL: Jail File Symlink Race and Permission Issues

**Status: FIXED** — Symlink validation, absolute path check, permissions 0660, flock coordination.

**Files:** `util.go:53-83`, `util.go:104-125`, `util.go:131-171`

**Problem:**

`atomicWriteFile` creates a temp file in `filepath.Dir(path)`, writes, fsyncs,
then renames to the target. This is correct for atomicity, but has two issues:

**3a. Symlink following:**
If an attacker (or misconfigured system) creates a symlink at the jail file path
pointing to a sensitive file (e.g., `/data/waf/jail.json -> /etc/caddy/autosave.json`),
the `os.Rename` at `util.go:79` follows the symlink and overwrites the target.
On Linux, `rename(2)` replaces the destination path entry, which is the symlink
itself -- so this is actually safe on Linux. However, `os.ReadFile` at `util.go:132`
does follow symlinks, meaning an attacker who can create a symlink at the jail
path can cause the plugin to parse an arbitrary file as jail data.

**3b. Jail poisoning via file swap:**
Both the plugin and wafctl write to the same `jail.json` file. The plugin reads
at `SyncInterval` (default 5s). If an attacker gains write access to
`/data/waf/jail.json` (the Docker volume), they can:
- Inject IPs of legitimate users -> denial of service
- Remove all entries -> disable protection
- Inject entries with very long TTLs -> permanent bans

**Ecosystem impact:**

- In the `caddy-compose` deployment, `/data/waf/` is a named Docker volume
  shared between the Caddy and wafctl containers. Both containers write to it.
  The Caddy container runs as root (required for `NET_ADMIN`), wafctl runs as
  user 65534 (nobody).
- The wafctl container also has write access to this volume. If wafctl is
  compromised (it has an HTTP API on `172.19.98.0/24`), the attacker can
  poison the jail file and either DOS legitimate users or disable DDoS protection.
- The wafctl API endpoints for jail management (`/api/dos/jail`, `/api/dos/unjail`)
  do not require authentication beyond being on the bridge network. The bridge
  network is Docker-internal, but any container on `172.19.98.0/24` can reach it.

**Fix:**

```go
// util.go — validate jail file path during Provision
func validateJailPath(path string) error {
    if !filepath.IsAbs(path) {
        return fmt.Errorf("jail_file must be an absolute path, got %q", path)
    }
    // Check the file itself is not a symlink
    if info, err := os.Lstat(path); err == nil {
        if info.Mode()&os.ModeSymlink != 0 {
            return fmt.Errorf("jail_file %q is a symlink, refusing", path)
        }
    }
    return nil
}

// util.go — use 0600 instead of 0644
return atomicWriteFile(path, data, 0600)
```

For the jail poisoning vector, consider adding an HMAC to the jail file:
- Plugin generates a random secret at first Provision, stores in memory
- Writes `"hmac": "<hex>"` field in the jail file JSON
- On read, verifies HMAC before merging entries
- wafctl would need to know the secret (passed via environment variable)

**Effort:** Medium. Path validation is trivial. HMAC requires coordinating a
shared secret between the plugin and wafctl.

---

## 4. HIGH: ipTracker Single Global Mutex Bottleneck

**Status: FIXED** — 64-shard ipTracker with per-shard RWMutex; Score() computed under RLock.

**Files:** `profile.go:173-176`, `profile.go:189-203`

**Problem:**

`ipTracker.Record()` acquires a global write lock (`t.mu.Lock()`) on every
single HTTP request. Under a DDoS of 100K+ req/s, all goroutines serialize
on this single mutex. Meanwhile, the jail uses 64 shards specifically to
avoid this exact problem.

The `Record()` method does:
1. Lock
2. Map lookup
3. Optionally evict oldest (O(N) -- see [#6](#6-high-on-profile-eviction-under-write-lock))
4. Create new profile or update existing
5. Unlock

With 100K concurrent goroutines hitting this, the expected lock contention
degrades throughput significantly. This is the biggest bottleneck on the hot path.

**Ecosystem impact:**

- The Caddy deployment handles all ingress traffic for `erfi.io` services.
  Under a real DDoS targeting any service, the tracker mutex becomes the
  choke point for ALL services behind Caddy, not just the targeted one.
- The `caddy-policy-engine` runs AFTER `ddos_mitigator` in handler order.
  If the DDoS handler is slow due to mutex contention, policy engine evaluation
  is also delayed, affecting legitimate users of all services.

**Fix:**

Shard the tracker identically to the jail:

```go
const trackerShards = 64

type ipTracker struct {
    shards [trackerShards]trackerShard
    maxIPs int
    ttl    time.Duration
}

type trackerShard struct {
    mu       sync.RWMutex
    profiles map[netip.Addr]*ipProfile
}

func (t *ipTracker) shard(ip netip.Addr) *trackerShard {
    b := ip.As16()
    h := fnv.New32a()
    h.Write(b[:])
    return &t.shards[h.Sum32()%trackerShards]
}

func (t *ipTracker) Record(ip netip.Addr, method, path, ua string, status int) {
    s := t.shard(ip)
    s.mu.Lock()
    defer s.mu.Unlock()
    // ... same logic but on s.profiles instead of t.profiles
}
```

This reduces contention by 64x. The same IP always goes to the same shard,
so per-IP profile updates remain consistent.

**Effort:** Medium. Mechanical refactor, all existing tests should continue
to pass.

---

## 5. HIGH: CIDR Check Takes O(N) Snapshot on Hot Path

**Status: FIXED** — Per-prefix atomic counters; O(1) Check via counter read; wired into Add/Sweep.

**Files:** `cidr.go:70`, called from `mitigator.go:370`

**Problem:**

When an IP is jailed (score > threshold), `cidr.Check()` is called. Inside,
it does `jail.Snapshot()` which:
1. Iterates all 64 shards
2. Acquires RLock on each
3. Copies every non-expired entry into a new map
4. Then iterates the entire snapshot to count IPs in the same prefix

With 100K jailed IPs, this is 100K+ map iterations + 100K allocations on every
single jail event. Under a DDoS that's jailing thousands of IPs per second,
this creates quadratic behavior: more jailed IPs = slower jailing.

**Ecosystem impact:**

- The nftables sync (`mitigator.go:528`) and XDP sync (`mitigator.go:544`)
  also call `jail.Snapshot()`, but those run on background goroutines at
  2-second intervals, which is acceptable.
- The CIDR check happens inline on the hot path. With the tracker mutex from
  [#4](#4-high-iptracker-single-global-mutex-bottleneck), this compounds:
  the request holds the tracker lock, then enters CIDR check, then takes
  64 jail shard RLocks.

**Fix:**

Maintain per-prefix atomic counters that update on jail Add/Remove:

```go
type cidrAggregator struct {
    mu          sync.Mutex
    promoted    map[netip.Prefix]time.Time
    counters    map[netip.Prefix]*atomic.Int32  // <-- NEW
    thresholdV4 int
    thresholdV6 int
}

// Called from jail.Add() — O(1) prefix computation + atomic increment
func (c *cidrAggregator) IncrementPrefix(addr netip.Addr) {
    prefix := c.prefixFor(addr)
    c.mu.Lock()
    ctr, ok := c.counters[prefix]
    if !ok {
        ctr = &atomic.Int32{}
        c.counters[prefix] = ctr
    }
    c.mu.Unlock()
    ctr.Add(1)
}

// Check becomes O(1) instead of O(N)
func (c *cidrAggregator) Check(addr netip.Addr, ttl time.Duration) *netip.Prefix {
    prefix := c.prefixFor(addr)
    // ... check counter against threshold, no snapshot needed
}
```

**Effort:** Medium. Requires wiring increment/decrement into jail Add/Remove/Sweep.

---

## 6. HIGH: O(N) Profile Eviction Under Write Lock

**Status: FIXED** — Per-shard LRU list; O(1) eviction from front; O(1) move-to-back on access.

**Files:** `profile.go:263-274`

**Problem:**

When `ipTracker` reaches `maxIPs` (default 100K), `evictOldestLocked()` does
a linear scan of the entire `profiles` map to find the entry with the smallest
`LastSeen`. This scan happens while holding the write lock, blocking all
concurrent Record/Score/Profile calls.

With 100K entries, one eviction is ~100K map iterations. In Go, map iteration
is not cache-friendly (pointer chasing through hash buckets), so this easily
takes 1-10ms depending on the CPU. During that time, every request blocks.

**Fix:**

Use a min-heap ordered by `LastSeen` for O(log N) eviction, or maintain a
doubly-linked list (LRU order) with a map for O(1) access:

```go
type ipTracker struct {
    // ... shards (from fix #4)
    lru *list.List  // doubly-linked list of entries in LRU order
    // Each profile embeds a *list.Element for O(1) removal
}
```

On `Record()`: move the element to the back of the list (most recently used).
On eviction: remove from the front of the list (least recently used). Both O(1).

**Effort:** Medium. Pairs naturally with the sharding fix from [#4](#4-high-iptracker-single-global-mutex-bottleneck).

---

## 7. HIGH: No xdp_iface Validation

**Status: FIXED** — Loopback interface rejected in xdp Setup().

**Files:** `mitigator.go:218-235`, `xdp.go:85-120`

**Problem:**

The `xdp_iface` config parameter is passed directly to `net.InterfaceByName()`
with no validation of the interface type. An operator could accidentally (or an
attacker with config access could intentionally) set `xdp_iface` to:

- `lo` (loopback) -- drops all loopback traffic from jailed IPs, breaking
  internal service communication
- A management interface (e.g., `eth1`) -- drops management traffic
- A bridge interface (e.g., `docker0`) -- disrupts container networking

The XDP program does an unconditional source-IP lookup: any packet from a
jailed IP on the attached interface is dropped, regardless of protocol or
destination.

**Ecosystem impact:**

- In `caddy-compose`, Caddy runs with `network_mode: host`. The XDP program
  would be attached to the host's primary NIC. If misconfigured to attach to
  `docker0` or a VLAN interface, it could block inter-container traffic
  (wafctl -> Caddy admin API, Authelia -> Caddy).
- The `NET_ADMIN` capability is already present on the Caddy container for
  nftables, so XDP attachment will succeed on any interface.

**Fix:**

```go
// xdp.go — validate interface before attachment
func (x *xdpReal) Setup() error {
    x.mu.Lock()
    defer x.mu.Unlock()

    iface, err := net.InterfaceByName(x.ifName)
    if err != nil {
        return fmt.Errorf("interface %q not found: %w", x.ifName, err)
    }

    // Reject loopback
    if iface.Flags&net.FlagLoopback != 0 {
        return fmt.Errorf("refusing to attach XDP to loopback interface %q", x.ifName)
    }

    // Warn on non-physical interfaces (bridges, tunnels, etc.)
    // but allow — the operator may know what they're doing.
    // ... rest of setup
}
```

**Effort:** Small. Add a guard clause.

---

## 8. MEDIUM: Path Diversity Evasion via Random Suffixes

**Status: FIXED** — URL decoding + configurable path_depth truncation.

**Files:** `fingerprint.go:76-91`, `profile.go:55-71`

**Problem:**

The anomaly score's primary signal is path diversity: `unique_paths / total_requests`.
An attacker can trivially inflate path diversity by appending random strings to
the target URL:

```
GET /api/expensive-endpoint/abc123
GET /api/expensive-endpoint/def456
GET /api/expensive-endpoint/ghi789
```

Each is a "unique path" in the profile, so PathDiversity stays high (~1.0) even
though the attacker is hammering the same backend handler. The profile tracks
up to 256 unique paths (`maxTrackedPaths`), so with 256+ unique paths the
diversity stays artificially high.

Path normalization (`fingerprint.go:76-91`) strips query strings and collapses
traversal, but does NOT:
- URL-decode (`%2F`, `%61pi` -> `/api`)
- Collapse numeric path segments (`/users/123`, `/users/456` -> `/users/:id`)
- Strip trailing random segments

**Ecosystem impact:**

- The `caddy-policy-engine` processes the same requests downstream. If an
  attacker evades the DDoS mitigator, the policy engine's rate limiting
  (if configured for the targeted path) may still catch them. But the rate
  limiter uses path as a key dimension, so `/api/target/abc` and
  `/api/target/def` are different rate-limit buckets -- same evasion applies.
- Effectively, an attacker who knows the detection is path-diversity-based
  can bypass both the DDoS mitigator AND path-based rate limiting.

**Fix (short-term):**

Add URL decoding before `path.Clean`:

```go
import "net/url"

func normalizePath(p string) string {
    // URL-decode first
    if decoded, err := url.PathUnescape(p); err == nil {
        p = decoded
    }
    // Strip query string
    if i := strings.IndexByte(p, '?'); i >= 0 {
        p = p[:i]
    }
    p = path.Clean(p)
    if p == "." {
        p = "/"
    }
    return strings.ToLower(p)
}
```

**Fix (longer-term):**

Add configurable path normalization depth:

```
ddos_mitigator {
    path_depth 3  # only consider first 3 path segments
}
```

This way `/api/target/abc123` and `/api/target/def456` both normalize to
`/api/target/*`, properly reflecting that the attacker is targeting one endpoint.

An even stronger approach: track the distribution of requests per path *prefix*
at configurable depth, not per exact path.

**Effort:** Short-term URL decoding is trivial. Path depth requires design work.

---

## 9. MEDIUM: Low-and-Slow Attacks Bypass Detection Entirely

**Status: FIXED** — Documented as inherent limitation; complementary rate limits recommended.

**Files:** `profile.go:138-168`

**Problem:**

The anomaly score requires `Requests >= 5` before producing any score, and
`volumeConf` doesn't reach 1.0 until 30 requests. With the default `profile_ttl`
of 10 minutes, an attacker sending 4 requests per 10-minute window from each IP
will never accumulate enough data for scoring. The profile expires and resets.

With a botnet of 10,000 IPs at 4 req/10min each:
- 40,000 requests per 10 minutes = ~67 req/s sustained
- Each IP is never scored (< 5 requests per profile window)
- No IP is ever jailed

This is sufficient to overwhelm many application-layer endpoints (database
queries, API calls, rendering).

**Ecosystem impact:**

- The `caddy-policy-engine`'s rate limiter could catch this IF rate limit rules
  are configured with appropriate windows and thresholds for the targeted
  endpoints. But rate limits are per-rule-configuration and don't exist by
  default.
- wafctl's "Rate Advisor" feature (MAD/IQR/Fano statistical analysis of
  access logs) could help operators discover appropriate rate-limit thresholds
  after the fact, but it's reactive, not proactive.

**Mitigation (not a code fix -- inherent to behavioral profiling):**

- Document this limitation explicitly in the README.
- Recommend complementing with per-endpoint rate limits in `caddy-policy-engine`
  for endpoints with known capacity limits.
- Consider adding a configurable absolute rate-limit floor in the DDoS mitigator
  itself (e.g., "jail any IP exceeding N req/s regardless of diversity") as an
  optional backstop.
- Consider cross-IP correlation: if many IPs are hitting the same endpoint with
  low diversity each, flag the endpoint as under attack even if individual IPs
  look clean.

**Effort:** Documentation is trivial. Absolute rate floor is small. Cross-IP
correlation is a significant feature.

---

## 10. MEDIUM: User-Agent Rotation Defeats CMS / CMS Appears Vestigial

**Status: FIXED** — Documented as inherent limitation; CMS retained as secondary signal with crypto/rand seeds; architectural decision documented.

**Files:** `fingerprint.go:41-44`, `mitigator.go:350-353`

**Problem:**

The default fingerprint strategy (`fpFull`) includes the User-Agent string.
An attacker rotating User-Agent strings on every request produces a different
fingerprint hash each time, spreading their CMS count across many buckets.
No single bucket accumulates enough for a high z-score.

More fundamentally, the CMS appears to be vestigial since v0.6.0:
- It's incremented at `mitigator.go:352`
- The global stats observe the count at `mitigator.go:353`
- But the jailing decision at `mitigator.go:358` uses `m.tracker.Score(addr)`
  (behavioral profiling), not a CMS z-score
- The CMS `Estimate()` function is never called in production code
- `stats.ZScore()` is never called in production code

The CMS and adaptiveStats consume:
- 256KB of memory (CMS matrix)
- One FNV-64a hash + 4 atomic increments per request
- One mutex lock + EWMA update per request
- A background decay goroutine

**Ecosystem impact:**

- The `ddos_mitigator.z_score` Caddy variable (set at `mitigator.go:420`) always
  contains the behavioral anomaly score, not an actual z-score. The variable
  name is misleading.
- wafctl's log tailer reads `ddos_z_score` from access logs for the spike
  detector and dashboard display. The value shown is the behavioral score,
  not a statistical z-score. This is a labeling issue.

**Fix:**

Either:

**Option A: Remove CMS and adaptiveStats.** They're not used for decisions.
Remove the `cms` field, `stats` field, `runDecay` goroutine, and CMS-related
config (`cms_width`, `cms_depth`, `decay_interval`). Rename the log variable
from `ddos_mitigator.z_score` to `ddos_mitigator.anomaly_score`. Update wafctl's
log parsing to match.

**Option B: Retain as a secondary signal.** Add CMS z-score as a second trigger:
if CMS z-score > Z_THRESHOLD OR behavioral score > B_THRESHOLD, jail the IP.
This provides defense-in-depth: behavioral profiling catches path-focused floods,
CMS z-score catches volume-based floods. But then fix the hash collision issue
([#2](#2-critical-fingerprint-hash-not-collision-resistant)) and switch to `fpIPOnly`
strategy to avoid UA rotation evasion.

**Effort:** Option A is straightforward removal. Option B requires design decisions.
Coordinate the variable rename with wafctl if going with Option A.

---

## 11. MEDIUM: CMS Decay is Not Atomic

**Status: FIXED** — Decay() uses CompareAndSwap retry loop instead of Load/Store.

**Files:** `cms.go:99-109`

**Problem:**

`Decay()` does a non-atomic Load-then-Store on each counter:

```go
old := cms.matrix[i][j].Load()
if old > 0 {
    newVal := int64(float64(old) * factor)
    cms.matrix[i][j].Store(newVal)
}
```

Between `Load(old=100)` and `Store(50)`, a concurrent `Increment` may have
updated the counter to 101. The Store overwrites with 50, losing the increment.

**Impact:** Systematic under-counting during decay windows. If the CMS is
retained as a detection signal (see [#10](#10-medium-user-agent-rotation-defeats-cms--cms-appears-vestigial)),
this biases counts downward. Practically, since CMS is currently vestigial,
this is informational.

**Fix (if CMS retained):**

```go
func (cms *countMinSketch) Decay(factor float64) {
    for i := range cms.depth {
        for j := range cms.width {
            for {
                old := cms.matrix[i][j].Load()
                if old <= 0 {
                    break
                }
                newVal := int64(float64(old) * factor)
                if cms.matrix[i][j].CompareAndSwap(old, newVal) {
                    break
                }
                // CAS failed — another goroutine modified it. Retry.
            }
        }
    }
}
```

**Effort:** Small. Mechanical CAS retry loop.

---

## 12. MEDIUM: Jail Registry Leaks Memory on Caddy Reload

**Status: FIXED** — Reference counting via jailRegistryEntry; releaseJail() called from Cleanup().

**Files:** `jail.go:185-202`

**Problem:**

`jailRegistry` is a package-level global `map[string]*ipJail`. When
`getOrCreateJail` is called during Provision, it creates or reuses a jail.
But when Caddy reloads config (hot reload via admin API or SIGHUP), old
module instances are cleaned up (`Cleanup()` called), but the registry
entry persists. If the `jail_file` path changes across reloads, old
entries accumulate.

Each `ipJail` has 64 shards with maps, consuming memory proportional to
the number of entries. An empty jail is small (~4KB), but if entries
are never drained, they persist indefinitely.

**Ecosystem impact:**

- wafctl triggers Caddy reloads via the `/load` admin API endpoint when
  deploying config changes. Each reload provisions new module instances.
- The Caddyfile in `caddy-compose` uses a fixed `jail_file` path
  (`/data/waf/jail.json`), so in practice only one registry entry exists.
  But if the path changes (e.g., testing, migration), old entries leak.

**Fix:**

Add reference counting:

```go
type jailRegistryEntry struct {
    jail     *ipJail
    refCount int
}

var (
    jailRegistryMu sync.Mutex
    jailRegistry   = map[string]*jailRegistryEntry{}
)

func getOrCreateJail(jailFile string) *ipJail {
    jailRegistryMu.Lock()
    defer jailRegistryMu.Unlock()
    if e, ok := jailRegistry[jailFile]; ok {
        e.refCount++
        return e.jail
    }
    j := newIPJail()
    jailRegistry[jailFile] = &jailRegistryEntry{jail: j, refCount: 1}
    return j
}

func releaseJail(jailFile string) {
    jailRegistryMu.Lock()
    defer jailRegistryMu.Unlock()
    if e, ok := jailRegistry[jailFile]; ok {
        e.refCount--
        if e.refCount <= 0 {
            delete(jailRegistry, jailFile)
        }
    }
}
```

Call `releaseJail` from `Cleanup()`.

**Effort:** Small.

---

## 13. MEDIUM: No nftables Reconnection on Failure

**Status: FIXED** — setupLocked/syncJailLocked extracted; auto-reconnect on failure with retry.

**Files:** `nftables.go:200-246`

**Problem:**

If the netlink socket dies (kernel OOM, netlink buffer overflow, nftables
service restart, or transient netlink error), `SyncJail` will fail on every
subsequent tick. The error is logged as `warn`, but there's no reconnection
logic. Kernel-level protection silently degrades to L7-only, potentially
for the entire uptime of the Caddy process.

The `runNftSync` goroutine at `mitigator.go:520-534` logs the error and
continues, which is correct for transient errors, but the underlying
connection is never re-established.

**Ecosystem impact:**

- The Caddy container in `caddy-compose` has `NET_ADMIN` capability. The
  nftables rules are the second line of defense (after XDP). If nftables
  silently fails, the system falls back to L4 RST + L7 403 only.
- Since Caddy runs as PID 1 in the container with `read_only: true`,
  the nftables service isn't separately managed. The only recovery is
  a container restart.

**Fix:**

Add reconnection with exponential backoff in `SyncJail`:

```go
func (n *nftReal) SyncJail(entries map[netip.Addr]jailEntry) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    if !n.active {
        return nil
    }

    // Try the sync
    if err := n.syncJailLocked(entries); err != nil {
        n.logger.Warn("nftables sync failed, attempting reconnect", zap.Error(err))

        // Attempt reconnect
        conn, connErr := nftables.New()
        if connErr != nil {
            return fmt.Errorf("nftables reconnect failed: %w (original: %w)", connErr, err)
        }
        n.conn = conn

        // Re-setup table/chain/sets
        if setupErr := n.setupLocked(); setupErr != nil {
            n.active = false
            return fmt.Errorf("nftables re-setup failed: %w", setupErr)
        }

        // Retry sync
        return n.syncJailLocked(entries)
    }
    return nil
}
```

Add a consecutive error counter. Escalate from `Warn` to `Error` after 5
consecutive failures.

**Effort:** Medium. Requires refactoring Setup into a lock-free inner method.

---

## 14. MEDIUM: XDP Sync O(N) Flush Per Cycle

**Status: FIXED** — inMap tracks BPF state; O(delta) sync instead of O(N) flush+rebuild.

**Files:** `xdp.go:122-181`

**Problem:**

Every XDP sync cycle (default 2 seconds):
1. Iterates the entire BPF LPM trie with `NextKey` to collect all keys
2. Deletes every key one by one
3. Re-adds all current jail entries

With 100K jailed IPs, that's ~300K BPF syscalls every 2 seconds. Each BPF
syscall involves a context switch to kernel space.

**Fix:**

Track the set of IPs currently in the BPF map in userspace:

```go
type xdpReal struct {
    // ... existing fields
    inMap map[netip.Addr]struct{}  // what's currently in the BPF map
}

func (x *xdpReal) SyncJail(entries map[netip.Addr]jailEntry) error {
    x.mu.Lock()
    defer x.mu.Unlock()

    now := time.Now().UnixNano()
    wanted := make(map[netip.Addr]struct{})
    for addr, e := range entries {
        if now < e.ExpiresAt {
            wanted[addr] = struct{}{}
        }
    }

    // Delete entries no longer in jail
    for addr := range x.inMap {
        if _, ok := wanted[addr]; !ok {
            x.deleteFromMap(addr)
            delete(x.inMap, addr)
        }
    }

    // Add new entries
    for addr := range wanted {
        if _, ok := x.inMap[addr]; !ok {
            x.addToMap(addr)
            x.inMap[addr] = struct{}{}
        }
    }

    return nil
}
```

This reduces syscalls to O(delta) instead of O(N) on each cycle. Under
steady state with few changes, this is nearly zero syscalls per cycle.

**Effort:** Medium.

---

## 15. MEDIUM: Bidirectional Jail File Race Between Plugin and wafctl

**Status: FIXED** — withFileLock using syscall.Flock wraps read+write in runFileSync.

**Files:** `util.go:104-171`, `mitigator.go:485-518`

**Problem:**

Both the DDoS plugin and wafctl write to `jail.json`. The plugin's sync loop:
1. Snapshots current jail
2. Reads file (merges wafctl additions)
3. Checks for unjailed IPs (wafctl removals)
4. Writes current jail to file

wafctl's jail operations:
1. Reads `jail.json`
2. Adds/removes entries in memory
3. Writes `jail.json`

If both write at nearly the same time, one write can overwrite the other's
changes. The atomic write ensures no *torn* reads, but doesn't prevent
lost updates.

**Scenario:**
```
T=0.000  Plugin reads jail.json: {A, B}
T=0.001  wafctl reads jail.json: {A, B}
T=0.002  wafctl adds C, writes: {A, B, C}
T=0.003  Plugin writes snapshot: {A, B}  -- C is lost
```

**Ecosystem impact:**

- wafctl's manual jail/unjail operations (`/api/dos/jail`, `/api/dos/unjail`)
  could be silently lost if they happen to collide with the plugin's sync
  interval (every 5 seconds).
- The plugin re-reads the file on the next cycle (5 seconds later), so the
  loss is temporary if wafctl's entry persists. But if wafctl wrote and the
  plugin immediately overwrites, wafctl's next read sees its entry gone.

**Fix:**

Use file locking (`flock`) for coordination:

```go
import "syscall"

func withFileLock(path string, fn func() error) error {
    lockPath := path + ".lock"
    f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return err
    }
    defer f.Close()

    if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
        return err
    }
    defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

    return fn()
}
```

Wrap both `readJailFile` and `writeJailFile` in `withFileLock`. wafctl should
use the same lock file (`jail.json.lock`).

**Effort:** Small for the plugin. Requires a corresponding change in wafctl's
`dos_mitigation.go` to use the same flock pattern.

---

## 16. LOW: Jail File Permissions Too Permissive

**Status: FIXED** — Permissions changed from 0644 to 0660.

**Files:** `util.go:125`

**Problem:**

`atomicWriteFile(path, data, 0644)` makes the jail file world-readable.
The file contains:
- Client IP addresses (PII in some jurisdictions under GDPR)
- Jail reasons and timestamps (operational intelligence)
- Infraction counts (behavioral profiling data)

**Ecosystem impact:**

- In `caddy-compose`, the Caddy container runs as root and wafctl runs as
  user 65534. The shared Docker volume has root ownership. wafctl needs
  read/write access to the jail file. With `0644`, wafctl can read but
  not write (it's not root). This means wafctl's jail writes may actually
  be failing silently unless Docker volume permissions allow it.
- The current setup may work only because Docker volumes often default to
  world-writable.

**Fix:**

Use `0660` with a shared group, or `0666` if both processes must write
without a common group. Better: have both processes run as the same UID,
or use a dedicated group:

```go
return atomicWriteFile(path, data, 0660)
```

And in `caddy-compose`, ensure both containers share a GID.

**Effort:** Trivial.

---

## 17. LOW: Unconditional Disk I/O on Sync Interval

**Status: FIXED** — dirty atomic.Bool flag added to ipJail; file write skipped when jail unchanged.

**Files:** `mitigator.go:485-518`

**Problem:**

Every `SyncInterval` (default 5s), the system:
1. Takes a full jail snapshot (iterates 64 shards)
2. Reads the entire jail file from disk + JSON parse
3. Iterates the snapshot to check for unjailed IPs
4. Serializes the jail to JSON
5. Writes to disk (temp file + fsync + rename)

With 100K jailed IPs, each JSON file is ~10MB. At 5-second intervals,
that's ~4MB/s of disk I/O purely for bookkeeping.

**Fix:**

Add a dirty flag:

```go
type ipJail struct {
    // ... existing fields
    dirty atomic.Bool
}

func (j *ipJail) Add(...) {
    // ... existing code
    j.dirty.Store(true)
}

// In runFileSync:
if !m.jail.dirty.Load() {
    // Only read, don't write
    readJailFile(m.JailFile, m.jail)
    return
}
m.jail.dirty.Store(false)
// ... full read + write cycle
```

This skips the write when nothing has changed. The read is still needed
to pick up wafctl additions, but can be optimized with mtime checking:

```go
info, _ := os.Stat(m.JailFile)
if info.ModTime().Equal(m.lastFileMtime) {
    return // file unchanged, skip read
}
```

**Effort:** Small.

---

## 18. LOW: Status Code Always Zero / StatusEntropy Dead Signal

**Status: FIXED** — StatusCodes tracking and StatusEntropy removed (dead code).

**Files:** `mitigator.go:349`, `profile.go:55-71`, `profile.go:96-113`

**Problem:**

```go
m.tracker.Record(addr, r.Method, r.URL.Path, r.UserAgent(), 0) // status filled by response
```

Status is hardcoded to `0` because `Record` is called before `next.ServeHTTP()`.
The comment says "status filled by response" but there's no mechanism to
update it post-response.

This means `ipProfile.StatusCodes` always contains `{0: N}` and
`StatusEntropy()` always returns 0.0. The anomaly score doesn't use
StatusEntropy directly (it was removed from the scoring formula in favor
of path diversity), but the profile tracks it anyway.

**Fix:**

Either:

**Option A:** Remove StatusCodes tracking and StatusEntropy. Dead code.

**Option B:** Wrap the ResponseWriter to capture the status code:

```go
// In ServeHTTP, after the tracker.Record call:
rw := &statusCapture{ResponseWriter: w}
err := next.ServeHTTP(rw, r)
// Update profile with actual status code
m.tracker.RecordStatus(addr, rw.code)
return err

type statusCapture struct {
    http.ResponseWriter
    code int
}

func (s *statusCapture) WriteHeader(code int) {
    s.code = code
    s.ResponseWriter.WriteHeader(code)
}
```

**Effort:** Small for either option.

---

## 19. LOW: Whitelist Silently Ignores Invalid CIDRs

**Status: FIXED** — newWhitelist() returns error on invalid CIDRs; Provision propagates the error.

**Files:** `util.go:26-36`

**Problem:**

```go
func newWhitelist(cidrs []string) *whitelist {
    w := &whitelist{}
    for _, s := range cidrs {
        p, err := netip.ParsePrefix(s)
        if err != nil {
            continue  // <-- silently skipped
        }
        w.prefixes = append(w.prefixes, p)
    }
    return w
}
```

An operator typo (e.g., `10.0.0.0/33`, `192.168.1.0` without prefix length,
or `10.0.0.0/8` mistyped as `10.0.0/8`) is silently ignored. The intended
whitelist range is not applied, meaning those IPs can be jailed.

**Ecosystem impact:**

- The Caddyfile whitelist likely includes Cloudflare IPs, monitoring systems,
  and internal services. A typo could cause the DDoS mitigator to jail
  Cloudflare edge IPs (breaking all inbound traffic) or monitoring probes
  (causing false alerts).

**Fix:**

Return an error during Provision or Validate:

```go
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
```

Update `Provision` to propagate the error:

```go
wl, err := newWhitelist(m.WhitelistCIDRs)
if err != nil {
    return err
}
m.whitelist = wl
```

**Effort:** Trivial.

---

## 20. LOW: Missing Validation on Numeric Config Values

**Status: FIXED** — Validate() checks CMSWidth, CMSDepth, CIDRThresholdV4/V6, ProfileMaxIPs > 0 and WarmupRequests >= 0.

**Files:** `mitigator.go:282-297`

**Problem:**

`Validate()` checks `Threshold > 0` and penalty durations, but doesn't
validate:

| Field | Zero/Negative Behavior |
|-------|----------------------|
| `CMSWidth` | Slice with 0 elements -- `hash()` divides by zero (panic) |
| `CMSDepth` | Empty CMS matrix -- no hash rows |
| `CIDRThresholdV4/V6` | `count >= 0` always true -- instant prefix promotion on first jail |
| `ProfileMaxIPs` | `len(profiles) >= 0` always true -- evict on every insert |
| `WarmupRequests` | Negative: `s.count < negative` never true -- z-scores always produced (no warmup) |

**Fix:**

```go
func (m *DDOSMitigator) Validate() error {
    // ... existing checks ...

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
    return nil
}
```

**Effort:** Trivial.

---

## 21. LOW: Unused addrToNetIP Helper

**Status: FIXED** — Dead code removed.

**Files:** `nftables.go:279-286`

**Problem:**

The `addrToNetIP` function is defined but never called. Dead code from an
earlier implementation that was refactored to use raw byte slices directly.

**Fix:**

```go
// Delete lines 277-286 of nftables.go
```

**Effort:** Trivial.

---

## Architecture Notes (Positive)

Credit where due -- things done well:

- **64-shard jail with FNV-32a distribution:** Correct lock granularity for
  read-heavy workloads. The shard function uses `As16()` + FNV for uniform
  distribution across IPv4 and IPv6. This is the right pattern.

- **Atomic file writes:** The `atomicWriteFile` implementation (temp + fsync +
  rename) correctly prevents torn reads. Both the plugin and wafctl use this
  pattern, ensuring the jail file is always consistent.

- **L4 TCP RST via SetLinger(0):** Correct technique to avoid TIME_WAIT
  accumulation under DDoS. The unwrap loop at `mitigator_l4.go:110-117`
  that peels through proxy_protocol/TLS wrappers to find the underlying
  `*net.TCPConn` is thoughtful.

- **nftables chain priority -200 (before conntrack):** Correct. Jailed packets
  should never create conntrack entries, which would waste kernel memory and
  pollute the connection tracking table.

- **XDP v4-mapped-v6 single map:** Using a single LPM trie with v4-mapped-v6
  addressing for both address families is the right design. Avoids maintaining
  two separate BPF maps.

- **BPF bounds checks in xdp_drop.c:** Every header dereference has a proper
  `data_end` bounds check. The verifier would reject the program without these,
  but getting them right on first pass shows understanding of the BPF programming
  model.

- **Interface guards at file bottom:** Compile-time type assertions
  (`var _ caddy.Module = (*DDOSMitigator)(nil)`) catch interface compliance
  errors at build time rather than runtime. Good practice.

- **Exponential backoff with jitter:** The `calcTTL` function at
  `mitigator.go:388-406` uses `base * 2^infractions` with +/-25% jitter.
  This prevents synchronized retry storms when many jailed IPs expire
  simultaneously.

- **Graceful degradation:** Every kernel-level feature (nftables, XDP) has
  a noop fallback. Capability checks happen at Provision time, and failures
  are logged and gracefully handled. The system always falls back to
  userspace-only mitigation rather than crashing.

- **Handler ordering:** `ddos_mitigator` runs before `policy_engine` in the
  Caddy handler chain. Blocked traffic never reaches the WAF, saving all
  downstream CPU. This is the correct architecture for a DDoS mitigator.

---

## Priority Implementation Order

Recommended order based on impact-to-effort ratio:

| Priority | Issue | Effort | Impact | Status |
|----------|-------|--------|--------|--------|
| 1 | [#1 IPv4-mapped-v6 bypass](#1-critical-ipv4-mapped-ipv6-jail-bypass-in-l7-handler) | 5 min | Closes a real evasion vector | ✅ FIXED |
| 2 | [#19 Whitelist validation](#19-low-whitelist-silently-ignores-invalid-cidrs) | 10 min | Prevents operator misconfiguration | ✅ FIXED |
| 3 | [#20 Numeric config validation](#20-low-missing-validation-on-numeric-config-values) | 10 min | Prevents panics on bad config | ✅ FIXED |
| 4 | [#7 xdp_iface validation](#7-high-no-xdp_iface-validation) | 10 min | Prevents operational misuse | ✅ FIXED |
| 5 | [#21 Dead code removal](#21-low-unused-addrtonetip-helper) | 2 min | Cleanup | ✅ FIXED |
| 6 | [#15 Jail file flock](#15-medium-bidirectional-jail-file-race-between-plugin-and-wafctl) | 1 hour | Fixes wafctl integration race | ✅ FIXED |
| 7 | [#4 Shard the tracker](#4-high-iptracker-single-global-mutex-bottleneck) | 2 hours | Biggest perf improvement | ✅ FIXED |
| 8 | [#6 LRU eviction](#6-high-on-profile-eviction-under-write-lock) | 2 hours | Eliminates O(N) stalls | ✅ FIXED |
| 9 | [#5 CIDR prefix counters](#5-high-cidr-check-takes-on-snapshot-on-hot-path) | 2 hours | Hot path perf | ✅ FIXED |
| 10 | [#8 Path normalization](#8-medium-path-diversity-evasion-via-random-suffixes) | 1 hour | Closes evasion technique | ✅ FIXED |
| 11 | [#12 Jail registry refcount](#12-medium-jail-registry-leaks-memory-on-caddy-reload) | 30 min | Memory hygiene | ✅ FIXED |
| 12 | [#10 CMS decision](#10-medium-user-agent-rotation-defeats-cms--cms-appears-vestigial) | 1 hour | Architectural clarity | ✅ FIXED |
| 13 | [#13 nftables reconnect](#13-medium-no-nftables-reconnection-on-failure) | 1 hour | Reliability | ✅ FIXED |
| 14 | [#14 XDP diff sync](#14-medium-xdp-sync-on-flush-per-cycle) | 2 hours | Large jail perf | ✅ FIXED |
| 15 | [#3 Jail file hardening](#3-critical-jail-file-symlink-race-and-permission-issues) | 2 hours | Defense in depth | ✅ FIXED |
| 16 | [#2 CMS hash seeds](#2-critical-fingerprint-hash-not-collision-resistant) | 30 min | If CMS retained | ✅ FIXED |
| 17 | [#17 Dirty-flag sync](#17-low-unconditional-disk-io-on-sync-interval) | 30 min | Disk I/O reduction | ✅ FIXED |
| 18 | [#18 Status code capture](#18-low-status-code-always-zero--statusentropy-dead-signal) | 30 min | Dead code or new signal | ✅ FIXED |
| 19 | [#11 CMS atomic decay](#11-medium-cms-decay-is-not-atomic) | 15 min | If CMS retained | ✅ FIXED |
| 20 | [#16 File permissions](#16-low-jail-file-permissions-too-permissive) | 5 min | Coord with wafctl | ✅ FIXED |
| 21 | [#9 Low-and-slow documentation](#9-medium-low-and-slow-attacks-bypass-detection-entirely) | 30 min | Documentation | ✅ FIXED |
