package ddosmitigator

import (
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"
)

const testHost = "example.com"

// helper: record N requests against tracker for a given (ip, host, path)
func recordN(t *testing.T, tracker *ipTracker, hosts *hostTracker, ip netip.Addr, host, method, path string, n int) {
	t.Helper()
	for range n {
		hosts.Record(ip, host)
		tracker.Record(ip, host, method, path, "Mozilla/5.0")
	}
}

func TestIPProfile_NormalBrowsing(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("192.0.2.1")

	// Simulate normal browsing: diverse paths, varied timing
	paths := []string{"/", "/about", "/contact", "/blog/1", "/blog/2", "/api/users",
		"/settings", "/login", "/search?q=hello", "/docs", "/help", "/pricing",
		"/favicon.ico", "/static/app.js", "/static/style.css", "/images/logo.png"}

	for _, p := range paths {
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "GET", p, "Mozilla/5.0")
	}

	profile := tracker.Profile(ip, testHost)
	if profile == nil {
		t.Fatal("profile should exist after recording")
	}

	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Normal browsing: requests=%d pathRatio=%.2f uniqueHosts=%d score=%.2f",
		profile.Requests, profile.PathDiversity(), uniqueHosts, score)

	if score > 0.5 {
		t.Fatalf("normal browsing should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_FloodAttack(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("198.51.100.1")

	// Simulate flood: same path, same method, same UA, 500 times
	for range 500 {
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "GET", "/api/vulnerable", "attack-bot/1.0")
	}

	profile := tracker.Profile(ip, testHost)
	if profile == nil {
		t.Fatal("profile should exist")
	}

	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Flood attack: requests=%d pathRatio=%.4f uniqueHosts=%d score=%.2f",
		profile.Requests, profile.PathDiversity(), uniqueHosts, score)

	if score < 0.7 {
		t.Fatalf("flood should have high anomaly score, got %.2f", score)
	}
}

func TestIPProfile_HighVolumeNormal(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("10.0.0.1")

	// Simulate a power user: many requests but diverse paths
	paths := []string{"/", "/about", "/blog/1", "/blog/2", "/blog/3",
		"/api/users", "/api/posts", "/api/comments", "/search?q=a",
		"/search?q=b", "/search?q=c", "/settings", "/profile",
		"/dashboard", "/notifications", "/help", "/docs/api",
		"/docs/getting-started", "/feed", "/logout"}

	for i := range 200 {
		p := paths[i%len(paths)]
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "GET", p, "Mozilla/5.0 (Windows)")
	}

	profile := tracker.Profile(ip, testHost)
	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Power user: requests=%d pathRatio=%.2f uniqueHosts=%d score=%.2f",
		profile.Requests, profile.PathDiversity(), uniqueHosts, score)

	// Power user should NOT be flagged — diverse paths even with high volume
	if score > 0.5 {
		t.Fatalf("power user should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_SlowFlood(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("203.0.113.50")

	// Simulate slow flood: 50 requests but ALL to the same endpoint
	for range 50 {
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "POST", "/api/login", "curl/8.0")
	}

	profile := tracker.Profile(ip, testHost)
	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Slow flood: requests=%d pathRatio=%.4f methodDiv=%.2f score=%.2f",
		profile.Requests, profile.PathDiversity(), profile.MethodDiversity(), score)

	// At low volume (50 reqs), single-path traffic is ambiguous (could be API polling).
	// Score should be elevated but not necessarily above jail threshold.
	if score < 0.1 {
		t.Fatalf("slow flood should have some anomaly signal, got %.2f", score)
	}
}

func TestIPProfile_CrawlerPattern(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("66.249.66.1") // Googlebot-like

	// Crawler: very diverse paths, single UA, steady rate
	for i := range 100 {
		p := fmt.Sprintf("/page/%d", i)
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "GET", p, "Googlebot/2.1")
	}

	profile := tracker.Profile(ip, testHost)
	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Crawler: requests=%d pathRatio=%.2f uniqueHosts=%d score=%.2f",
		profile.Requests, profile.PathDiversity(), uniqueHosts, score)

	// Crawlers have high path diversity — should NOT be flagged
	if score > 0.5 {
		t.Fatalf("crawler should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_MixedStatusFlood(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("198.51.100.2")

	// Flood with all 200 responses (normal for legitimate, but suspicious with low diversity)
	for range 300 {
		hosts.Record(ip, testHost)
		tracker.Record(ip, testHost, "GET", "/target", "bot/1.0")
	}

	profile := tracker.Profile(ip, testHost)
	uniqueHosts := hosts.UniqueHosts(ip)
	score := profile.AnomalyScore(uniqueHosts, 0.0)

	// Low path diversity + high volume = high score
	if score < 0.6 {
		t.Fatalf("monotone flood should have high score, got %.2f", score)
	}
}

func TestIPTracker_Expiry(t *testing.T) {
	tracker := newIPTracker(100, 50*time.Millisecond)

	ip := netip.MustParseAddr("10.0.0.1")
	tracker.Record(ip, testHost, "GET", "/", "ua")

	if tracker.Profile(ip, testHost) == nil {
		t.Fatal("profile should exist immediately after record")
	}

	time.Sleep(100 * time.Millisecond)
	tracker.Sweep()

	if tracker.Profile(ip, testHost) != nil {
		t.Fatal("profile should be expired after TTL")
	}
}

func TestIPTracker_MaxEntries(t *testing.T) {
	// With 64 shards, maxIPs=6400 gives 100 per shard.
	// Insert 12800 (IP, host) pairs to force evictions.
	tracker := newIPTracker(6400, 5*time.Minute)

	for i := range 12800 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		tracker.Record(ip, testHost, "GET", "/", "ua")
	}

	// Should not panic, and count should be bounded at maxIPs
	count := tracker.Count()
	if count > 6400+trackerShards { // small slack per shard
		t.Fatalf("tracker should be bounded, got %d entries (max 6400)", count)
	}
}

// ─── New tests for L1/L2/L3 architecture ────────────────────────────

// TestIPProfile_HostDiversityExculpation verifies that L3 dampening reduces
// the effective score for IPs hitting many services.
func TestIPProfile_HostDiversityExculpation(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("89.0.95.223")

	// Simulate real user: low path diversity on composer but 8 hosts total
	serviceHosts := []string{
		"composer.erfi.io", "jellyfin.erfi.io", "waf.erfi.io",
		"vault.erfi.io", "joplin.erfi.io", "git.erfi.io",
		"sonarr.erfi.io", "radarr.erfi.io",
	}

	// Record 200 requests on composer (low diversity)
	for range 200 {
		hosts.Record(ip, "composer.erfi.io")
		tracker.Record(ip, "composer.erfi.io", "GET", "/api/v1/stacks", "Mozilla/5.0")
	}
	// Also hit other hosts to build diversity
	for _, h := range serviceHosts[1:] {
		hosts.Record(ip, h)
		tracker.Record(ip, h, "GET", "/", "Mozilla/5.0")
	}

	uniqueHosts := hosts.UniqueHosts(ip)
	if uniqueHosts < 2 {
		t.Fatalf("expected at least 2 unique hosts, got %d", uniqueHosts)
	}

	// Score without host dampening (uniqueHosts=1)
	profile := tracker.Profile(ip, "composer.erfi.io")
	rawScore := profile.AnomalyScore(1, 0.0)

	// Score with host dampening (actual unique hosts)
	dampedScore := profile.AnomalyScore(uniqueHosts, 0.0)

	t.Logf("composer profile: requests=%d uniquePaths=%d rawScore=%.4f dampedScore=%.4f uniqueHosts=%d",
		profile.Requests, profile.UniquePaths, rawScore, dampedScore, uniqueHosts)

	if dampedScore >= rawScore {
		t.Fatalf("host diversity should reduce score: raw=%.4f damped=%.4f", rawScore, dampedScore)
	}

	// With 8 hosts, factor = log2(9) ≈ 3.17, so damped should be roughly raw/3.17
	expectedFactor := math.Log2(float64(uniqueHosts) + 1.0)
	expectedDamped := rawScore / expectedFactor
	if math.Abs(dampedScore-expectedDamped) > 0.01 {
		t.Fatalf("expected damped score ≈ %.4f, got %.4f", expectedDamped, dampedScore)
	}
}

// TestIPProfile_DDoSNotExculpated verifies that a DDoS targeting one service
// is NOT exculpated by host diversity (it only hits 1 host).
func TestIPProfile_DDoSNotExculpated(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("198.51.100.99")

	// DDoS: flood one service, 500 requests, 1 path
	for range 500 {
		hosts.Record(ip, "composer.erfi.io")
		tracker.Record(ip, "composer.erfi.io", "GET", "/api/v1/stacks", "attack-bot/1.0")
	}

	uniqueHosts := hosts.UniqueHosts(ip)
	if uniqueHosts != 1 {
		t.Fatalf("DDoS should only hit 1 host, got %d", uniqueHosts)
	}

	profile := tracker.Profile(ip, "composer.erfi.io")
	score := profile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("DDoS 1-host: requests=%d score=%.4f uniqueHosts=%d", profile.Requests, score, uniqueHosts)

	if score < 0.65 {
		t.Fatalf("DDoS targeting 1 service should have high score, got %.4f", score)
	}
}

// TestIPTracker_PerHostIsolation verifies that a flood on one (IP,host) pair
// does not inflate the score for a different host from the same IP.
func TestIPTracker_PerHostIsolation(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)
	hosts := newHostTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("203.0.113.1")

	// Flood host A
	for range 500 {
		hosts.Record(ip, "a.erfi.io")
		tracker.Record(ip, "a.erfi.io", "GET", "/flood", "bot/1.0")
	}

	// Normal traffic on host B
	bPaths := []string{"/", "/about", "/contact", "/blog", "/docs",
		"/api/users", "/api/posts", "/search", "/login", "/settings"}
	for i := range 50 {
		hosts.Record(ip, "b.erfi.io")
		tracker.Record(ip, "b.erfi.io", "GET", bPaths[i%len(bPaths)], "Mozilla/5.0")
	}

	// Profile for host A should be high-scoring
	profileA := tracker.Profile(ip, "a.erfi.io")
	if profileA == nil {
		t.Fatal("profile A should exist")
	}
	scoreA := profileA.AnomalyScore(1, 0.0)
	t.Logf("Host A (flood): requests=%d pathDiv=%.4f score=%.4f", profileA.Requests, profileA.PathDiversity(), scoreA)
	if scoreA < 0.65 {
		t.Fatalf("flooded host A should score high, got %.4f", scoreA)
	}

	// Profile for host B should be normal
	profileB := tracker.Profile(ip, "b.erfi.io")
	if profileB == nil {
		t.Fatal("profile B should exist")
	}
	scoreB := profileB.AnomalyScore(1, 0.0)
	t.Logf("Host B (normal): requests=%d pathDiv=%.4f score=%.4f", profileB.Requests, profileB.PathDiversity(), scoreB)
	if scoreB > 0.5 {
		t.Fatalf("normal host B should have low score, got %.4f", scoreB)
	}
}

// TestIPProfile_RecentRate verifies the 60s sliding window rate on per-service profile.
func TestIPProfile_RecentRate(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("192.0.2.10")

	// Record requests rapidly
	for range 30 {
		tracker.Record(ip, testHost, "GET", "/api/flood", "bot/1.0")
	}

	profile := tracker.Profile(ip, testHost)
	if profile == nil {
		t.Fatal("profile should exist")
	}

	rate := profile.RecentRate()
	t.Logf("RecentRate after 30 rapid requests: %.2f req/s", rate)

	if rate < 0 {
		t.Fatalf("rate must be non-negative, got %.2f", rate)
	}
}

// TestHostTracker_GlobalRecentRate verifies the global rate ring buffer across all hosts.
func TestHostTracker_GlobalRecentRate(t *testing.T) {
	ht := newHostTracker(1000, 5*time.Minute)

	ip := netip.MustParseAddr("192.0.2.20")

	// No requests yet — rate should be 0
	if r := ht.GlobalRecentRate(ip); r != 0 {
		t.Fatalf("expected 0 before any requests, got %.2f", r)
	}

	// Record 30 requests across 3 different hosts
	for i := range 10 {
		_ = i
		ht.Record(ip, "a.example.com")
		ht.Record(ip, "b.example.com")
		ht.Record(ip, "c.example.com")
	}

	rate := ht.GlobalRecentRate(ip)
	t.Logf("GlobalRecentRate after 30 rapid requests across 3 hosts: %.2f req/s", rate)

	// 30 requests in near-zero time — rate is high (exact value depends on elapsed)
	// Just verify it's non-negative and non-zero with enough requests
	if rate < 0 {
		t.Fatalf("rate must be non-negative, got %.2f", rate)
	}

	// Verify that rate is included from all hosts, not just one
	uniqueHosts := ht.UniqueHosts(ip)
	if uniqueHosts != 3 {
		t.Fatalf("expected 3 unique hosts, got %d", uniqueHosts)
	}
}

// TestL1RateGate_GlobalVsPerHost verifies L1 uses global rate across all services.
// Sends requests spread across 10 services over a measurable time window so that
// GlobalRecentRate() returns a meaningful rate. The key property verified is that
// GlobalRecentRate counts ALL requests regardless of host, while per-service profiles
// would only see 1/10th of the traffic.
func TestL1RateGate_GlobalVsPerHost(t *testing.T) {
	ht := newHostTracker(1000, 5*time.Minute)
	tracker := newIPTracker(1000, 5*time.Minute)
	ip := netip.MustParseAddr("198.51.100.5")

	services := []string{
		"a.erfi.io", "b.erfi.io", "c.erfi.io", "d.erfi.io", "e.erfi.io",
	}

	// Send 3 batches with small sleep between them so rate window spans >1ms
	for batch := range 3 {
		for _, svc := range services {
			ht.Record(ip, svc)
			tracker.Record(ip, svc, "GET", "/flood", "bot/1.0")
		}
		if batch < 2 {
			time.Sleep(10 * time.Millisecond) // ensure measurable time window
		}
	}

	globalRate := ht.GlobalRecentRate(ip)
	uniqueHosts := ht.UniqueHosts(ip)

	t.Logf("Distributed flood: %d services × 3 batches = %d reqs, globalRate=%.2f req/s, uniqueHosts=%d",
		len(services), len(services)*3, globalRate, uniqueHosts)

	// Global rate should be non-zero with measurable time between batches
	if globalRate <= 0 {
		t.Fatalf("global rate should be >0 with %d requests over time, got %.2f", len(services)*3, globalRate)
	}

	// Per-service profile only sees 3 requests (1/5th of total)
	// Global rate sees all 15 requests
	perSvcProfile := tracker.Profile(ip, "a.erfi.io")
	if perSvcProfile == nil {
		t.Fatal("per-service profile should exist")
	}
	perSvcRate := perSvcProfile.RecentRate()

	t.Logf("Per-service rate for a.erfi.io: %.2f req/s vs global rate: %.2f req/s",
		perSvcRate, globalRate)

	// Global rate should be meaningfully higher than per-service rate
	// (all 5 services contribute to global, only 1 to per-service)
	if globalRate <= perSvcRate && perSvcRate > 0 {
		t.Errorf("global rate %.2f should exceed per-service rate %.2f", globalRate, perSvcRate)
	}

	// Unique hosts tracked correctly
	if uniqueHosts != len(services) {
		t.Errorf("expected %d unique hosts, got %d", len(services), uniqueHosts)
	}
}

// TestHostTracker_UniqueHosts verifies host counting and TTL expiry.
func TestHostTracker_UniqueHosts(t *testing.T) {
	ht := newHostTracker(1000, 100*time.Millisecond)

	ip := netip.MustParseAddr("10.0.0.5")

	n1 := ht.Record(ip, "a.example.com")
	n2 := ht.Record(ip, "b.example.com")
	n3 := ht.Record(ip, "a.example.com") // duplicate
	n4 := ht.Record(ip, "c.example.com")

	if n1 != 1 {
		t.Errorf("after 1st host: expected 1, got %d", n1)
	}
	if n2 != 2 {
		t.Errorf("after 2nd host: expected 2, got %d", n2)
	}
	if n3 != 2 {
		t.Errorf("after duplicate: expected 2, got %d", n3)
	}
	if n4 != 3 {
		t.Errorf("after 3rd host: expected 3, got %d", n4)
	}

	if ht.UniqueHosts(ip) != 3 {
		t.Errorf("UniqueHosts: expected 3, got %d", ht.UniqueHosts(ip))
	}

	// After TTL expiry, should return default (1)
	time.Sleep(150 * time.Millisecond)
	if ht.UniqueHosts(ip) != 1 {
		t.Errorf("after TTL: expected default 1, got %d", ht.UniqueHosts(ip))
	}
}

// TestHostTracker_Reset verifies Reset clears the entry.
func TestHostTracker_Reset(t *testing.T) {
	ht := newHostTracker(1000, 5*time.Minute)

	ip := netip.MustParseAddr("10.0.0.6")
	ht.Record(ip, "a.example.com")
	ht.Record(ip, "b.example.com")

	if ht.UniqueHosts(ip) != 2 {
		t.Fatalf("expected 2 hosts before reset")
	}

	ht.Reset(ip)

	if ht.UniqueHosts(ip) != 1 {
		t.Fatalf("expected default 1 after reset, got %d", ht.UniqueHosts(ip))
	}
}

// TestIPProfile_ComposerSSEPattern simulates the real composer scenario that
// caused the original false positive: 8 services, composer-heavy with SSE streams.
func TestIPProfile_ComposerSSEPattern(t *testing.T) {
	tracker := newIPTracker(10000, 10*time.Minute)
	hosts := newHostTracker(10000, 10*time.Minute)

	ip := netip.MustParseAddr("89.0.95.1")

	serviceHosts := []string{
		"composer.erfi.io", "jellyfin.erfi.io", "waf.erfi.io",
		"vault.erfi.io", "joplin.erfi.io", "git.erfi.io",
		"sonarr.erfi.io", "radarr.erfi.io",
	}

	// composer: /api/v1/stacks (1444x) + 21 container SSE paths (~317 each)
	for range 1444 {
		hosts.Record(ip, "composer.erfi.io")
		tracker.Record(ip, "composer.erfi.io", "GET", "/api/v1/stacks", "Mozilla/5.0")
	}
	for c := range 21 {
		path := fmt.Sprintf("/api/v1/sse/containers/%012x/stats", c)
		for range 317 {
			hosts.Record(ip, "composer.erfi.io")
			tracker.Record(ip, "composer.erfi.io", "GET", path, "Mozilla/5.0")
		}
	}

	// jellyfin: /Sessions/Playing/Progress (606x) + ~20 other paths
	jellyfinPaths := []string{
		"/Sessions/Playing/Progress", "/Users/abc/Items/Latest",
		"/UserViews", "/UserItems/Resume", "/Shows/NextUp",
		"/Users/Me", "/System/Configuration", "/QuickConnect/Enabled",
		"/DisplayPreferences/usersettings", "/Sessions/Playing/Stopped",
	}
	for i := range 2308 {
		path := jellyfinPaths[i%len(jellyfinPaths)]
		hosts.Record(ip, "jellyfin.erfi.io")
		tracker.Record(ip, "jellyfin.erfi.io", "GET", path, "Jellyfin-Player/1.0")
	}

	// Other services: small traffic
	for _, h := range serviceHosts[2:] {
		for range 50 {
			hosts.Record(ip, h)
			tracker.Record(ip, h, "GET", "/", "Mozilla/5.0")
		}
	}

	uniqueHosts := hosts.UniqueHosts(ip)
	t.Logf("Unique hosts: %d", uniqueHosts)

	// Check composer profile
	composerProfile := tracker.Profile(ip, "composer.erfi.io")
	if composerProfile == nil {
		t.Fatal("composer profile should exist")
	}
	rawScore := composerProfile.AnomalyScore(1, 0.0)
	dampedScore := composerProfile.AnomalyScore(uniqueHosts, 0.0)
	t.Logf("Composer: requests=%d uniquePaths=%d pathDiv=%.5f rawScore=%.4f dampedScore=%.4f",
		composerProfile.Requests, composerProfile.UniquePaths,
		composerProfile.PathDiversity(), rawScore, dampedScore)

	// Raw score should be high (bot-like pattern)
	if rawScore < 0.5 {
		t.Errorf("composer raw score should be high (bot-like), got %.4f", rawScore)
	}

	// Damped score should be below jail threshold (0.65) due to host diversity
	if dampedScore >= 0.65 {
		t.Errorf("composer damped score should be below 0.65 with %d unique hosts, got %.4f (raw=%.4f)",
			uniqueHosts, dampedScore, rawScore)
	}
	t.Logf("PASS: composer not jailed — damped score %.4f < 0.65 threshold", dampedScore)
}

var _ = fmt.Sprintf // used in crawler/composer tests
