package ddosmitigator

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestIPProfile_NormalBrowsing(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("192.0.2.1")

	// Simulate normal browsing: diverse paths, varied timing
	paths := []string{"/", "/about", "/contact", "/blog/1", "/blog/2", "/api/users",
		"/settings", "/login", "/search?q=hello", "/docs", "/help", "/pricing",
		"/favicon.ico", "/static/app.js", "/static/style.css", "/images/logo.png"}

	for i, p := range paths {
		tracker.Record(ip, "GET", p, "Mozilla/5.0", 200)
		_ = i
	}

	profile := tracker.Profile(ip)
	if profile == nil {
		t.Fatal("profile should exist after recording")
	}

	score := profile.AnomalyScore()
	t.Logf("Normal browsing: requests=%d pathRatio=%.2f score=%.2f",
		profile.Requests, profile.PathDiversity(), score)

	if score > 0.5 {
		t.Fatalf("normal browsing should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_FloodAttack(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("198.51.100.1")

	// Simulate flood: same path, same method, same UA, 500 times
	for range 500 {
		tracker.Record(ip, "GET", "/api/vulnerable", "attack-bot/1.0", 200)
	}

	profile := tracker.Profile(ip)
	if profile == nil {
		t.Fatal("profile should exist")
	}

	score := profile.AnomalyScore()
	t.Logf("Flood attack: requests=%d pathRatio=%.4f score=%.2f",
		profile.Requests, profile.PathDiversity(), score)

	if score < 0.7 {
		t.Fatalf("flood should have high anomaly score, got %.2f", score)
	}
}

func TestIPProfile_HighVolumeNormal(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("10.0.0.1")

	// Simulate a power user: many requests but diverse paths
	paths := []string{"/", "/about", "/blog/1", "/blog/2", "/blog/3",
		"/api/users", "/api/posts", "/api/comments", "/search?q=a",
		"/search?q=b", "/search?q=c", "/settings", "/profile",
		"/dashboard", "/notifications", "/help", "/docs/api",
		"/docs/getting-started", "/feed", "/logout"}

	for i := range 200 {
		p := paths[i%len(paths)]
		tracker.Record(ip, "GET", p, "Mozilla/5.0 (Windows)", 200)
	}

	profile := tracker.Profile(ip)
	score := profile.AnomalyScore()
	t.Logf("Power user: requests=%d pathRatio=%.2f score=%.2f",
		profile.Requests, profile.PathDiversity(), score)

	// Power user should NOT be flagged — diverse paths even with high volume
	if score > 0.5 {
		t.Fatalf("power user should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_SlowFlood(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("203.0.113.50")

	// Simulate slow flood: 50 requests but ALL to the same endpoint
	for range 50 {
		tracker.Record(ip, "POST", "/api/login", "curl/8.0", 200)
	}

	profile := tracker.Profile(ip)
	score := profile.AnomalyScore()
	t.Logf("Slow flood: requests=%d pathRatio=%.4f methodDiv=%.2f score=%.2f",
		profile.Requests, profile.PathDiversity(), profile.MethodDiversity(), score)

	// At low volume (50 reqs), single-path traffic is ambiguous (could be API polling).
	// Score should be elevated but not necessarily above jail threshold.
	// If they continue, the score will rise as volume increases.
	if score < 0.1 {
		t.Fatalf("slow flood should have some anomaly signal, got %.2f", score)
	}
}

func TestIPProfile_CrawlerPattern(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("66.249.66.1") // Googlebot-like

	// Crawler: very diverse paths, single UA, steady rate
	for i := range 100 {
		p := fmt.Sprintf("/page/%d", i)
		tracker.Record(ip, "GET", p, "Googlebot/2.1", 200)
	}

	profile := tracker.Profile(ip)
	score := profile.AnomalyScore()
	t.Logf("Crawler: requests=%d pathRatio=%.2f score=%.2f",
		profile.Requests, profile.PathDiversity(), score)

	// Crawlers have high path diversity — should NOT be flagged
	if score > 0.5 {
		t.Fatalf("crawler should have low anomaly score, got %.2f", score)
	}
}

func TestIPProfile_MixedStatusFlood(t *testing.T) {
	tracker := newIPTracker(10000, 5*time.Minute)

	ip := netip.MustParseAddr("198.51.100.2")

	// Flood with all 200 responses (normal for legitimate, but suspicious with low diversity)
	for range 300 {
		tracker.Record(ip, "GET", "/target", "bot/1.0", 200)
	}

	profile := tracker.Profile(ip)
	score := profile.AnomalyScore()

	// Low path diversity + high volume = high score
	if score < 0.6 {
		t.Fatalf("monotone flood should have high score, got %.2f", score)
	}
}

func TestIPTracker_Expiry(t *testing.T) {
	tracker := newIPTracker(100, 50*time.Millisecond)

	ip := netip.MustParseAddr("10.0.0.1")
	tracker.Record(ip, "GET", "/", "ua", 200)

	if tracker.Profile(ip) == nil {
		t.Fatal("profile should exist immediately after record")
	}

	time.Sleep(100 * time.Millisecond)
	tracker.Sweep()

	if tracker.Profile(ip) != nil {
		t.Fatal("profile should be expired after TTL")
	}
}

func TestIPTracker_MaxEntries(t *testing.T) {
	tracker := newIPTracker(10, 5*time.Minute)

	// Fill beyond capacity
	for i := range 20 {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		tracker.Record(ip, "GET", "/", "ua", 200)
	}

	// Should not panic, and count should be bounded
	count := tracker.Count()
	if count > 15 { // some slack for concurrent adds before eviction
		t.Fatalf("tracker should be bounded, got %d entries", count)
	}
}

var _ = fmt.Sprintf // used in crawler test
