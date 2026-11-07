// Package ipinfo provides a thread-safe, cached client for the ipinfo.io
// free-tier API, used to resolve bridge IP addresses to their Autonomous
// System Number (ASN) and country code.
// Free tier: no API key required for under 50 000 requests/month.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxConcurrentLookups bounds simultaneous ipinfo.io requests no matter how
	// many probe workers run; the free anonymous tier is easily rate limited.
	maxConcurrentLookups = 24
	// breakerThreshold is the number of consecutive failed lookups after which
	// the circuit opens for the rest of the run. A failed lookup only means
	// "ASN unknown" for that bridge (never blocked, never working), so skipping
	// the remaining calls is safe and keeps the run inside its deadline.
	breakerThreshold = 12
)

// Response is the subset of the ipinfo.io JSON response we care about.
type Response struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`     // e.g. "AS12880 Information Technology Company"
	Country string `json:"country"` // ISO 3166-1 alpha-2
}

// ASN extracts just the ASN string from the Org field (e.g. "AS12880").
func (r *Response) ASN() string {
	if r == nil || r.Org == "" {
		return ""
	}
	parts := strings.SplitN(r.Org, " ", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0] // "AS12880"
}

// Client is a cached, concurrency-safe ipinfo.io lookup client.
type Client struct {
	mu    sync.Mutex
	cache map[string]*Response
	hc    *http.Client

	base        string        // overridable in tests
	sem         chan struct{} // concurrency cap
	consecFails atomic.Int64  // consecutive failures (reset on success)
	skipped     atomic.Int64  // lookups short-circuited by the open breaker
}

// New creates a new Client with a pre-allocated cache and an HTTP client
// that enforces a total timeout per request.
func New() *Client {
	return &Client{
		cache: make(map[string]*Response),
		hc: &http.Client{
			Timeout: 10 * time.Second,
		},
		base: "https://ipinfo.io",
		sem:  make(chan struct{}, maxConcurrentLookups),
	}
}

// BreakerOpen reports whether lookups are being short-circuited.
func (c *Client) BreakerOpen() bool { return c.consecFails.Load() >= breakerThreshold }

// SkippedLookups reports how many lookups the open breaker skipped.
func (c *Client) SkippedLookups() int64 { return c.skipped.Load() }

// Lookup resolves an IP address to its ASN and country code.
// Results are cached in-memory to avoid duplicate API calls within one run.
// Returns nil if the lookup fails (network error or non-200 response).
func (c *Client) Lookup(ctx context.Context, ip string) (*Response, error) {
	if ip == "" || ip == "snowflake-broker" {
		return nil, fmt.Errorf("not a routable IP: %q", ip)
	}

	// Check cache first (fast path, no lock held during HTTP).
	c.mu.Lock()
	if cached, ok := c.cache[ip]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	if c.BreakerOpen() {
		c.skipped.Add(1)
		return nil, fmt.Errorf("ipinfo.io circuit open after %d consecutive failures", breakerThreshold)
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	base := c.base
	if base == "" {
		base = "https://ipinfo.io"
	}
	url := fmt.Sprintf("%s/%s/json", base, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "TorShield-IR/1.0 (github.com/user/torshield-ir)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			c.consecFails.Add(1)
		}
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.consecFails.Add(1)
		return nil, fmt.Errorf("ipinfo.io returned HTTP %d for %s", resp.StatusCode, ip)
	}

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.consecFails.Add(1)
		return nil, fmt.Errorf("decode response: %w", err)
	}
	c.consecFails.Store(0)

	c.mu.Lock()
	c.cache[ip] = &result
	c.mu.Unlock()

	return &result, nil
}
