package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLookupParsesASNAndCaches(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ip":"198.51.100.9","org":"AS12880 Example Org","country":"DE"}`))
	}))
	defer srv.Close()
	c := New()
	c.base = srv.URL
	for i := 0; i < 3; i++ {
		r, err := c.Lookup(context.Background(), "198.51.100.9")
		if err != nil || r.ASN() != "AS12880" || r.Country != "DE" {
			t.Fatalf("lookup %d: %+v err=%v", i, r, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("server hit %d times, want 1 (cache)", hits.Load())
	}
}

// Repeated 429s open the breaker; later lookups are skipped without any
// network traffic, and a failed lookup is an error (unknown), never a verdict.
func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New()
	c.base = srv.URL
	for i := 0; i < breakerThreshold+20; i++ {
		if _, err := c.Lookup(context.Background(), "198.51.100."+itoa(i)); err == nil {
			t.Fatal("429 must be an error")
		}
	}
	if !c.BreakerOpen() {
		t.Fatal("breaker must be open")
	}
	if hits.Load() != breakerThreshold {
		t.Fatalf("server hit %d times, want exactly %d", hits.Load(), breakerThreshold)
	}
	if c.SkippedLookups() != 20 {
		t.Fatalf("skipped=%d, want 20", c.SkippedLookups())
	}
}

func TestSuccessResetsFailureCounter(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"org":"AS1 X","country":"US"}`))
	}))
	defer srv.Close()
	c := New()
	c.base = srv.URL
	for i := 0; i < 40; i++ {
		_, _ = c.Lookup(context.Background(), "203.0.113."+itoa(i))
	}
	if c.BreakerOpen() {
		t.Fatal("alternating success must keep the breaker closed")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
