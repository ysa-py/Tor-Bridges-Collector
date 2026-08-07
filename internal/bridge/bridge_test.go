package bridge

import (
	"testing"
)

func TestParseWebTransportIPv4(t *testing.T) {
	line := "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://cdn.cloudflare.com/ws/tunnel ver=0.0.4"
	tr, err := parseWebTransport(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.Host != "192.0.2.1" {
		t.Errorf("expected host 192.0.2.1, got %s", tr.Host)
	}
	if tr.Port != 443 {
		t.Errorf("expected port 443, got %d", tr.Port)
	}
	if tr.AddressFamily != "ipv4" {
		t.Errorf("expected address family ipv4, got %s", tr.AddressFamily)
	}
	if tr.Params["url"] != "https://cdn.cloudflare.com/ws/tunnel" {
		t.Errorf("unexpected url param: %s", tr.Params["url"])
	}
	if tr.Params["ver"] != "0.0.4" {
		t.Errorf("unexpected ver param: %s", tr.Params["ver"])
	}
}

func TestParseWebTransportIPv6(t *testing.T) {
	line := `webtunnel [2001:db8::1]:443 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB url=https://example.com/path ver=0.0.4`
	tr, err := parseWebTransport(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.Host != "2001:db8::1" {
		t.Errorf("expected host 2001:db8::1, got %s", tr.Host)
	}
	if tr.Port != 443 {
		t.Errorf("expected port 443, got %d", tr.Port)
	}
	if tr.AddressFamily != "ipv6" {
		t.Errorf("expected address family ipv6, got %s", tr.AddressFamily)
	}
	if tr.Params["url"] != "https://example.com/path" {
		t.Errorf("unexpected url param: %s", tr.Params["url"])
	}
}

func TestParseWebTransportURLOnly(t *testing.T) {
	// URL-only WebTunnel lines are now valid — the url= host serves as the
	// implicit endpoint (CDN/domain-fronted delivery). ver=0.0.3, 0.0.4,
	// 0.0.5, and 0.0.6+ are all accepted.
	line := "webtunnel FINGERPRINT url=https://example.com/path ver=0.0.4"
	tr, err := parseWebTransport(line)
	if err != nil {
		t.Fatalf("unexpected error for URL-only WebTunnel: %v", err)
	}
	if tr.AddressFamily != "dns" {
		t.Errorf("expected dns for URL-only, got %s", tr.AddressFamily)
	}
	if tr.Params["url"] != "https://example.com/path" {
		t.Errorf("unexpected url param: %s", tr.Params["url"])
	}
	if tr.Params["ver"] != "0.0.4" {
		t.Errorf("unexpected ver param: %s", tr.Params["ver"])
	}
}

func TestParseWebTransportIPv6Complex(t *testing.T) {
	line := `webtunnel [2001:db8:f3f8:1a33:dba0:17f6:35ce:24f3]:443 963668851C177DC162895A33F1473E32E1E4BE56 url=https://pod05.oneclickhost.eu/path ver=0.0.4`
	tr, err := parseWebTransport(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.AddressFamily != "ipv6" {
		t.Errorf("expected ipv6, got %s", tr.AddressFamily)
	}
	if tr.Port != 443 {
		t.Errorf("expected port 443, got %d", tr.Port)
	}
	if tr.Params["ver"] != "0.0.4" {
		t.Errorf("expected ver=0.0.4, got %s", tr.Params["ver"])
	}
}

func TestParseWebTransportFQDN(t *testing.T) {
	line := "webtunnel cdn.cloudflare.com:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://backend.example.com ver=0.0.4"
	tr, err := parseWebTransport(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.AddressFamily != "dns" {
		t.Errorf("expected dns, got %s", tr.AddressFamily)
	}
	if tr.Host != "cdn.cloudflare.com" {
		t.Errorf("expected host cdn.cloudflare.com, got %s", tr.Host)
	}
	if tr.Port != 443 {
		t.Errorf("expected port 443, got %d", tr.Port)
	}
}

func TestParseWebTransportVersionFlexibility(t *testing.T) {
	versions := []string{"0.0.3", "0.0.4", "0.0.5", "0.0.6", "1.0.0"}
	for _, ver := range versions {
		t.Run("ver="+ver, func(t *testing.T) {
			line := "webtunnel 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA url=https://example.com ver=" + ver
			tr, err := parseWebTransport(line)
			if err != nil {
				t.Fatalf("unexpected error for ver=%s: %v", ver, err)
			}
			if tr.Params["ver"] != ver {
				t.Errorf("expected ver=%s, got %s", ver, tr.Params["ver"])
			}
		})
	}
}

func TestParseWebTransportEmpty(t *testing.T) {
	_, err := parseWebTransport("")
	if err == nil {
		t.Fatal("expected error for empty line")
	}
}

func TestParseWebTransportNotWebTunnel(t *testing.T) {
	_, err := parseWebTransport("obfs4 192.0.2.1:443 cert=abc iat-mode=2")
	if err == nil {
		t.Fatal("expected error for non-webtunnel line")
	}
}

func TestParseLineIPv6WebTunnel(t *testing.T) {
	line := `webtunnel [2001:db8::1]:443 FINGERPRINT url=https://example.com ver=0.0.4`
	tr, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.Type != "webtunnel" {
		t.Errorf("expected type webtunnel, got %s", tr.Type)
	}
	if tr.Host != "2001:db8::1" {
		t.Errorf("expected host 2001:db8::1, got %s", tr.Host)
	}
}

func TestParseLineIPv4Vanilla(t *testing.T) {
	tr, err := ParseLine("192.0.2.1:9001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.Host != "192.0.2.1" {
		t.Errorf("expected host 192.0.2.1, got %s", tr.Host)
	}
	if tr.Port != 9001 {
		t.Errorf("expected port 9001, got %d", tr.Port)
	}
}

func TestParseLineIPv6Vanilla(t *testing.T) {
	tr, err := ParseLine("[2001:db8::1]:9001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.Host != "2001:db8::1" {
		t.Errorf("expected host 2001:db8::1, got %s", tr.Host)
	}
	if tr.Port != 9001 {
		t.Errorf("expected port 9001, got %d", tr.Port)
	}
	if tr.AddressFamily != "ipv6" {
		t.Errorf("expected ipv6, got %s", tr.AddressFamily)
	}
}
