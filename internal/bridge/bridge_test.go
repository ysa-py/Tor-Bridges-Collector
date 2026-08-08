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

// ── v2.6.0: Modern protocol URI parser tests ─────────────────────────

func TestParseVlessReality(t *testing.T) {
	uri := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@192.0.2.1:443?security=reality&pbk=Z84J2IelR9u0s9nPd5Bl7Jo0LkNpVz8p&sid=6ba85179e30d4fc2&fp=chrome&sni=cloudflare.com&flow=xtls-rprx-vision&type=tcp"
	tr, err := parseTransportLine(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Type != "vless" {
		t.Errorf("expected type vless, got %s", tr.Type)
	}
	if tr.Host != "192.0.2.1" {
		t.Errorf("expected host 192.0.2.1, got %s", tr.Host)
	}
	if tr.Port != 443 {
		t.Errorf("expected port 443, got %d", tr.Port)
	}
	if tr.AddressFamily != "ipv4" {
		t.Errorf("expected ipv4, got %s", tr.AddressFamily)
	}
}

func TestParseHysteria2(t *testing.T) {
	uri := "hysteria2://letmein@192.0.2.1:8443?sni=cloudflare.com&obfs=salamander&obfs-password=secret"
	tr, err := parseTransportLine(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Type != "hysteria2" {
		t.Errorf("expected type hysteria2, got %s", tr.Type)
	}
	if tr.Port != 8443 {
		t.Errorf("expected port 8443, got %d", tr.Port)
	}
}

func TestParseTuicV5(t *testing.T) {
	uri := "tuic://550e8400-e29b-41d4-a716-446655440000:somepassword@192.0.2.1:8443?sni=cloudflare.com&congestion_control=bbr&alpn=h3"
	tr, err := parseTransportLine(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Type != "tuic" {
		t.Errorf("expected type tuic, got %s", tr.Type)
	}
	if tr.Port != 8443 {
		t.Errorf("expected port 8443, got %d", tr.Port)
	}
	if tr.Params["uuid"] != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("unexpected uuid: %s", tr.Params["uuid"])
	}
}

func TestParseShadowTLS(t *testing.T) {
	uri := "shadow-tls://192.0.2.1:443?sni=cloudflare.com&password=mypass&version=3"
	tr, err := parseTransportLine(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Type != "shadow-tls" {
		t.Errorf("expected type shadow-tls, got %s", tr.Type)
	}
	if tr.Params["version"] != "3" {
		t.Errorf("expected version=3, got %s", tr.Params["version"])
	}
}

func TestParseTransportLineUnknownScheme(t *testing.T) {
	tr, err := parseTransportLine("obfs4 192.0.2.1:443 cert=abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr != nil {
		t.Fatal("expected nil for non-URI transport")
	}
}

func TestParseTransportLineEmpty(t *testing.T) {
	tr, err := parseTransportLine("")
	if err == nil {
		t.Fatal("expected error for empty")
	}
	if tr != nil {
		t.Fatal("expected nil")
	}
}

func TestSplitHostPortIPv4(t *testing.T) {
	h, p, af := splitHostPort("192.0.2.1:443")
	if h != "192.0.2.1" || p != 443 || af != "ipv4" {
		t.Errorf("got host=%s port=%d af=%s", h, p, af)
	}
}

func TestSplitHostPortIPv6(t *testing.T) {
	h, p, af := splitHostPort("[2001:db8::1]:443")
	if h != "2001:db8::1" || p != 443 || af != "ipv6" {
		t.Errorf("got host=%s port=%d af=%s", h, p, af)
	}
}

func TestSplitHostPortDNS(t *testing.T) {
	h, p, af := splitHostPort("cloudflare.com:443")
	if h != "cloudflare.com" || p != 443 || af != "dns" {
		t.Errorf("got host=%s port=%d af=%s", h, p, af)
	}
}
