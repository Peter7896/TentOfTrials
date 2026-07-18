package ws

import (
	"net/http"
	"testing"
)

func requestWithOrigin(origin string) *http.Request {
	req := &http.Request{Header: make(http.Header)}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func TestOriginConfigAllowsConfiguredOrigin(t *testing.T) {
	config := OriginConfig{
		AllowedOrigins: []string{"https://market.example.com"},
		AllowLocalhost: true,
		AllowMissing:   true,
	}

	if !config.CheckOrigin(requestWithOrigin("https://market.example.com")) {
		t.Fatal("expected configured origin to be allowed")
	}
}

func TestOriginConfigRejectsUntrustedOrigin(t *testing.T) {
	config := OriginConfig{
		AllowedOrigins: []string{"https://market.example.com"},
		AllowLocalhost: true,
		AllowMissing:   true,
	}

	if config.CheckOrigin(requestWithOrigin("https://evil.example.net")) {
		t.Fatal("expected untrusted origin to be rejected")
	}
}

func TestOriginConfigHandlesMissingOrigin(t *testing.T) {
	allowMissing := OriginConfig{AllowMissing: true}
	if !allowMissing.CheckOrigin(requestWithOrigin("")) {
		t.Fatal("expected missing origin to be allowed for non-browser clients when configured")
	}

	rejectMissing := OriginConfig{AllowMissing: false}
	if rejectMissing.CheckOrigin(requestWithOrigin("")) {
		t.Fatal("expected missing origin to be rejected when disabled")
	}
}

func TestOriginConfigAllowsLocalhostDevelopmentOrigins(t *testing.T) {
	config := OriginConfig{AllowLocalhost: true}
	origins := []string{
		"http://localhost:3000",
		"https://127.0.0.1:8443",
		"ws://[::1]:9000",
	}

	for _, origin := range origins {
		if !config.CheckOrigin(requestWithOrigin(origin)) {
			t.Fatalf("expected localhost origin %q to be allowed", origin)
		}
	}
}

func TestSplitOriginListTrimsAndDeduplicates(t *testing.T) {
	origins := splitOriginList(" https://a.example.com/ ,https://b.example.com,https://a.example.com,, ")
	want := []string{"https://a.example.com", "https://b.example.com"}
	if len(origins) != len(want) {
		t.Fatalf("got %d origins, want %d: %#v", len(origins), len(want), origins)
	}
	for i := range want {
		if origins[i] != want[i] {
			t.Fatalf("origin %d = %q, want %q", i, origins[i], want[i])
		}
	}
}
