package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: testHandler returns 200 OK
// ---------------------------------------------------------------------------

func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
}

// ---------------------------------------------------------------------------
// Helper: extract JSON body
// ---------------------------------------------------------------------------

func decodeBody(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// AuthMiddleware Tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware_MissingToken(t *testing.T) {
	handler := AuthMiddleware(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	body := decodeBody(t, rec.Result())
	if body["error"] != "unauthorized" {
		t.Errorf("expected error 'unauthorized', got %v", body["error"])
	}
}

func TestAuthMiddleware_EmptyBearerToken(t *testing.T) {
	handler := AuthMiddleware(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ValidBearerToken(t *testing.T) {
	handler := AuthMiddleware(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("Authorization", "Bearer valid-token-12345")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify user context was set
	userID := req.Context().Value(ContextKeyUserID)
	if userID == nil {
		t.Error("expected user ID in context, got nil")
	}
	if userID.(string) != "user_stub" {
		t.Errorf("expected user ID 'user_stub', got %v", userID)
	}

	sessionID := req.Context().Value(ContextKeySessionID)
	if sessionID == nil {
		t.Error("expected session ID in context, got nil")
	}

	authMethod := req.Context().Value(ContextKeyAuthMethod)
	if authMethod.(string) != "bearer" {
		t.Errorf("expected auth method 'bearer', got %v", authMethod)
	}
}

func TestAuthMiddleware_APIKeyInHeader(t *testing.T) {
	handler := AuthMiddleware(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("X-API-Key", "some-api-key-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 with valid API key, got %d", rec.Code)
	}
}

func TestAuthMiddleware_WrongAuthScheme(t *testing.T) {
	handler := AuthMiddleware(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// extractToken only handles "Bearer " prefix and X-API-Key
	// "Basic" auth should result in an empty token → 401
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for Basic auth, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware Tests
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_UnderLimit(t *testing.T) {
	handler := RateLimitMiddleware(100, 200)(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify rate limit headers are set
	limit := rec.Header().Get("X-RateLimit-Limit")
	remaining := rec.Header().Get("X-RateLimit-Remaining")
	reset := rec.Header().Get("X-RateLimit-Reset")

	if limit == "" {
		t.Error("expected X-RateLimit-Limit header")
	}
	if remaining == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
	if reset == "" {
		t.Error("expected X-RateLimit-Reset header")
	}
}

func TestRateLimitMiddleware_ExceedsLimit(t *testing.T) {
	// Use a very low rate (1 req/s, burst 1) so the second request is blocked
	handler := RateLimitMiddleware(1, 1)(testHandler())

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec1.Code)
	}

	// Wait for the token bucket to be exhausted (already did one request above,
	// the bucket had 1 token and now has 0; but there's a race with the refill).
	// To reliably exceed, consume tokens in a tight loop.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request with burst=1: expected 429, got %d", rec2.Code)
	}

	body := decodeBody(t, rec2.Result())
	if body["error"] != "rate_limit_exceeded" {
		t.Errorf("expected error 'rate_limit_exceeded', got %v", body["error"])
	}
	if body["retry_after"] == nil {
		t.Error("expected retry_after field in rate limit response")
	}
}

func TestRateLimitMiddleware_DifferentClientsSeparateBuckets(t *testing.T) {
	handler := RateLimitMiddleware(1, 1)(testHandler())

	// Client A: first request succeeds
	reqA1 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	reqA1.RemoteAddr = "10.0.0.1:12345"
	recA1 := httptest.NewRecorder()
	handler.ServeHTTP(recA1, reqA1)
	if recA1.Code != http.StatusOK {
		t.Errorf("client A first request: expected 200, got %d", recA1.Code)
	}

	// Client A: second request blocked (same bucket, burst=1)
	reqA2 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	reqA2.RemoteAddr = "10.0.0.1:12345"
	recA2 := httptest.NewRecorder()
	handler.ServeHTTP(recA2, reqA2)
	if recA2.Code != http.StatusTooManyRequests {
		t.Errorf("client A second request: expected 429, got %d", recA2.Code)
	}

	// Client B: different IP → separate bucket, should succeed
	reqB := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	reqB.RemoteAddr = "10.0.0.2:54321"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Errorf("client B (different IP): expected 200, got %d", recB.Code)
	}
}

func TestRateLimitHeaders_AreConsistent(t *testing.T) {
	handler := RateLimitMiddleware(50, 100)(testHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	limit := rec.Header().Get("X-RateLimit-Limit")
	if limit != "100" {
		t.Errorf("expected X-RateLimit-Limit 100, got %s", limit)
	}

	remaining := rec.Header().Get("X-RateLimit-Remaining")
	// After 1 request with burst=100, remaining should be 99
	if remaining != "99" {
		t.Errorf("expected X-RateLimit-Remaining 99, got %s", remaining)
	}
}

func TestRateLimitMiddleware_APIKeyBucketing(t *testing.T) {
	handler := RateLimitMiddleware(1, 1)(testHandler())

	// Same IP but different API keys should use the API key as the bucket key
	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("X-API-Key", "key-1")
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("key-1 first request: expected 200, got %d", rec.Code)
	}

	// Same key → blocked
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req2.Header.Set("X-API-Key", "key-1")
	req2.RemoteAddr = "10.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("key-1 second request: expected 429, got %d", rec2.Code)
	}

	// Different key (same IP) → separate bucket, should succeed
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req3.Header.Set("X-API-Key", "key-2")
	req3.RemoteAddr = "10.0.0.1:12345"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("key-2 (different key): expected 200, got %d", rec3.Code)
	}
}

// ---------------------------------------------------------------------------
// Middleware Ordering Tests
// ---------------------------------------------------------------------------

// TestAuthBeforeRateLimit verifies that authentication runs before rate limiting,
// so unauthenticated requests are rejected before consuming rate limit budget.
func TestAuthBeforeRateLimit_UnauthenticatedNotRateLimited(t *testing.T) {
	// Apply auth then rate limiter (correct order)
	handler := AuthMiddleware(RateLimitMiddleware(1, 1)(testHandler()))

	// An unauthenticated request should be rejected by auth middleware
	// BEFORE the rate limiter gets a chance to consume a token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated request: expected 401, got %d", rec.Code)
	}

	// The rate limit remaining header should NOT be set
	// because the request never reached the rate limiter
	if remaining := rec.Header().Get("X-RateLimit-Remaining"); remaining != "" {
		t.Errorf("rate limit headers should not be set for rejected auth: got %s", remaining)
	}
}

func TestAuthenticatedRequests_ConsumeRateLimit(t *testing.T) {
	handler := AuthMiddleware(RateLimitMiddleware(10, 5)(testHandler()))

	// Authenticated request should pass both middleware layers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	req.Header.Set("Authorization", "Bearer token-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("authenticated request: expected 200, got %d", rec.Code)
	}

	// Should have rate limit headers since it reached the rate limiter
	remaining := rec.Header().Get("X-RateLimit-Remaining")
	if remaining == "" {
		t.Error("authenticated request should set rate limit headers")
	}
}

func TestFullMiddlewareChain(t *testing.T) {
	// Simulate the production order: Recovery → RequestID → Logging → CORS → Auth → RateLimit → Metrics → Context → Handler
	handler := RecoveryMiddleware(
		RequestIDMiddleware(
			AuthMiddleware(
				RateLimitMiddleware(100, 200)(testHandler()),
			),
		),
	)

	// Unauthenticated: should fail at AuthMiddleware before hitting RateLimitMiddleware
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	recNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated in chain: expected 401, got %d", recNoAuth.Code)
	}

	// Authenticated: should pass through and get 200
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/market", nil)
	reqAuth.Header.Set("Authorization", "Bearer my-token")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Errorf("authenticated in chain: expected 200, got %d", recAuth.Code)
	}

	// Verify request ID was set by RequestIDMiddleware
	if recAuth.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID header in chain response")
	}
}

// ---------------------------------------------------------------------------
// Token Extract Helper Tests
// ---------------------------------------------------------------------------

func TestExtractToken_Bearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	token := extractToken(req)
	if token != "my-secret-token" {
		t.Errorf("expected 'my-secret-token', got '%s'", token)
	}
}

func TestExtractToken_APIKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "api-key-value")
	token := extractToken(req)
	if token != "api-key-value" {
		t.Errorf("expected 'api-key-value', got '%s'", token)
	}
}

func TestExtractToken_NoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := extractToken(req)
	if token != "" {
		t.Errorf("expected empty token, got '%s'", token)
	}
}

func TestExtractToken_PreferBearerOverAPIKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bearer-token")
	req.Header.Set("X-API-Key", "api-key")
	token := extractToken(req)
	// extractToken checks Authorization first, so should return "bearer-token"
	if token != "bearer-token" {
		t.Errorf("expected bearer token to take precedence, got '%s'", token)
	}
}

// ---------------------------------------------------------------------------
// Token Bucket Unit Tests
// ---------------------------------------------------------------------------

func TestTokenBucket_InitialState(t *testing.T) {
	tb := &tokenBucket{
		tokens:     10,
		maxTokens:  10,
		rate:       5,
		lastAccess: time.Now(),
		lastCheck:  time.Now(),
	}

	allowed, remaining, _ := tb.allow()
	if !allowed {
		t.Error("expected initial token bucket to allow")
	}
	if remaining != 9 {
		t.Errorf("expected 9 remaining, got %d", remaining)
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	tb := &tokenBucket{
		tokens:     0,
		maxTokens:  10,
		rate:       100, // 100 tokens/sec
		lastAccess: time.Now(),
		lastCheck:  time.Now().Add(-100 * time.Millisecond), // 100ms ago
	}

	// After 100ms at rate 100 tokens/s, 10 tokens should have been added
	// But we were at 0, so we should have 10 (capped at maxTokens=10)
	allowed, remaining, _ := tb.allow()
	if !allowed {
		t.Error("expected bucket to allow after refill")
	}
	if remaining != 9 {
		t.Errorf("expected 9 remaining after refill and consume, got %d", remaining)
	}
}

func TestTokenBucket_EmptyDoesNotAllow(t *testing.T) {
	tb := &tokenBucket{
		tokens:     0,
		maxTokens:  10,
		rate:       1,
		lastAccess: time.Now(),
		lastCheck:  time.Now(),
	}

	allowed, remaining, reset := tb.allow()
	if allowed {
		t.Error("expected empty bucket to deny")
	}
	if remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", remaining)
	}
	if reset <= time.Now().Unix() {
		t.Error("expected reset to be in the future")
	}
}
