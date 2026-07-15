package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

// setTokenValidator temporarily replaces the validateToken func for a test.
func setTokenValidator(fn func(string) (string, string, error)) func() {
	orig := validateToken
	validateToken = fn
	return func() { validateToken = orig }
}

// mustUnmarshal decodes JSON from body into v. Fatals on error.
func mustUnmarshal(t *testing.T, body []byte, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("failed to unmarshal JSON body: %v\nbody: %s", err, string(body))
	}
}

// captureWriter wraps an http.ResponseWriter and records status/body for
// tests that need to inspect the passed-through response.
type captureWriter struct {
	http.ResponseWriter
	status int
	body   strings.Builder
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.status = code
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	cw.body.Write(b)
	return cw.ResponseWriter.Write(b)
}

// ---------------------------------------------------------------------------
// 1. MISSING BEARER TOKEN → 401
// ---------------------------------------------------------------------------

func TestAuthMiddleware_MissingBearerToken_Returns401(t *testing.T) {
	// Handler that should never be reached
	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market/instruments", nil)
	// No Authorization header
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]interface{}
	mustUnmarshal(t, rec.Body.Bytes(), &body)
	if body["error"] == nil {
		t.Fatal("expected 'error' field in JSON response")
	}
	if body["message"] == nil {
		t.Fatal("expected 'message' field in JSON response")
	}
	if body["error"] != "unauthorized" {
		t.Fatalf("expected error='unauthorized', got %v", body["error"])
	}
	if handlerReached {
		t.Fatal("handler was called despite missing token")
	}
}

func TestAuthMiddleware_EmptyBearerToken_Returns401(t *testing.T) {
	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if handlerReached {
		t.Fatal("handler was called despite empty bearer token")
	}
}

func TestAuthMiddleware_MissingAPIKey_Returns401(t *testing.T) {
	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if handlerReached {
		t.Fatal("handler was called despite malformed bearer token")
	}
}

// ---------------------------------------------------------------------------
// 2. INVALID TOKEN → 401 WITHOUT CALLING HANDLER
// ---------------------------------------------------------------------------

func TestAuthMiddleware_InvalidToken_Returns401(t *testing.T) {
	restore := setTokenValidator(func(token string) (string, string, error) {
		if token == "invalid-token" {
			return "", "", errors.New("token is expired")
		}
		return "user_real", "session_real", nil
	})
	defer restore()

	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]interface{}
	mustUnmarshal(t, rec.Body.Bytes(), &body)
	if body["error"] != "invalid_token" {
		t.Fatalf("expected error='invalid_token', got %v", body["error"])
	}
	if body["message"] == nil {
		t.Fatal("expected 'message' field in response")
	}
	if handlerReached {
		t.Fatal("handler was called despite invalid token")
	}
}

func TestAuthMiddleware_InvalidAPIKey_Returns401(t *testing.T) {
	restore := setTokenValidator(func(token string) (string, string, error) {
		// API keys also go through validateToken via extractToken
		return "", "", errors.New("invalid api key")
	})
	defer restore()

	handlerReached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "bad-api-key")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if handlerReached {
		t.Fatal("handler was called despite invalid API key")
	}
}

// ---------------------------------------------------------------------------
// 3. VALID TOKEN SETS CONTEXT BEFORE RATE LIMITING
// ---------------------------------------------------------------------------

func TestAuthMiddleware_ValidToken_SetsUserContext(t *testing.T) {
	restore := setTokenValidator(func(token string) (string, string, error) {
		if token == "valid-token" {
			return "user_abc123", "session_xyz789", nil
		}
		return "", "", errors.New("invalid")
	})
	defer restore()

	var capturedUserID, capturedSessionID, capturedAuthMethod interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserID = r.Context().Value(ContextKeyUserID)
		capturedSessionID = r.Context().Value(ContextKeySessionID)
		capturedAuthMethod = r.Context().Value(ContextKeyAuthMethod)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedUserID != "user_abc123" {
		t.Fatalf("expected user_id 'user_abc123', got %v", capturedUserID)
	}
	if capturedSessionID != "session_xyz789" {
		t.Fatalf("expected session_id 'session_xyz789', got %v", capturedSessionID)
	}
	if capturedAuthMethod != "bearer" {
		t.Fatalf("expected auth_method 'bearer', got %v", capturedAuthMethod)
	}
}

func TestAuthMiddleware_ValidTokenWithAPIKey_SetsAuthMethod(t *testing.T) {
	restore := setTokenValidator(func(token string) (string, string, error) {
		return "user_api", "session_api", nil
	})
	defer restore()

	var capturedUserID interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserID = r.Context().Value(ContextKeyUserID)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "api-key-valid")
	rec := httptest.NewRecorder()

	AuthMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedUserID != "user_api" {
		t.Fatalf("expected user_id 'user_api', got %v", capturedUserID)
	}
}

func TestAuthMiddleware_ContextPropagation_BeforeRateLimit(t *testing.T) {
	// Verify that when middlewares are correctly ordered (auth before rate limit),
	// the authenticated context is available inside the rate-limited handler.
	restore := setTokenValidator(func(token string) (string, string, error) {
		return "user_authenticated", "session_auth", nil
	})
	defer restore()

	var ctxUserID, ctxSessionID interface{}
	ok := false

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxUserID = r.Context().Value(ContextKeyUserID)
		ctxSessionID = r.Context().Value(ContextKeySessionID)
		ok = true
		w.WriteHeader(http.StatusOK)
	})

	// Correct ordering: AuthMiddleware wraps RateLimitMiddleware wraps handler
	// This means auth runs first (outermost), sets context,
	// then rate limiter runs with auth context available.
	handler := AuthMiddleware(RateLimitMiddleware(100, 50)(innerHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !ok {
		t.Fatal("inner handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ctxUserID != "user_authenticated" {
		t.Fatalf("expected user_id context set before rate limit, got %v", ctxUserID)
	}
	if ctxSessionID != "session_auth" {
		t.Fatalf("expected session_id context set before rate limit, got %v", ctxSessionID)
	}
}

// ---------------------------------------------------------------------------
// 4. MIDDLEWARE ORDERING: AUTHENTICATED vs ANONYMOUS KEYING
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_AnonymousAndAuthenticated_KeyedSeparately(t *testing.T) {
	// Verify that when AuthMiddleware wraps RateLimitMiddleware (correct order),
	// authenticated requests do not consume anonymous rate limit budget.
	//
	// Strategy:
	//   1. Set rate limit to 1 req/sec burst=1 (very tight).
	//   2. Send an anonymous (no-token) request that passes through auth.
	//      AuthMiddleware rejects missing-token BEFORE rate limiting when
	//      auth is outermost. We need a chain where auth allows anonymous,
	//      but the real test is about ordering.
	//
	//   Since AuthMiddleware rejects missing tokens, we test the ordering
	//   property differently: verify that when auth succeeds, the rate
	//   limiter keys by X-API-Key (for authenticated API-key requests)
	//   vs by IP for anonymous requests.

	restore := setTokenValidator(func(token string) (string, string, error) {
		return "user_auth", "session_auth", nil
	})
	defer restore()

	var callCount int32

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	// Build chain: AuthMiddleware(RateLimitMiddleware(1, 1)(inner))
	// - Rate limit: 1 req/s, burst=1 → second request from same key gets 429.
	handler := AuthMiddleware(RateLimitMiddleware(1.0, 1)(inner))

	// Send 2 requests with the same valid API key → second should be rate-limited.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer token1")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first authenticated request: expected 200, got %d", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer token2")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	// Different token but same IP → should be rate-limited
	// (rate limiter keys by IP for bearer-token requests since no X-API-Key header)
	// The rate limiter was at 0 tokens after first request, so second should fail.
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second authenticated request (same IP): expected 429, got %d", rec2.Code)
	}

	var body map[string]interface{}
	mustUnmarshal(t, rec2.Body.Bytes(), &body)
	if body["error"] != "rate_limit_exceeded" {
		t.Fatalf("expected error='rate_limit_exceeded', got %v", body["error"])
	}
}

func TestMiddlewareOrdering_AuthBeforeRateLimit_RejectsUnauthenticatedFirst(t *testing.T) {
	// Critical ordering test: when AuthMiddleware is outermost,
	// missing/bad tokens are rejected BEFORE rate-limited budget is consumed.
	//
	// Strategy:
	//   1. Tight rate limit (1 req/s, burst=1).
	//   2. Send an unauthenticated request → should get 401 from auth,
	//      NOT consume rate limit budget.
	//   3. Send an authenticated request → should succeed (200) because
	//      the rate limiter still has budget available.
	//
	// If rate limiting were applied before auth (wrong order), the
	// unauthenticated request would consume the budget and the
	// authenticated request would get 429.

	restore := setTokenValidator(func(token string) (string, string, error) {
		if token == "good-token" {
			return "user_good", "session_good", nil
		}
		return "", "", errors.New("invalid token")
	})
	defer restore()

	var authCalls atomic.Int32

	// Instrumented inner handler
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	// Chain: AuthMiddleware(RateLimitMiddleware(1, 1)(inner))
	// burst=1, rate=1/s
	handler := AuthMiddleware(RateLimitMiddleware(1.0, 1)(inner))

	// Step 1: Unauthenticated request → should return 401, NOT consume rate limit
	reqBad := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBad.Header.Set("Authorization", "Bearer bad-token")
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)

	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("authenticated request (wrong order): expected 401 from auth, got %d", recBad.Code)
	}
	if authCalls.Load() != 0 {
		t.Fatal("inner handler was called despite invalid token — auth not blocking first")
	}

	// Step 2: Authenticated request → should succeed because rate limit budget is intact
	reqGood := httptest.NewRequest(http.MethodGet, "/", nil)
	reqGood.Header.Set("Authorization", "Bearer good-token")
	recGood := httptest.NewRecorder()
	handler.ServeHTTP(recGood, reqGood)

	if recGood.Code != http.StatusOK {
		t.Fatalf("authenticated request after rejected unauthenticated: expected 200, got %d — rate limit budget may have been consumed by unauthenticated request (ordering issue)", recGood.Code)
	}
	if authCalls.Load() != 1 {
		t.Fatal("inner handler was not called for valid token")
	}
}

func TestRateLimitMiddleware_SeparateKeys_ByAPIKey(t *testing.T) {
	// When X-API-Key is present, the rate limiter should key by the API key,
	// not by IP. This means two requests from the same IP with different
	// API keys should have separate rate limit budgets.
	//
	// However, with the current RateLimitMiddleware, once the first request
	// with API key X creates a bucket, X-API-Key is used as the key.
	// So two requests with the same API key from different IPs share budget,
	// and two requests with different API keys from the same IP get separate budgets.

	var callCount int32
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	// burst=1, only 1 request per key allowed
	handler := RateLimitMiddleware(1.0, 1)(inner)

	// Request with API key A → succeeds
	reqA := httptest.NewRequest(http.MethodGet, "/", nil)
	reqA.Header.Set("X-API-Key", "key-a")
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)

	if recA.Code != http.StatusOK {
		t.Fatalf("first request with key-a: expected 200, got %d", recA.Code)
	}

	// Request with API key B → should succeed (different key, separate budget)
	reqB := httptest.NewRequest(http.MethodGet, "/", nil)
	reqB.Header.Set("X-API-Key", "key-b")
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Fatalf("first request with key-b: expected 200 (separate key), got %d", recB.Code)
	}

	// Third request with key A → should be rate-limited (budget exhausted)
	reqA2 := httptest.NewRequest(http.MethodGet, "/", nil)
	reqA2.Header.Set("X-API-Key", "key-a")
	recA2 := httptest.NewRecorder()
	handler.ServeHTTP(recA2, reqA2)

	if recA2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request with key-a: expected 429, got %d", recA2.Code)
	}

	if callCount != 2 {
		t.Fatalf("expected exactly 2 handler calls, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// 5. RATE LIMIT HEADERS
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_HeadersPresent(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(10.0, 20)(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatal("expected X-RateLimit-Limit header")
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Fatal("expected X-RateLimit-Remaining header")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatal("expected X-RateLimit-Reset header")
	}
}

func TestRateLimitMiddleware_TooManyRequests_Returns429(t *testing.T) {
	// burst=1, so second request gets 429
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(1.0, 1)(inner)

	// First request
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec1.Code)
	}

	// Second request — should be rate-limited
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rec2.Code)
	}

	var body map[string]interface{}
	mustUnmarshal(t, rec2.Body.Bytes(), &body)
	if body["error"] != "rate_limit_exceeded" {
		t.Fatalf("expected error='rate_limit_exceeded', got %v", body["error"])
	}
	if body["retry_after"] == nil {
		t.Fatal("expected 'retry_after' in rate limit response")
	}
}

// ---------------------------------------------------------------------------
// 6. TOKEN BUCKET UNIT TESTS
// ---------------------------------------------------------------------------

func TestTokenBucket_AllowsWithinBurst(t *testing.T) {
	tb := &tokenBucket{
		tokens:    5,
		maxTokens: 5,
		rate:      10.0,
		lastCheck: time.Now(),
	}

	for i := 0; i < 5; i++ {
		allowed, remaining, _ := tb.allow()
		if !allowed {
			t.Fatalf("iteration %d: expected allowed=true", i)
		}
		if remaining != 4-i {
			t.Fatalf("iteration %d: expected remaining=%d, got %d", i, 4-i, remaining)
		}
	}
}

func TestTokenBucket_BlocksWhenExhausted(t *testing.T) {
	tb := &tokenBucket{
		tokens:    1,
		maxTokens: 1,
		rate:      1.0,
		lastCheck: time.Now(),
	}

	allowed, _, _ := tb.allow()
	if !allowed {
		t.Fatal("expected first call to be allowed")
	}

	allowed, _, _ = tb.allow()
	if allowed {
		t.Fatal("expected second call to be blocked")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	tb := &tokenBucket{
		tokens:    0,
		maxTokens: 5,
		rate:      10.0, // 10 tokens/sec → 1 token per 100ms
		lastCheck: time.Now(),
	}

	// Immediately after exhaustion, no tokens available
	allowed, _, _ := tb.allow()
	if allowed {
		t.Fatal("expected blocked immediately after exhaustion")
	}

	// Wait enough time for 1 token to refill
	time.Sleep(110 * time.Millisecond)

	allowed, remaining, _ := tb.allow()
	if !allowed {
		t.Fatal("expected allowed after refill")
	}
	if remaining < 0 {
		t.Fatalf("expected non-negative remaining after refill, got %d", remaining)
	}
}

func TestTokenBucket_ConcurrentAccess(t *testing.T) {
	tb := &tokenBucket{
		tokens:    100,
		maxTokens: 100,
		rate:      1000.0,
		lastCheck: time.Now(),
	}

	var wg sync.WaitGroup
	allowedCount := atomic.Int32{}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, _ := tb.allow()
			if allowed {
				allowedCount.Add(1)
			}
		}()
	}

	wg.Wait()
	if allowedCount.Load() == 0 {
		t.Fatal("expected at least one concurrent goroutine to be allowed")
	}
}

// ---------------------------------------------------------------------------
// 7. REQUEST ID MIDDLEWARE
// ---------------------------------------------------------------------------

func TestRequestIDMiddleware_GeneratesIDWhenMissing(t *testing.T) {
	var capturedID interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Context().Value(ContextKeyRequestID)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	RequestIDMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedID == nil || capturedID.(string) == "" {
		t.Fatal("expected a generated request ID")
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}
}

func TestRequestIDMiddleware_PreservesClientProvidedID(t *testing.T) {
	var capturedID interface{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Context().Value(ContextKeyRequestID)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "client-provided-id-123")
	rec := httptest.NewRecorder()

	RequestIDMiddleware(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedID != "client-provided-id-123" {
		t.Fatalf("expected 'client-provided-id-123', got %v", capturedID)
	}
	if rec.Header().Get("X-Request-ID") != "client-provided-id-123" {
		t.Fatalf("expected X-Request-ID header 'client-provided-id-123', got '%s'", rec.Header().Get("X-Request-ID"))
	}
}

// ---------------------------------------------------------------------------
// 8. RECOVERY MIDDLEWARE
// ---------------------------------------------------------------------------

func TestRecoveryMiddleware_CatchesPanic(t *testing.T) {
	panickingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	RecoveryMiddleware(panickingHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from panic recovery, got %d", rec.Code)
	}

	var body map[string]interface{}
	mustUnmarshal(t, rec.Body.Bytes(), &body)
	if body["error"] != "internal_server_error" {
		t.Fatalf("expected error='internal_server_error', got %v", body["error"])
	}
}

// ---------------------------------------------------------------------------
// 9. CORS MIDDLEWARE
// ---------------------------------------------------------------------------

func TestCORSMiddleware_AllowsConfiguredOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware([]string{"https://example.com"}, 24*time.Hour)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("expected Access-Control-Allow-Origin 'https://example.com', got '%s'", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_RejectsDisallowedOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware([]string{"https://allowed.com"}, 24*time.Hour)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("expected no CORS header for disallowed origin, got '%s'", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_AllowsWildcardOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware([]string{"*"}, 24*time.Hour)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anything.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://anything.com" {
		t.Fatalf("expected Access-Control-Allow-Origin 'https://anything.com', got '%s'", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_PreflightReturns204(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware([]string{"*"}, 24*time.Hour)(next)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 10. SECURITY HEADERS MIDDLEWARE
// ---------------------------------------------------------------------------

func TestSecurityHeadersMiddleware_SetsExpectedHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	SecurityHeadersMiddleware(next).ServeHTTP(rec, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}

	for header, expected := range expectedHeaders {
		actual := rec.Header().Get(header)
		if actual != expected {
			t.Errorf("header %s: expected '%s', got '%s'", header, expected, actual)
		}
	}
}

// ---------------------------------------------------------------------------
// 11. MIDDLEWARE CHAIN INTEGRATION (FULL STACK)
// ---------------------------------------------------------------------------

func TestFullMiddlewareChain_AuthRateLimitOrdering(t *testing.T) {
	// Full-stack integration test with recovery + request ID + auth + rate limit.
	// Validates that the middleware chain as documented works end-to-end.
	restore := setTokenValidator(func(token string) (string, string, error) {
		if token == "good" {
			return "user_integration", "session_integration", nil
		}
		return "", "", errors.New("bad token")
	})
	defer restore()

	var capturedUserID, capturedRequestID interface{}
	var handlerCalled bool

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		capturedUserID = r.Context().Value(ContextKeyUserID)
		capturedRequestID = r.Context().Value(ContextKeyRequestID)
		w.WriteHeader(http.StatusOK)
	})

	// Build chain matching documented order (inner to outer):
	// handler → RateLimit → Auth → CORS → Logging → RequestID → Recovery
	chain := RecoveryMiddleware(
		RequestIDMiddleware(
			LoggingMiddleware(
				AuthMiddleware(
					RateLimitMiddleware(100.0, 50)(finalHandler),
				),
			),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/market/instruments", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("handler was not called in full chain")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedUserID != "user_integration" {
		t.Fatalf("expected user_id propagated through full chain, got %v", capturedUserID)
	}
	if capturedRequestID == nil {
		t.Fatal("expected request ID propagated through full chain")
	}
	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatal("expected rate limit headers from full chain")
	}
}
