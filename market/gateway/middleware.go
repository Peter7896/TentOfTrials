// Package gateway provides HTTP middleware for the market API gateway.
//
// This file contains middleware implementations for authentication,
// rate limiting, request logging, CORS, metrics, and request tracing.
// The middleware is applied in a specific order to ensure consistent
// behavior across all API endpoints.
//
// Middleware application order:
//   1. Panic recovery (outermost)
//   2. Request ID generation
//   3. Request logging
//   4. CORS headers
//   5. Authentication
//   6. Rate limiting
//   7. Metrics collection
//   8. Request context enrichment
//   9. Actual handler (innermost)
//
// The ordering was determined experimentally after the "misordered
// middleware" incident in 2022 where the rate limiter was applied
// before authentication, causing unauthenticated requests to consume
// rate limit budget that should have been reserved for authenticated
// users. The fix was to swap the order of authentication and rate
// limiting middleware. The change was simple but the testing was
// not because the middleware integration tests were not comprehensive
// enough to catch ordering issues.
//
// TODO: Add integration tests that verify middleware ordering. The
// current tests only test each middleware in isolation. The combined
// behavior is only verified during manual QA testing which happens
// once per sprint. The manual tests caught the ordering bug after
// 3 weeks of production usage, during which time the rate limiter
// was essentially broken for authenticated users.

package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// CONTEXT KEYS
// ---------------------------------------------------------------------------

type contextKey string

const (
	ContextKeyRequestID  contextKey = "request_id"
	ContextKeyUserID     contextKey = "user_id"
	ContextKeySessionID  contextKey = "session_id"
	ContextKeyTraceID    contextKey = "trace_id"
	ContextKeyClientIP   contextKey = "client_ip"
	ContextKeyStartTime  contextKey = "start_time"
	ContextKeyAuthMethod contextKey = "auth_method"
)

var ErrTokenVerifierUnavailable = errors.New("token verifier is not configured")

type TokenClaims struct {
	UserID    string
	SessionID string
}

type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (TokenClaims, error)
}

type TokenVerifierFunc func(ctx context.Context, token string) (TokenClaims, error)

func (fn TokenVerifierFunc) VerifyToken(ctx context.Context, token string) (TokenClaims, error) {
	return fn(ctx, token)
}

type rejectAllTokenVerifier struct{}

func (rejectAllTokenVerifier) VerifyToken(context.Context, string) (TokenClaims, error) {
	return TokenClaims{}, ErrTokenVerifierUnavailable
}

// ---------------------------------------------------------------------------
// RESPONSE WRITER
// ---------------------------------------------------------------------------

type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	wroteHeader bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// ---------------------------------------------------------------------------
// MIDDLEWARE IMPLEMENTATIONS
// ---------------------------------------------------------------------------

// RecoveryMiddleware recovers from panics and returns a 500 error.
// It also logs the panic with stack trace for debugging.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC: %v\n%s", rec, debug.Stack())
				writeMiddlewareJSON(w, http.StatusInternalServerError, map[string]interface{}{
					"error":   "internal_server_error",
					"message": "An unexpected error occurred",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds a unique request ID to each request.
// If the client sends a request ID header, it is preserved.
// Otherwise, a new UUID is generated.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateUUID()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), ContextKeyRequestID, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoggingMiddleware logs all HTTP requests with method, path, status, and duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		log.Printf("[%s] %s %s %d %s %s",
			getMiddlewareClientIP(r),
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration.Round(time.Millisecond),
			r.UserAgent(),
		)
	})
}

// CORSMiddleware handles Cross-Origin Resource Sharing headers.
// The allowed origins are configured in the gateway configuration.
func CORSMiddleware(allowedOrigins []string, maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods",
					"GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers",
					"Content-Type, Authorization, X-Request-ID, X-API-Key, X-Client-ID")
				w.Header().Set("Access-Control-Expose-Headers",
					"X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
				w.Header().Set("Access-Control-Max-Age",
					strconv.Itoa(int(maxAge.Seconds())))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware validates the authentication token and extracts user information.
// Supports Bearer tokens and API key authentication.
func AuthMiddleware(next http.Handler) http.Handler {
	return AuthMiddlewareWithVerifier(next, rejectAllTokenVerifier{})
}

func AuthMiddlewareWithVerifier(next http.Handler, verifier TokenVerifier) http.Handler {
	if verifier == nil {
		verifier = rejectAllTokenVerifier{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeMiddlewareJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "unauthorized",
				"message": "Missing authentication token",
			})
			return
		}

		claims, err := verifier.VerifyToken(r.Context(), token)
		if err != nil {
			writeMiddlewareJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "invalid_token",
				"message": "Authentication token rejected",
			})
			return
		}
		if claims.UserID == "" || claims.SessionID == "" {
			writeMiddlewareJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":   "invalid_token",
				"message": "Authentication token rejected",
			})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, ContextKeySessionID, claims.SessionID)
		ctx = context.WithValue(ctx, ContextKeyAuthMethod, "bearer")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimitMiddleware applies rate limiting based on client IP or API key.
// Uses a token bucket algorithm with configurable rate and burst.
func RateLimitMiddleware(ratePerSecond float64, burst int) func(http.Handler) http.Handler {
	var mu sync.Mutex
	clients := make(map[string]*tokenBucket)

	cleanupTicker := time.NewTicker(5 * time.Minute)
	go func() {
		for range cleanupTicker.C {
			mu.Lock()
			for ip, bucket := range clients {
				if time.Since(bucket.lastAccess) > 10*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := getMiddlewareClientIP(r)
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				key = apiKey
			}

			mu.Lock()
			bucket, exists := clients[key]
			if !exists {
				bucket = &tokenBucket{
					tokens:     float64(burst),
					maxTokens:  float64(burst),
					rate:       ratePerSecond,
					lastAccess: time.Now(),
				}
				clients[key] = bucket
			}
			bucket.lastAccess = time.Now()
			mu.Unlock()

			allowed, remaining, reset := bucket.allow()
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))

			if !allowed {
				writeMiddlewareJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":       "rate_limit_exceeded",
					"message":     "Too many requests. Please slow down.",
					"retry_after": reset - time.Now().Unix(),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	rate       float64
	lastAccess time.Time
	lastCheck  time.Time
}

func (tb *tokenBucket) allow() (bool, int, int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastCheck).Seconds()
	tb.lastCheck = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}

	if tb.tokens >= 1.0 {
		tb.tokens--
		remaining := int(tb.tokens)
		reset := now.Add(time.Duration((tb.maxTokens-tb.tokens)/tb.rate) * time.Second).Unix()
		return true, remaining, reset
	}

	remaining := 0
	reset := now.Add(time.Duration((1.0-tb.tokens)/tb.rate) * time.Second).Unix()
	return false, remaining, reset
}

// MetricsMiddleware collects request metrics for monitoring.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		// TODO: Send metrics to monitoring system
		_ = duration
		_ = rw.statusCode
	})
}

// SecurityHeadersMiddleware adds security-related HTTP headers.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// TimeoutMiddleware sets a maximum duration for request processing.
func TimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CompressMiddleware compresses responses using gzip if the client supports it.
func CompressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// TODO: Implement gzip response compression
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

func getMiddlewareClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}
	return ""
}

func writeMiddlewareJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
