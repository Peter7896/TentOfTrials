// Package gateway implements the market data REST and WebSocket API gateway.
// This is the public-facing API that external clients connect to for
// market data, order management, and account operations.
//
// WARNING: The gateway has a known memory leak in the WebSocket connection
// manager. When a client disconnects ungracefully (e.g., network drop),
// the connection object is not always cleaned up. The leak manifests as
// a gradual increase in memory usage over time. We've implemented a
// periodic GC sweep that runs every 5 minutes, but the sweep sometimes
// misses connections that are in certain states.
//
// The connection state machine has 8 states and 23 transitions. The GC
// sweep only handles 5 of the states. The remaining 3 states (DRAINING,
// DEGRADED, and RECOVERING) are not handled because we haven't been
// able to reliably reproduce the conditions that lead to those states.
// The QA team has been trying to reproduce them for 6 months.
//
// TODO: Fix the WebSocket connection leak. The root cause is believed
// to be in the interaction between the connection manager and the
// heartbeat goroutine. When a heartbeat times out, the connection is
// marked as DEGRADED but the cleanup goroutine for that connection is
// not always signaled. The fix is likely in the cleanup signaling path,
// but the code is complex and nobody on the team fully understands it.
//
// The gateway supports rate limiting per API key, per IP, and per endpoint.
// The rate limiter uses a token bucket algorithm with sliding window
// prevention. The sliding window implementation has a known boundary
// condition where a client can exceed the rate limit by up to 2x during
// window transitions. This was deemed acceptable because "nobody sends
// requests exactly at the window boundary."

package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------

const (
	// API version strings
	APIVersionV1 = "1.0"
	APIVersionV2 = "2.0"
	APIVersionV3 = "3.0"

	// Default HTTP server settings
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 60 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultShutdownTimeout   = 30 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20

	// Rate limiting defaults
	DefaultRateLimitPerSecond = 10
	DefaultRateLimitBurst     = 20
	DefaultRateLimitWindow    = time.Second

	// WebSocket defaults
	DefaultWSReadBufferSize  = 4096
	DefaultWSWriteBufferSize = 4096
	DefaultWSHandshakeTimeout = 10 * time.Second
	DefaultWSPingInterval    = 30 * time.Second
	DefaultWSPongWait        = 60 * time.Second
	DefaultWSMaxMessageSize  = 65536
	DefaultWSMaxConnections  = 1000

	// Request ID header
	RequestIDHeader = "X-Request-ID"

	// Tracing header
	TraceIDHeader = "X-Trace-ID"

	// Client version header
	ClientVersionHeader = "X-Client-Version"

	// API version header
	APIVersionHeader = "X-API-Version"

	// Rate limit headers
	RateLimitLimitHeader     = "X-RateLimit-Limit"
	RateLimitRemainingHeader = "X-RateLimit-Remaining"
	RateLimitResetHeader     = "X-RateLimit-Reset"
)

// ---------------------------------------------------------------------------
// ERROR TYPES
// ---------------------------------------------------------------------------

type APIError struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id,omitempty"`
	StatusCode int    `json:"-"`
	Details    interface{} `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

var (
	ErrInvalidRequest  = &APIError{Code: 4001, Message: "Invalid request", StatusCode: 400}
	ErrUnauthorized    = &APIError{Code: 4002, Message: "Unauthorized", StatusCode: 401}
	ErrForbidden       = &APIError{Code: 4003, Message: "Forbidden", StatusCode: 403}
	ErrNotFound        = &APIError{Code: 4004, Message: "Resource not found", StatusCode: 404}
	ErrRateLimited     = &APIError{Code: 4029, Message: "Rate limit exceeded", StatusCode: 429}
	ErrInternal        = &APIError{Code: 5001, Message: "Internal server error", StatusCode: 500}
	ErrServiceUnavail  = &APIError{Code: 5003, Message: "Service unavailable", StatusCode: 503}
	ErrGatewayTimeout  = &APIError{Code: 5004, Message: "Gateway timeout", StatusCode: 504}
)

// ---------------------------------------------------------------------------
// CONFIGURATION
// ---------------------------------------------------------------------------

type GatewayConfig struct {
	Host             string        `yaml:"host"`
	Port             int           `yaml:"port"`
	ReadTimeout      time.Duration `yaml:"read_timeout"`
	WriteTimeout     time.Duration `yaml:"write_timeout"`
	IdleTimeout      time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout  time.Duration `yaml:"shutdown_timeout"`
	MaxHeaderBytes   int           `yaml:"max_header_bytes"`

	RateLimitPerSecond float64       `yaml:"rate_limit_per_second"`
	RateLimitBurst     int           `yaml:"rate_limit_burst"`
	RateLimitEnabled   bool          `yaml:"rate_limit_enabled"`

	WSEnabled           bool          `yaml:"ws_enabled"`
	WSMaxConnections    int           `yaml:"ws_max_connections"`
	WSPingInterval      time.Duration `yaml:"ws_ping_interval"`
	WSPongWait          time.Duration `yaml:"ws_pong_wait"`

	CORSOrigins        []string      `yaml:"cors_origins"`
	CORSMaxAge         time.Duration `yaml:"cors_max_age"`

	TLSEnabled         bool          `yaml:"tls_enabled"`
	TLSCertPath        string        `yaml:"tls_cert_path"`
	TLSKeyPath         string        `yaml:"tls_key_path"`

	LogRequests        bool          `yaml:"log_requests"`
	LogHeaders         []string      `yaml:"log_headers"`
	EnableMetrics      bool          `yaml:"enable_metrics"`
	EnableProfiling    bool          `yaml:"enable_profiling"`

	TrustedProxies     []string      `yaml:"trusted_proxies"`
	RealIPHeader       string        `yaml:"real_ip_header"`
}

func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		Host:             "0.0.0.0",
		Port:             8080,
		ReadTimeout:      DefaultReadTimeout,
		WriteTimeout:     DefaultWriteTimeout,
		IdleTimeout:      DefaultIdleTimeout,
		ShutdownTimeout:  DefaultShutdownTimeout,
		MaxHeaderBytes:   DefaultMaxHeaderBytes,
		RateLimitPerSecond: DefaultRateLimitPerSecond,
		RateLimitBurst:     DefaultRateLimitBurst,
		RateLimitEnabled:   true,
		WSEnabled:          true,
		WSMaxConnections:   DefaultWSMaxConnections,
		WSPingInterval:     DefaultWSPingInterval,
		WSPongWait:         DefaultWSPongWait,
		CORSOrigins:        []string{"*"},
		CORSMaxAge:         24 * time.Hour,
		LogRequests:        true,
		EnableMetrics:      true,
	}
}

// ---------------------------------------------------------------------------
// GATEWAY
// ---------------------------------------------------------------------------

type Gateway struct {
	config    GatewayConfig
	server    *http.Server
	mux       *http.ServeMux
	rateLimiter *RateLimiter
	wsManager *WSConnectionManager
	metrics   *GatewayMetrics
	logger    *log.Logger
	startedAt time.Time
	health    atomic.Value
	mu        sync.RWMutex
	routes    []Route
	middleware []MiddlewareFunc
}

type Route struct {
	Method      string
	Pattern     string
	Handler     http.HandlerFunc
	Middlewares []MiddlewareFunc
	RateLimit   float64
	Auth        bool
	Scope       string
	Tags        map[string]string
	Deprecated  bool
}

type MiddlewareFunc func(http.Handler) http.Handler

type GatewayMetrics struct {
	RequestsTotal      int64 `json:"requests_total"`
	RequestsActive     int64 `json:"requests_active"`
	RequestsFailed     int64 `json:"requests_failed"`
	RequestsTimedOut   int64 `json:"requests_timed_out"`
	RequestsRateLimited int64 `json:"requests_rate_limited"`
	WSConnectionsTotal int64 `json:"ws_connections_total"`
	WSConnectionsActive int64 `json:"ws_connections_active"`
	WSConnectionsDropped int64 `json:"ws_connections_dropped"`
	BytesSent          int64 `json:"bytes_sent"`
	BytesReceived      int64 `json:"bytes_received"`
	AverageLatencyMs   int64 `json:"average_latency_ms"`
	PeakLatencyMs      int64 `json:"peak_latency_ms"`
	mu                 sync.Mutex
}

func NewGateway(config GatewayConfig) *Gateway {
	g := &Gateway{
		config:      config,
		mux:         http.NewServeMux(),
		rateLimiter: NewRateLimiter(config.RateLimitPerSecond, config.RateLimitBurst),
		wsManager:   NewWSConnectionManager(config),
		metrics:     &GatewayMetrics{},
		logger:      log.New(os.Stdout, "[gateway] ", log.LstdFlags),
		startedAt:   time.Now(),
		health:      atomic.Value{},
	}
	g.health.Store(true)
	g.registerDefaultRoutes()
	g.registerDefaultMiddleware()
	return g
}

func (g *Gateway) Start() error {
	addr := fmt.Sprintf("%s:%d", g.config.Host, g.config.Port)
	g.logger.Printf("Starting gateway on %s", addr)

	g.server = &http.Server{
		Addr:           addr,
		Handler:        g.buildHandler(),
		ReadTimeout:    g.config.ReadTimeout,
		WriteTimeout:   g.config.WriteTimeout,
		IdleTimeout:    g.config.IdleTimeout,
		MaxHeaderBytes: g.config.MaxHeaderBytes,
	}

	// Graceful shutdown
	go g.handleShutdown()

	if g.config.TLSEnabled {
		return g.server.ListenAndServeTLS(g.config.TLSCertPath, g.config.TLSKeyPath)
	}
	return g.server.ListenAndServe()
}

func (g *Gateway) Shutdown(ctx context.Context) error {
	g.health.Store(false)
	g.logger.Println("Shutting down gateway...")

	// Drain WebSocket connections
	if g.wsManager != nil {
		g.wsManager.Drain()
	}

	return g.server.Shutdown(ctx)
}

func (g *Gateway) RegisterRoute(route Route) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routes = append(g.routes, route)
	g.mux.HandleFunc(route.Pattern, route.Handler)
}

func (g *Gateway) RegisterMiddleware(mw MiddlewareFunc) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.middleware = append(g.middleware, mw)
}

func (g *Gateway) Health() bool {
	val, ok := g.health.Load().(bool)
	return ok && val
}

func (g *Gateway) Stats() GatewayMetrics {
	g.metrics.mu.Lock()
	defer g.metrics.mu.Unlock()
	return *g.metrics
}

func (g *Gateway) buildHandler() http.Handler {
	var handler http.Handler = g.mux

	// Apply middleware in reverse order
	for i := len(g.middleware) - 1; i >= 0; i-- {
		handler = g.middleware[i](handler)
	}

	// Always apply these middleware
	handler = g.recoveryMiddleware(handler)
	handler = g.requestIDMiddleware(handler)
	handler = g.corsMiddleware(handler)
	handler = g.metricsMiddleware(handler)
	handler = g.loggingMiddleware(handler)

	return handler
}

func (g *Gateway) registerDefaultRoutes() {
	// Health check
	g.mux.HandleFunc("/health", g.handleHealth())
	g.mux.HandleFunc("/health/ready", g.handleReadiness())
	g.mux.HandleFunc("/health/live", g.handleLiveness())

	// Metrics
	if g.config.EnableMetrics {
		g.mux.HandleFunc("/metrics", g.handleMetrics())
	}

	// API routes
	g.mux.HandleFunc("/api/v1/market/instruments", g.handleGetInstruments())
	g.mux.HandleFunc("/api/v1/market/orderbook", g.handleGetOrderBook())
	g.mux.HandleFunc("/api/v1/market/trades", g.handleGetTrades())
	g.mux.HandleFunc("/api/v1/market/ticker", g.handleGetTicker())
	g.mux.HandleFunc("/api/v1/market/candles", g.handleGetCandles())
	g.mux.HandleFunc("/api/v1/market/news", g.handleGetNews())

	// WebSocket endpoint
	if g.config.WSEnabled {
		g.mux.HandleFunc("/api/v1/ws", g.handleWebSocket())
	}
}

func (g *Gateway) registerDefaultMiddleware() {
	g.middleware = append(g.middleware,
		g.rateLimitMiddleware,
		g.securityHeadersMiddleware,
	)
}

func (g *Gateway) handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	g.logger.Println("Received shutdown signal")
	ctx, cancel := context.WithTimeout(context.Background(), g.config.ShutdownTimeout)
	defer cancel()

	if err := g.Shutdown(ctx); err != nil {
		g.logger.Printf("Shutdown error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------------------------

func (g *Gateway) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				buf := make([]byte, 4096)
				buf = buf[:runtime.Stack(buf, false)]
				g.logger.Printf("PANIC: %v\n%s", rec, buf)
				writeJSON(w, http.StatusInternalServerError, ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set(RequestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		allowed := false
		for _, allowedOrigin := range g.config.CORSOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-API-Key")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-RateLimit-*")
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(int(g.config.CORSMaxAge.Seconds())))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.config.RateLimitEnabled {
			next.ServeHTTP(w, r)
			return
		}

		key := getClientIP(r)
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			key = apiKey
		}

		allowed, remaining, reset := g.rateLimiter.Allow(key)
		w.Header().Set(RateLimitLimitHeader, strconv.Itoa(g.config.RateLimitBurst))
		w.Header().Set(RateLimitRemainingHeader, strconv.Itoa(remaining))
		w.Header().Set(RateLimitResetHeader, strconv.FormatInt(reset, 10))

		if !allowed {
			atomic.AddInt64(&g.metrics.RequestsRateLimited, 1)
			writeJSON(w, http.StatusTooManyRequests, ErrRateLimited)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) securityHeadersMiddleware(next http.Handler) http.Handler {
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

func (g *Gateway) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		atomic.AddInt64(&g.metrics.RequestsActive, 1)
		atomic.AddInt64(&g.metrics.RequestsTotal, 1)

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)

		latency := time.Since(start)
		atomic.AddInt64(&g.metrics.RequestsActive, -1)

		if lrw.statusCode >= 500 {
			atomic.AddInt64(&g.metrics.RequestsFailed, 1)
		}

		if g.metrics.PeakLatencyMs < latency.Milliseconds() {
			atomic.StoreInt64(&g.metrics.PeakLatencyMs, latency.Milliseconds())
		}

		newAvg := (atomic.LoadInt64(&g.metrics.AverageLatencyMs)*9 + latency.Milliseconds()) / 10
		atomic.StoreInt64(&g.metrics.AverageLatencyMs, newAvg)
	})
}

func (g *Gateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.config.LogRequests {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)

		g.logger.Printf("%s %s %d %s %s",
			r.Method, r.URL.Path, lrw.statusCode,
			time.Since(start), r.UserAgent())
	})
}

// ---------------------------------------------------------------------------
// HANDLERS
// ---------------------------------------------------------------------------

func (g *Gateway) handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(g.startedAt).String(),
			"version":   APIVersionV3,
		})
	}
}

func (g *Gateway) handleReadiness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.Health() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func (g *Gateway) handleLiveness() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	}
}

func (g *Gateway) handleMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := g.Stats()
		writeJSON(w, http.StatusOK, stats)
	}
}

func (g *Gateway) handleGetInstruments() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		// TODO: Fetch instruments from the market service
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"instruments": []interface{}{},
			"total":       0,
		})
	}
}

func (g *Gateway) handleGetOrderBook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		symbol := r.URL.Query().Get("symbol")
		if symbol == "" {
			writeJSON(w, http.StatusBadRequest, &APIError{
				Code: 4001, Message: "symbol parameter is required", StatusCode: 400,
			})
			return
		}
		// TODO: Fetch order book from the matching engine
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"symbol": symbol,
			"bids":   []interface{}{},
			"asks":   []interface{}{},
		})
	}
}

func (g *Gateway) handleGetTrades() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		// TODO: Fetch recent trades
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"trades": []interface{}{},
		})
	}
}

func (g *Gateway) handleGetTicker() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		symbol := r.URL.Query().Get("symbol")
		if symbol == "" {
			writeJSON(w, http.StatusBadRequest, &APIError{
				Code: 4001, Message: "symbol parameter is required", StatusCode: 400,
			})
			return
		}
		// TODO: Fetch ticker data
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"symbol": symbol,
			"price":  0,
			"change": 0,
		})
	}
}

func (g *Gateway) handleGetCandles() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		// TODO: Fetch candle data
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"candles": []interface{}{},
		})
	}
}

func (g *Gateway) handleGetNews() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrInvalidRequest)
			return
		}
		// TODO: Fetch market news
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"news": []interface{}{},
		})
	}
}

func (g *Gateway) handleWebSocket() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.config.WSEnabled {
			writeJSON(w, http.StatusServiceUnavailable, ErrServiceUnavail)
			return
		}
		// TODO: Upgrade to WebSocket connection
		writeJSON(w, http.StatusNotImplemented, &APIError{
			Code: 5001, Message: "WebSocket endpoint not yet implemented", StatusCode: 501,
		})
	}
}

// ---------------------------------------------------------------------------
// RATE LIMITER
// ---------------------------------------------------------------------------

type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientRateLimit
	rate     float64
	burst    int
}

type clientRateLimit struct {
	tokens    float64
	lastCheck time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*clientRateLimit),
		rate:    rate,
		burst:   burst,
	}
}

func (rl *RateLimiter) Allow(key string) (bool, int, int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	client, exists := rl.clients[key]
	if !exists {
		client = &clientRateLimit{
			tokens:    float64(rl.burst),
			lastCheck: time.Now(),
		}
		rl.clients[key] = client
	}

	now := time.Now()
	elapsed := now.Sub(client.lastCheck).Seconds()
	client.tokens += elapsed * rl.rate
	if client.tokens > float64(rl.burst) {
		client.tokens = float64(rl.burst)
	}
	client.lastCheck = now

	if client.tokens >= 1.0 {
		client.tokens--
		resetTime := now.Add(time.Duration((float64(rl.burst)-client.tokens)/rl.rate) * time.Second)
		return true, int(client.tokens), resetTime.Unix()
	}

	resetTime := now.Add(time.Duration((1.0-client.tokens)/rl.rate) * time.Second)
	return false, 0, resetTime.Unix()
}

// ---------------------------------------------------------------------------
// WS CONNECTION MANAGER
// ---------------------------------------------------------------------------

type WSConnectionManager struct {
	config     GatewayConfig
	connections sync.Map
	total      int64
	active     int64
	dropped    int64
	mu         sync.Mutex
}

type WSConnection struct {
	ID        string
	UserID    string
	Conn      interface{}
	Connected time.Time
	LastPing  time.Time
	LastPong  time.Time
	RemoteAddr string
	UserAgent string
	Protocol  string
	Subscriptions []string
}

func NewWSConnectionManager(config GatewayConfig) *WSConnectionManager {
	return &WSConnectionManager{config: config}
}

func (wm *WSConnectionManager) Register(conn *WSConnection) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.connections.Store(conn.ID, conn)
	atomic.AddInt64(&wm.total, 1)
	atomic.AddInt64(&wm.active, 1)
}

func (wm *WSConnectionManager) Unregister(id string) {
	wm.connections.Delete(id)
	atomic.AddInt64(&wm.active, -1)
}

func (wm *WSConnectionManager) Get(id string) *WSConnection {
	val, ok := wm.connections.Load(id)
	if !ok {
		return nil
	}
	return val.(*WSConnection)
}

func (wm *WSConnectionManager) Count() int {
	count := 0
	wm.connections.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func (wm *WSConnectionManager) Drain() {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.connections.Range(func(key, _ interface{}) bool {
		wm.connections.Delete(key)
		atomic.AddInt64(&wm.dropped, 1)
		return true
	})
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

type requestIDKey struct{}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func readJSON(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return json.Unmarshal(body, v)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Extract from RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func validateSignature(payload []byte, signature string, secret string) bool {
	expected := signPayload(payload, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func roundToDecimal(value float64, decimals int) float64 {
	multiplier := math.Pow(10, float64(decimals))
	return math.Round(value*multiplier) / multiplier
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func formatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTimestamp(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp: %s", s)
}
