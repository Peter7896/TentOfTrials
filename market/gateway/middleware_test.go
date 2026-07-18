package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddlewareWithVerifierAllowsValidToken(t *testing.T) {
	verifier := TokenVerifierFunc(func(ctx context.Context, token string) (TokenClaims, error) {
		if token != "good-token" {
			return TokenClaims{}, errors.New("unexpected token")
		}
		return TokenClaims{
			UserID:    "user-123",
			SessionID: "session-456",
		}, nil
	})

	handler := AuthMiddlewareWithVerifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Context().Value(ContextKeyUserID); got != "user-123" {
			t.Fatalf("user id context = %v", got)
		}
		if got := r.Context().Value(ContextKeySessionID); got != "session-456" {
			t.Fatalf("session id context = %v", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}), verifier)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestAuthMiddlewareWithVerifierRejectsInvalidToken(t *testing.T) {
	calledProtectedHandler := false
	verifier := TokenVerifierFunc(func(ctx context.Context, token string) (TokenClaims, error) {
		return TokenClaims{}, errors.New("bad token")
	})
	handler := AuthMiddlewareWithVerifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledProtectedHandler = true
	}), verifier)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if calledProtectedHandler {
		t.Fatal("protected handler was called for rejected token")
	}
}

func TestAuthMiddlewareRejectsMissingVerifierByDefault(t *testing.T) {
	calledProtectedHandler := false
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledProtectedHandler = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer arbitrary-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if calledProtectedHandler {
		t.Fatal("protected handler was called without a configured verifier")
	}
}

func TestAuthMiddlewareRejectsMissingAndMalformedTokens(t *testing.T) {
	handler := AuthMiddlewareWithVerifier(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("protected handler should not be called")
	}), TokenVerifierFunc(func(ctx context.Context, token string) (TokenClaims, error) {
		t.Fatal("verifier should not be called for missing token")
		return TokenClaims{}, nil
	}))

	for _, authorization := range []string{"", "Bearer "} {
		t.Run("authorization="+authorization, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", authorization)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	}
}
