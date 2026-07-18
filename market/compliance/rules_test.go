package compliance

import (
	"testing"
	"time"
)

func TestRuleEngineCacheHitReturnsCachedResult(t *testing.T) {
	engine := newCacheTestEngine()
	engine.SetCacheTTL(time.Minute)

	ctx := validRuleContext()
	first, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}

	ctx.KYCStatus = "expired"
	second, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if second != first {
		t.Fatalf("expected cached result pointer, got first=%p second=%p", first, second)
	}
	if !second.Passed {
		t.Fatalf("expected cached passing result, got %+v", second)
	}
}

func TestRuleEngineDefaultCacheTTL(t *testing.T) {
	engine := NewRuleEngine()

	if engine.cacheTTL != 5*time.Minute {
		t.Fatalf("expected default cache TTL to be 5m, got %s", engine.cacheTTL)
	}
}

func TestRuleEngineCacheEntryExpiresAfterTTL(t *testing.T) {
	engine := newCacheTestEngine()
	engine.SetCacheTTL(time.Millisecond)

	ctx := validRuleContext()
	first, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}

	cacheKey := engine.generateCacheKey(ctx)
	engine.mu.Lock()
	entry := engine.cache[cacheKey]
	entry.cachedAt = time.Now().Add(-time.Second)
	engine.cache[cacheKey] = entry
	engine.mu.Unlock()

	ctx.KYCStatus = "expired"
	second, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if second == first {
		t.Fatal("expected expired cache entry to be refreshed")
	}
	if second.Passed || second.RuleID != "KYC-002" {
		t.Fatalf("expected refreshed KYC expiry failure, got %+v", second)
	}

	engine.mu.RLock()
	_, ok := engine.cache[cacheKey]
	engine.mu.RUnlock()
	if !ok {
		t.Fatal("expected refreshed result to be cached after expiry")
	}
}

func TestRuleEngineZeroTTLDisablesCache(t *testing.T) {
	engine := newCacheTestEngine()
	engine.SetCacheTTL(0)

	ctx := validRuleContext()
	first, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}

	ctx.KYCStatus = "expired"
	second, err := engine.Evaluate(ctx)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if second == first {
		t.Fatal("expected cache to be disabled")
	}
	if second.Passed || second.RuleID != "KYC-002" {
		t.Fatalf("expected KYC expiry failure when cache disabled, got %+v", second)
	}

	engine.mu.RLock()
	cacheSize := len(engine.cache)
	engine.mu.RUnlock()
	if cacheSize != 0 {
		t.Fatalf("expected disabled cache to stay empty, got %d entries", cacheSize)
	}
}

func newCacheTestEngine() *RuleEngine {
	engine := NewRuleEngine()
	engine.frameworks = []*RegulatoryFramework{
		{
			ID:           "TEST-KYC",
			Name:         "Test KYC Rules",
			Jurisdiction: JurisdictionGlobal,
			Version:      "test",
			Rules: []ComplianceRule{
				{
					ID:       "TEST-KYC-001",
					Name:     "Test KYC Rule",
					Category: RuleCategoryKYC,
					Severity: RuleSeverityHigh,
					Action:   RuleActionBlock,
				},
			},
		},
	}
	return engine
}

func validRuleContext() *RuleContext {
	return &RuleContext{
		UserID:             "user-123",
		AccountID:          "acct-123",
		InstrumentID:       "AAPL",
		Side:               "buy",
		OrderType:          "limit",
		Quantity:           1,
		Price:              100,
		TotalValue:         100,
		CountryOfResidence: "US",
		KYCStatus:          "approved",
		AMLStatus:          "approved",
		RiskScore:          0.1,
	}
}
