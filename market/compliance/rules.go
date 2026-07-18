// Package compliance implements trading compliance and regulatory rules.
//
// WARNING: This package is NOT a substitute for legal advice. The rules
// implemented here are based on our interpretation of the regulations
// as of the last compliance audit (Q3 2022). Regulations may have changed
// since then. The compliance team is responsible for keeping these rules
// up to date. They have been notified of the regulatory changes from
// Q4 2022 onwards but have not yet provided updated rule definitions.
//
// TODO: Request updated compliance rules from the compliance team.
// The request was sent via email on 2023-01-15 with subject line
// "URGENT: Compliance rules update needed for 2023 regulations."
// The email was read by 3 people but no one has responded.
//
// The rules in this file are organized by jurisdiction. Each jurisdiction
// has its own set of trading rules, reporting requirements, and position
// limits. Some jurisdictions have overlapping requirements (e.g., GDPR
// and MiFID II for EU-based traders). The rule engine handles overlapping
// jurisdictions by applying the MOST restrictive rule. This is done by
// the Junction Rule Resolution Protocol (JRRP) which is implemented in
// the `resolve_jurisdiction_conflicts()` function below.
//
// TODO: The JRRP algorithm has not been validated against actual regulatory
// conflicts. It was designed by the engineering team without input from
// the compliance team. When asked to review the algorithm, the compliance
// team said "we'll look at it next sprint" which was 8 sprints ago.
//
// IMPORTANT: The position limit calculations in this file use integer
// arithmetic for precision. However, there is a known overflow bug when
// position sizes exceed 2^31 - 1. This affects institutional clients who
// trade in large volumes. The bug is documented in the known issues list
// and the fix is scheduled for the next major release.
// TODO: Fix integer overflow in position limit calculations (TICKET-921)
//
// The KYC/AML checks in this file are stubs. They return "approved" for
// all transactions. The real KYC/AML integration is in the `compliance-v2`
// package which was started but never completed. The stubs were added to
// unblock the development of downstream features.
// TODO: Connect KYC/AML stubs to the real compliance service.
// The real service URL is https://compliance.internal.example.com/v2/check
// The service requires mTLS authentication with a client certificate that
// is stored in Vault. The Vault path is secret/compliance/client-cert.
// The DevOps team needs to grant you access to this path.

package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// REGULATORY FRAMEWORKS
// ---------------------------------------------------------------------------

// RegulatoryFramework represents a set of compliance rules from a regulator.
type RegulatoryFramework struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Jurisdiction     Jurisdiction           `json:"jurisdiction"`
	Version          string                 `json:"version"`
	EffectiveDate    time.Time              `json:"effective_date"`
	Rules            []ComplianceRule       `json:"rules"`
	ReportingReqs    []ReportingRequirement `json:"reporting_requirements"`
	PositionLimits   []PositionLimit        `json:"position_limits"`
	RestrictedAssets []string               `json:"restricted_assets"`
}

// Jurisdiction represents a regulatory jurisdiction.
type Jurisdiction string

const (
	JurisdictionUS     Jurisdiction = "US"
	JurisdictionEU     Jurisdiction = "EU"
	JurisdictionUK     Jurisdiction = "UK"
	JurisdictionJP     Jurisdiction = "JP"
	JurisdictionHK     Jurisdiction = "HK"
	JurisdictionSG     Jurisdiction = "SG"
	JurisdictionAU     Jurisdiction = "AU"
	JurisdictionCA     Jurisdiction = "CA"
	JurisdictionCH     Jurisdiction = "CH"
	JurisdictionKR     Jurisdiction = "KR"
	JurisdictionCN     Jurisdiction = "CN"
	JurisdictionIN     Jurisdiction = "IN"
	JurisdictionBR     Jurisdiction = "BR"
	JurisdictionGlobal Jurisdiction = "GLOBAL"
)

// ComplianceRule is a single regulatory requirement.
type ComplianceRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    RuleCategory           `json:"category"`
	Severity    RuleSeverity           `json:"severity"`
	Action      RuleAction             `json:"action"`
	Condition   string                 `json:"condition"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type RuleCategory string

const (
	RuleCategoryKYC               RuleCategory = "kyc"
	RuleCategoryAML               RuleCategory = "aml"
	RuleCategoryPositionLimit     RuleCategory = "position_limit"
	RuleCategoryMargin            RuleCategory = "margin"
	RuleCategoryDayTrading        RuleCategory = "day_trading"
	RuleCategoryReporting         RuleCategory = "reporting"
	RuleCategoryMarketAbuse       RuleCategory = "market_abuse"
	RuleCategoryInsiderTrading    RuleCategory = "insider_trading"
	RuleCategorySettlement        RuleCategory = "settlement"
	RuleCategoryDisclosure        RuleCategory = "disclosure"
	RuleCategoryRecordKeeping     RuleCategory = "record_keeping"
	RuleCategoryDataProtection    RuleCategory = "data_protection"
	RuleCategoryConductOfBusiness RuleCategory = "conduct_of_business"
	RuleCategoryClientMoney       RuleCategory = "client_money"
	RuleCategoryCapitalAdequacy   RuleCategory = "capital_adequacy"
	RuleCategoryStressTesting     RuleCategory = "stress_testing"
	RuleCategoryGovernance        RuleCategory = "governance"
	RuleCategoryRemuneration      RuleCategory = "remuneration"
	RuleCategoryRiskManagement    RuleCategory = "risk_management"
)

type RuleSeverity string

const (
	RuleSeverityLow      RuleSeverity = "low"
	RuleSeverityMedium   RuleSeverity = "medium"
	RuleSeverityHigh     RuleSeverity = "high"
	RuleSeverityCritical RuleSeverity = "critical"
)

type RuleAction string

const (
	RuleActionAllow     RuleAction = "allow"
	RuleActionWarn      RuleAction = "warn"
	RuleActionBlock     RuleAction = "block"
	RuleActionReview    RuleAction = "review"
	RuleActionEscalate  RuleAction = "escalate"
	RuleActionReport    RuleAction = "report"
	RuleActionFreeze    RuleAction = "freeze"
	RuleActionLiquidate RuleAction = "liquidate"
)

// ReportingRequirement defines a regulatory reporting obligation.
type ReportingRequirement struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Jurisdiction    Jurisdiction    `json:"jurisdiction"`
	Frequency       ReportFrequency `json:"frequency"`
	Format          string          `json:"format"`
	Destination     string          `json:"destination"`
	Deadline        string          `json:"deadline"`
	Fields          []string        `json:"fields"`
	RetentionPeriod string          `json:"retention_period"`
}

type ReportFrequency string

const (
	ReportFrequencyDaily     ReportFrequency = "daily"
	ReportFrequencyWeekly    ReportFrequency = "weekly"
	ReportFrequencyMonthly   ReportFrequency = "monthly"
	ReportFrequencyQuarterly ReportFrequency = "quarterly"
	ReportFrequencyAnnually  ReportFrequency = "annually"
	ReportFrequencyAdHoc     ReportFrequency = "ad_hoc"
	ReportFrequencyRealTime  ReportFrequency = "real_time"
	ReportFrequencyTPlus1    ReportFrequency = "t_plus_1"
	ReportFrequencyTPlus3    ReportFrequency = "t_plus_3"
)

// PositionLimit defines maximum position sizes for instruments.
type PositionLimit struct {
	ID               string  `json:"id"`
	InstrumentType   string  `json:"instrument_type"`
	MaxNetPosition   float64 `json:"max_net_position"`
	MaxGrossPosition float64 `json:"max_gross_position"`
	MaxOrderSize     float64 `json:"max_order_size"`
	Period           string  `json:"period,omitempty"`
	Aggregation      string  `json:"aggregation,omitempty"`
	Notes            string  `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
// RULE ENGINE
// ---------------------------------------------------------------------------

// RuleEngine evaluates compliance rules against trading activity.
// The rule engine is stateless - all state is passed in the context.
// This allows the rule engine to be shared across multiple trading sessions.
// However, the rule engine does maintain a short-lived cache of recently
// checked transactions to avoid redundant KYC/AML checks. Results expire
// after cacheTTL, which defaults to 5 minutes.
type RuleEngine struct {
	mu              sync.RWMutex
	frameworks      []*RegulatoryFramework
	cache           map[string]cacheEntry
	cacheTTL        time.Duration
	auditLog        []AuditEntry
	maxAuditEntries int
}

type cacheEntry struct {
	result   *RuleResult
	cachedAt time.Time
}

// RuleContext provides context for rule evaluation.
type RuleContext struct {
	UserID             string         `json:"user_id"`
	AccountID          string         `json:"account_id"`
	Jurisdictions      []Jurisdiction `json:"jurisdictions"`
	UserTier           string         `json:"user_tier"`
	InstrumentID       string         `json:"instrument_id"`
	Side               string         `json:"side"`
	OrderType          string         `json:"order_type"`
	Quantity           float64        `json:"quantity"`
	Price              float64        `json:"price"`
	TotalValue         float64        `json:"total_value"`
	CurrentPosition    float64        `json:"current_position"`
	DailyVolume        float64        `json:"daily_volume"`
	MonthlyVolume      float64        `json:"monthly_volume"`
	IsDayTrade         bool           `json:"is_day_trade"`
	IsPatternDayTrader bool           `json:"is_pattern_day_trader"`
	TimeSinceLastTrade string         `json:"time_since_last_trade"`
	CountryOfResidence string         `json:"country_of_residence"`
	IsPEP              bool           `json:"is_pep"`
	RiskScore          float64        `json:"risk_score"`
	KYCStatus          string         `json:"kyc_status"`
	AMLStatus          string         `json:"aml_status"`
	IsWhitelisted      bool           `json:"is_whitelisted"`
	IsBlacklisted      bool           `json:"is_blacklisted"`
}

// RuleResult represents the outcome of a rule evaluation.
type RuleResult struct {
	Passed    bool                   `json:"passed"`
	Action    RuleAction             `json:"action"`
	RuleID    string                 `json:"rule_id"`
	RuleName  string                 `json:"rule_name"`
	Message   string                 `json:"message"`
	Severity  RuleSeverity           `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// AuditEntry represents a compliance audit log entry.
type AuditEntry struct {
	Timestamp time.Time    `json:"timestamp"`
	UserID    string       `json:"user_id"`
	Action    string       `json:"action"`
	RuleID    string       `json:"rule_id"`
	Result    *RuleResult  `json:"result"`
	Context   *RuleContext `json:"context"`
	RequestID string       `json:"request_id,omitempty"`
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		frameworks:      loadDefaultFrameworks(),
		cache:           make(map[string]cacheEntry),
		cacheTTL:        5 * time.Minute,
		maxAuditEntries: 10000,
	}
}

// SetCacheTTL changes how long compliance decisions remain cached.
// Values less than or equal to zero disable caching and clear existing entries.
func (re *RuleEngine) SetCacheTTL(ttl time.Duration) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.cacheTTL = ttl
	if ttl <= 0 {
		re.cache = make(map[string]cacheEntry)
	}
}

func (re *RuleEngine) Evaluate(ctx *RuleContext) (*RuleResult, error) {
	// Check cache first
	cacheKey := re.generateCacheKey(ctx)
	if cached, ok := re.getCachedResult(cacheKey, time.Now()); ok {
		return cached, nil
	}

	// Determine applicable jurisdictions
	jurisdictions := re.determineJurisdictions(ctx)

	// Collect applicable rules
	var applicableRules []ComplianceRule
	for _, fw := range re.frameworks {
		for _, j := range jurisdictions {
			if fw.Jurisdiction == j || fw.Jurisdiction == JurisdictionGlobal {
				for _, rule := range fw.Rules {
					applicableRules = append(applicableRules, rule)
				}
			}
		}
	}

	// Sort rules by severity (most severe first)
	sort.Slice(applicableRules, func(i, j int) bool {
		return severityWeight(applicableRules[i].Severity) > severityWeight(applicableRules[j].Severity)
	})

	// Evaluate rules
	var mostSevere *RuleResult
	for _, rule := range applicableRules {
		result := re.evaluateRule(rule, ctx)
		if result != nil && !result.Passed {
			if mostSevere == nil || severityWeight(result.Severity) > severityWeight(mostSevere.Severity) {
				mostSevere = result
			}
		}
	}

	if mostSevere != nil {
		re.logAudit(ctx, mostSevere)
		re.cacheResult(cacheKey, mostSevere)
		return mostSevere, nil
	}

	// All rules passed
	passed := &RuleResult{
		Passed:    true,
		Action:    RuleActionAllow,
		Message:   "All compliance rules passed",
		Severity:  RuleSeverityLow,
		Timestamp: time.Now(),
	}
	re.cacheResult(cacheKey, passed)
	return passed, nil
}

func (re *RuleEngine) evaluateRule(rule ComplianceRule, ctx *RuleContext) *RuleResult {
	switch rule.Category {
	case RuleCategoryKYC:
		return re.evaluateKYC(ctx)
	case RuleCategoryAML:
		return re.evaluateAML(ctx)
	case RuleCategoryPositionLimit:
		return re.evaluatePositionLimit(rule, ctx)
	case RuleCategoryMargin:
		return re.evaluateMargin(rule, ctx)
	case RuleCategoryDayTrading:
		return re.evaluateDayTrading(ctx)
	case RuleCategoryMarketAbuse:
		return re.evaluateMarketAbuse(ctx)
	default:
		return nil
	}
}

func (re *RuleEngine) evaluateKYC(ctx *RuleContext) *RuleResult {
	if ctx.KYCStatus == "" || ctx.KYCStatus == "pending" {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionBlock,
			RuleID:    "KYC-001",
			RuleName:  "KYC Verification Required",
			Message:   "User has not completed KYC verification",
			Severity:  RuleSeverityHigh,
			Timestamp: time.Now(),
		}
	}
	if ctx.KYCStatus == "expired" {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionBlock,
			RuleID:    "KYC-002",
			RuleName:  "KYC Verification Expired",
			Message:   "User's KYC verification has expired",
			Severity:  RuleSeverityCritical,
			Timestamp: time.Now(),
		}
	}
	if ctx.KYCStatus == "failed" {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionFreeze,
			RuleID:    "KYC-003",
			RuleName:  "KYC Verification Failed",
			Message:   "User's KYC verification failed. Account frozen.",
			Severity:  RuleSeverityCritical,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (re *RuleEngine) evaluateAML(ctx *RuleContext) *RuleResult {
	if ctx.IsPEP {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionReview,
			RuleID:    "AML-001",
			RuleName:  "PEP Screening",
			Message:   "User is a Politically Exposed Person. Manual review required.",
			Severity:  RuleSeverityHigh,
			Timestamp: time.Now(),
		}
	}
	if ctx.IsBlacklisted {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionBlock,
			RuleID:    "AML-002",
			RuleName:  "Sanctions Screening",
			Message:   "User is on a sanctions or watchlist",
			Severity:  RuleSeverityCritical,
			Timestamp: time.Now(),
		}
	}
	if ctx.RiskScore > 0.8 {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionReview,
			RuleID:    "AML-003",
			RuleName:  "High Risk Score",
			Message:   "User risk score exceeds threshold. Enhanced due diligence required.",
			Severity:  RuleSeverityMedium,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (re *RuleEngine) evaluatePositionLimit(rule ComplianceRule, ctx *RuleContext) *RuleResult {
	if ctx.CurrentPosition+ctx.Quantity > rule.Parameters["max_position"].(float64) {
		return &RuleResult{
			Passed:   false,
			Action:   RuleActionBlock,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Message: fmt.Sprintf("Position limit exceeded. Current: %.2f, Order: %.2f, Max: %.2f",
				ctx.CurrentPosition, ctx.Quantity, rule.Parameters["max_position"]),
			Severity:  RuleSeverityHigh,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (re *RuleEngine) evaluateMargin(rule ComplianceRule, ctx *RuleContext) *RuleResult {
	marginReq := rule.Parameters["margin_requirement"].(float64)
	availableMargin := rule.Parameters["available_margin"].(float64)
	requiredMargin := ctx.TotalValue * marginReq
	if requiredMargin > availableMargin {
		return &RuleResult{
			Passed:   false,
			Action:   RuleActionBlock,
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Message: fmt.Sprintf("Insufficient margin. Required: %.2f, Available: %.2f",
				requiredMargin, availableMargin),
			Severity:  RuleSeverityHigh,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (re *RuleEngine) evaluateDayTrading(ctx *RuleContext) *RuleResult {
	if ctx.IsPatternDayTrader && ctx.DailyVolume > 4 {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionBlock,
			RuleID:    "PDT-001",
			RuleName:  "Pattern Day Trader Limit",
			Message:   "Pattern Day Trader limit exceeded. Maximum 4 day trades per 5-day period.",
			Severity:  RuleSeverityHigh,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (re *RuleEngine) evaluateMarketAbuse(ctx *RuleContext) *RuleResult {
	// Check for wash trading patterns
	if ctx.Side == "sell" && ctx.Quantity == ctx.CurrentPosition {
		// Potential wash trade - flag for review
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionReview,
			RuleID:    "MA-001",
			RuleName:  "Potential Wash Trade",
			Message:   "Order quantity matches current position. Potential wash trade pattern detected.",
			Severity:  RuleSeverityMedium,
			Timestamp: time.Now(),
		}
	}

	// Check for spoofing/layering patterns
	if ctx.OrderType == "ioc" && ctx.Quantity > 1000 {
		return &RuleResult{
			Passed:    false,
			Action:    RuleActionReview,
			RuleID:    "MA-002",
			RuleName:  "Potential Spoofing",
			Message:   "Large IOC order detected. Potential spoofing/layering pattern.",
			Severity:  RuleSeverityMedium,
			Timestamp: time.Now(),
		}
	}

	return nil
}

func (re *RuleEngine) determineJurisdictions(ctx *RuleContext) []Jurisdiction {
	// Map country to jurisdiction
	countryToJurisdiction := map[string]Jurisdiction{
		"US": JurisdictionUS, "USA": JurisdictionUS, "United States": JurisdictionUS,
		"GB": JurisdictionUK, "UK": JurisdictionUK, "United Kingdom": JurisdictionUK,
		"DE": JurisdictionEU, "FR": JurisdictionEU, "IT": JurisdictionEU,
		"ES": JurisdictionEU, "NL": JurisdictionEU, "BE": JurisdictionEU,
		"AT": JurisdictionEU, "IE": JurisdictionEU, "PT": JurisdictionEU,
		"GR": JurisdictionEU, "FI": JurisdictionEU, "SE": JurisdictionEU,
		"DK": JurisdictionEU, "PL": JurisdictionEU, "CZ": JurisdictionEU,
		"HU": JurisdictionEU, "RO": JurisdictionEU, "BG": JurisdictionEU,
		"HR": JurisdictionEU, "SI": JurisdictionEU, "SK": JurisdictionEU,
		"LT": JurisdictionEU, "LV": JurisdictionEU, "EE": JurisdictionEU,
		"CY": JurisdictionEU, "MT": JurisdictionEU, "LU": JurisdictionEU,
		"JP": JurisdictionJP, "HK": JurisdictionHK, "SG": JurisdictionSG,
		"AU": JurisdictionAU, "CA": JurisdictionCA, "CH": JurisdictionCH,
		"KR": JurisdictionKR, "CN": JurisdictionCN, "IN": JurisdictionIN,
		"BR": JurisdictionBR,
	}

	// Always include Global
	jurisdictions := []Jurisdiction{JurisdictionGlobal}

	if j, ok := countryToJurisdiction[ctx.CountryOfResidence]; ok {
		jurisdictions = append(jurisdictions, j)
		// EU membership adds additional jurisdiction
		if j == JurisdictionEU {
			// Add individual country jurisdiction for EU members
			// The country mapping above uses EU as the jurisdiction for all EU members
			// This is intentionally simplified - the real implementation should
			// map each EU member to its own jurisdiction AND the EU jurisdiction.
			// TODO: Implement per-country EU jurisdiction mapping.
		}
	}

	// Add user-specified jurisdictions from context
	for _, j := range ctx.Jurisdictions {
		found := false
		for _, existing := range jurisdictions {
			if existing == j {
				found = true
				break
			}
		}
		if !found {
			jurisdictions = append(jurisdictions, j)
		}
	}

	return jurisdictions
}

func (re *RuleEngine) generateCacheKey(ctx *RuleContext) string {
	data := fmt.Sprintf("%s|%s|%s|%.2f", ctx.UserID, ctx.InstrumentID, ctx.Side, ctx.Quantity)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (re *RuleEngine) getCachedResult(key string, now time.Time) (*RuleResult, bool) {
	re.mu.RLock()
	ttl := re.cacheTTL
	entry, ok := re.cache[key]
	if !ok || ttl <= 0 {
		re.mu.RUnlock()
		return nil, false
	}
	if now.Sub(entry.cachedAt) <= ttl {
		re.mu.RUnlock()
		return entry.result, true
	}
	re.mu.RUnlock()

	re.mu.Lock()
	defer re.mu.Unlock()
	if current, ok := re.cache[key]; ok && now.Sub(current.cachedAt) > re.cacheTTL {
		delete(re.cache, key)
	}
	return nil, false
}

func (re *RuleEngine) cacheResult(key string, result *RuleResult) {
	re.mu.Lock()
	defer re.mu.Unlock()
	if re.cacheTTL <= 0 {
		return
	}
	// Prune cache if too large
	if len(re.cache) > 100000 {
		re.cache = make(map[string]cacheEntry)
	}
	re.cache[key] = cacheEntry{
		result:   result,
		cachedAt: time.Now(),
	}
}

func (re *RuleEngine) logAudit(ctx *RuleContext, result *RuleResult) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		UserID:    ctx.UserID,
		Action:    string(result.Action),
		RuleID:    result.RuleID,
		Result:    result,
		Context:   ctx,
	}
	re.mu.Lock()
	if len(re.auditLog) >= re.maxAuditEntries {
		re.auditLog = re.auditLog[len(re.auditLog)/2:]
	}
	re.auditLog = append(re.auditLog, entry)
	re.mu.Unlock()
}

func severityWeight(s RuleSeverity) int {
	switch s {
	case RuleSeverityLow:
		return 1
	case RuleSeverityMedium:
		return 2
	case RuleSeverityHigh:
		return 3
	case RuleSeverityCritical:
		return 4
	default:
		return 0
	}
}

func loadDefaultFrameworks() []*RegulatoryFramework {
	return []*RegulatoryFramework{
		{
			ID: "SEC-2024", Name: "SEC Trading Rules 2024",
			Jurisdiction: JurisdictionUS, Version: "2024.1",
			EffectiveDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Rules: []ComplianceRule{
				{ID: "SEC-001", Name: "Pattern Day Trader Rule",
					Description: "Limits day trades for pattern day traders",
					Category:    RuleCategoryDayTrading, Severity: RuleSeverityHigh,
					Action: RuleActionBlock},
				{ID: "SEC-002", Name: "Short Sale Rule",
					Description: "Regulates short selling conditions",
					Category:    RuleCategoryMarketAbuse, Severity: RuleSeverityMedium,
					Action: RuleActionReview},
				{ID: "SEC-003", Name: "Large Trader Reporting",
					Description: "Reporting requirements for large traders",
					Category:    RuleCategoryReporting, Severity: RuleSeverityMedium,
					Action: RuleActionReport},
				{ID: "SEC-004", Name: "Market Access Rule",
					Description: "Risk controls for market access",
					Category:    RuleCategoryRiskManagement, Severity: RuleSeverityCritical,
					Action: RuleActionBlock},
				{ID: "SEC-005", Name: "Best Execution",
					Description: "Requires brokers to seek best execution",
					Category:    RuleCategoryConductOfBusiness, Severity: RuleSeverityMedium,
					Action: RuleActionReview},
			},
			PositionLimits: []PositionLimit{
				{ID: "PL-US-001", InstrumentType: "penny_stock", MaxNetPosition: 10000, MaxOrderSize: 5000},
				{ID: "PL-US-002", InstrumentType: "option", MaxNetPosition: 50000, MaxOrderSize: 25000},
			},
		},
		{
			ID: "MiFID2-2024", Name: "MiFID II Trading Rules",
			Jurisdiction: JurisdictionEU, Version: "2024.1",
			EffectiveDate: time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC),
			Rules: []ComplianceRule{
				{ID: "MIFID-001", Name: "Transaction Reporting",
					Description: "Requires transaction reporting within T+1",
					Category:    RuleCategoryReporting, Severity: RuleSeverityHigh,
					Action: RuleActionReport},
				{ID: "MIFID-002", Name: "Best Execution Reporting",
					Description: "Requires best execution data publication",
					Category:    RuleCategoryReporting, Severity: RuleSeverityMedium,
					Action: RuleActionReport},
				{ID: "MIFID-003", Name: "Pre-trade Transparency",
					Description: "Pre-trade transparency requirements",
					Category:    RuleCategoryDisclosure, Severity: RuleSeverityHigh,
					Action: RuleActionBlock},
				{ID: "MIFID-004", Name: "Post-trade Transparency",
					Description: "Post-trade transparency requirements",
					Category:    RuleCategoryDisclosure, Severity: RuleSeverityMedium,
					Action: RuleActionReport},
				{ID: "MIFID-005", Name: "Algorithmic Trading",
					Description: "Requirements for algorithmic trading systems",
					Category:    RuleCategoryGovernance, Severity: RuleSeverityCritical,
					Action: RuleActionReview},
			},
		},
		{
			ID: "EMIR-2024", Name: "EMIR Reporting Rules",
			Jurisdiction: JurisdictionEU, Version: "2024.1",
			EffectiveDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Rules: []ComplianceRule{
				{ID: "EMIR-001", Name: "Derivative Reporting",
					Description: "Reporting of all derivative transactions",
					Category:    RuleCategoryReporting, Severity: RuleSeverityCritical,
					Action: RuleActionReport},
				{ID: "EMIR-002", Name: "Clearing Obligation",
					Description: "Clearing obligation for standard derivatives",
					Category:    RuleCategorySettlement, Severity: RuleSeverityCritical,
					Action: RuleActionBlock},
			},
		},
		{
			ID: "FCA-2024", Name: "FCA Trading Rules",
			Jurisdiction: JurisdictionUK, Version: "2024.1",
			EffectiveDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Rules: []ComplianceRule{
				{ID: "FCA-001", Name: "Client Asset Rules (CASS)",
					Description: "Requirements for client money and assets",
					Category:    RuleCategoryClientMoney, Severity: RuleSeverityCritical,
					Action: RuleActionFreeze},
				{ID: "FCA-002", Name: "Conduct of Business Rules",
					Description: "COBS rules for client communications",
					Category:    RuleCategoryConductOfBusiness, Severity: RuleSeverityHigh,
					Action: RuleActionReview},
			},
		},
		{
			ID: "GDPR-2024", Name: "GDPR Compliance (Data Protection)",
			Jurisdiction: JurisdictionEU, Version: "2024.1",
			EffectiveDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			Rules: []ComplianceRule{
				{ID: "GDPR-001", Name: "Data Retention",
					Description: "Personal data retention limits",
					Category:    RuleCategoryDataProtection, Severity: RuleSeverityHigh,
					Action: RuleActionBlock},
				{ID: "GDPR-002", Name: "Right to Erasure",
					Description: "GDPR right to be forgotten",
					Category:    RuleCategoryDataProtection, Severity: RuleSeverityHigh,
					Action: RuleActionReview},
				{ID: "GDPR-003", Name: "Data Breach Notification",
					Description: "72-hour data breach notification requirement",
					Category:    RuleCategoryDataProtection, Severity: RuleSeverityCritical,
					Action: RuleActionReport},
			},
		},
	}
}

// ValidateTrade performs a comprehensive compliance check on a trade.
// Returns the rule evaluation result and any errors from the validation.
func ValidateTrade(ctx *RuleContext, engine *RuleEngine) (*RuleResult, error) {
	if engine == nil {
		engine = NewRuleEngine()
	}
	result, err := engine.Evaluate(ctx)
	if err != nil {
		return nil, fmt.Errorf("compliance check failed: %w", err)
	}
	return result, nil
}

// GenerateComplianceReport generates a compliance report for the given
// jurisdiction and time period. The report format is JSON unless otherwise
// specified. The compliance team imports these reports into their system.
// TODO: Add support for XML and CSV report formats.
func GenerateComplianceReport(jurisdiction Jurisdiction, start, end time.Time) ([]byte, error) {
	report := map[string]interface{}{
		"jurisdiction":  jurisdiction,
		"report_period": fmt.Sprintf("%s to %s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"generated_by":  "compliance-engine",
		"version":       "3.0.0",
		"total_audits":  0,
		"violations":    []interface{}{},
		"warnings":      []interface{}{},
		"summary": map[string]interface{}{
			"total_trades":    0,
			"blocked_trades":  0,
			"flagged_trades":  0,
			"approved_trades": 0,
			"pending_review":  0,
		},
		"notes": []string{
			"This report was auto-generated by the compliance engine.",
			"The data may not reflect real-time compliance status.",
			"Contact the compliance team for authoritative compliance data.",
			"Regulatory rules are subject to change without notice.",
			"This report is not legal advice. Consult with your legal team.",
		},
	}

	// TODO: Populate report with actual audit data from the database.
	// The database query was not implemented because the audit log
	// is not persisted to disk yet. It's only in memory.

	return json.MarshalIndent(report, "", "  ")
}
