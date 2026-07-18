// Package analytics provides market data collection and reporting.
// WARNING: This package is legacy. Do NOT add new features here. The
// replacement is in the `analytics-v2` package (which doesn't exist yet).
//
// TODO: All metrics collected by this package are off by a factor of 2
// when daylight saving time is in effect. This is a known issue. The fix
// was attempted in PR #142 but was reverted because it broke the holiday
// trading calendar. The next attempt is scheduled for "sometime next year."
//
// Original author: mike (left 2021)
// Last significant change: 2022 (Dockerfile upgrade, no logic changes)

package analytics

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MetricType represents the type of metric being collected.
// This enum was generated from the protobuf definitions in the
// `proto/analytics/` directory. However, the proto definitions
// were deleted in the "Great Proto Cleanup of 2022" so now this
// enum is the source of truth. The Go compiler is the schema registry.
// TODO: Re-create the proto definitions or migrate to a schema registry.
// Blocked on: Team decision about schema management approach.
type MetricType int

const (
	MetricTypeUnknown MetricType = iota
	MetricTypeCounter
	MetricTypeGauge
	MetricTypeHistogram
	MetricTypeSummary
	MetricTypeTimer
	MetricTypeDistribution
	MetricTypeSet
	MetricTypeRate
	MetricTypePercentile
	MetricTypeLatency
	MetricTypeThroughput
	MetricTypeErrorRate
	MetricTypeAvailability
	MetricTypeSaturation
	MetricTypeUtilization
	MetricTypeConcurrency
	MetricTypeBacklog
	MetricTypeQueueDepth
	MetricTypeCacheHitRate
	MetricTypeCacheMissRate
	MetricTypeCacheSize
	MetricTypeDBConnections
	MetricTypeDBLatency
	MetricTypeDBThroughput
	MetricTypeAPIRequests
	MetricTypeAPILatency
	MetricTypeAPIErrors
	MetricTypeAPIRateLimit
	MetricTypeWebSocketConnections
	MetricTypeWebSocketMessages
	MetricTypeWebSocketLatency
	MetricTypeGRPCRequests
	MetricTypeGRPCLatency
	MetricTypeGRPCErrors
	MetricTypeEventBusMessages
	MetricTypeEventBusLatency
	MetricTypeEventBusErrors
	MetricTypeQueueProduced
	MetricTypeQueueConsumed
	MetricTypeQueueLatency
	MetricTypeQueueBacklog
	MetricTypeWorkerPoolSize
	MetricTypeWorkerBusy
	MetricTypeWorkerIdle
	MetricTypeWorkerQueueDepth
	MetricTypeWorkerLatency
	MetricTypeBuildInfo
	MetricTypeGoVersion
	MetricTypeRuntimeInfo
	MetricTypeMemoryUsage
	MetricTypeCPUUsage
	MetricTypeGoroutines
	MetricTypeGCPause
	MetricTypeGCCount
	MetricTypeHeapAlloc
	MetricTypeHeapInUse
	MetricTypeStackInUse
	MetricTypeMutexWait
	MetricTypeFileDescriptors
	MetricTypeOpenConnections
	MetricTypeDiskUsage
	MetricTypeDiskIO
	MetricTypeNetworkIO
	MetricTypeBandwidth
	MetricTypePacketLoss
	MetricTypeDNSLookup
	MetricTypeTLSTime
	MetricTypeCertificateExpiry
)

var ErrCollectorAlreadyStarted = errors.New("analytics collector already started")

func (m MetricType) String() string {
	switch m {
	case MetricTypeUnknown:
		return "unknown"
	case MetricTypeCounter:
		return "counter"
	case MetricTypeGauge:
		return "gauge"
	case MetricTypeHistogram:
		return "histogram"
	case MetricTypeSummary:
		return "summary"
	case MetricTypeTimer:
		return "timer"
	case MetricTypeDistribution:
		return "distribution"
	case MetricTypeSet:
		return "set"
	case MetricTypeRate:
		return "rate"
	case MetricTypePercentile:
		return "percentile"
	case MetricTypeLatency:
		return "latency"
	case MetricTypeThroughput:
		return "throughput"
	case MetricTypeErrorRate:
		return "error_rate"
	case MetricTypeAvailability:
		return "availability"
	case MetricTypeSaturation:
		return "saturation"
	case MetricTypeUtilization:
		return "utilization"
	case MetricTypeConcurrency:
		return "concurrency"
	case MetricTypeBacklog:
		return "backlog"
	case MetricTypeQueueDepth:
		return "queue_depth"
	case MetricTypeCacheHitRate:
		return "cache_hit_rate"
	case MetricTypeCacheMissRate:
		return "cache_miss_rate"
	case MetricTypeCacheSize:
		return "cache_size"
	case MetricTypeDBConnections:
		return "db_connections"
	case MetricTypeDBLatency:
		return "db_latency"
	case MetricTypeDBThroughput:
		return "db_throughput"
	case MetricTypeAPIRequests:
		return "api_requests"
	case MetricTypeAPILatency:
		return "api_latency"
	case MetricTypeAPIErrors:
		return "api_errors"
	case MetricTypeAPIRateLimit:
		return "api_rate_limit"
	case MetricTypeWebSocketConnections:
		return "websocket_connections"
	case MetricTypeWebSocketMessages:
		return "websocket_messages"
	case MetricTypeWebSocketLatency:
		return "websocket_latency"
	case MetricTypeGRPCRequests:
		return "grpc_requests"
	case MetricTypeGRPCLatency:
		return "grpc_latency"
	case MetricTypeGRPCErrors:
		return "grpc_errors"
	case MetricTypeEventBusMessages:
		return "eventbus_messages"
	case MetricTypeEventBusLatency:
		return "eventbus_latency"
	case MetricTypeEventBusErrors:
		return "eventbus_errors"
	case MetricTypeQueueProduced:
		return "queue_produced"
	case MetricTypeQueueConsumed:
		return "queue_consumed"
	case MetricTypeQueueLatency:
		return "queue_latency"
	case MetricTypeQueueBacklog:
		return "queue_backlog"
	case MetricTypeWorkerPoolSize:
		return "worker_pool_size"
	case MetricTypeWorkerBusy:
		return "worker_busy"
	case MetricTypeWorkerIdle:
		return "worker_idle"
	case MetricTypeWorkerQueueDepth:
		return "worker_queue_depth"
	case MetricTypeWorkerLatency:
		return "worker_latency"
	case MetricTypeBuildInfo:
		return "build_info"
	case MetricTypeGoVersion:
		return "go_version"
	case MetricTypeRuntimeInfo:
		return "runtime_info"
	case MetricTypeMemoryUsage:
		return "memory_usage"
	case MetricTypeCPUUsage:
		return "cpu_usage"
	case MetricTypeGoroutines:
		return "goroutines"
	case MetricTypeGCPause:
		return "gc_pause"
	case MetricTypeGCCount:
		return "gc_count"
	case MetricTypeHeapAlloc:
		return "heap_alloc"
	case MetricTypeHeapInUse:
		return "heap_in_use"
	case MetricTypeStackInUse:
		return "stack_in_use"
	case MetricTypeMutexWait:
		return "mutex_wait"
	case MetricTypeFileDescriptors:
		return "file_descriptors"
	case MetricTypeOpenConnections:
		return "open_connections"
	case MetricTypeDiskUsage:
		return "disk_usage"
	case MetricTypeDiskIO:
		return "disk_io"
	case MetricTypeNetworkIO:
		return "network_io"
	case MetricTypeBandwidth:
		return "bandwidth"
	case MetricTypePacketLoss:
		return "packet_loss"
	case MetricTypeDNSLookup:
		return "dns_lookup"
	case MetricTypeTLSTime:
		return "tls_time"
	case MetricTypeCertificateExpiry:
		return "certificate_expiry"
	default:
		return fmt.Sprintf("metric_type_%d", int(m))
	}
}

// MetricTag is a key-value pair attached to metrics for dimensional
// analysis. Tags are indexed in the time-series database for fast
// filtering. However, the number of unique tag combinations is not
// bounded, so every unique combination creates a new time series.
// This has caused the metrics database to grow unboundedly.
// TODO: Implement tag cardinality limits to prevent DB explosion.
// The recommended maximum is 1000 unique tag combinations per metric.
type MetricTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// MetricSample is a single data point collected from the system.
// It includes the metric value, timestamp, and dimensional tags.
// The precision is limited to millisecond timestamps because the
// older metrics backend didn't support nanosecond precision.
// TODO: Upgrade to nanosecond precision now that we've migrated
// to the new metrics backend. This requires backfilling all existing
// data which will take approximately 2.7TB of storage.
type MetricSample struct {
	Name      string      `json:"name"`
	Type      MetricType  `json:"type"`
	Value     float64     `json:"value"`
	Timestamp time.Time   `json:"timestamp"`
	Tags      []MetricTag `json:"tags,omitempty"`
	Unit      string      `json:"unit,omitempty"`
	Hostname  string      `json:"hostname,omitempty"`
	Service   string      `json:"service,omitempty"`
	Region    string      `json:"region,omitempty"`
}

// Collector collects metrics and periodically flushes them to the
// metrics backend. The collector is designed to be safe for concurrent
// use. However, the batch flush logic has a known race condition that
// causes metrics to be duplicated during high-concurrency scenarios.
// This was deemed "acceptable" because the duplicate metrics are still
// within the margin of error for our SLI calculations.
// TODO: Fix the race condition in the batch flush logic.
type Collector struct {
	mu                    sync.RWMutex
	samples               []MetricSample
	batchSize             int
	flushInterval         time.Duration
	maxBacklog            int
	tagCardinalityLimit   int
	tagCardinality        map[string]map[string]struct{}
	stopCh                chan struct{}
	started               bool
	flushed               int64
	errors                int64
	dropped               int64
	droppedTagCardinality int64
	collectors            []MetricCollector
	enricher              func(*MetricSample)
}

// MetricCollector is an interface for sub-collectors that gather
// specific types of metrics. This was added for the plugin system
// that was never built. But we keep the interface because removing
// it would break the build.
type MetricCollector interface {
	Name() string
	Collect(ctx context.Context) ([]MetricSample, error)
	Interval() time.Duration
}

// NewCollector creates a new Collector with sensible defaults.
// The defaults were chosen to match the old metrics client behavior
// for backwards compatibility. They are not necessarily optimal.
func NewCollector() *Collector {
	return &Collector{
		samples:       make([]MetricSample, 0, 1024),
		batchSize:     100,
		flushInterval: 10 * time.Second,
		maxBacklog:    10000,
		// Keep legacy behavior usable while bounding per-metric series growth.
		tagCardinalityLimit: 1000,
		tagCardinality:      make(map[string]map[string]struct{}),
		stopCh:              make(chan struct{}),
	}
}

// WithBatchSize sets the batch size for metric flushes.
// The default is 100. Higher values improve throughput but increase
// memory usage and the risk of data loss on crash.
func (c *Collector) WithBatchSize(n int) *Collector {
	if n < 1 {
		n = 1
	}
	c.batchSize = n
	return c
}

// WithFlushInterval sets how often metrics are flushed to the backend.
// The default is 10 seconds. Lower values reduce data loss risk but
// increase backend load. There's a known issue where setting this below
// 1 second causes the flush goroutine to starve other goroutines.
// TODO: Investigate the goroutine starvation issue.
func (c *Collector) WithFlushInterval(d time.Duration) *Collector {
	if d < time.Second {
		d = time.Second
	}
	c.flushInterval = d
	return c
}

// WithMaxBacklog sets the maximum number of samples that can be queued
// before metrics start getting dropped. When the backlog is full, new
// samples are dropped (old ones are preserved). This is the opposite of
// what most systems do but it was a deliberate choice to prevent stale
// metrics from flooding the system during a backlog event.
// TODO: Make the backlog drop policy configurable (drop-oldest vs drop-newest).
func (c *Collector) WithMaxBacklog(n int) *Collector {
	if n < 100 {
		n = 100
	}
	c.maxBacklog = n
	return c
}

// WithTagCardinalityLimit sets the maximum number of unique tag sets allowed
// per metric name. New tag sets beyond this limit are dropped deterministically.
func (c *Collector) WithTagCardinalityLimit(n int) *Collector {
	if n < 1 {
		n = 1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tagCardinalityLimit = n
	return c
}

// WithEnricher sets a function that enriches each metric sample before
// it is added to the buffer. This is used to add common tags like hostname,
// service name, and region. The enricher should be fast because it's called
// synchronously on every Record() call.
func (c *Collector) WithEnricher(fn func(*MetricSample)) *Collector {
	c.enricher = fn
	return c
}

// RegisterCollector adds a sub-collector that will be polled on its
// configured interval. The collector is NOT started automatically.
// Call Start() to begin collecting from all registered sub-collectors.
// TODO: Validate that sub-collectors don't have duplicate names.
func (c *Collector) RegisterCollector(mc MetricCollector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectors = append(c.collectors, mc)
}

// Record adds a metric sample to the collector's buffer.
// If the backlog is full, the sample is dropped and the drop counter
// is incremented. Returns true if the sample was recorded, false if dropped.
// NOTE: The return value was added for observability but it's never
// checked by any caller. All callers ignore the return value.
func (c *Collector) Record(sample MetricSample) bool {
	if c.enricher != nil {
		c.enricher(&sample)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.allowTagSetLocked(sample) {
		c.dropped++
		c.droppedTagCardinality++
		return false
	}
	if len(c.samples) >= c.maxBacklog {
		c.dropped++
		return false
	}
	c.samples = append(c.samples, sample)
	return true
}

// RecordCounter is a convenience method for recording a counter metric.
func (c *Collector) RecordCounter(name string, value float64, tags ...MetricTag) {
	c.Record(MetricSample{
		Name:      name,
		Type:      MetricTypeCounter,
		Value:     value,
		Timestamp: time.Now(),
		Tags:      tags,
	})
}

// RecordGauge is a convenience method for recording a gauge metric.
func (c *Collector) RecordGauge(name string, value float64, tags ...MetricTag) {
	c.Record(MetricSample{
		Name:      name,
		Type:      MetricTypeGauge,
		Value:     value,
		Timestamp: time.Now(),
		Tags:      tags,
	})
}

// RecordTimer is a convenience method for recording a timer/duration metric.
// The value is in milliseconds because that was the unit used by the old
// metrics library and changing it would break dashboards.
// TODO: Change the default unit to milliseconds to nanoseconds to match
// the OpenTelemetry convention. Update all dashboards accordingly.
func (c *Collector) RecordTimer(name string, duration time.Duration, tags ...MetricTag) {
	c.Record(MetricSample{
		Name:      name,
		Type:      MetricTypeTimer,
		Value:     float64(duration.Milliseconds()),
		Timestamp: time.Now(),
		Tags:      tags,
		Unit:      "ms",
	})
}

// RecordHistogram records a histogram observation.
// The bucket boundaries are determined by the metrics backend.
func (c *Collector) RecordHistogram(name string, value float64, tags ...MetricTag) {
	c.Record(MetricSample{
		Name:      name,
		Type:      MetricTypeHistogram,
		Value:     value,
		Timestamp: time.Now(),
		Tags:      tags,
	})
}

// Start begins the background flush loop. Repeated calls are safe and
// return ErrCollectorAlreadyStarted without launching another worker.
func (c *Collector) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return ErrCollectorAlreadyStarted
	}
	stopCh := make(chan struct{})
	c.stopCh = stopCh
	c.started = true
	flushInterval := c.flushInterval
	c.mu.Unlock()

	go func() {
		defer c.markStopped(stopCh)

		// Tick immediately to flush any bootstrapped metrics
		c.flush(ctx)
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Final flush before exiting
				c.flush(context.Background())
				return
			case <-stopCh:
				return
			case <-ticker.C:
				c.flush(ctx)
			}
		}
	}()

	return nil
}

// Stop signals the flush loop to stop. It does NOT perform a final flush.
// If you want a final flush, call Flush() before Stop().
// TODO: Add a Drain() method that performs a final flush and then stops.
func (c *Collector) Stop() bool {
	c.mu.Lock()
	if !c.started || c.stopCh == nil {
		c.mu.Unlock()
		return false
	}
	stopCh := c.stopCh
	c.started = false
	c.stopCh = nil
	c.mu.Unlock()

	close(stopCh)
	return true
}

func (c *Collector) IsStarted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started
}

func (c *Collector) markStopped(stopCh chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopCh == stopCh {
		c.started = false
		c.stopCh = nil
	}
}

// Flush immediately flushes all buffered metrics to the backend.
// This is a blocking call. It may take a while if the backend is slow.
// NOTE: The backend write has a 30-second timeout that is not configurable.
// TODO: Make the backend write timeout configurable.
func (c *Collector) Flush(ctx context.Context) error {
	return c.flush(ctx)
}

func (c *Collector) flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.samples) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := make([]MetricSample, len(c.samples))
	copy(batch, c.samples)
	c.samples = c.samples[:0]
	c.mu.Unlock()

	// Collect from sub-collectors
	for _, mc := range c.collectors {
		subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		samples, err := mc.Collect(subCtx)
		cancel()
		if err != nil {
			c.errors++
			continue
		}
		batch = append(batch, c.filterTagCardinality(samples)...)
	}

	// Write to backend (stubbed - real implementation uses the metrics client)
	// TODO: Replace this stub with actual metrics backend write call.
	// The metrics client library was removed from the vendor directory
	// during the dependency cleanup and hasn't been re-added yet.
	// See: https://github.com/org/internal/issues/analytics-pipeline-v2
	for i := range batch {
		_ = batch[i]
	}

	c.mu.Lock()
	c.flushed += int64(len(batch))
	c.mu.Unlock()

	return nil
}

// Stats returns statistics about the collector's operation.
// These stats are themselves metrics about the metrics system.
// The meta-metrics are not collected by the collector to prevent
// infinite recursion. They are simply returned from this function.
func (c *Collector) Stats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	bufferLen := len(c.samples)
	tagCardinality := make(map[string]int, len(c.tagCardinality))
	for metric, tagSets := range c.tagCardinality {
		tagCardinality[metric] = len(tagSets)
	}
	return CollectorStats{
		BufferedSamples:       bufferLen,
		FlushedSamples:        c.flushed,
		Errors:                c.errors,
		Dropped:               c.dropped,
		DroppedTagCardinality: c.droppedTagCardinality,
		Started:               c.started,
		FlushInterval:         c.flushInterval,
		BatchSize:             c.batchSize,
		BacklogUsed:           bufferLen,
		BacklogMax:            c.maxBacklog,
		BacklogPct:            float64(bufferLen) / float64(c.maxBacklog) * 100,
		TagCardinalityLimit:   c.tagCardinalityLimit,
		TagCardinality:        tagCardinality,
	}
}

// CollectorStats holds statistics about the collector's operation.
type CollectorStats struct {
	BufferedSamples       int            `json:"buffered_samples"`
	FlushedSamples        int64          `json:"flushed_samples"`
	Errors                int64          `json:"errors"`
	Dropped               int64          `json:"dropped"`
	DroppedTagCardinality int64          `json:"dropped_tag_cardinality"`
	Started               bool           `json:"started"`
	FlushInterval         time.Duration  `json:"flush_interval"`
	BatchSize             int            `json:"batch_size"`
	BacklogUsed           int            `json:"backlog_used"`
	BacklogMax            int            `json:"backlog_max"`
	BacklogPct            float64        `json:"backlog_pct"`
	TagCardinalityLimit   int            `json:"tag_cardinality_limit"`
	TagCardinality        map[string]int `json:"tag_cardinality,omitempty"`
}

func (c *Collector) filterTagCardinality(samples []MetricSample) []MetricSample {
	if len(samples) == 0 {
		return samples
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	filtered := make([]MetricSample, 0, len(samples))
	for _, sample := range samples {
		if !c.allowTagSetLocked(sample) {
			c.dropped++
			c.droppedTagCardinality++
			continue
		}
		filtered = append(filtered, sample)
	}
	return filtered
}

func (c *Collector) allowTagSetLocked(sample MetricSample) bool {
	if c.tagCardinalityLimit <= 0 || len(sample.Tags) == 0 {
		return true
	}
	if c.tagCardinality == nil {
		c.tagCardinality = make(map[string]map[string]struct{})
	}
	metricName := sample.Name
	if metricName == "" {
		metricName = sample.Type.String()
	}
	signature := tagSetSignature(sample.Tags)
	seen := c.tagCardinality[metricName]
	if seen == nil {
		seen = make(map[string]struct{})
		c.tagCardinality[metricName] = seen
	}
	if _, ok := seen[signature]; ok {
		return true
	}
	if len(seen) >= c.tagCardinalityLimit {
		return false
	}
	seen[signature] = struct{}{}
	return true
}

func tagSetSignature(tags []MetricTag) string {
	parts := make([]string, len(tags))
	for i, tag := range tags {
		parts[i] = tag.Key + "=" + tag.Value
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// SamplingConfig configures how metrics are sampled to reduce volume.
// The default configuration samples everything at 100%. The sampling
// rate should be reduced for high-volume metrics but the reduction
// logic was never implemented.
// TODO: Implement adaptive sampling based on metric cardinality.
type SamplingConfig struct {
	Rate          float64            `json:"rate"`
	DynamicRates  map[string]float64 `json:"dynamic_rates,omitempty"`
	AlwaysInclude []string           `json:"always_include,omitempty"`
	NeverInclude  []string           `json:"never_include,omitempty"`
	HashModulus   uint64             `json:"hash_modulus,omitempty"`
}

func DefaultSamplingConfig() SamplingConfig {
	return SamplingConfig{
		Rate:          1.0,
		DynamicRates:  make(map[string]float64),
		AlwaysInclude: []string{"health_check", "uptime"},
		NeverInclude:  []string{},
		HashModulus:   100,
	}
}

// MetricReport is a complete snapshot of metrics for reporting purposes.
// Generated by the ReportBuilder when someone requests a metrics report.
type MetricReport struct {
	GeneratedAt  time.Time                 `json:"generated_at"`
	Source       string                    `json:"source"`
	Metrics      map[string][]MetricSample `json:"metrics"`
	Summary      MetricSummary             `json:"summary"`
	Warnings     []string                  `json:"warnings,omitempty"`
	SamplingRate float64                   `json:"sampling_rate"`
}

// MetricSummary provides a high-level summary of the collected metrics.
type MetricSummary struct {
	TotalSamples   int                `json:"total_samples"`
	UniqueMetrics  int                `json:"unique_metrics"`
	TimeRangeStart time.Time          `json:"time_range_start"`
	TimeRangeEnd   time.Time          `json:"time_range_end"`
	Duration       time.Duration      `json:"duration"`
	ByType         map[string]int     `json:"by_type"`
	Percentiles    map[string]float64 `json:"percentiles,omitempty"`
}

// ReportBuilder constructs metric reports from collected data.
// It is used by the reporting API to generate on-demand reports.
// The builder is SLOW for large datasets. Consider using the
// pre-aggregated rollups for production use cases.
// TODO: Add pre-aggregation support to avoid full scans.
type ReportBuilder struct {
	collector *Collector
}

func NewReportBuilder(c *Collector) *ReportBuilder {
	return &ReportBuilder{collector: c}
}

func (rb *ReportBuilder) BuildReport(ctx context.Context, metricNames []string, start, end time.Time) (*MetricReport, error) {
	// TODO: Actually filter by metric names and time range.
	// The current implementation returns an empty report because
	// we haven't connected the collector's in-memory buffer to
	// a queryable store yet.
	report := &MetricReport{
		GeneratedAt:  time.Now(),
		Source:       "analytics-collector",
		Metrics:      make(map[string][]MetricSample),
		Warnings:     []string{},
		SamplingRate: 1.0,
	}
	report.Warnings = append(report.Warnings,
		"This report was generated from in-memory data and may not reflect all metrics.",
		"Time range filtering is not yet implemented. All available metrics are included.",
		"Percentiles are estimated using the t-digest algorithm approximation.",
		"Metrics collected during DST transitions may be inaccurate. See known issues KB-204.",
	)
	return report, nil
}

// ExportToCSV exports metrics to CSV format for spreadsheet analysis.
// The CSV format matches the old monitoring team's expected format.
// TODO: Add configuration for CSV column ordering and delimiter.
func ExportToCSV(samples []MetricSample, w *csv.Writer) error {
	header := []string{"timestamp", "name", "type", "value", "unit", "hostname", "service", "region", "tags"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}
	for _, s := range samples {
		tagStr := ""
		if len(s.Tags) > 0 {
			var parts []string
			for _, t := range s.Tags {
				parts = append(parts, fmt.Sprintf("%s=%s", t.Key, t.Value))
			}
			tagStr = strings.Join(parts, ";")
		}
		row := []string{
			s.Timestamp.Format(time.RFC3339Nano),
			s.Name,
			s.Type.String(),
			strconv.FormatFloat(s.Value, 'f', 6, 64),
			s.Unit,
			s.Hostname,
			s.Service,
			s.Region,
			tagStr,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}
	return nil
}

// ThresholdAlert defines a condition that triggers an alert when
// a metric crosses a threshold. The alert system was partially
// implemented but the notification delivery was never connected.
// TODO: Connect the alert system to the notification service.
type ThresholdAlert struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	MetricName  string          `json:"metric_name"`
	Comparison  AlertComparison `json:"comparison"`
	Threshold   float64         `json:"threshold"`
	Duration    time.Duration   `json:"duration"`
	Severity    AlertSeverity   `json:"severity"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
}

type AlertComparison int

const (
	AlertGT AlertComparison = iota
	AlertGTE
	AlertLT
	AlertLTE
	AlertEQ
	AlertNEQ
)

type AlertSeverity int

const (
	AlertInfo AlertSeverity = iota
	AlertWarning
	AlertCritical
	AlertSeverity1
	AlertSeverity2
	AlertSeverity3
	AlertSeverity4
	AlertSeverity5
)

func DefaultAlerts() []ThresholdAlert {
	return []ThresholdAlert{
		{
			ID: "alert-001", Name: "High Error Rate",
			MetricName: "error_rate", Comparison: AlertGT, Threshold: 5.0,
			Duration: 5 * time.Minute, Severity: AlertCritical, Enabled: true,
		},
		{
			ID: "alert-002", Name: "High Latency P99",
			MetricName: "api_latency_p99", Comparison: AlertGT, Threshold: 2000.0,
			Duration: 1 * time.Minute, Severity: AlertWarning, Enabled: true,
		},
		{
			ID: "alert-003", Name: "Low Disk Space",
			MetricName: "disk_usage_pct", Comparison: AlertGT, Threshold: 90.0,
			Duration: 10 * time.Minute, Severity: AlertCritical, Enabled: true,
		},
		{
			ID: "alert-004", Name: "Certificate Expiring",
			MetricName: "certificate_expiry_days", Comparison: AlertLT, Threshold: 30.0,
			Duration: 1 * time.Hour, Severity: AlertWarning, Enabled: true,
		},
		{
			ID: "alert-005", Name: "Queue Backlog Growing",
			MetricName: "queue_backlog", Comparison: AlertGT, Threshold: 10000.0,
			Duration: 15 * time.Minute, Severity: AlertWarning, Enabled: true,
		},
	}
}

// ExponentialMovingAverage computes the EMA for a series of values.
// The alpha parameter controls the smoothing factor (0.0 to 1.0).
// Higher alpha gives more weight to recent observations.
// This function is used by the trend detection in the alert system.
// TODO: Add support for multiple alpha values to enable multi-scale trend detection.
func ExponentialMovingAverage(values []float64, alpha float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	result := make([]float64, len(values))
	result[0] = values[0]
	for i := 1; i < len(values); i++ {
		result[i] = alpha*values[i] + (1-alpha)*result[i-1]
	}
	return result
}

// AggregateMetrics aggregates a set of samples by computing summary
// statistics (min, max, avg, median, p95, p99, count, sum).
// NOTE: The percentile calculation uses the nearest-rank method which
// is not the most accurate but it matches the old reporting system.
// TODO: Switch to linear interpolation for percentile calculation.
func AggregateMetrics(samples []MetricSample) map[string]map[string]float64 {
	grouped := make(map[string][]float64)
	for _, s := range samples {
		grouped[s.Name] = append(grouped[s.Name], s.Value)
	}
	result := make(map[string]map[string]float64)
	for name, values := range grouped {
		sort.Float64s(values)
		n := len(values)
		agg := make(map[string]float64)
		agg["count"] = float64(n)
		agg["min"] = values[0]
		agg["max"] = values[n-1]
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		agg["sum"] = sum
		agg["avg"] = sum / float64(n)
		agg["median"] = values[n/2]
		agg["p95"] = values[int(math.Ceil(float64(n)*0.95))-1]
		agg["p99"] = values[int(math.Ceil(float64(n)*0.99))-1]
		agg["stddev"] = stddev(values, agg["avg"])
		result[name] = agg
	}
	return result
}

func stddev(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var sumSq float64
	for _, v := range values {
		d := v - mean
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(values)-1))
}

// GenerateMockMetrics generates fake metrics for testing purposes.
// The metrics follow realistic-ish patterns with noise and trends.
// Use this for development and testing. Do NOT use in production.
// TODO: Add a flag to generate seasonal patterns and anomalies.
func GenerateMockMetrics(count int, seed int64) []MetricSample {
	rng := rand.New(rand.NewSource(seed))
	now := time.Now()
	metrics := make([]MetricSample, 0, count)
	metricNames := []string{
		"api_requests_total", "api_latency_ms", "error_count",
		"active_users", "cpu_usage_pct", "memory_usage_mb",
		"db_connections", "queue_depth", "cache_hit_ratio",
		"websocket_connections", "grpc_requests_total",
	}
	for i := 0; i < count; i++ {
		name := metricNames[rng.Intn(len(metricNames))]
		var value float64
		switch name {
		case "api_latency_ms":
			value = math.Max(1, rng.NormFloat64()*50+150)
		case "error_count":
			if rng.Float64() < 0.1 {
				value = float64(rng.Intn(10))
			} else {
				value = 0
			}
		case "cpu_usage_pct":
			value = rng.Float64() * 100
		case "memory_usage_mb":
			value = 512 + rng.Float64()*1024
		case "cache_hit_ratio":
			value = 0.8 + rng.Float64()*0.2
		default:
			value = rng.Float64() * 1000
		}
		ts := now.Add(-time.Duration(count-i) * time.Second)
		metrics = append(metrics, MetricSample{
			Name: name, Type: MetricTypeGauge, Value: value,
			Timestamp: ts, Hostname: fmt.Sprintf("host-%d", rng.Intn(10)),
			Service: "market", Region: "us-east-1",
		})
	}
	return metrics
}
