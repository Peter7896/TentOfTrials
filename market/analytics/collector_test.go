package analytics

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCollectorStartSetsStartedState(t *testing.T) {
	collector := NewCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if !collector.IsStarted() {
		t.Fatal("collector should report started after Start")
	}
	if !collector.Stats().Started {
		t.Fatal("stats should report started after Start")
	}
	if !collector.Stop() {
		t.Fatal("Stop() should report that a running collector was stopped")
	}
	waitForStopped(t, collector)
}

func TestCollectorStartIsIdempotent(t *testing.T) {
	collector := NewCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("first Start() unexpected error: %v", err)
	}
	if err := collector.Start(ctx); !errors.Is(err, ErrCollectorAlreadyStarted) {
		t.Fatalf("second Start() error = %v, want ErrCollectorAlreadyStarted", err)
	}

	collector.RecordCounter("boot_metric", 1)
	if !collector.Stop() {
		t.Fatal("Stop() should still stop after a repeated Start attempt")
	}
	waitForStopped(t, collector)
	if collector.Stop() {
		t.Fatal("second Stop() should report no running collector")
	}
}

func TestCollectorConcurrentStartOnlyStartsOnce(t *testing.T) {
	collector := NewCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- collector.Start(ctx)
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	alreadyStarted := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrCollectorAlreadyStarted):
			alreadyStarted++
		default:
			t.Fatalf("unexpected Start() error: %v", err)
		}
	}

	if successes != 1 {
		t.Fatalf("successful starts = %d, want 1", successes)
	}
	if alreadyStarted != 15 {
		t.Fatalf("already-started errors = %d, want 15", alreadyStarted)
	}
	if !collector.Stop() {
		t.Fatal("Stop() should stop the one running worker")
	}
	waitForStopped(t, collector)
}

func TestCollectorContextCancelStopsWorker(t *testing.T) {
	collector := NewCollector()
	ctx, cancel := context.WithCancel(context.Background())

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	cancel()

	waitForStopped(t, collector)
	if collector.Stop() {
		t.Fatal("Stop() should report no running collector after context cancellation")
	}
}

func TestCollectorTagCardinalityUnderLimitRecordsSamples(t *testing.T) {
	collector := NewCollector().WithTagCardinalityLimit(2)

	if !collector.Record(counterSample("orders_total", "tenant", "alpha")) {
		t.Fatal("first tag set should be recorded")
	}
	if !collector.Record(counterSample("orders_total", "tenant", "beta")) {
		t.Fatal("second tag set should be recorded")
	}

	stats := collector.Stats()
	if stats.BufferedSamples != 2 {
		t.Fatalf("buffered samples = %d, want 2", stats.BufferedSamples)
	}
	if stats.Dropped != 0 || stats.DroppedTagCardinality != 0 {
		t.Fatalf("drops = %d/%d, want 0/0", stats.Dropped, stats.DroppedTagCardinality)
	}
	if got := stats.TagCardinality["orders_total"]; got != 2 {
		t.Fatalf("tag cardinality = %d, want 2", got)
	}
}

func TestCollectorTagCardinalityOverLimitDropsNewTagSet(t *testing.T) {
	collector := NewCollector().WithTagCardinalityLimit(1)

	if !collector.Record(counterSample("orders_total", "tenant", "alpha")) {
		t.Fatal("first tag set should be recorded")
	}
	if collector.Record(counterSample("orders_total", "tenant", "beta")) {
		t.Fatal("second unique tag set should be dropped")
	}

	stats := collector.Stats()
	if stats.BufferedSamples != 1 {
		t.Fatalf("buffered samples = %d, want 1", stats.BufferedSamples)
	}
	if stats.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1", stats.Dropped)
	}
	if stats.DroppedTagCardinality != 1 {
		t.Fatalf("tag-cardinality drops = %d, want 1", stats.DroppedTagCardinality)
	}
}

func TestCollectorTagCardinalityRepeatedHighCardinalityInputDropsDeterministically(t *testing.T) {
	collector := NewCollector().WithTagCardinalityLimit(1)

	if !collector.Record(counterSample("orders_total", "tenant", "alpha")) {
		t.Fatal("first tag set should be recorded")
	}
	for i := 0; i < 3; i++ {
		if collector.Record(counterSample("orders_total", "tenant", "overflow")) {
			t.Fatalf("overflow tag set attempt %d should be dropped", i+1)
		}
	}
	if !collector.Record(counterSample("orders_total", "tenant", "alpha")) {
		t.Fatal("previously accepted tag set should still be recorded")
	}

	stats := collector.Stats()
	if stats.BufferedSamples != 2 {
		t.Fatalf("buffered samples = %d, want 2", stats.BufferedSamples)
	}
	if stats.DroppedTagCardinality != 3 {
		t.Fatalf("tag-cardinality drops = %d, want 3", stats.DroppedTagCardinality)
	}
	if got := stats.TagCardinality["orders_total"]; got != 1 {
		t.Fatalf("tracked tag cardinality = %d, want 1", got)
	}
}

func TestCollectorTagCardinalityUsesDeterministicTagSignature(t *testing.T) {
	collector := NewCollector().WithTagCardinalityLimit(1)

	first := MetricSample{
		Name: "orders_total",
		Type: MetricTypeCounter,
		Tags: []MetricTag{{Key: "tenant", Value: "alpha"}, {Key: "region", Value: "us"}},
	}
	second := MetricSample{
		Name: "orders_total",
		Type: MetricTypeCounter,
		Tags: []MetricTag{{Key: "region", Value: "us"}, {Key: "tenant", Value: "alpha"}},
	}

	if !collector.Record(first) {
		t.Fatal("first tag ordering should be recorded")
	}
	if !collector.Record(second) {
		t.Fatal("same tag set in different order should still be recorded")
	}

	stats := collector.Stats()
	if stats.DroppedTagCardinality != 0 {
		t.Fatalf("tag-cardinality drops = %d, want 0", stats.DroppedTagCardinality)
	}
	if got := stats.TagCardinality["orders_total"]; got != 1 {
		t.Fatalf("tracked tag cardinality = %d, want 1", got)
	}
}

func counterSample(name, key, value string) MetricSample {
	return MetricSample{
		Name: name,
		Type: MetricTypeCounter,
		Tags: []MetricTag{{Key: key, Value: value}},
	}
}

func waitForStopped(t *testing.T, collector *Collector) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !collector.IsStarted() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("collector did not stop before deadline")
}
