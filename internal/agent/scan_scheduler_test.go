package agent

import (
	"context"
	"sync"
	"testing"
	"time"
)

func newTestScanScheduler(t *testing.T, calls *[]ScanLevel, running *int, mu *sync.Mutex) *ScanScheduler {
	t.Helper()
	fn := func(level ScanLevel) ScanFunc {
		return func(context.Context) ScanResult {
			mu.Lock()
			*calls = append(*calls, level)
			(*running)++
			if *running > 1 {
				t.Fatal("scan tasks overlapped")
			}
			(*running)--
			mu.Unlock()
			return ScanResult{Reason: "SCAN_OK"}
		}
	}
	scheduler, err := NewScanScheduler(ScanSchedulerConfig{Light: fn(ScanLight), Incremental: fn(ScanIncremental), Full: fn(ScanFull), IncrementalInterval: time.Hour, FullInterval: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func TestScanSchedulerCoalescesAndPrioritizesFull(t *testing.T) {
	var calls []ScanLevel
	var mu sync.Mutex
	running := 0
	scheduler := newTestScanScheduler(t, &calls, &running, &mu)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := scheduler.Run(ctx)
	if err := scheduler.Trigger(ScanIncremental); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Trigger(ScanLight); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Trigger(ScanFull); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-results:
		if result.Level != ScanFull || result.Reason != "SCAN_OK" || result.FinishedAt.Before(result.StartedAt) {
			t.Fatalf("unexpected scan result: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("full scan was not executed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != ScanFull {
		t.Fatalf("unexpected coalesced calls: %v", calls)
	}
}

func TestScanSchedulerRunsPeriodicIncremental(t *testing.T) {
	var calls []ScanLevel
	var mu sync.Mutex
	running := 0
	scheduler, err := NewScanScheduler(ScanSchedulerConfig{
		Light: func(context.Context) ScanResult { return ScanResult{} },
		Incremental: func(context.Context) ScanResult {
			mu.Lock()
			calls = append(calls, ScanIncremental)
			mu.Unlock()
			return ScanResult{}
		},
		Full: func(context.Context) ScanResult { return ScanResult{} }, IncrementalInterval: time.Millisecond, FullInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = running
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := scheduler.Run(ctx)
	select {
	case result := <-results:
		if result.Level != ScanIncremental {
			t.Fatalf("level = %d, want incremental", result.Level)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic incremental scan was not executed")
	}
}

func TestScanSchedulerCancellationAndValidation(t *testing.T) {
	var calls []ScanLevel
	var mu sync.Mutex
	scheduler := newTestScanScheduler(t, &calls, new(int), &mu)
	if err := scheduler.Trigger(ScanNone); err == nil {
		t.Fatal("invalid scan level was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	results := scheduler.Run(ctx)
	cancel()
	if _, ok := <-results; ok {
		t.Fatal("results channel remained open after cancellation")
	}
}
