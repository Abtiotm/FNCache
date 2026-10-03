package agent

import (
	"context"
	"errors"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type RuntimeScanAdapter struct {
	observer *DynamicObserver
	light    []func(context.Context) error
}

func NewRuntimeScanAdapter(observer *DynamicObserver, light ...func(context.Context) error) (*RuntimeScanAdapter, error) {
	if observer == nil {
		return nil, errors.New("dynamic observer is required")
	}
	return &RuntimeScanAdapter{observer: observer, light: append([]func(context.Context) error(nil), light...)}, nil
}

func (s *RuntimeScanAdapter) Light(ctx context.Context) ScanResult {
	for _, check := range s.light {
		if err := check(ctx); err != nil {
			return failedScan(ScanLight, err)
		}
	}
	return ScanResult{Level: ScanLight, Reason: "SCAN_LIGHT_OK"}
}

func (s *RuntimeScanAdapter) Incremental(ctx context.Context) ScanResult {
	actual, err := s.observer.IncrementalScan(ctx)
	return classifyScan(ScanIncremental, actual, err)
}

func (s *RuntimeScanAdapter) Full(ctx context.Context) ScanResult {
	actual, err := s.observer.Scan(ctx)
	return classifyScan(ScanFull, actual, err)
}

func failedScan(level ScanLevel, err error) ScanResult {
	return ScanResult{Level: level, Critical: true, InvalidateEpoch: true, Reason: "SCAN_FAILED", Err: err}
}

func classifyScan(level ScanLevel, actual reconcile.ActualState, err error) ScanResult {
	if err != nil {
		return failedScan(level, err)
	}
	result := ScanResult{Level: level, Reason: "SCAN_OK"}
	if len(actual.Conflicts) != 0 {
		result.Critical = true
		result.InvalidateEpoch = true
		result.Reason = "SCAN_CONFLICT"
		return result
	}
	if actual.Control.Verified && actual.Control.Enabled && (len(actual.Programs) < 4 || len(actual.Maps) < 8 || !actual.FlannelRule.Present) {
		result.Critical = true
		result.InvalidateEpoch = true
		result.Reason = "DATAPATH_STATE_INCOMPLETE"
	}
	return result
}
