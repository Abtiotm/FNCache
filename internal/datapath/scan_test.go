package datapath

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakePinBackend struct {
	names      map[string][]string
	maps       map[string]reconcile.MapState
	control    reconcile.ControlState
	programs   map[string]reconcile.ProgramState
	listErr    error
	mapErr     error
	controlErr error
	progErr    error
	inspected  map[string]MapSchema
}

func (f *fakePinBackend) List(path string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.names[filepath.Base(path)], nil
}
func (f *fakePinBackend) InspectMap(path string, expected MapSchema) (reconcile.MapState, error) {
	if f.mapErr != nil {
		return reconcile.MapState{}, f.mapErr
	}
	if f.inspected != nil {
		f.inspected[filepath.Base(path)] = expected
	}
	return f.maps[filepath.Base(path)], nil
}
func (f *fakePinBackend) InspectControl(string) (reconcile.ControlState, error) {
	if f.controlErr != nil {
		return reconcile.ControlState{}, f.controlErr
	}
	return f.control, nil
}
func (f *fakePinBackend) InspectProgram(path, _ string) (reconcile.ProgramState, error) {
	if f.progErr != nil {
		return reconcile.ProgramState{}, f.progErr
	}
	return f.programs[filepath.Base(path)], nil
}

func testPinScanner(t *testing.T, backend pinBackend) *PinScanner {
	scanner, err := newPinScanner("/sys/fs/bpf/oncache/v1", backend)
	if err != nil {
		t.Fatal(err)
	}
	scanner.now = func() time.Time { return time.Unix(10, 0).UTC() }
	return scanner
}

func TestPinScannerCollectsObjectsAndOrphans(t *testing.T) {
	backend := &fakePinBackend{
		names:    map[string][]string{"maps": {"control_map", "foreign_map"}, "programs": {"tc_masq"}},
		maps:     map[string]reconcile.MapState{"control_map": {ID: 7, Name: "control_map"}},
		control:  reconcile.ControlState{Verified: true, Enabled: true, Generation: 42},
		programs: map[string]reconcile.ProgramState{"tc_masq": {ID: 8, Name: "tc_masq", Tag: "tag"}},
	}
	actual, err := testPinScanner(t, backend).Scan(context.Background())
	if err != nil || actual.Maps["control_map"].ID != 7 || !actual.Control.Verified || !actual.Control.Enabled || actual.Control.Generation != 42 || actual.Programs["tc_masq"].ID != 8 || len(actual.Orphans) != 1 || actual.ScannedAt.Unix() != 10 {
		t.Fatalf("unexpected scan result: actual=%+v err=%v", actual, err)
	}
	if actual.Orphans[0].Kind != "map-pin" || actual.Orphans[0].Identity != "/sys/fs/bpf/oncache/v1/maps/foreign_map" {
		t.Fatalf("unexpected orphan: %+v", actual.Orphans[0])
	}
}

func TestPinScannerAllowsMissingDirectories(t *testing.T) {
	actual, err := testPinScanner(t, &fakePinBackend{names: map[string][]string{}}).Scan(context.Background())
	if err != nil || len(actual.Maps) != 0 || len(actual.Programs) != 0 {
		t.Fatalf("missing pin directories should be empty state: actual=%+v err=%v", actual, err)
	}
}

func TestPinScannerUsesConfiguredMapCapacities(t *testing.T) {
	capacities := DefaultMapCapacities()
	capacities.IngressCacheMaxEntries = 2048
	schema := V1SchemaWithCapacities(capacities)
	backend := &fakePinBackend{
		names:     map[string][]string{"maps": {"ingress_cache"}},
		maps:      map[string]reconcile.MapState{"ingress_cache": {ID: 7, Name: "ingress_cache", KeySize: 4, ValueSize: 16, MaxEntries: 2048}},
		inspected: make(map[string]MapSchema),
	}
	scanner, err := newPinScannerWithSchema("/sys/fs/bpf/oncache/v1", schema, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := backend.inspected["ingress_cache"].MaxEntries; got != 2048 {
		t.Fatalf("scanner expected max entries = %d, want 2048", got)
	}
}

func TestPinScannerPropagatesInspectionError(t *testing.T) {
	want := errors.New("map info failed")
	backend := &fakePinBackend{names: map[string][]string{"maps": {"control_map"}}, mapErr: want}
	if _, err := testPinScanner(t, backend).Scan(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected map inspection error: %v", err)
	}
}

func TestPinScannerPropagatesControlInspectionError(t *testing.T) {
	want := errors.New("control value failed")
	backend := &fakePinBackend{
		names:      map[string][]string{"maps": {"control_map"}},
		maps:       map[string]reconcile.MapState{"control_map": {ID: 7, Name: "control_map"}},
		controlErr: want,
	}
	if _, err := testPinScanner(t, backend).Scan(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected control inspection error: %v", err)
	}
}

func TestPinScannerHonorsCancellation(t *testing.T) {
	backend := &fakePinBackend{names: map[string][]string{"maps": {"control_map"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testPinScanner(t, backend).Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}
