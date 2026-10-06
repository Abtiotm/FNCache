package datapath

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

type fakeControlMap struct {
	value       ControlV1
	lookupErr   error
	updateErr   error
	closeErr    error
	updated     ControlV1
	lookupCalls int
	updateCalls int
	closeCalls  int
}

func (m *fakeControlMap) Lookup(_ interface{}, value interface{}) error {
	m.lookupCalls++
	if m.lookupErr != nil {
		return m.lookupErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected lookup value")
	}
	*control = m.value
	return nil
}

func (m *fakeControlMap) Update(_ interface{}, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected update value")
	}
	m.updated = *control
	return nil
}

func (m *fakeControlMap) Close() error {
	m.closeCalls++
	return m.closeErr
}

func TestReadControlState(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		want      reconcile.ControlState
		wantErr   string
	}{
		{name: "enabled", value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42}, want: reconcile.ControlState{Verified: true, Enabled: true, Generation: 42}},
		{name: "disabled", value: ControlV1{ABIVersion: 1, Enabled: 0}, want: reconcile.ControlState{Verified: true}},
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, wantErr: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), wantErr: "read control Map"},
		{name: "invalid enabled value", value: ControlV1{ABIVersion: 1, Enabled: 2}, wantErr: "invalid control Map enabled value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := readControlState(&fakeControlMap{value: test.value, lookupErr: test.lookupErr})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("unexpected read error: %v", err)
				}
				return
			}
			if err != nil || state != test.want {
				t.Fatalf("unexpected control state: state=%+v err=%v want=%+v", state, err, test.want)
			}
		})
	}
}

func TestControlWriterDisablePreservesControlState(t *testing.T) {
	mapValue := ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Flags: 3, Reserved: 7}
	fake := &fakeControlMap{value: mapValue}
	root := t.TempDir()
	writer, err := newControlWriter(root, func(path string) (controlMap, error) {
		want := filepath.Join(root, "maps", "control_map")
		if path != want {
			t.Fatalf("unexpected control Map path: got=%q want=%q", path, want)
		}
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 0 || fake.updated.ABIVersion != mapValue.ABIVersion ||
		fake.updated.Generation != mapValue.Generation || fake.updated.HeartbeatNS != mapValue.HeartbeatNS ||
		fake.updated.HeartbeatTimeoutNS != mapValue.HeartbeatTimeoutNS || fake.updated.Flags != mapValue.Flags ||
		fake.updated.Reserved != mapValue.Reserved {
		t.Fatalf("disable did not preserve control state: got=%+v want=%+v", fake.updated, mapValue)
	}
	if fake.lookupCalls != 1 || fake.updateCalls != 1 || fake.closeCalls != 1 {
		t.Fatalf("unexpected Map calls: lookup=%d update=%d close=%d", fake.lookupCalls, fake.updateCalls, fake.closeCalls)
	}
}

func TestControlWriterDisableInitializesUninitializedMap(t *testing.T) {
	fake := &fakeControlMap{}
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated != (ControlV1{ABIVersion: 1}) {
		t.Fatalf("unexpected initialized control state: %+v", fake.updated)
	}
}

func TestControlWriterInitializeDisablesAndResetsState(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 9, HeartbeatNS: 10, HeartbeatTimeoutNS: 20, Flags: 3, Reserved: 4}}
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated != (ControlV1{ABIVersion: 1}) {
		t.Fatalf("unexpected initialized control state: %+v", fake.updated)
	}
}

func TestControlWriterInitializeRejectsIncompatibleOrFailedMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", updateErr: errors.New("update failed"), want: "initialize control Map"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Initialize(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected initialize error: %v", err)
			}
		})
	}
}

func TestControlWriterDisableRejectsInvalidOrUnavailableMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", value: ControlV1{ABIVersion: 1}, updateErr: errors.New("update failed"), want: "disable fast path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Disable(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected disable error: %v", err)
			}
		})
	}
}

func TestControlWriterPublishEnablesNewGeneration(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 0, Generation: 4, Flags: 1}}
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Publish(context.Background(), 42, 100, 500, 3, 1, 8472); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 1 || fake.updated.Generation != 42 || fake.updated.HeartbeatNS != 100 ||
		fake.updated.HeartbeatTimeoutNS != 500 || fake.updated.Flags != 3|(uint32(8472)<<controlVXLANUDPShift) || fake.updated.Reserved != 1 {
		t.Fatalf("unexpected published control state: %+v", fake.updated)
	}
}

func TestControlWriterPublishRejectsInvalidVXLANConfig(t *testing.T) {
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		return &fakeControlMap{value: ControlV1{ABIVersion: 1}}, nil
	})
	for _, test := range []struct {
		name string
		vni  uint32
		port uint16
	}{
		{name: "zero VNI", vni: 0, port: 8472},
		{name: "too large VNI", vni: 0x1000000, port: 8472},
		{name: "zero UDP port", vni: 1, port: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := writer.Publish(context.Background(), 42, 100, 500, 3, test.vni, test.port); err == nil {
				t.Fatal("invalid VXLAN configuration was accepted")
			}
		})
	}
}

func TestControlWriterRefreshHeartbeatPreservesControlState(t *testing.T) {
	mapValue := ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Flags: 3, Reserved: 7}
	fake := &fakeControlMap{value: mapValue}
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.RefreshHeartbeat(context.Background(), 900); err != nil {
		t.Fatal(err)
	}
	want := mapValue
	want.HeartbeatNS = 900
	if fake.updated != want {
		t.Fatalf("heartbeat refresh changed unrelated control state: got=%+v want=%+v", fake.updated, want)
	}
}

func TestControlWriterRefreshHeartbeatRejectsInvalidState(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "disabled", value: ControlV1{ABIVersion: 1}, want: "control Map is not ready"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", value: ControlV1{ABIVersion: 1, Enabled: 1}, updateErr: errors.New("update failed"), want: "refresh heartbeat"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.RefreshHeartbeat(context.Background(), 900); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected heartbeat refresh error: %v", err)
			}
		})
	}
}

func TestControlWriterRefreshHeartbeatClassifiesMissingMap(t *testing.T) {
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return nil, os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.RefreshHeartbeat(context.Background(), 900); !errors.Is(err, ErrControlMapNotReady) {
		t.Fatalf("error = %v, want ErrControlMapNotReady", err)
	}
}

func TestControlWriterPublishRejectsInvalidHeartbeat(t *testing.T) {
	called := false
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		called = true
		return &fakeControlMap{value: ControlV1{ABIVersion: 1}}, nil
	})
	if err := writer.Publish(context.Background(), 1, 0, 500, 0, 1, 8472); err == nil || called {
		t.Fatalf("invalid heartbeat was accepted: err=%v called=%v", err, called)
	}
}

func TestControlWriterDisableHonorsCancellation(t *testing.T) {
	called := false
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		called = true
		return &fakeControlMap{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.Disable(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("unexpected cancellation result: err=%v called=%v", err, called)
	}
}
