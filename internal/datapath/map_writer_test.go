package datapath

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type fakeMapHandle struct {
	value         []byte
	lookupErr     error
	updateErr     error
	deleteErr     error
	updated       []byte
	lookupCalls   int
	updateCalls   int
	deleted       [][]byte
	closeCalls    int
	updateStarted chan struct{}
	updateRelease <-chan struct{}
}

func (m *fakeMapHandle) LookupBytes(any) ([]byte, error) {
	m.lookupCalls++
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	return append([]byte(nil), m.value...), nil
}

func (m *fakeMapHandle) Update(_, value any, _ ebpf.MapUpdateFlags) error {
	m.updateCalls++
	if m.updateStarted != nil {
		close(m.updateStarted)
		if m.updateRelease != nil {
			<-m.updateRelease
		}
	}
	if m.updateErr != nil {
		return m.updateErr
	}
	data, ok := value.([]byte)
	if !ok {
		return errors.New("unexpected Map value")
	}
	m.updated = append([]byte(nil), data...)
	m.value = append([]byte(nil), data...)
	return nil
}

func (m *fakeMapHandle) Delete(key any) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	data, ok := key.([]byte)
	if !ok {
		return errors.New("unexpected Map key")
	}
	m.deleted = append(m.deleted, append([]byte(nil), data...))
	return nil
}

func (m *fakeMapHandle) ListKeys() ([][]byte, error) {
	if m.value == nil {
		return nil, nil
	}
	return [][]byte{append([]byte(nil), m.value...)}, nil
}

func (m *fakeMapHandle) Close() error {
	m.closeCalls++
	return nil
}

func TestMapWriterEnsureUpdatesOnlyWhenValueChanges(t *testing.T) {
	root := t.TempDir()
	handle := &fakeMapHandle{value: []byte{1, 2}}
	control := &fakeControlMap{value: ControlV1{ABIVersion: controlMapABIVersion}}
	writer, err := newMapWriterWithControl(root, func(path string) (mapHandle, error) {
		if path != filepath.Join(root, "maps", "ingress_cache") {
			t.Fatalf("unexpected Map path: %q", path)
		}
		return handle, nil
	}, func(string) (controlMap, error) { return control, nil })
	if err != nil {
		t.Fatal(err)
	}
	changed, err := writer.Ensure(context.Background(), "ingress_cache", []byte{9}, []byte{1, 2})
	if err != nil || changed || handle.updateCalls != 0 {
		t.Fatalf("unchanged value was updated: changed=%v updates=%d err=%v", changed, handle.updateCalls, err)
	}
	changed, err = writer.Ensure(context.Background(), "ingress_cache", []byte{9}, []byte{3, 4})
	if err != nil || !changed || handle.updateCalls != 1 || string(handle.updated) != string([]byte{3, 4}) {
		t.Fatalf("changed value was not updated: changed=%v updates=%d value=%v err=%v", changed, handle.updateCalls, handle.updated, err)
	}
	if handle.lookupCalls != 2 || handle.closeCalls != 2 {
		t.Fatalf("unexpected Map calls: lookups=%d closes=%d", handle.lookupCalls, handle.closeCalls)
	}
}

func TestMapWriterEnsureHandlesMissingKeyAndRejectsTraversal(t *testing.T) {
	handle := &fakeMapHandle{}
	control := &fakeControlMap{value: ControlV1{ABIVersion: controlMapABIVersion}}
	writer, _ := newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) { return handle, nil }, func(string) (controlMap, error) { return control, nil })
	changed, err := writer.Ensure(context.Background(), "devmap", []byte{1}, []byte{2})
	if err != nil || !changed || handle.updateCalls != 1 {
		t.Fatalf("missing key was not created: changed=%v updates=%d err=%v", changed, handle.updateCalls, err)
	}
	if _, err := writer.Ensure(context.Background(), "../devmap", []byte{1}, []byte{2}); err == nil {
		t.Fatal("Map path traversal was accepted")
	}
}

func TestMapWriterEnsurePropagatesFailuresAndCancellation(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	control := &fakeControlMap{value: ControlV1{ABIVersion: controlMapABIVersion}}
	writer, _ := newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) {
		return &fakeMapHandle{lookupErr: lookupErr}, nil
	}, func(string) (controlMap, error) { return control, nil })
	if _, err := writer.Ensure(context.Background(), "devmap", []byte{1}, []byte{2}); !errors.Is(err, lookupErr) {
		t.Fatalf("lookup error was not propagated: %v", err)
	}
	called := false
	writer, _ = newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) {
		called = true
		return &fakeMapHandle{}, nil
	}, func(string) (controlMap, error) { return control, nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writer.Ensure(ctx, "devmap", []byte{1}, []byte{2}); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancellation was not honored: err=%v called=%v", err, called)
	}
}

func TestMapWriterEnsureRequiresVerifiedDisabledControlMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
	}{
		{name: "enabled", value: ControlV1{ABIVersion: controlMapABIVersion, Enabled: 1}},
		{name: "invalid enabled value", value: ControlV1{ABIVersion: controlMapABIVersion, Enabled: 2}},
		{name: "ABI mismatch", value: ControlV1{ABIVersion: controlMapABIVersion + 1}},
		{name: "lookup failure", lookupErr: errors.New("lookup failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handle := &fakeMapHandle{value: []byte{1, 2}}
			control := &fakeControlMap{value: test.value, lookupErr: test.lookupErr}
			writer, err := newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) { return handle, nil }, func(string) (controlMap, error) { return control, nil })
			if err != nil {
				t.Fatal(err)
			}
			if changed, err := writer.Ensure(context.Background(), "ingress_cache", []byte{1}, []byte{3, 4}); err == nil || changed || handle.updateCalls != 0 {
				t.Fatalf("unsafe Ensure was not rejected: changed=%v updates=%d err=%v", changed, handle.updateCalls, err)
			}
		})
	}
}

func TestMapWriterEnsureSerializesWithControlPublish(t *testing.T) {
	root := t.TempDir()
	publishUpdateStarted := make(chan struct{})
	control := &fakeControlMap{value: ControlV1{ABIVersion: controlMapABIVersion}, updateStarted: publishUpdateStarted}
	updateStarted := make(chan struct{})
	updateRelease := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(updateRelease) }) }
	defer release()
	handle := &fakeMapHandle{value: []byte{1, 2}, updateStarted: updateStarted, updateRelease: updateRelease}
	writer, err := newMapWriterWithControl(root, func(string) (mapHandle, error) { return handle, nil }, func(string) (controlMap, error) { return control, nil })
	if err != nil {
		t.Fatal(err)
	}
	publishOpened := make(chan struct{})
	controlWriter, err := newControlWriter(root, func(string) (controlMap, error) {
		close(publishOpened)
		return control, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ensureDone := make(chan error, 1)
	go func() {
		changed, err := writer.Ensure(context.Background(), "ingress_cache", []byte{1}, []byte{3, 4})
		if err == nil && !changed {
			err = errors.New("Ensure reported no change")
		}
		ensureDone <- err
	}()
	<-updateStarted

	publishDone := make(chan error, 1)
	go func() {
		publishDone <- controlWriter.Publish(context.Background(), 2, 100, 500, 0, 1, 8472)
	}()
	<-publishOpened
	select {
	case err := <-publishDone:
		t.Fatalf("control publish completed during Map mutation: %v", err)
	case <-publishUpdateStarted:
		t.Fatal("control Map was updated during Map mutation")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	if err := <-ensureDone; err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	if err := <-publishDone; err != nil {
		t.Fatalf("control publish failed after Map mutation: %v", err)
	}
	if control.updated.Enabled != 1 {
		t.Fatalf("control publish did not enable the fast path: %+v", control.updated)
	}
}

func TestMapWriterDeleteAndClearAreIdempotent(t *testing.T) {
	handle := &fakeMapHandle{value: []byte{1, 2}}
	control := &fakeControlMap{value: ControlV1{ABIVersion: controlMapABIVersion}}
	writer, _ := newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) { return handle, nil }, func(string) (controlMap, error) { return control, nil })
	deleted, err := writer.Delete(context.Background(), "ingress_cache", []byte{1, 2})
	if err != nil || !deleted || len(handle.deleted) != 1 {
		t.Fatalf("Map key was not deleted: deleted=%v calls=%d err=%v", deleted, len(handle.deleted), err)
	}
	count, err := writer.Clear(context.Background(), "policy_cache")
	if err != nil || count != 1 || len(handle.deleted) != 2 {
		t.Fatalf("Map was not cleared: count=%d calls=%d err=%v", count, len(handle.deleted), err)
	}
	missing := &fakeMapHandle{deleteErr: ebpf.ErrKeyNotExist}
	writer, _ = newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) { return missing, nil }, func(string) (controlMap, error) { return control, nil })
	deleted, err = writer.Delete(context.Background(), "ingress_cache", []byte{1})
	if err != nil || deleted {
		t.Fatalf("missing Map key was not idempotent: deleted=%v err=%v", deleted, err)
	}
}

func TestMapWriterDeleteAndClearRequireVerifiedDisabledControlMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
	}{
		{name: "enabled", value: ControlV1{ABIVersion: controlMapABIVersion, Enabled: 1}},
		{name: "invalid enabled value", value: ControlV1{ABIVersion: controlMapABIVersion, Enabled: 2}},
		{name: "ABI mismatch", value: ControlV1{ABIVersion: controlMapABIVersion + 1}},
		{name: "lookup failure", lookupErr: errors.New("lookup failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handle := &fakeMapHandle{value: []byte{1, 2}}
			control := &fakeControlMap{value: test.value, lookupErr: test.lookupErr}
			writer, err := newMapWriterWithControl(t.TempDir(), func(string) (mapHandle, error) { return handle, nil }, func(string) (controlMap, error) { return control, nil })
			if err != nil {
				t.Fatal(err)
			}
			if deleted, err := writer.Delete(context.Background(), "ingress_cache", []byte{1, 2}); err == nil || deleted || len(handle.deleted) != 0 {
				t.Fatalf("unsafe Delete was not rejected: deleted=%v calls=%d err=%v", deleted, len(handle.deleted), err)
			}
			handle.deleted = nil
			if count, err := writer.Clear(context.Background(), "policy_cache"); err == nil || count != 0 || len(handle.deleted) != 0 {
				t.Fatalf("unsafe Clear was not rejected: count=%d calls=%d err=%v", count, len(handle.deleted), err)
			}
		})
	}
}
