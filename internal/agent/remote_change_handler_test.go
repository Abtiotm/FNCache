package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type remoteMaps struct {
	calls          []string
	remoteMappings int
	baseCalls      int
	deviceMapCalls int
	err            error
	baseErr        error
	deviceMapErr   error
}

func (m *remoteMaps) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, name)
	return 2, m.err
}

func (m *remoteMaps) EnsureRemoteMappings(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState, _ bool) (bool, error) {
	m.remoteMappings++
	return true, m.err
}

func (m *remoteMaps) EnsureBase(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) (bool, error) {
	m.baseCalls++
	return true, m.baseErr
}

func (m *remoteMaps) EnsureDeviceMap(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState, _ bool) (bool, error) {
	m.deviceMapCalls++
	return true, m.deviceMapErr
}

func remoteChangeStore(t *testing.T) *kube.SnapshotStore {
	t.Helper()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-b", UID: "node-2"}, InternalIPv4: netip.MustParseAddr("192.0.2.11")}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "remote", UID: "pod-remote"}, NodeName: "node-b", PodIPv4: netip.MustParseAddr("10.42.1.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	return store
}

func newRemoteChangeHandler(t *testing.T, store *kube.SnapshotStore, maps *remoteMaps, events *[]string, publisher *localHandlerPublisher) *RemoteChangeHandler {
	t.Helper()
	base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}}
	control := &localHandlerControl{events: events}
	scanner := &localHandlerScanner{events: events}
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: store, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Maps: maps, Base: maps, DeviceMap: maps, Generation: testLocalGeneration(control, scanner, publisher)})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestRemoteChangeHandlerInvalidatesAndPublishesLatestMapping(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &localHandlerPublisher{events: &events}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"}); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 3 || maps.remoteMappings != 1 || maps.baseCalls != 0 || maps.deviceMapCalls != 0 || len(events) != 5 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || events[3] != "scan" || events[4] != "publish" {
		t.Fatalf("unexpected invalidation order: maps=%v events=%v", maps.calls, events)
	}
	remote, ok := publisher.desired.RemoteEndpoints[netip.MustParseAddr("10.42.1.2")]
	if !ok || remote.NodeIPv4 != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("latest remote mapping was not published: %#v", publisher.desired.RemoteEndpoints)
	}
}

func TestRemoteChangeHandlerGlobalRefreshesBaseDatapath(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &localHandlerPublisher{events: &events}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err != nil {
		t.Fatal(err)
	}
	if maps.baseCalls != 1 || maps.deviceMapCalls != 1 || len(maps.calls) != 3 || maps.remoteMappings != 1 {
		t.Fatalf("global change did not refresh base datapath: base=%d devmap=%d clears=%v remote=%d", maps.baseCalls, maps.deviceMapCalls, maps.calls, maps.remoteMappings)
	}
}

func TestRemoteChangeHandlerGlobalDatapathFailureStopsBeforeRemoteMaps(t *testing.T) {
	tests := []struct {
		name          string
		maps          *remoteMaps
		baseCalls     int
		deviceMapCall int
	}{
		{name: "base", maps: &remoteMaps{baseErr: errors.New("base failed")}, baseCalls: 1},
		{name: "devmap", maps: &remoteMaps{deviceMapErr: errors.New("devmap failed")}, baseCalls: 1, deviceMapCall: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			publisher := &localHandlerPublisher{events: &events}
			handler := newRemoteChangeHandler(t, remoteChangeStore(t), test.maps, &events, publisher)
			if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err == nil {
				t.Fatal("global datapath failure was ignored")
			}
			if test.maps.baseCalls != test.baseCalls || test.maps.deviceMapCalls != test.deviceMapCall || len(test.maps.calls) != 0 || test.maps.remoteMappings != 0 {
				t.Fatalf("remote maps were touched after datapath failure: base=%d devmap=%d clears=%v remote=%d", test.maps.baseCalls, test.maps.deviceMapCalls, test.maps.calls, test.maps.remoteMappings)
			}
			if len(events) != 3 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" {
				t.Fatalf("generation continued after datapath failure: %v", events)
			}
		})
	}
}

func TestRemoteChangeHandlerGlobalEventAndFailure(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{err: errors.New("clear failed")}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err == nil || maps.baseCalls != 1 || maps.deviceMapCalls != 1 || len(events) != 3 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || len(maps.calls) != 1 {
		t.Fatalf("clear failure was not contained: err=%v maps=%v events=%v", err, maps.calls, events)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint}); err != nil {
		t.Fatal(err)
	}
}
