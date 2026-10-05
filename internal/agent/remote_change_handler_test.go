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
	calls []string
	err   error
}

func (m *remoteMaps) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, name)
	return 2, m.err
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
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: store, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Maps: maps, Generation: testLocalGeneration(control, scanner, publisher)})
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
	if len(maps.calls) != 3 || len(events) != 5 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || events[3] != "scan" || events[4] != "publish" {
		t.Fatalf("unexpected invalidation order: maps=%v events=%v", maps.calls, events)
	}
	remote, ok := publisher.desired.RemoteEndpoints[netip.MustParseAddr("10.42.1.2")]
	if !ok || remote.NodeIPv4 != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("latest remote mapping was not published: %#v", publisher.desired.RemoteEndpoints)
	}
}

func TestRemoteChangeHandlerGlobalEventAndFailure(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{err: errors.New("clear failed")}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err == nil || len(events) != 3 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || len(maps.calls) != 1 {
		t.Fatalf("clear failure was not contained: err=%v maps=%v events=%v", err, maps.calls, events)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint}); err != nil {
		t.Fatal(err)
	}
}
