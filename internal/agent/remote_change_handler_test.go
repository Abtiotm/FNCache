package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type remoteMaps struct {
	calls          []string
	remoteMappings int
	err            error
}

type remoteTestOwnership struct{ commits int }

func (s *remoteTestOwnership) Commit(context.Context, reconcile.OwnershipState) error {
	s.commits++
	return nil
}

type remoteTestControlPublisher struct{ publishes int }

func (p *remoteTestControlPublisher) Publish(context.Context, uint64, uint64, uint64, uint32) error {
	p.publishes++
	return nil
}

func (m *remoteMaps) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, name)
	return 2, m.err
}

func (m *remoteMaps) EnsureRemoteMappings(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState, _ bool) (bool, error) {
	m.remoteMappings++
	return true, m.err
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
	return newRemoteChangeHandlerWithDesired(t, store, maps, events, publisher, reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}})
}

func newRemoteChangeHandlerWithDesired(t *testing.T, store *kube.SnapshotStore, maps *remoteMaps, events *[]string, publisher *localHandlerPublisher, base reconcile.DesiredState) *RemoteChangeHandler {
	t.Helper()
	control := &localHandlerControl{events: events}
	scanner := &localHandlerScanner{events: events}
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: store, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Maps: maps, Generation: testLocalGeneration(control, scanner, publisher)})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestRemoteChangeHandlerRetriesWhenEndpointScanIsIncomplete(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	ownership := &remoteTestOwnership{}
	controlPublisher := &remoteTestControlPublisher{}
	publisher, err := controlplane.NewPublisher(ownership, controlPublisher, controlplane.PublishConfig{
		InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "build-a", HeartbeatNS: 1, HeartbeatTimeoutNS: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	generation, err := controlplane.NewGenerationTransaction(control, scanner, publisher)
	if err != nil {
		t.Fatal(err)
	}
	base := reconcile.DesiredState{
		Generation: 1, Enabled: true, Capability: discovery.CapabilityReport{Supported: true},
		EndpointScanSkipped: map[string]string{"pod-local": resolver.ErrEndpointNotReady.Error()},
	}
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{
		Store: remoteChangeStore(t), LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: &events}, Maps: maps, Generation: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete endpoint scan was not retried: err=%v", err)
	}
	if len(events) != 2 || events[0] != "desired" || events[1] != "disable" || len(maps.calls) != 0 || maps.remoteMappings != 0 || ownership.commits != 0 || controlPublisher.publishes != 0 {
		t.Fatalf("incomplete endpoint scan reached mutation: events=%v maps=%v remote=%d commits=%d publishes=%d", events, maps.calls, maps.remoteMappings, ownership.commits, controlPublisher.publishes)
	}
}

func TestRemoteChangeHandlerInvalidatesAndPublishesLatestMapping(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &localHandlerPublisher{events: &events}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"}); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 3 || maps.remoteMappings != 1 || len(events) != 5 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || events[3] != "scan" || events[4] != "publish" {
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
