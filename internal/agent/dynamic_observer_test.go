package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type dynamicObserverPreflight struct{}

func (dynamicObserverPreflight) Check(context.Context, discovery.PreflightRequest) (discovery.CapabilityReport, error) {
	return discovery.CapabilityReport{Supported: true}, nil
}

type dynamicObserverFlannel struct{}

func (dynamicObserverFlannel) Discover(context.Context, flannel.DiscoveryRequest) (flannel.FlannelConfig, error) {
	return flannel.FlannelConfig{BackendType: "vxlan", VXLANLink: resolver.LinkIdentity{IfIndex: 9, IfName: "flannel.1"}, UnderlayLink: resolver.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{1, 2, 3, 4, 5, 6}}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10"), PodCIDR: netip.MustParsePrefix("10.42.0.0/24"), VNI: 1, UDPPort: 8472, MTU: 1450, MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft", Fingerprint: "dynamic"}, nil
}

type dynamicObserverEndpoints struct{}

func (dynamicObserverEndpoints) Scan(context.Context, []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	return resolver.EndpointScanResult{Endpoints: map[string]resolver.Endpoint{"pod-local": {Pod: resolver.PodIdentity{Namespace: "default", Name: "local", UID: "pod-local"}, Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}, HostLink: resolver.LinkIdentity{IfIndex: 8}}}}, nil
}

type dynamicObserverSkippedEndpoints struct{}

func (dynamicObserverSkippedEndpoints) Scan(context.Context, []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	return resolver.EndpointScanResult{Skipped: map[string]error{"pod-local": resolver.ErrEndpointNotReady}}, nil
}

type dynamicObserverTerminalEndpoints struct{}

func (dynamicObserverTerminalEndpoints) Scan(_ context.Context, pods []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	result := resolver.EndpointScanResult{Endpoints: make(map[string]resolver.Endpoint), Skipped: make(map[string]error)}
	for _, pod := range pods {
		if pod.Identity.UID != "pod-local" {
			continue
		}
		if pod.Phase == "Running" {
			result.Endpoints[pod.Identity.UID] = resolver.Endpoint{Pod: pod.Identity, Node: resolver.NodeIdentity{Name: pod.NodeName}, PodIPv4: pod.PodIPv4, NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}, HostLink: resolver.LinkIdentity{IfIndex: 8}}
			continue
		}
		result.Skipped[pod.Identity.UID] = resolver.ErrEndpointNotReady
	}
	return result, nil
}

type dynamicObserverPins struct{}

func (dynamicObserverPins) Scan(context.Context) (reconcile.ActualState, error) {
	return reconcile.ActualState{Programs: map[string]reconcile.ProgramState{"tc_init_e": {ID: 1, Name: "tc_init_e"}, "tc_restore": {ID: 2, Name: "tc_restore"}, "tc_init_in": {ID: 3, Name: "tc_init_in"}, "tc_masq": {ID: 4, Name: "tc_masq"}}, Maps: map[string]reconcile.MapState{}}, nil
}

type dynamicObserverTC struct {
	links *[]resolver.LinkIdentity
}

func (t dynamicObserverTC) Scan(_ context.Context, links []resolver.LinkIdentity) (reconcile.ActualState, error) {
	if t.links != nil {
		*t.links = append([]resolver.LinkIdentity(nil), links...)
	}
	return reconcile.ActualState{}, nil
}

type dynamicObserverRules struct{}

func (dynamicObserverRules) Scan(_ context.Context, spec flannel.MarkerRuleSpec) (reconcile.RuleState, error) {
	return reconcile.RuleState{Present: true, JumpsPresent: true, Identity: spec.Chain + "/" + spec.Comment, Fingerprint: flannel.ExpectedMarkerFingerprint(spec)}, nil
}

func TestDynamicObserverBuildsLatestDesiredAndActualState(t *testing.T) {
	cfg := dynamicTestConfig()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-b", UID: "node-b"}, InternalIPv4: netip.MustParseAddr("192.0.2.11")}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "local", UID: "pod-local"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "remote", UID: "pod-remote"}, NodeName: "node-b", PodIPv4: netip.MustParseAddr("10.42.1.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	var scannedLinks []resolver.LinkIdentity
	tc := dynamicObserverTC{links: &scannedLinks}
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicObserverPins{}, TC: tc, Rules: dynamicObserverRules{}}
	observer, err := NewDynamicObserver(cfg, store, sources)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := observer.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := desired.LocalEndpoints["pod-local"]; !ok {
		t.Fatalf("local endpoint missing: %#v", desired.LocalEndpoints)
	}
	if desired.RemoteEndpoints[netip.MustParseAddr("10.42.1.2")].NodeIPv4 != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("remote mapping missing: %#v", desired.RemoteEndpoints)
	}
	if _, err := observer.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(scannedLinks) != 3 || scannedLinks[0].IfIndex != 2 || scannedLinks[1].IfIndex != 7 || scannedLinks[2].IfIndex != 8 {
		t.Fatalf("unexpected dynamic TC links: %+v", scannedLinks)
	}
}
func TestDynamicObserverScanPropagatesEndpointScanSkipped(t *testing.T) {
	cfg := dynamicTestConfig()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-a"}}); err != nil {
		t.Fatal(err)
	}
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverSkippedEndpoints{}, Pins: dynamicObserverPins{}, TC: dynamicObserverTC{}, Rules: dynamicObserverRules{}}
	observer, err := NewDynamicObserver(cfg, store, sources)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := observer.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reason := actual.EndpointScanSkipped["pod-local"]; reason != resolver.ErrEndpointNotReady.Error() {
		t.Fatalf("dynamic actual scan lost endpoint skip: got=%q", reason)
	}
}

func TestDynamicObserverRetainsSkippedEndpointLinksForActualScan(t *testing.T) {
	cfg := dynamicTestConfig()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-a"}}); err != nil {
		t.Fatal(err)
	}
	pod := resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "local", UID: "pod-local"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}
	if err := store.UpsertPod(pod); err != nil {
		t.Fatal(err)
	}
	var scannedLinks []resolver.LinkIdentity
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverTerminalEndpoints{}, Pins: dynamicObserverPins{}, TC: dynamicObserverTC{links: &scannedLinks}, Rules: dynamicObserverRules{}}
	observer, err := NewDynamicObserver(cfg, store, sources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Desired(context.Background()); err != nil {
		t.Fatal(err)
	}
	pod.Phase = "Succeeded"
	if err := store.UpsertPod(pod); err != nil {
		t.Fatal(err)
	}
	desired, err := observer.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.LocalEndpoints) != 0 {
		t.Fatalf("terminal Pod endpoint remained desired: %#v", desired.LocalEndpoints)
	}
	scannedLinks = nil
	if _, err := observer.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(scannedLinks) != 3 || scannedLinks[0].IfIndex != 2 || scannedLinks[1].IfIndex != 7 || scannedLinks[2].IfIndex != 8 {
		t.Fatalf("terminal Pod links were not retained for actual scan: %+v", scannedLinks)
	}
}
