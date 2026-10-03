package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type dynamicRuntimeMaps struct{}

func (dynamicRuntimeMaps) Delete(context.Context, string, []byte) (bool, error) { return true, nil }
func (dynamicRuntimeMaps) Clear(context.Context, string) (int, error)           { return 0, nil }

type dynamicRuntimeTC struct{}

func (dynamicRuntimeTC) RemoveFilter(context.Context, datapath.TCFilterSpec) error { return nil }

type dynamicRuntimeCommitter struct{}

func (dynamicRuntimeCommitter) Commit(context.Context, reconcile.OwnershipState) error { return nil }

type dynamicRuntimePublisherControl struct{}

func (dynamicRuntimePublisherControl) Publish(context.Context, uint64, uint64, uint64, uint32) error {
	return nil
}

type dynamicRuntimeHeartbeatControl struct {
	*localHandlerControl
	mu         sync.Mutex
	heartbeats []uint64
	refreshErr error
}

func (c *dynamicRuntimeHeartbeatControl) RefreshHeartbeat(_ context.Context, heartbeat uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshErr != nil {
		return c.refreshErr
	}
	c.heartbeats = append(c.heartbeats, heartbeat)
	return nil
}

func (c *dynamicRuntimeHeartbeatControl) HeartbeatCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.heartbeats)
}

func dynamicRuntimePublisher(t *testing.T) *controlplane.Publisher {
	t.Helper()
	publisher, err := controlplane.NewPublisher(dynamicRuntimeCommitter{}, dynamicRuntimePublisherControl{}, controlplane.PublishConfig{InstallationID: "install", NodeUID: "node-a", ELFBuildID: "sha256:test", HeartbeatNS: 1, HeartbeatTimeoutNS: 5})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func dynamicTestConfig() config.AgentConfiguration {
	return config.AgentConfiguration{
		APIVersion: "oncache.io/v1alpha1", Kind: "AgentConfiguration", NodeName: "node-a", RuntimeEndpoint: "unix:///run/containerd/containerd.sock",
		PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", Datapath: config.DatapathConfig{ELFPath: "/opt/oncache/bpf/tc_prog_kern.o", ELFBuildID: "sha256:test"}, Overlay: config.OverlayConfig{Type: "flannel-vxlan", Device: "auto", VXLANLinkName: "flannel.1"},
		Markers: config.MarkerConfig{Chain: "ONCACHE", Comment: "oncache:test", MissMask: 0x04, EstablishedMask: 0x08}, Heartbeat: config.HeartbeatConfig{Interval: config.Duration(time.Second), Timeout: config.Duration(5 * time.Second)},
		Kube: config.KubeConfig{MaxStaleness: config.Duration(30 * time.Second), ResyncInterval: config.Duration(10 * time.Millisecond)}, Health: config.HealthConfig{Interval: config.Duration(5 * time.Second)},
		Scan: config.ScanConfig{IncrementalInterval: config.Duration(30 * time.Second), FullInterval: config.Duration(5 * time.Minute)}, Maps: config.MapConfig{IngressCacheMaxEntries: 1024, EgressIPCacheMaxEntries: 4096, EgressCacheMaxEntries: 1024, PolicyCacheMaxEntries: 4096, DevMapMaxEntries: 8},
		Server: config.ServerConfig{ListenAddress: ":9090"}, Features: config.FeatureConfig{Enabled: true},
	}
}

func TestDynamicRuntimeStartsKubernetesControlChain(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicObserverPins{}, TC: dynamicObserverTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return &datapathComponents{
			cri: &fakeCloser{}, endpointResolver: &localHandlerResolver{endpoint: handlerEndpoint("unused"), events: &events}, sources: sources,
			tc: dynamicRuntimeTC{}, mapWriter: dynamicRuntimeMaps{}, ownership: &deleteOwnership{state: reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install", NodeUID: "node-a"}},
			control: control, endpoint: &localHandlerEndpoint{events: &events}, maps: &localHandlerMaps{events: &events}, publisher: dynamicRuntimePublisher(t),
		}, nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for runtime.State() != KubeBootstrapReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.State() != KubeBootstrapReady {
		t.Fatalf("dynamic runtime state = %s", runtime.State())
	}
	deadline = time.Now().Add(time.Second)
	for runtime.AgentState() != reconcile.AgentReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.AgentState() != reconcile.AgentReady {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentReady)
	}
	deadline = time.Now().Add(time.Second)
	for control.HeartbeatCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if control.HeartbeatCount() == 0 {
		t.Fatal("dynamic runtime did not start heartbeat refresh")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic runtime did not stop")
	}
	if runtime.AgentState() != reconcile.AgentStopping {
		t.Fatalf("agent state after stop = %s, want %s", runtime.AgentState(), reconcile.AgentStopping)
	}
	heartbeats := control.HeartbeatCount()
	time.Sleep(20 * time.Millisecond)
	if control.HeartbeatCount() != heartbeats {
		t.Fatalf("heartbeat continued after runtime stop: before=%d after=%d", heartbeats, control.HeartbeatCount())
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("restarting a stopped runtime unexpectedly succeeded")
	}
}

func TestDynamicRuntimeDegradesWhenHeartbeatFails(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicObserverPins{}, TC: dynamicObserverTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	wantErr := errors.New("heartbeat map unavailable")
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}, refreshErr: wantErr}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return &datapathComponents{
			cri: &fakeCloser{}, endpointResolver: &localHandlerResolver{endpoint: handlerEndpoint("unused"), events: &events}, sources: sources,
			tc: dynamicRuntimeTC{}, mapWriter: dynamicRuntimeMaps{}, ownership: &deleteOwnership{state: reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install", NodeUID: "node-a"}},
			control: control, endpoint: &localHandlerEndpoint{events: &events}, maps: &localHandlerMaps{events: &events}, publisher: dynamicRuntimePublisher(t),
		}, nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want %v", err, wantErr)
	}
	if runtime.AgentState() != reconcile.AgentDegraded {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDegraded)
	}
	if len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("heartbeat failure did not disable fast path: events=%v", events)
	}
}

func TestDynamicRuntimeDisablesAfterDatapathInitializationFailure(t *testing.T) {
	wantErr := errors.New("datapath unavailable")
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return nil, wantErr
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(dynamicTestConfig(), fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want %v", err, wantErr)
	}
	if runtime.AgentState() != reconcile.AgentDisabled {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDisabled)
	}
}

func TestNewDynamicRuntimeRejectsInvalidConfiguration(t *testing.T) {
	cfg := dynamicTestConfig()
	cfg.NodeName = ""
	if _, err := newDynamicRuntime(cfg, fake.NewSimpleClientset()); err == nil {
		t.Fatal("invalid dynamic configuration was accepted")
	}
}
