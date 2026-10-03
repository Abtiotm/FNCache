package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DynamicRuntime struct {
	config      config.AgentConfiguration
	store       *kube.SnapshotStore
	source      *kube.InformerSource
	bootstrap   *KubeBootstrap
	resync      *kube.ResyncScheduler
	queue       *queue.Queue
	barrier     *reconcile.CoordinationBarrier
	lifecycle   *reconcile.AgentStateMachine
	healthEpoch *HealthEpoch
	factory     datapathComponentFactory
	components  *datapathComponents
	observer    *DynamicObserver
	worker      *queue.Worker
	heartbeat   *HeartbeatRefresher
}

type datapathComponentFactory func(context.Context, datapathComponentConfig) (*datapathComponents, error)

func NewDynamicRuntime(configPath string) (*DynamicRuntime, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load agent configuration: %w", err)
	}
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster Kubernetes configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return newDynamicRuntime(cfg, client)
}

func newDynamicRuntime(cfg config.AgentConfiguration, client kubernetes.Interface) (*DynamicRuntime, error) {
	return newDynamicRuntimeWithFactory(cfg, client, newDatapathComponents)
}

func newDynamicRuntimeWithFactory(cfg config.AgentConfiguration, client kubernetes.Interface, factory datapathComponentFactory) (*DynamicRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil || factory == nil {
		return nil, fmt.Errorf("Kubernetes client is required")
	}
	store := kube.NewSnapshotStore()
	interval := time.Duration(cfg.Kube.ResyncInterval)
	source, err := kube.NewInformerSource(client, store, interval)
	if err != nil {
		return nil, err
	}
	target, err := queue.New(queue.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("create coordination queue: %w", err)
	}
	classifier, err := kube.NewEventClassifier(cfg.NodeName)
	if err != nil {
		return nil, err
	}
	if _, err := kube.NewEventDispatcher(source, classifier, target); err != nil {
		return nil, err
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		return nil, err
	}
	resync, err := kube.NewResyncScheduler(store, cfg.NodeName, target, interval)
	if err != nil {
		return nil, err
	}
	return &DynamicRuntime{config: cfg, store: store, source: source, bootstrap: bootstrap, resync: resync, queue: target, barrier: reconcile.NewCoordinationBarrier(), lifecycle: reconcile.NewAgentStateMachine(), healthEpoch: NewHealthEpoch(), factory: factory}, nil
}

func (r *DynamicRuntime) Run(ctx context.Context) error {
	if err := r.bootstrap.Start(ctx); err != nil {
		if transitionErr := r.lifecycle.Transition(reconcile.AgentDisabled); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
		return err
	}
	if err := r.lifecycle.Transition(reconcile.AgentReconciling); err != nil {
		return err
	}
	if err := r.initializeDatapath(ctx); err != nil {
		if transitionErr := r.lifecycle.Transition(reconcile.AgentDisabled); transitionErr != nil {
			return errors.Join(err, transitionErr)
		}
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.resync.Run(runCtx)
	workerDone := make(chan struct{})
	go func() {
		r.worker.Run(runCtx)
		close(workerDone)
	}()
	if err := r.lifecycle.Transition(reconcile.AgentReady); err != nil {
		cancel()
		r.queue.ShutDown()
		<-workerDone
		_ = r.components.Close()
		return err
	}
	r.healthEpoch.Advance()
	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- r.heartbeat.Run(runCtx) }()
	heartbeatObserved := false
	workerStopped := false
	var runErr, stopErr error
	select {
	case heartbeatErr := <-heartbeatDone:
		heartbeatObserved = true
		if ctx.Err() != nil {
			r.healthEpoch.Invalidate()
			stopErr = r.lifecycle.Transition(reconcile.AgentStopping)
		} else {
			r.healthEpoch.Invalidate()
			if heartbeatErr == nil {
				heartbeatErr = fmt.Errorf("heartbeat refresher stopped unexpectedly")
			}
		}
		cancel()
		r.queue.ShutDown()
		if ctx.Err() == nil {
			<-workerDone
			workerStopped = true
			disableErr := r.components.control.Disable(ctx)
			degradedErr := r.lifecycle.Transition(reconcile.AgentDegraded)
			runErr = errors.Join(heartbeatErr, disableErr, degradedErr)
		}
	case <-ctx.Done():
		r.healthEpoch.Invalidate()
		stopErr = r.lifecycle.Transition(reconcile.AgentStopping)
		cancel()
		r.queue.ShutDown()
	}
	if !heartbeatObserved {
		<-heartbeatDone
	}
	r.queue.ShutDown()
	if !workerStopped {
		<-workerDone
	}
	if r.components != nil {
		return errors.Join(runErr, stopErr, r.components.Close())
	}
	return errors.Join(runErr, stopErr)
}

func (r *DynamicRuntime) State() KubeBootstrapState { return r.bootstrap.State() }

func (r *DynamicRuntime) AgentState() reconcile.AgentState { return r.lifecycle.State() }

func (r *DynamicRuntime) initializeDatapath(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := r.bootstrap.Snapshot()
	if err != nil {
		return err
	}
	node, ok := snapshot.Nodes[r.config.NodeName]
	if !ok || node.Identity.UID == "" {
		return fmt.Errorf("local Node %q is missing from Snapshot", r.config.NodeName)
	}
	heartbeat, err := monotonicNowNS()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	components, err := r.factory(ctx, datapathComponentConfig{
		ELFPath: r.config.Datapath.ELFPath, PinRoot: r.config.PinRoot, StatePath: filepath.Join(r.config.StateDir, "state.json"),
		InstallationID: r.config.InstallationID, ELFBuildID: r.config.Datapath.ELFBuildID, HeartbeatNS: heartbeat,
		HeartbeatTimeoutNS: uint64(time.Duration(r.config.Heartbeat.Timeout)), Flags: 0,
		Preflight: discovery.PreflightRequest{Node: node.Identity, PinRoot: r.config.PinRoot, StateDir: r.config.StateDir, RuntimeURI: r.config.RuntimeEndpoint, Overlay: r.config.Overlay.Type},
		Flannel:   flannel.DiscoveryRequest{VXLANLinkName: r.config.Overlay.VXLANLinkName, UnderlayDevice: r.config.Overlay.Device, MissMask: r.config.Markers.MissMask, EstablishedMask: r.config.Markers.EstablishedMask, IPTablesBackend: "iptables-nft"},
		Marker:    flannel.MarkerRuleSpec{Chain: r.config.Markers.Chain, Comment: r.config.Markers.Comment},
	})
	if err != nil {
		return fmt.Errorf("create dynamic datapath components: %w", err)
	}
	heartbeatControl, ok := components.control.(HeartbeatControl)
	if !ok {
		_ = components.Close()
		return fmt.Errorf("dynamic datapath heartbeat control is unavailable")
	}
	heartbeatRefresher, err := NewHeartbeatRefresher(HeartbeatRefresherConfig{
		Control: heartbeatControl, Epoch: r.healthEpoch, State: r.AgentState,
		Interval: time.Duration(r.config.Heartbeat.Interval), Now: monotonicNowNS,
	})
	if err != nil {
		_ = components.Close()
		return err
	}
	observer, err := NewDynamicObserver(r.config, r.store, components.sources)
	if err != nil {
		_ = components.Close()
		return err
	}
	remover, err := controlplane.NewEndpointRemover(components.mapWriter, components.tc)
	if err != nil {
		_ = components.Close()
		return err
	}
	guard, err := NewEndpointReuseGuard(components.endpointResolver, r.config.NodeName)
	if err != nil {
		_ = components.Close()
		return err
	}
	local, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: r.store, Resolver: components.endpointResolver, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Endpoint: components.endpoint, Maps: components.maps, Remover: remover, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	deleting, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{Store: r.store, Ownership: components.ownership, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Remover: remover, ReuseGuard: guard, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	remote, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: r.store, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Maps: components.mapWriter, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	router, err := NewDynamicHandlerRouter(local, deleting, remote)
	if err != nil {
		_ = components.Close()
		return err
	}
	worker, err := queue.NewWorkerWithBarrier(r.queue, router.Handle, r.barrier)
	if err != nil {
		_ = components.Close()
		return err
	}
	r.components, r.observer, r.worker, r.heartbeat = components, observer, worker, heartbeatRefresher
	return nil
}
