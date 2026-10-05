package agent

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type remoteMapInvalidator interface {
	Clear(context.Context, string) (int, error)
}

type remoteMapEnsurer interface {
	EnsureRemoteMappings(context.Context, reconcile.DesiredState, reconcile.ActualState, bool) (bool, error)
}

type RemoteChangeHandlerConfig struct {
	Store      *kube.SnapshotStore
	LocalNode  string
	Desired    localDesiredSource
	Maps       remoteMapInvalidator
	Generation localGenerationTransaction
}

type RemoteChangeHandler struct {
	config RemoteChangeHandlerConfig
}

func NewRemoteChangeHandler(config RemoteChangeHandlerConfig) (*RemoteChangeHandler, error) {
	if config.Store == nil || config.LocalNode == "" || config.Desired == nil || config.Maps == nil || config.Generation == nil {
		return nil, fmt.Errorf("remote change handler dependencies are required")
	}
	return &RemoteChangeHandler{config: config}, nil
}

func (h *RemoteChangeHandler) Handle(ctx context.Context, key reconcile.ReconcileKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key.Kind != reconcile.ReconcileRemoteEndpoint && key.Kind != reconcile.ReconcileGlobal {
		return nil
	}
	base, err := h.config.Desired.Desired(ctx)
	if err != nil {
		return fmt.Errorf("read desired state after remote change: %w", err)
	}
	if !base.Enabled {
		if !base.Capability.Supported {
			return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, reconcile.ReasonCapabilityUnsupported, 0, nil)
		}
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonDatapathNotReady, 0, nil)
	}
	resolved := make(map[string]resolver.Endpoint, len(base.LocalEndpoints))
	for uid, endpoint := range base.LocalEndpoints {
		resolved[uid] = endpoint
	}
	desired, err := kube.BuildDesiredState(h.config.Store.Snapshot(), base, h.config.LocalNode, resolved)
	if err != nil {
		return fmt.Errorf("build desired state after remote change: %w", err)
	}
	if err := h.config.Generation.Execute(ctx, desired, func(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) error {
		for _, name := range []string{"egressip_cache", "egress_cache", "policy_cache"} {
			if _, err := h.config.Maps.Clear(ctx, name); err != nil {
				return fmt.Errorf("clear %s for remote change: %w", name, err)
			}
		}
		ensurer, ok := h.config.Maps.(remoteMapEnsurer)
		if !ok {
			return fmt.Errorf("remote Map writer does not support remote mappings")
		}
		if _, err := ensurer.EnsureRemoteMappings(ctx, desired, actual, true); err != nil {
			return fmt.Errorf("ensure remote mappings: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("publish remote change: %w", err)
	}
	return nil
}
