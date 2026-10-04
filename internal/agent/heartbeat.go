package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type HeartbeatControl interface {
	RefreshHeartbeat(context.Context, uint64) error
}

type HealthEpoch struct {
	mu    sync.RWMutex
	value uint64
	valid bool
}

func NewHealthEpoch() *HealthEpoch {
	return &HealthEpoch{value: 1, valid: true}
}

func (e *HealthEpoch) Advance() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.value++
	e.valid = true
	return e.value
}

func (e *HealthEpoch) Invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.value++
	e.valid = false
}

func (e *HealthEpoch) Snapshot() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.value
}

func (e *HealthEpoch) IsCurrent(value uint64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.valid && e.value == value
}

type HeartbeatRefresherConfig struct {
	Control  HeartbeatControl
	Epoch    *HealthEpoch
	State    func() reconcile.AgentState
	Interval time.Duration
	Now      func() (uint64, error)
}

type HeartbeatRefresher struct {
	control  HeartbeatControl
	epoch    *HealthEpoch
	state    func() reconcile.AgentState
	interval time.Duration
	now      func() (uint64, error)
}

func NewHeartbeatRefresher(config HeartbeatRefresherConfig) (*HeartbeatRefresher, error) {
	if config.Control == nil || config.Epoch == nil || config.State == nil || config.Interval <= 0 || config.Now == nil {
		return nil, fmt.Errorf("heartbeat refresher dependencies are required")
	}
	return &HeartbeatRefresher{control: config.Control, epoch: config.Epoch, state: config.State, interval: config.Interval, now: config.Now}, nil
}

func (h *HeartbeatRefresher) Tick(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.state() != reconcile.AgentReady || !h.epoch.IsCurrent(epoch) {
		return nil
	}
	heartbeat, err := h.now()
	if err != nil {
		return fmt.Errorf("read heartbeat clock: %w", err)
	}
	if err := h.control.RefreshHeartbeat(ctx, heartbeat); err != nil {
		if errors.Is(err, datapath.ErrControlMapNotReady) {
			return nil
		}
		return fmt.Errorf("refresh heartbeat: %w", err)
	}
	return nil
}

func (h *HeartbeatRefresher) Run(ctx context.Context) error {
	epoch := h.epoch.Snapshot()
	if h.state() != reconcile.AgentReady || !h.epoch.IsCurrent(epoch) {
		return nil
	}
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if h.state() != reconcile.AgentReady || !h.epoch.IsCurrent(epoch) {
				return nil
			}
			if err := h.Tick(ctx, epoch); err != nil {
				return err
			}
		}
	}
}
