package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeHeartbeatControl struct {
	heartbeats []uint64
	err        error
}

func (f *fakeHeartbeatControl) RefreshHeartbeat(_ context.Context, heartbeat uint64) error {
	if f.err != nil {
		return f.err
	}
	f.heartbeats = append(f.heartbeats, heartbeat)
	return nil
}

func testHeartbeatRefresher(t *testing.T, control *fakeHeartbeatControl, state *reconcile.AgentState, epoch *HealthEpoch) *HeartbeatRefresher {
	t.Helper()
	refresher, err := NewHeartbeatRefresher(HeartbeatRefresherConfig{
		Control: control, Epoch: epoch, State: func() reconcile.AgentState { return *state }, Interval: time.Second,
		Now: func() (uint64, error) { return 123, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return refresher
}

func TestHealthEpochInvalidationBlocksOldHeartbeat(t *testing.T) {
	epoch := NewHealthEpoch()
	if first := epoch.Snapshot(); !epoch.IsCurrent(first) {
		t.Fatal("new health epoch is not current")
	}
	state := reconcile.AgentReady
	control := &fakeHeartbeatControl{}
	refresher := testHeartbeatRefresher(t, control, &state, epoch)
	old := epoch.Snapshot()
	if err := refresher.Tick(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	epoch.Invalidate()
	if err := refresher.Tick(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if len(control.heartbeats) != 1 {
		t.Fatalf("stale epoch refreshed heartbeat: %v", control.heartbeats)
	}
	newEpoch := epoch.Advance()
	if newEpoch == old || !epoch.IsCurrent(newEpoch) || epoch.IsCurrent(old) {
		t.Fatalf("epoch transition is invalid: old=%d new=%d", old, newEpoch)
	}
}

func TestHeartbeatRefresherSkipsNonReadyState(t *testing.T) {
	epoch := NewHealthEpoch()
	state := reconcile.AgentDegraded
	control := &fakeHeartbeatControl{}
	refresher := testHeartbeatRefresher(t, control, &state, epoch)
	if err := refresher.Tick(context.Background(), epoch.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if len(control.heartbeats) != 0 {
		t.Fatalf("non-Ready state refreshed heartbeat: %v", control.heartbeats)
	}
}

func TestHeartbeatRefresherPropagatesRefreshFailure(t *testing.T) {
	epoch := NewHealthEpoch()
	state := reconcile.AgentReady
	control := &fakeHeartbeatControl{err: errors.New("map unavailable")}
	refresher := testHeartbeatRefresher(t, control, &state, epoch)
	err := refresher.Tick(context.Background(), epoch.Snapshot())
	if err == nil || !strings.Contains(err.Error(), "refresh heartbeat") {
		t.Fatalf("unexpected refresh error: %v", err)
	}
}

func TestHeartbeatRefresherHonorsCancellation(t *testing.T) {
	epoch := NewHealthEpoch()
	state := reconcile.AgentReady
	control := &fakeHeartbeatControl{}
	refresher := testHeartbeatRefresher(t, control, &state, epoch)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := refresher.Tick(ctx, epoch.Snapshot()); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation result: %v", err)
	}
}
