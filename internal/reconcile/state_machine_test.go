package reconcile

import (
	"context"
	"errors"
	"testing"
)

func TestCanTransitionAgentState(t *testing.T) {
	tests := []struct {
		from AgentState
		to   AgentState
		want bool
	}{
		{AgentBootstrapping, AgentDisabled, true},
		{AgentBootstrapping, AgentReconciling, true},
		{AgentDisabled, AgentReconciling, true},
		{AgentReconciling, AgentReady, true},
		{AgentReconciling, AgentDegraded, true},
		{AgentReconciling, AgentDisabled, true},
		{AgentReady, AgentReconciling, true},
		{AgentReady, AgentDegraded, true},
		{AgentReady, AgentStopping, true},
		{AgentDegraded, AgentReconciling, true},
		{AgentDegraded, AgentDisabled, true},
		{AgentDegraded, AgentStopping, true},
		{AgentBootstrapping, AgentReady, false},
		{AgentDisabled, AgentReady, false},
		{AgentReady, AgentDisabled, false},
		{AgentStopping, AgentReconciling, false},
		{AgentStopping, AgentStopping, false},
	}
	for _, tt := range tests {
		if got := CanTransition(tt.from, tt.to); got != tt.want {
			t.Errorf("CanTransition(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestInvalidStateTransitionReturnsStableError(t *testing.T) {
	err := validateStateTransition(AgentStopping, AgentReady)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("error = %v, want ErrInvalidStateTransition", err)
	}
}

func TestCoordinatorStopTransitionsAndBlocksReconcile(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}}
	coordinator, err := NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.FullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if coordinator.State() != AgentStopping {
		t.Fatalf("state = %s, want %s", coordinator.State(), AgentStopping)
	}
	if err := coordinator.Stop(context.Background()); err != nil {
		t.Fatalf("repeated Stop returned error: %v", err)
	}
	steps := len(backend.steps)
	result, err := coordinator.FullReconcile(context.Background())
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("reconcile error = %v, want ErrInvalidStateTransition", err)
	}
	if result.State != AgentStopping || len(backend.steps) != steps {
		t.Fatalf("reconcile after Stop changed state or backend: result=%+v steps=%v", result, backend.steps)
	}
}
