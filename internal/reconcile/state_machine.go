package reconcile

import (
	"errors"
	"fmt"
	"sync"
)

var ErrInvalidStateTransition = errors.New("invalid agent state transition")

// CanTransition reports whether the transition is part of the documented
// agent lifecycle. Equal states are not transitions; callers should treat an
// already reached terminal state explicitly when idempotence is required.
func CanTransition(from, to AgentState) bool {
	switch from {
	case AgentBootstrapping:
		return to == AgentDisabled || to == AgentReconciling
	case AgentDisabled:
		return to == AgentReconciling
	case AgentReconciling:
		return to == AgentReady || to == AgentDegraded || to == AgentDisabled
	case AgentReady:
		return to == AgentReconciling || to == AgentDegraded || to == AgentStopping
	case AgentDegraded:
		return to == AgentReconciling || to == AgentDisabled || to == AgentStopping
	case AgentStopping:
		return false
	default:
		return false
	}
}

func validateStateTransition(from, to AgentState) error {
	if CanTransition(from, to) {
		return nil
	}
	return fmt.Errorf("%w: %s -> %s", ErrInvalidStateTransition, from, to)
}

// AgentStateMachine owns the lifecycle state shared by static and dynamic
// runtimes. All transitions are validated and published atomically.
type AgentStateMachine struct {
	mu    sync.RWMutex
	state AgentState
}

func NewAgentStateMachine() *AgentStateMachine {
	return &AgentStateMachine{state: AgentBootstrapping}
}

func (m *AgentStateMachine) State() AgentState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *AgentStateMachine) Transition(to AgentState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateStateTransition(m.state, to); err != nil {
		return err
	}
	m.state = to
	return nil
}
