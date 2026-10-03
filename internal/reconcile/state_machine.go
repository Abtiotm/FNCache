package reconcile

import (
	"errors"
	"fmt"
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
