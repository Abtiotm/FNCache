package cleanup

import (
	"context"
	"fmt"
	"sort"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const (
	ActionTC      = "tc-filter"
	ActionMarker  = "marker-rule"
	ActionMap     = "map-pin"
	ActionProgram = "program-pin"
	ActionState   = "ownership-state"
)

type Options struct {
	PinRoot, StatePath, InstallationID string
	MarkerChain, MarkerComment         string
}

type Action struct {
	Kind       string   `json:"kind"`
	Identity   string   `json:"identity"`
	Evidence   []string `json:"evidence"`
	attachment *reconcile.AttachmentState
	marker     *reconcile.OwnedRule
	name       string
	id         uint32
}

type Plan struct {
	Actions []Action `json:"actions"`
	Blocked []Action `json:"blocked"`
}

type Executor interface {
	Disable(context.Context) error
	RemoveAttachment(context.Context, reconcile.AttachmentState) error
	RemoveMarker(context.Context, reconcile.OwnedRule) error
	RemoveMap(context.Context, string, uint32) error
	RemoveProgram(context.Context, string, uint32) error
	RemoveState(context.Context) error
}

func (p Plan) Execute(ctx context.Context, executor Executor, dryRun bool) error {
	if executor == nil {
		return fmt.Errorf("cleanup executor is required")
	}
	if dryRun {
		return nil
	}
	if len(p.Blocked) != 0 {
		return fmt.Errorf("cleanup blocked by %d ownership conflicts", len(p.Blocked))
	}
	if err := executor.Disable(ctx); err != nil {
		return fmt.Errorf("disable before cleanup: %w", err)
	}
	for _, action := range p.Actions {
		var err error
		switch action.Kind {
		case ActionTC:
			err = executor.RemoveAttachment(ctx, *action.attachment)
		case ActionMarker:
			err = executor.RemoveMarker(ctx, *action.marker)
		case ActionMap:
			err = executor.RemoveMap(ctx, action.name, action.id)
		case ActionProgram:
			err = executor.RemoveProgram(ctx, action.name, action.id)
		case ActionState:
			err = executor.RemoveState(ctx)
		default:
			err = fmt.Errorf("unknown cleanup action %q", action.Kind)
		}
		if err != nil {
			return fmt.Errorf("cleanup %s %s: %w", action.Kind, action.Identity, err)
		}
	}
	return nil
}

func BuildPlan(state reconcile.OwnershipState, actual reconcile.ActualState, marker reconcile.RuleState, markerIdentity string, unresolvedNetNS []reconcile.AttachmentState) Plan {
	plan := Plan{}
	for _, attachment := range unresolvedNetNS {
		plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(attachment), Evidence: []string{"netns path is not persisted and could not be resolved"}})
	}
	for _, owned := range state.Attachments {
		if hasAttachment(unresolvedNetNS, owned) || state.Programs[owned.Program].ID != owned.ProgramID {
			continue
		}
		if _, err := datapath.NewFixedFilter(owned.Link, owned.Program, owned.ProgramID, true); err != nil {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"persisted TC identity is invalid"}})
			continue
		}
		found, slotConflict := findAttachment(actual.Attachments, owned)
		if found {
			copy := owned
			plan.Actions = append(plan.Actions, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"link identity", "program ID", "fixed handle"}, attachment: &copy})
		} else if slotConflict {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"TC slot is occupied by a different program"}})
		}
	}
	if state.FlannelRule.Identity != "" {
		if state.FlannelRule.Identity != markerIdentity {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMarker, Identity: state.FlannelRule.Identity, Evidence: []string{"configured marker identity differs"}})
		} else if marker.Present && marker.Fingerprint == state.FlannelRule.Fingerprint {
			owned := state.FlannelRule
			plan.Actions = append(plan.Actions, Action{Kind: ActionMarker, Identity: owned.Identity, Evidence: []string{"marker fingerprint"}, marker: &owned})
		} else if marker.Present {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMarker, Identity: state.FlannelRule.Identity, Evidence: []string{"marker fingerprint changed"}})
		}
	}
	mapNames := make([]string, 0, len(state.Maps))
	for name := range state.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		owned, ok := state.Maps[name]
		if !ok {
			continue
		}
		actualMap, present := actual.Maps[name]
		if !present {
			continue
		}
		if actualMap.ID != owned.ID {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMap, Identity: "maps/" + name, Evidence: []string{"Map ID changed"}})
			continue
		}
		plan.Actions = append(plan.Actions, Action{Kind: ActionMap, Identity: "maps/" + name, Evidence: []string{"Map ID"}, name: name, id: owned.ID})
	}
	programNames := make([]string, 0, len(state.Programs))
	for name := range state.Programs {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)
	for _, name := range programNames {
		owned := state.Programs[name]
		actualProgram, present := actual.Programs[name]
		if !present {
			continue
		}
		if actualProgram.ID != owned.ID {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionProgram, Identity: "programs/" + name, Evidence: []string{"program ID changed"}})
			continue
		}
		plan.Actions = append(plan.Actions, Action{Kind: ActionProgram, Identity: "programs/" + name, Evidence: []string{"program ID"}, name: name, id: owned.ID})
	}
	plan.Actions = append(plan.Actions, Action{Kind: ActionState, Identity: "state.json", Evidence: []string{"validated ownership state"}})
	return plan
}

func hasAttachment(list []reconcile.AttachmentState, wanted reconcile.AttachmentState) bool {
	for _, item := range list {
		if attachmentIdentity(item) == attachmentIdentity(wanted) {
			return true
		}
	}
	return false
}

func findAttachment(list []reconcile.AttachmentState, wanted reconcile.AttachmentState) (bool, bool) {
	conflict := false
	for _, item := range list {
		if item.Link.NetNSInode != wanted.Link.NetNSInode || item.Link.IfIndex != wanted.Link.IfIndex || item.Hook != wanted.Hook || item.Priority != wanted.Priority || item.Handle != wanted.Handle {
			continue
		}
		if attachmentIdentity(item) == attachmentIdentity(wanted) {
			return true, false
		}
		conflict = true
	}
	return false, conflict
}

func attachmentIdentity(a reconcile.AttachmentState) string {
	return fmt.Sprintf("%d/%d/%s/%d/%d/%s/%d", a.Link.NetNSInode, a.Link.IfIndex, a.Hook, a.Priority, a.Handle, a.Program, a.ProgramID)
}
