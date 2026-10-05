package flannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type MarkerRuleSpec struct {
	Chain   string
	Comment string
}

type RuleScanner struct {
	run CommandRunner
}

type MarkerRuleManager struct {
	run CommandRunner
}

type markerRuleMatch struct {
	state       reconcile.RuleState
	line        string
	lineNumber  int
	chainExists bool
	found       bool
	jumps       map[string]bool
}

const markerConflictReason = "NETFILTER_MARKER_CONFLICT"

var markerJumpHooks = []string{"PREROUTING", "POSTROUTING"}

func NewRuleScanner(run CommandRunner) *RuleScanner {
	discovery := NewDiscovery(run)
	return &RuleScanner{run: discovery.run}
}

func NewMarkerRuleManager(run CommandRunner) *MarkerRuleManager {
	discovery := NewDiscovery(run)
	return &MarkerRuleManager{run: discovery.run}
}

func (s *RuleScanner) Scan(ctx context.Context, spec MarkerRuleSpec) (reconcile.RuleState, error) {
	match, err := readMarkerRule(ctx, s.run, spec)
	if err != nil {
		return reconcile.RuleState{}, fmt.Errorf("scan Flannel marker rules: %w", err)
	}
	return match.state, nil
}

func (m *MarkerRuleManager) Ensure(ctx context.Context, spec MarkerRuleSpec) (reconcile.RuleState, bool, error) {
	if err := validateMarkerRuleSpec(spec); err != nil {
		return reconcile.RuleState{}, false, err
	}
	match, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return reconcile.RuleState{}, false, err
	}
	desiredLine := markerRuleLine(spec)
	changed := false
	if !match.found || match.line != desiredLine {
		var args []string
		if match.found {
			args = append([]string{"-t", "mangle", "-R", spec.Chain, strconv.Itoa(match.lineNumber)}, markerRuleArgs(spec)...)
		} else {
			if !match.chainExists {
				if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-N", spec.Chain); err != nil {
					return reconcile.RuleState{}, false, fmt.Errorf("create marker chain: %w", err)
				}
			}
			args = append([]string{"-t", "mangle", "-A", spec.Chain}, markerRuleArgs(spec)...)
		}
		if _, err := m.run(ctx, "iptables-nft", args...); err != nil {
			return reconcile.RuleState{}, false, fmt.Errorf("apply marker rule: %w", err)
		}
		changed = true
		match, err = readMarkerRule(ctx, m.run, spec)
		if err != nil {
			return reconcile.RuleState{}, false, fmt.Errorf("verify marker rule: %w", err)
		}
	}
	for _, hook := range markerJumpHooks {
		if match.jumps[hook] {
			continue
		}
		if _, err := m.run(ctx, "iptables-nft", append([]string{"-t", "mangle", "-A", hook}, markerJumpArgs(spec, hook)...)...); err != nil {
			return reconcile.RuleState{}, changed, fmt.Errorf("apply marker jump %s: %w", hook, err)
		}
		changed = true
		match, err = readMarkerRule(ctx, m.run, spec)
		if err != nil {
			return reconcile.RuleState{}, changed, fmt.Errorf("verify marker jump %s: %w", hook, err)
		}
	}
	if !match.found || match.line != desiredLine || !match.state.JumpsPresent {
		return reconcile.RuleState{}, changed, fmt.Errorf("marker rule verification mismatch")
	}
	return match.state, changed, nil
}

func (m *MarkerRuleManager) Remove(ctx context.Context, owned reconcile.OwnedRule) error {
	spec, err := markerSpecFromOwned(owned)
	if err != nil {
		return err
	}
	match, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return err
	}
	if !match.found && !match.state.JumpsPresent {
		return nil
	}
	if match.found && (owned.Fingerprint == "" || match.state.Fingerprint != owned.Fingerprint) {
		return markerConflict("marker rule identity changed before removal")
	}
	for _, hook := range markerJumpHooks {
		if !match.jumps[hook] {
			continue
		}
		if _, err := m.run(ctx, "iptables-nft", append([]string{"-t", "mangle", "-D", hook}, markerJumpArgs(spec, hook)...)...); err != nil {
			return fmt.Errorf("remove marker jump %s: %w", hook, err)
		}
	}
	if match.found {
		if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-D", spec.Chain, strconv.Itoa(match.lineNumber)); err != nil {
			return fmt.Errorf("remove marker rule: %w", err)
		}
	}
	remaining, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return fmt.Errorf("verify marker removal: %w", err)
	}
	if remaining.found || remaining.state.JumpsPresent {
		return fmt.Errorf("marker rule or jump remains after removal")
	}
	return nil
}

func readMarkerRule(ctx context.Context, run CommandRunner, spec MarkerRuleSpec) (markerRuleMatch, error) {
	if err := validateMarkerRuleSpec(spec); err != nil {
		return markerRuleMatch{}, err
	}
	if err := ctx.Err(); err != nil {
		return markerRuleMatch{}, err
	}
	output, err := run(ctx, "iptables-nft", "-t", "mangle", "-S")
	if err != nil {
		return markerRuleMatch{}, err
	}
	match := markerRuleMatch{state: reconcile.RuleState{Identity: spec.Chain + "/" + spec.Comment}, jumps: make(map[string]bool)}
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "-N" && fields[1] == spec.Chain {
			match.chainExists = true
		}
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		chain := fields[1]
		if chain == spec.Chain {
			match.lineNumber++
		}
		if ruleHasExactComment(line, spec.Comment) {
			if chain != spec.Chain {
				return markerRuleMatch{}, markerConflict("marker comment found in another chain")
			}
			if match.found {
				return markerRuleMatch{}, markerConflict("marker rule comment is duplicated")
			}
			match.found = true
			match.line = line
			match.state.Present = true
			match.state.Fingerprint = ruleFingerprint(line)
			continue
		}
		for _, hook := range markerJumpHooks {
			if chain != hook || !strings.Contains(line, "-j "+spec.Chain) {
				continue
			}
			if !ruleHasExactComment(line, markerJumpComment(spec, hook)) {
				return markerRuleMatch{}, markerConflict("marker jump is not owned")
			}
			match.jumps[hook] = true
		}
	}
	match.state.JumpsPresent = match.jumps[markerJumpHooks[0]] && match.jumps[markerJumpHooks[1]]
	return match, nil
}

func markerRuleArgs(spec MarkerRuleSpec) []string {
	return []string{"-m", "comment", "--comment", spec.Comment, "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "tos", "--tos", "0x04/0x04", "-j", "TOS", "--set-tos", "0x08/0x08"}
}

func markerJumpComment(spec MarkerRuleSpec, hook string) string {
	return spec.Comment + "-jump-" + hook
}

func markerJumpArgs(spec MarkerRuleSpec, hook string) []string {
	return []string{"-m", "comment", "--comment", markerJumpComment(spec, hook), "-j", spec.Chain}
}

func markerJumpLine(spec MarkerRuleSpec, hook string) string {
	args := markerJumpArgs(spec, hook)
	args[3] = strconv.Quote(args[3])
	return strings.Join(append([]string{"-A", hook}, args...), " ")
}

func markerRuleLine(spec MarkerRuleSpec) string {
	args := markerRuleArgs(spec)
	for i, arg := range args {
		if i == 3 {
			args[i] = strconv.Quote(arg)
		}
	}
	return strings.Join(append([]string{"-A", spec.Chain}, args...), " ")
}

func markerSpecFromOwned(owned reconcile.OwnedRule) (MarkerRuleSpec, error) {
	parts := strings.SplitN(owned.Identity, "/", 2)
	if len(parts) != 2 {
		return MarkerRuleSpec{}, fmt.Errorf("owned marker identity is invalid: %q", owned.Identity)
	}
	comment := owned.Comment
	if comment == "" || comment == owned.Identity {
		comment = parts[1]
	}
	return MarkerRuleSpec{Chain: parts[0], Comment: comment}, validateMarkerRuleSpec(MarkerRuleSpec{Chain: parts[0], Comment: comment})
}

func markerConflict(message string) error {
	return reconcile.NewClassifiedError(reconcile.ErrorConflict, markerConflictReason, 0, fmt.Errorf("%s", message))
}

func validateMarkerRuleSpec(spec MarkerRuleSpec) error {
	if strings.TrimSpace(spec.Chain) == "" || strings.ContainsAny(spec.Chain, " \t\r\n") {
		return fmt.Errorf("marker rule chain is invalid")
	}
	if spec.Comment == "" || strings.ContainsAny(spec.Comment, " \t\"\r\n/") {
		return fmt.Errorf("marker rule comment is invalid")
	}
	return nil
}

func ruleChain(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" {
		return "", false
	}
	return fields[1], true
}

func ruleHasComment(line, comment string) bool {
	return strings.Contains(line, "--comment "+strconv.Quote(comment)) || strings.Contains(line, "--comment "+comment)
}

func ruleHasExactComment(line, comment string) bool {
	fields := strings.Fields(line)
	for index, field := range fields {
		if field != "--comment" || index+1 >= len(fields) {
			continue
		}
		return strings.Trim(fields[index+1], "\"") == comment
	}
	return false
}

func ruleFingerprint(line string) string {
	normalized := strings.Join(strings.Fields(line), " ")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func ExpectedMarkerFingerprint(spec MarkerRuleSpec) string {
	return ruleFingerprint(markerRuleLine(spec))
}
