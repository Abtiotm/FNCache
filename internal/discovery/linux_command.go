package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

var requiredBPFHelpers = []string{
	"bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_get_hash_recalc",
	"bpf_skb_adjust_room", "bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_spin_lock", "bpf_spin_unlock",
}

func hasHelper(output []byte, helper string) bool {
	for _, field := range strings.Fields(string(output)) {
		if strings.Trim(field, "[](){}:,\"'") == helper {
			return true
		}
	}
	return false
}

func hasDirectAction(output []byte) bool {
	text := strings.ToLower(string(output))
	if strings.Contains(text, "direct_action") || strings.Contains(text, "direct-action") {
		return true
	}
	if strings.Contains(text, "ebpf program_type sched_cls is available") {
		return true
	}
	return strings.Contains(text, "config_net_cls_act is set to y") &&
		strings.Contains(text, "sched_cls")
}

func validRouteOutput(output []byte) bool {
	var routes []json.RawMessage
	return json.Unmarshal(bytes.TrimSpace(output), &routes) == nil && len(routes) > 0
}

func hasReservedTOSConflict(output []byte, markerChain, markerComment string) bool {
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.Join(strings.Fields(raw), " ")
		if isMarkerRule(line, markerChain, markerComment) {
			continue
		}
		normalized := strings.ToLower(line)
		if !strings.Contains(normalized, "set-tos") && !strings.Contains(normalized, "set-dscp") && !strings.Contains(normalized, "set-xmark") {
			continue
		}
		if strings.Contains(normalized, "0x04") || strings.Contains(normalized, "0x08") {
			return true
		}
	}
	return false
}

func isMarkerRule(line, markerChain, markerComment string) bool {
	if markerChain == "" || markerComment == "" {
		return isOncacheMarkerRule(line)
	}
	fields := strings.Fields(line)
	return len(fields) == 18 && fields[1] == markerChain && strings.Trim(fields[5], "\"") == markerComment && markerRuleFieldsMatch(fields)
}

func isOncacheMarkerRule(line string) bool {
	fields := strings.Fields(line)
	return len(fields) == 18 && fields[1] == "ONCACHE" && strings.HasPrefix(strings.Trim(fields[5], "\""), "oncache:") && markerRuleFieldsMatch(fields)
}

func markerRuleFieldsMatch(fields []string) bool {
	expected := []string{"-A", "", "-m", "comment", "--comment", "", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "tos", "--tos", "0x04/0x04", "-j", "TOS", "--set-tos", "0x08/0x08"}
	if len(fields) != len(expected) {
		return false
	}
	for index, want := range expected {
		if index == 1 || index == 5 {
			continue
		}
		if !strings.EqualFold(fields[index], want) {
			return false
		}
	}
	return true
}

func hasFixedTCConflict(output []byte) bool {
	text := strings.ToLower(string(output))
	for _, marker := range []string{
		"\"pref\":1000", "\"pref\": 1000", "pref 1000",
		"\"handle\":256", "\"handle\": 256", "handle 0x100",
		"\"handle\":257", "\"handle\": 257", "handle 0x101",
		"\"handle\":512", "\"handle\": 512", "handle 0x200",
		"\"handle\":513", "\"handle\": 513", "handle 0x201",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func hasPinnedObject(output []byte, pinRoot string) bool {
	if pinRoot == "" {
		return false
	}
	root := filepath.Clean(pinRoot)
	text := string(output)
	return strings.Contains(text, `"`+root+`"`) ||
		strings.Contains(text, `"`+root+string(filepath.Separator))
}
