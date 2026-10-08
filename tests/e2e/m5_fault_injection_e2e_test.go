//go:build m3e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var faultRelease = "oncache-m5-fault"

func TestM5FaultInjectionE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M5_FAULT_E2E") != "1" {
		t.Skip("set ONCACHE_M5_FAULT_E2E=1 to run M5 fault injection E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	remotePodCIDR := strings.TrimSpace(mustOutput(t, "kubectl", "get", "node/"+nodeB, "-o", "jsonpath={.spec.podCIDR}"))
	remotePodNetwork := strings.SplitN(remotePodCIDR, "/", 2)[0]
	chart := getenv("ONCACHE_M3_E2E_CHART", "../../charts/oncache")
	evidence := getenv("ONCACHE_M5_FAULT_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m5-fault"))
	namespace := fmt.Sprintf("oncache-m5-fault-%d", time.Now().UnixNano())
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	manifest := faultManifest(t, namespace, nodeA, nodeB, image)
	applyManifest(t, []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: "+namespace+"\n"))
	obsA := installFaultObserver(t, namespace, nodeA, image)
	obsB := installFaultObserver(t, namespace, nodeB, image)
	resetFaultDatapath(t, namespace, obsA, obsB)
	t.Cleanup(func() {
		faultCleanup(t, namespace, obsA, obsB)
		_, _ = run("helm", "uninstall", faultRelease, "--namespace", "kube-system", "--wait=false")
		_, _ = run("kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=false")
	})
	deployFaultRelease(t, chart, image)
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "initial")
	waitFaultEnabled(t, namespace, obsB, evidence, "initial-node-b")
	applyManifest(t, manifest)
	waitM5FaultPod(t, namespace, "pod-a")
	waitM5FaultPod(t, namespace, "pod-b")
	waitFaultEnabled(t, namespace, obsA, evidence, "after-pods")
	assertFaultTraffic(t, namespace)
	runFaultScenario(t, namespace, obsA, evidence, "flt-001-sigterm", func() {
		signalAgent(t, agentPodForNode(t, nodeA), "TERM")
	}, func() { waitFaultPodsRunning(t) })
	blockFaultRecovery(t)
	runFaultScenario(t, namespace, obsA, evidence, "flt-002-sigkill", func() {
		signalAgent(t, agentPodForNode(t, nodeA), "KILL")
	}, func() {
		restoreFaultRelease(t, chart, image)
		waitFaultPodsRunning(t)
	})
	writeFault(t, namespace, obsA, "flt-003-stall-start", "pkill -STOP -f '^/oncache-agent'")
	waitFaultStable(t, namespace, obsA, evidence, "flt-003-stall", 6*time.Second)
	writeFault(t, namespace, obsA, "flt-003-stall-restore", "pkill -CONT -f '^/oncache-agent'")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-003-recovered")
	blockFaultAPI(t, namespace, obsA, obsB, true)
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-004-api")
	blockFaultAPI(t, namespace, obsA, obsB, false)
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-004-recovered")
	writeFault(t, namespace, obsA, "flt-005-flannel-down", "/opt/oncache/sbin/ip link set dev flannel.1 down")
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-005-flannel")
	writeFault(t, namespace, obsA, "flt-005-flannel-up", fmt.Sprintf("/opt/oncache/sbin/ip link set dev flannel.1 up; /opt/oncache/sbin/ip route replace %s via %s dev flannel.1 onlink", remotePodCIDR, remotePodNetwork))
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-005-recovered")
	writeFault(t, namespace, obsA, "flt-006-delete-flannel", fmt.Sprintf(`nsenter -t 1 -m -u -i -n -p -- /proc/1/root/usr/bin/systemd-run --unit=oncache-m5-flannel-recover --collect /bin/sh -c 'sleep 12; /usr/bin/systemctl restart k3s; sleep 8; /opt/oncache/sbin/ip route replace %s via %s dev flannel.1 onlink'; /opt/oncache/sbin/ip link delete flannel.1`, remotePodCIDR, remotePodNetwork))
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-006-flannel")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-006-recovered")
	writeFault(t, namespace, obsA, "flt-007-drift", "/opt/oncache/sbin/ip link set dev flannel.1 mtu 1400")
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-007-drift")
	writeFault(t, namespace, obsA, "flt-007-restore", "/opt/oncache/sbin/ip link set dev flannel.1 mtu 1450")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-007-recovered")
	writeFault(t, namespace, obsA, "flt-008-marker-delete", "iptables-nft -t mangle -F ONCACHE")
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-008-marker")
	writeFault(t, namespace, obsA, "flt-008-marker-restore", fmt.Sprintf("iptables-nft -t mangle -A ONCACHE -m comment --comment \"oncache:%s\" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08", faultRelease))
	restoreFaultRelease(t, chart, image)
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-008-recovered")
	externalRule(t, namespace, obsA, true)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-009-external")
	writeFault(t, namespace, obsA, "flt-010-pin-delete", "rm -f /sys/fs/bpf/oncache/v1/maps/control_map")
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-010-pin")
	restoreFaultRelease(t, chart, image)
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-010-recovered")
	writeFault(t, namespace, obsA, "flt-011-state-corrupt", "cp /host-state/v1/state.json /host-state/v1/state.json.m5-fault-backup && printf '{' > /host-state/v1/state.json")
	signalAgent(t, agentPodForNode(t, nodeA), "KILL")
	waitFaultDisabled(t, namespace, obsA, evidence, "flt-011-state")
	writeFault(t, namespace, obsA, "flt-011-state-restore", "cp /host-state/v1/state.json.m5-fault-backup /host-state/v1/state.json && rm -f /host-state/v1/state.json.m5-fault-backup")
	restoreFaultRelease(t, chart, image)
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-011-recovered")
	stateFault(t, namespace, nodeA, image, evidence, "flt-012-readonly", "mount -o remount,bind,ro /var/lib/oncache")
	stateFault(t, namespace, nodeA, image, evidence, "flt-014-disk-pressure", "mount -t tmpfs -o size=128k tmpfs /var/lib/oncache && mkdir -p /var/lib/oncache/v1 && dd if=/dev/zero of=/var/lib/oncache/fill bs=1k count=120")
	writeFault(t, namespace, obsA, "flt-014-restore-state-dir", "nsenter -t 1 -m -u -i -n -p -- /proc/1/root/usr/bin/umount /var/lib/oncache 2>/dev/null || true; nsenter -t 1 -m -u -i -n -p -- /proc/1/root/usr/bin/mount -o remount,bind,rw /var/lib/oncache 2>/dev/null || true")
	writeFault(t, namespace, obsB, "flt-013-reboot", "nsenter -t 1 -m -u -i -n -p -- /proc/1/root/usr/bin/systemctl reboot")
	if _, err := run("kubectl", "wait", "--for=condition=Ready", "node/"+nodeB, "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-013-recovered")
	assertFaultTraffic(t, namespace)
	fillPolicyMap(t, namespace, obsA)
	assertFaultTraffic(t, namespace)
	signalAgent(t, agentPodForNode(t, nodeA), "TERM")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "flt-015-recovered")
	writeFault(t, namespace, obsB, "flt-016-netem", "/opt/oncache/sbin/tc qdisc replace dev flannel.1 root netem delay 20ms 5ms loss 1%")
	assertFaultTraffic(t, namespace)
	writeFault(t, namespace, obsB, "flt-016-netem-restore", "/opt/oncache/sbin/tc qdisc del dev flannel.1 root")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, obsA, evidence, "final")
	captureEvidence(t, namespace, faultRelease+"-oncache", evidence)
}

func resetFaultDatapath(t *testing.T, namespace, obsA, obsB string) {
	t.Helper()
	command := `set +e; rm -f /host-state/v1/state.json; iptables-nft -t mangle -D POSTROUTING -j ONCACHE 2>/dev/null || true; iptables-nft -t mangle -F ONCACHE 2>/dev/null || true; iptables-nft -t mangle -X ONCACHE 2>/dev/null || true; for dev in $(ip -o link show | awk -F": " '{print $2}' | cut -d@ -f1); do tc filter del dev "$dev" ingress pref 1000 handle 0x100 bpf 2>/dev/null || true; tc filter del dev "$dev" ingress pref 1000 handle 0x101 bpf 2>/dev/null || true; tc filter del dev "$dev" ingress pref 1000 handle 0x200 bpf 2>/dev/null || true; tc filter del dev "$dev" ingress pref 1000 handle 0x201 bpf 2>/dev/null || true; tc filter del dev "$dev" egress pref 1000 handle 0x100 bpf 2>/dev/null || true; tc filter del dev "$dev" egress pref 1000 handle 0x101 bpf 2>/dev/null || true; done; rm -f /sys/fs/bpf/oncache/v1/maps/* /sys/fs/bpf/oncache/v1/programs/*`
	writeFault(t, namespace, obsA, "preflight-reset-a", command)
	writeFault(t, namespace, obsB, "preflight-reset-b", command)
}
func faultManifest(t *testing.T, namespace, nodeA, nodeB, image string) []byte {
	t.Helper()
	data, err := os.ReadFile("fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte(e2eNamespace), []byte(namespace))
	data = bytes.ReplaceAll(data, []byte("NODE_A"), []byte(nodeA))
	data = bytes.ReplaceAll(data, []byte("NODE_B"), []byte(nodeB))
	data = bytes.ReplaceAll(data, []byte("oncache-agent:m3-e2e"), []byte(image))
	return data
}
func deployFaultRelease(t *testing.T, chart, image string) {
	t.Helper()
	_, _ = run("kubectl", "-n", "kube-system", "delete", "daemonset/"+faultRelease+"-oncache", "--ignore-not-found=true", "--wait=true", "--timeout=60s")
	_, _ = run("kubectl", "-n", "kube-system", "delete", "pod", "-l", "app.kubernetes.io/instance="+faultRelease, "--force", "--grace-period=0", "--wait=false")
	waitFaultAgentPodsGone(t)
	repository, tag := splitImage(image)
	if _, err := run("helm", "upgrade", "--install", "--reset-values", faultRelease, chart, "--namespace", "kube-system", "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "image.pullPolicy=IfNotPresent", "--set", "agent.installationID="+faultRelease, "--set", "config.features.debugState=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/"+faultRelease+"-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
}

func waitFaultAgentPodsGone(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out, err := run("kubectl", "-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/instance="+faultRelease, "-o", "name")
		if err != nil || strings.TrimSpace(out) == "" {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("old fault-injection agent Pods did not disappear")
}
func restoreFaultRelease(t *testing.T, chart, image string) {
	t.Helper()
	deployFaultRelease(t, chart, image)
	if _, err := run("kubectl", "-n", "kube-system", "delete", "pod", "-l", "app.kubernetes.io/instance="+faultRelease, "--force", "--grace-period=0", "--wait=false"); err != nil {
		t.Fatal(err)
	}
}
func installFaultObserver(t *testing.T, namespace, node, image string) string {
	t.Helper()
	name := "oncache-m5-fault-" + strings.TrimPrefix(node, "oncache-node-")
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  nodeName: %s
  hostNetwork: true
  hostPID: true
  restartPolicy: Always
  containers:
    - name: observer
      image: %s
      command: ["sh", "-c", "while :; do sleep 3600; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - {name: bpf, mountPath: /sys/fs/bpf}
        - {name: state, mountPath: /host-state}
        - {name: tools, mountPath: /opt/oncache}
  volumes:
    - {name: bpf, hostPath: {path: /sys/fs/bpf, type: Directory}}
    - {name: state, hostPath: {path: /var/lib/oncache, type: Directory}}
    - {name: tools, hostPath: {path: /opt/oncache, type: Directory}}
`, name, namespace, node, image)
	applyManifest(t, []byte(manifest))
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=jsonpath={.status.phase}=Running", "pod/"+name, "--timeout=60s"); err != nil {
		t.Fatal(err)
	}
	return name
}
func runFaultScenario(t *testing.T, namespace, observer, evidence, label string, inject, recover func()) {
	t.Helper()
	inject()
	waitFaultDisabled(t, namespace, observer, evidence, label)
	recover()
	waitFaultEnabled(t, namespace, observer, evidence, label+"-ready")
	assertFaultTraffic(t, namespace)
}
func waitM5FaultPod(t *testing.T, namespace, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
}
func waitFaultPodsRunning(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		output, err := run("kubectl", "-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/instance="+faultRelease, "-o", `jsonpath={range .items[*]}{.spec.nodeName}{" "}{.status.phase}{" "}{.status.containerStatuses[0].ready}{" "}{.metadata.deletionTimestamp}{"\n"}{end}`)
		if err == nil {
			seen := make(map[string]bool)
			ready := true
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 3 && len(fields) != 4 {
					ready = false
					break
				}
				if fields[1] != "Running" || fields[2] != "true" || (len(fields) == 4 && fields[3] != "<none>") || seen[fields[0]] {
					ready = false
					break
				}
				seen[fields[0]] = true
			}
			if ready && len(seen) == 2 {
				return
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("fault-injection DaemonSet did not settle to one running Pod per node")
}
func faultControlDump(t *testing.T, namespace, observer, evidence, label string) (string, error) {
	t.Helper()
	var out string
	var err error
	if strings.HasSuffix(observer, "-a") {
		out, err = run("sudo", "-n", "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/control_map")
	} else {
		out, err = runFaultObserver(namespace, observer, "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/control_map")
	}
	if strings.HasPrefix(label, "flt-010-recovered") {
		out, err = run("sudo", "-n", "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/control_map")
	}
	if err != nil && strings.HasSuffix(observer, "-a") {
		out, err = run("sudo", "-n", "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/control_map")
	}
	if err != nil && strings.Contains(out, "No such file or directory") {
		missing := `{"control_map":"missing"}`
		_ = os.WriteFile(filepath.Join(evidence, "control-"+label+".json"), []byte(missing), 0600)
		return missing, nil
	}
	if err != nil || strings.TrimSpace(out) == "" {
		if err == nil {
			err = fmt.Errorf("empty control Map output")
		}
		return "", fmt.Errorf("control evidence %s unavailable: %w", label, err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "control-"+label+".json"), []byte(out), 0600); err != nil {
		return "", err
	}
	return out, nil
}
func waitFaultEnabled(t *testing.T, namespace, observer, evidence, label string) {
	waitFaultControl(t, namespace, observer, evidence, label, true)
}
func waitFaultDisabled(t *testing.T, namespace, observer, evidence, label string) {
	waitFaultControl(t, namespace, observer, evidence, label, false)
}
func waitFaultControl(t *testing.T, namespace, observer, evidence, label string, enabled bool) {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		if output, err := faultControlDump(t, namespace, observer, evidence, label+"-sample"); err == nil && (controlEnabled(output, enabled) || (!enabled && strings.Contains(output, `"control_map":"missing"`))) {
			if !enabled {
				return
			}
			time.Sleep(2 * time.Second)
			if next, err := faultControlDump(t, namespace, observer, evidence, label+"-heartbeat"); err == nil && next != output {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("control Map did not reach enabled=%t for %s", enabled, label)
}
func controlEnabled(output string, enabled bool) bool {
	if strings.Contains(output, fmt.Sprintf(`"enabled":%d`, map[bool]int{false: 0, true: 1}[enabled])) {
		return true
	}
	marker := `"value":["0x01","0x00","0x00","0x00","0x` + map[bool]string{false: "00", true: "01"}[enabled] + `"`
	return strings.Contains(output, marker)
}
func waitFaultStable(t *testing.T, namespace, observer, evidence, label string, duration time.Duration) {
	previous, err := faultControlDump(t, namespace, observer, evidence, label+"-start")
	if err != nil {
		t.Fatal(err)
	}
	stable := time.Now()
	deadline := time.Now().Add(duration + 3*time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		current, err := faultControlDump(t, namespace, observer, evidence, label+"-sample")
		if err != nil {
			t.Fatal(err)
		}
		if current != previous {
			previous, stable = current, time.Now()
		}
		if time.Since(stable) >= duration {
			return
		}
	}
	t.Fatalf("control Map did not remain stable during %s", label)
}
func runFaultObserver(namespace, observer string, args ...string) (string, error) {
	command := append([]string{"kubectl", "-n", namespace, "exec", observer, "--"}, args...)
	return run(command[0], command[1:]...)
}
func writeFault(t *testing.T, namespace, observer, label, command string) {
	t.Helper()
	out, err := runFaultObserver(namespace, observer, "sh", "-c", command)
	if err != nil {
		t.Fatalf("%s: %v %s", label, err, out)
	}
}
func blockFaultRecovery(t *testing.T) {
	t.Helper()
	if _, err := run("kubectl", "-n", "kube-system", "patch", "configmap/"+faultRelease+"-oncache", "--type=merge", "-p", `{"data":{"agent.yaml":"invalid: ["}}`); err != nil {
		t.Fatal(err)
	}
}
func blockFaultAPI(t *testing.T, namespace, obsA, obsB string, block bool) {
	t.Helper()
	_ = namespace
	_ = obsA
	_ = obsB
	binding := faultRelease + "-oncache"
	if block {
		if _, err := run("kubectl", "delete", "clusterrolebinding", binding, "--ignore-not-found=true"); err != nil {
			t.Fatal(err)
		}
		if _, err := run("kubectl", "-n", "kube-system", "delete", "pod", "-l", "app.kubernetes.io/instance="+faultRelease, "--wait=false"); err != nil {
			t.Fatal(err)
		}
		return
	}
	applyManifest(t, []byte(fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s
subjects:
  - kind: ServiceAccount
    name: %s
    namespace: kube-system
`, binding, binding, binding)))
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/"+faultRelease+"-oncache"); err != nil {
		t.Fatal(err)
	}
}
func externalRule(t *testing.T, namespace, observer string, add bool) {
	command := "iptables-nft -t mangle -N ONCACHE_M5_EXTERNAL 2>/dev/null || true; iptables-nft -t mangle -F ONCACHE_M5_EXTERNAL; iptables-nft -t mangle -A ONCACHE_M5_EXTERNAL -m comment --comment oncache-m5-external -j RETURN"
	if !add {
		command = "iptables-nft -t mangle -F ONCACHE_M5_EXTERNAL 2>/dev/null || true; iptables-nft -t mangle -X ONCACHE_M5_EXTERNAL 2>/dev/null || true"
	}
	_, _ = runFaultObserver(namespace, observer, "sh", "-c", command)
}
func assertFaultTraffic(t *testing.T, namespace string) {
	ip := mustOutput(t, "kubectl", "-n", namespace, "get", "pod/pod-b", "-o", "jsonpath={.status.podIP}")
	for deadline := time.Now().Add(180 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if _, err := run("kubectl", "-n", namespace, "exec", "pod-a", "--", "ping", "-c", "2", "-W", "3", ip); err == nil {
			return
		}
	}
	t.Fatal("cross-node traffic did not recover")
}
func stateFault(t *testing.T, namespace, node, image, evidence, label, command string) {
	pod := agentPodForNode(t, node)
	if _, err := run("kubectl", "-n", "kube-system", "exec", pod, "--", "sh", "-c", command); err != nil {
		t.Fatalf("%s inject: %v", label, err)
	}
	trigger := []byte(fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s-trigger\n  namespace: %s\nspec:\n  nodeName: %s\n  containers:\n    - name: app\n      image: %s\n      command: [\"sh\", \"-c\", \"sleep 60\"]\n", label, namespace, node, image))
	applyManifest(t, trigger)
	waitM5FaultPod(t, namespace, label+"-trigger")
	_, _ = run("kubectl", "-n", namespace, "delete", "pod/"+label+"-trigger", "--wait=true")
	observer := "oncache-m5-fault-" + strings.TrimPrefix(node, "oncache-node-")
	waitFaultDisabled(t, namespace, observer, evidence, label)
	signalAgent(t, agentPodForNode(t, node), "KILL")
	waitFaultPodsRunning(t)
	waitFaultEnabled(t, namespace, observer, evidence, label+"-recovered")
}
func fillPolicyMap(t *testing.T, namespace, observer string) {
	command := `set -eu; for i in $(seq 1 4096); do h=$(printf "%08x" "$i"); /opt/oncache/bin/bpftool map update pinned /sys/fs/bpf/oncache/v1/maps/policy_cache key hex 0a 00 00 ${h:6:2} 0a 00 01 ${h:4:2} 00 01 ${h:2:2} ${h:0:2} 00 06 00 00 value hex 01 00 01 00 any >/dev/null 2>&1 || true; done`
	if out, err := runFaultObserver(namespace, observer, "bash", "-c", command); err != nil {
		t.Fatalf("FLT-015 map fill: %v %s", err, out)
	}
}
func faultCleanup(t *testing.T, namespace, obsA, obsB string) {
	t.Helper()
	_, _ = runFaultObserver(namespace, obsA, "sh", "-c", "iptables-nft -t mangle -F ONCACHE_M5_EXTERNAL 2>/dev/null || true; iptables-nft -t mangle -X ONCACHE_M5_EXTERNAL 2>/dev/null || true; /opt/oncache/sbin/ip link set dev flannel.1 mtu 1450 2>/dev/null || true; /opt/oncache/sbin/tc qdisc del dev flannel.1 root 2>/dev/null || true; iptables-nft -D OUTPUT -d 10.43.0.1/32 -p tcp --dport 443 -m comment --comment oncache-m5-api-block -j REJECT 2>/dev/null || true")
	_, _ = runFaultObserver(namespace, obsB, "sh", "-c", "/opt/oncache/sbin/ip link set dev flannel.1 mtu 1450 2>/dev/null || true; /opt/oncache/sbin/tc qdisc del dev flannel.1 root 2>/dev/null || true; iptables-nft -D OUTPUT -d 10.43.0.1/32 -p tcp --dport 443 -m comment --comment oncache-m5-api-block -j REJECT 2>/dev/null || true")
	stateCleanup := fmt.Sprintf("if grep -q '\"installationID\": \"%s\"' /host-state/v1/state.json 2>/dev/null; then rm -f /host-state/v1/state.json; fi; test ! -e /host-state/v1/state.json.m5-fault-backup || cp /host-state/v1/state.json.m5-fault-backup /host-state/v1/state.json; rm -f /host-state/v1/state.json.m5-fault-backup", faultRelease)
	_, _ = runFaultObserver(namespace, obsA, "sh", "-c", stateCleanup)
}
