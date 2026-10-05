//go:build m3e2e

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestM4AccelerationE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M4_ACCEL_E2E") != "1" {
		t.Skip("set ONCACHE_M4_ACCEL_E2E=1 to run the real acceleration closure")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	chart := getenv("ONCACHE_M3_E2E_CHART", "../../charts/oncache")
	evidence := getenv("ONCACHE_M4_ACCEL_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m4-acceleration"))
	namespace := fmt.Sprintf("oncache-m4-accel-%d", time.Now().UnixNano())
	heartbeatTimeout := parseM4Duration(t, "ONCACHE_M4_HEARTBEAT_TIMEOUT", 5*time.Second)
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	manifest := accelerationManifest(t, namespace, nodeA, nodeB, image)
	applyManifest(t, manifest)
	if os.Getenv("ONCACHE_M4_ACCEL_CLEANUP") == "1" {
		t.Cleanup(func() {
			_, _ = run("kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=false")
		})
	}
	if os.Getenv("ONCACHE_M4_ACCEL_REUSE") != "1" {
		deployAcceleration(t, chart, image)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	waitM4Pod(t, namespace, "pod-a")
	waitM4Pod(t, namespace, "pod-b")
	installObserver(t, namespace, nodeA, image)
	verifyM4Tools(t, namespace, evidence)
	waitControlEnabled(t, namespace, evidence)
	assertReadyz(t, nodeA, nodeB)

	podAIP := mustOutput(t, "kubectl", "-n", namespace, "get", "pod", "pod-a", "-o", "jsonpath={.status.podIP}")
	podBIP := mustOutput(t, "kubectl", "-n", namespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	firstBefore := dumpAccelerationMap(t, namespace, evidence, "first-before", "policy_cache")
	firstCapture := startAccelerationCapture(t, namespace, evidence, "first", podAIP, podBIP)
	assertPing(t, namespace, podBIP, 1)
	_, firstUnderlay := firstCapture()
	firstAfter := dumpAccelerationMap(t, namespace, evidence, "first-after", "policy_cache")
	if firstBefore == firstAfter || !policyReady(firstAfter) || !hasPacket(firstUnderlay) {
		t.Fatalf("first flow did not show fallback and bidirectional learning: before=%s after=%s underlay=%q", firstBefore, firstAfter, firstUnderlay)
	}

	warmCapture := startAccelerationCapture(t, namespace, evidence, "warm", podAIP, podBIP)
	assertPing(t, namespace, podBIP, 4)
	warmFlannel, warmUnderlay := warmCapture()
	if hasPacket(warmFlannel) || !hasPacket(warmUnderlay) {
		t.Fatalf("warm flow evidence does not show Flannel bypass: flannel=%q underlay=%q", warmFlannel, warmUnderlay)
	}
	strictAccelerationEvidence(t, namespace, evidence, "warm")

	blockM4Recovery(t)
	agent := agentPodForNode(t, nodeA)
	signalAgent(t, agent, "KILL")
	waitHeartbeatStable(t, namespace, heartbeatTimeout+time.Second, evidence, "heartbeat-timeout")
	assertPing(t, namespace, podBIP, 4)
	deployAcceleration(t, chart, image)
	waitAgentPodsStable(t, nodeA, nodeB)
	waitControlEnabled(t, namespace, evidence)
	assertReadyz(t, nodeA, nodeB)
	assertPing(t, namespace, podBIP, 2)

	agent = agentPodForNode(t, nodeA)
	signalAgent(t, agent, "TERM")
	waitAgentPodsStable(t, nodeA, nodeB)
	waitControlEnabled(t, namespace, evidence)
	assertReadyz(t, nodeA, nodeB)
	assertPing(t, namespace, podBIP, 2)
	strictAccelerationEvidence(t, namespace, evidence, "final")
}

func accelerationManifest(t *testing.T, namespace, nodeA, nodeB, image string) []byte {
	t.Helper()
	data, err := os.ReadFile("fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("NODE_A"), []byte(nodeA))
	data = bytes.ReplaceAll(data, []byte("NODE_B"), []byte(nodeB))
	data = bytes.ReplaceAll(data, []byte(e2eNamespace), []byte(namespace))
	data = bytes.ReplaceAll(data, []byte("oncache-agent:m3-e2e"), []byte(image))
	return data
}

func deployAcceleration(t *testing.T, chart, image string) {
	t.Helper()
	repository, tag := splitImage(image)
	installation := getenv("ONCACHE_M4_INSTALLATION_ID", "m4-shutdown")
	if _, err := run("helm", "upgrade", "--install", "oncache-m4", chart, "--namespace", "kube-system",
		"--set", "image.repository="+repository, "--set", "image.tag="+tag,
		"--set", "image.pullPolicy=IfNotPresent", "--set", "agent.installationID="+installation,
		"--set", "config.datapath.elfBuildID=sha256:"+tag, "--set", "config.features.debugState=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/oncache-m4-oncache"); err != nil {
		t.Fatal(err)
	}
}

func assertReadyz(t *testing.T, nodes ...string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	for _, node := range nodes {
		ip := mustOutput(t, "kubectl", "get", "node", node, "-o", "jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}")
		response, err := client.Get("http://" + ip + ":9090/readyz")
		if err != nil {
			t.Fatalf("/readyz node=%s: %v", node, err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ready":true`) {
			t.Fatalf("/readyz node=%s status=%d body=%q err=%v", node, response.StatusCode, body, readErr)
		}
	}
}

func assertPing(t *testing.T, namespace, ip string, count int) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "exec", "pod-a", "--", "ping", "-c", fmt.Sprint(count), "-W", "3", ip); err != nil {
		t.Fatal(err)
	}
}

func dumpAccelerationMap(t *testing.T, namespace, evidence, label, name string) string {
	t.Helper()
	output, err := runObserver(namespace, "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/"+name)
	if err != nil || strings.TrimSpace(output) == "" {
		t.Fatalf("map evidence unavailable name=%s err=%v output=%q", name, err, output)
	}
	if err := os.WriteFile(filepath.Join(evidence, "map-"+label+"-"+name+".json"), []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
	return output
}

func policyReady(output string) bool {
	return strings.Contains(output, `"ingress_ready":1`) && strings.Contains(output, `"egress_ready":1`)
}

func startAccelerationCapture(t *testing.T, namespace, evidence, label, sourceIP, targetIP string) func() (string, string) {
	t.Helper()
	base := fmt.Sprintf("/tmp/oncache-m4-%s-%d", label, time.Now().UnixNano())
	flannelPath, underlayPath := base+"-flannel.txt", base+"-underlay.txt"
	for _, capture := range []struct{ path, iface, filter string }{
		{flannelPath, "flannel.1", fmt.Sprintf("host %s and host %s", sourceIP, targetIP)},
		{underlayPath, "enp1s0", "udp port 8472"},
	} {
		command := fmt.Sprintf("nohup timeout -s INT 8 tcpdump -l -U -i %s -nn -tt '%s' > %s 2>&1 </dev/null & echo $!", capture.iface, capture.filter, capture.path)
		if _, err := runObserver(namespace, "sh", "-c", command); err != nil {
			t.Fatal(err)
		}
	}
	return func() (string, string) {
		t.Helper()
		time.Sleep(2 * time.Second)
		flannel, err := runObserver(namespace, "cat", flannelPath)
		if err != nil {
			t.Fatal(err)
		}
		underlay, err := runObserver(namespace, "cat", underlayPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(evidence, "capture-"+label+"-flannel.txt"), []byte(flannel), 0600)
		_ = os.WriteFile(filepath.Join(evidence, "capture-"+label+"-underlay.txt"), []byte(underlay), 0600)
		return flannel, underlay
	}
}

func hasPacket(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, " IP ") || strings.Contains(line, " IP6 ") {
			return true
		}
	}
	return false
}

func strictAccelerationEvidence(t *testing.T, namespace, evidence, label string) {
	t.Helper()
	tcScript := `set -eu
tc=/opt/oncache/sbin/tc
ip=/opt/oncache/sbin/ip
for dev in $($ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  echo "=== $dev ingress"
  $tc -j filter show dev "$dev" ingress 2>/dev/null || true
  echo "=== $dev egress"
  $tc -j filter show dev "$dev" egress 2>/dev/null || true
done`
	commands := map[string][]string{
		"programs.txt": {"/opt/oncache/bin/bpftool", "prog", "show"},
		"maps.txt":     {"/opt/oncache/bin/bpftool", "map", "show"},
		"iptables.txt": {"iptables-nft", "-t", "mangle", "-S"},
	}
	outputs := make(map[string]string, len(commands)+1)
	for name, args := range commands {
		output, err := runObserver(namespace, args...)
		if err != nil || strings.TrimSpace(output) == "" {
			t.Fatalf("required M4.14 evidence unavailable %s: err=%v output=%q", name, err, output)
		}
		outputs[name] = output
		if err := os.WriteFile(filepath.Join(evidence, label+"-"+name), []byte(output), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tcOutput, err := runObserver(namespace, "sh", "-c", tcScript)
	if err != nil || strings.TrimSpace(tcOutput) == "" {
		t.Fatalf("required M4.14 evidence unavailable tc.txt: err=%v output=%q", err, tcOutput)
	}
	if !strings.Contains(tcOutput, `"bpf_name":"tc_restore"`) ||
		!strings.Contains(tcOutput, `"bpf_name":"tc_init_e"`) ||
		!strings.Contains(tcOutput, `"bpf_name":"tc_masq"`) {
		t.Fatalf("TC evidence did not contain all host-side ONCache filters: %q", tcOutput)
	}
	if err := os.WriteFile(filepath.Join(evidence, label+"-tc.txt"), []byte(tcOutput), 0600); err != nil {
		t.Fatal(err)
	}
}
