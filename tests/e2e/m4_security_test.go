//go:build m3e2e

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestM4ChartSecurityRender(t *testing.T) {
	if os.Getenv("ONCACHE_M4_SECURITY_RENDER") != "1" {
		t.Skip("set ONCACHE_M4_SECURITY_RENDER=1 to render the hardened chart")
	}
	chart := getenv("ONCACHE_M4_E2E_CHART", "../../charts/oncache")
	output, err := exec.Command("helm", "template", "oncache-security", chart, "--set", "agent.installationID=m4-security").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v: %s", err, output)
	}
	rendered := string(output)
	for _, forbidden := range []string{"mountPath: /boot", "mountPath: /host/proc", "mountPath: /run\n", "privileged: true"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("hardened chart contains forbidden setting %q", forbidden)
		}
	}
	for _, required := range []string{"allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true", "type: RuntimeDefault", "- ALL", "mountPath: /run/k3s/containerd"} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("hardened chart is missing %q", required)
		}
	}
	if !strings.Contains(rendered, "hostPID: true") || !strings.Contains(rendered, "hostNetwork: true") {
		t.Fatal("required host network namespace settings were removed")
	}
}
