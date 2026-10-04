package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestParseLevel(t *testing.T) {
	for _, value := range []string{"", "debug", "info", "warn", "warning", "error"} {
		if _, err := ParseLevel(value); err != nil {
			t.Fatalf("ParseLevel(%q) failed: %v", value, err)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Fatal("unsupported log level was accepted")
	}
}

func TestLoggerRateLimitsReconcileErrorsAndReportsSuppressed(t *testing.T) {
	var output bytes.Buffer
	now := time.Unix(100, 0)
	logger, err := New(Config{Level: "debug", Component: "queue", Node: "node-a", Writer: &output, RateInterval: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	key := reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, Namespace: "default", Name: "web", UID: "pod-1"}
	err = reconcile.NewClassifiedError(reconcile.ErrorRetryable, "ENDPOINT_NOT_READY", time.Second, context.Canceled)
	logger.LogReconcileError(context.Background(), key, err)
	logger.LogReconcileError(context.Background(), key, err)
	now = now.Add(2 * time.Second)
	logger.LogReconcileError(context.Background(), key, err)

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("unexpected rate-limited log count: %d\n%s", len(lines), output.String())
	}
	var first, second map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatal(err)
	}
	if first["component"] != "queue" || first["node"] != "node-a" || first["reason"] != "ENDPOINT_NOT_READY" || first["class"] != "Retryable" {
		t.Fatalf("missing structured fields: %#v", first)
	}
	if second["suppressed"] != float64(1) {
		t.Fatalf("suppressed count was not reported: %#v", second)
	}
}
