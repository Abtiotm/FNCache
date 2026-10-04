package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeStatus struct{ snapshot Snapshot }

func (f fakeStatus) Status(context.Context) Snapshot { return f.snapshot }

func TestHTTPEndpoints(t *testing.T) {
	provider := fakeStatus{snapshot: Snapshot{State: reconcile.AgentReady, Ready: true, Generation: 7, DatapathEnabled: true, APIHealthy: true, HeartbeatFresh: true, QueueDepth: 2}}
	server, err := New(Config{ListenAddress: "127.0.0.1:0"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	if response := request("/livez"); response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("livez response = %d %q", response.Code, response.Body.String())
	}
	if response := request("/readyz"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ready":true`) {
		t.Fatalf("readyz response = %d %s", response.Code, response.Body.String())
	}
	metrics := request("/metrics")
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), `oncache_agent_state{state="Ready"} 1`) || strings.Contains(metrics.Body.String(), "pod-") {
		t.Fatalf("unexpected metrics response = %d %s", metrics.Code, metrics.Body.String())
	}
	if response := request("/debug/state"); response.Code != http.StatusNotFound {
		t.Fatalf("debug state was not disabled: %d", response.Code)
	}

	debugServer, err := New(Config{ListenAddress: "127.0.0.1:0", DebugState: true}, provider)
	if err != nil {
		t.Fatal(err)
	}
	debugResponse := httptest.NewRecorder()
	debugServer.Handler().ServeHTTP(debugResponse, httptest.NewRequest(http.MethodGet, "/debug/state", nil))
	if debugResponse.Code != http.StatusOK || !strings.Contains(debugResponse.Body.String(), `"generation":7`) {
		t.Fatalf("debug state response = %d %s", debugResponse.Code, debugResponse.Body.String())
	}
}

func TestReadyzReturnsUnavailableForDisabledState(t *testing.T) {
	provider := fakeStatus{snapshot: Snapshot{State: reconcile.AgentDisabled, Reason: "CAPABILITY_UNSUPPORTED"}}
	server, err := New(Config{ListenAddress: "127.0.0.1:0"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "CAPABILITY_UNSUPPORTED") {
		t.Fatalf("unexpected disabled readiness response = %d %s", recorder.Code, recorder.Body.String())
	}
}
