package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type Snapshot struct {
	State           reconcile.AgentState `json:"state"`
	Ready           bool                 `json:"ready"`
	Reason          string               `json:"reason,omitempty"`
	Generation      uint64               `json:"generation"`
	DatapathEnabled bool                 `json:"datapathEnabled"`
	APIHealthy      bool                 `json:"apiHealthy"`
	HeartbeatFresh  bool                 `json:"heartbeatFresh"`
	QueueDepth      int                  `json:"queueDepth"`
	KnownLinks      int                  `json:"knownLinks"`
}

type StatusProvider interface {
	Status(context.Context) Snapshot
}

type Config struct {
	ListenAddress string
	DebugState    bool
}

type Server struct {
	http       *http.Server
	provider   StatusProvider
	debugState bool
	listener   net.Listener
}

func New(config Config, provider StatusProvider) (*Server, error) {
	if config.ListenAddress == "" || provider == nil {
		return nil, fmt.Errorf("HTTP listen address and status provider are required")
	}
	s := &Server{provider: provider, debugState: config.DebugState}
	s.http = &http.Server{Handler: s.Handler(), Addr: config.ListenAddress, ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", s.livez)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/debug/state", s.debug)
	return mux
}

func (s *Server) Start() error {
	if s.listener != nil {
		return fmt.Errorf("HTTP server is already started")
	}
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.listener = listener
	go func() { _ = s.http.Serve(listener) }()
	return nil
}

func (s *Server) Close(ctx context.Context) error {
	if s.listener == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) livez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	snapshot := s.provider.Status(r.Context())
	status := http.StatusServiceUnavailable
	if snapshot.Ready {
		status = http.StatusOK
	}
	writeJSON(w, status, snapshot)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	snapshot := s.provider.Status(r.Context())
	var b strings.Builder
	b.WriteString("# TYPE oncache_agent_state gauge\n")
	for _, state := range []reconcile.AgentState{reconcile.AgentBootstrapping, reconcile.AgentDisabled, reconcile.AgentReconciling, reconcile.AgentReady, reconcile.AgentDegraded, reconcile.AgentStopping} {
		value := 0
		if snapshot.State == state {
			value = 1
		}
		_, _ = fmt.Fprintf(&b, "oncache_agent_state{state=%q} %d\n", state, value)
	}
	_, _ = fmt.Fprintf(&b, "oncache_datapath_enabled %d\n", boolValue(snapshot.DatapathEnabled))
	_, _ = fmt.Fprintf(&b, "oncache_datapath_generation %d\n", snapshot.Generation)
	_, _ = fmt.Fprintf(&b, "oncache_queue_depth %d\n", snapshot.QueueDepth)
	_, _ = fmt.Fprintf(&b, "oncache_kube_api_healthy %d\n", boolValue(snapshot.APIHealthy))
	_, _ = fmt.Fprintf(&b, "oncache_heartbeat_fresh %d\n", boolValue(snapshot.HeartbeatFresh))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) debug(w http.ResponseWriter, r *http.Request) {
	if !s.debugState {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.provider.Status(r.Context()))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func boolValue(value bool) int {
	if value {
		return 1
	}
	return 0
}
