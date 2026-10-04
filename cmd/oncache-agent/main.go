package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/agent"
	"github.com/cat-cc-Lcos/FNCache/internal/logging"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/server"
)

func main() {
	manifest := flag.String("static-config", "", "path to a StaticRuntimeConfiguration manifest")
	configPath := flag.String("config", "", "path to an AgentConfiguration for dynamic Kubernetes mode")
	flag.Parse()
	logger, loggerErr := logging.NewFromEnvironment("oncache-agent")
	if loggerErr != nil {
		fmt.Fprintln(os.Stderr, loggerErr)
		os.Exit(2)
	}
	if (*manifest == "") == (*configPath == "") {
		logger.Error(context.Background(), "invalid command line", "error", "exactly one of -static-config or -config is required")
		os.Exit(2)
	}
	var err error
	if *manifest != "" {
		err = run(*manifest)
	} else {
		err = runDynamic(*configPath)
	}
	if err != nil {
		logger.Error(context.Background(), "agent exited", "error", err.Error())
		os.Exit(1)
	}
}

func runDynamic(path string) error {
	runtime, err := agent.NewDynamicRuntime(path)
	if err != nil {
		return fmt.Errorf("create dynamic runtime: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	httpServer, err := server.New(server.Config{ListenAddress: runtime.HTTPAddress(), DebugState: runtime.DebugStateEnabled()}, runtime)
	if err != nil {
		return fmt.Errorf("create HTTP server: %w", err)
	}
	if err := httpServer.Start(); err != nil {
		return fmt.Errorf("start HTTP server: %w", err)
	}
	runErr := runtime.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return errors.Join(runErr, httpServer.Close(shutdownCtx))
}

func run(path string) (err error) {
	config, err := agent.LoadStaticRuntimeManifest(path)
	if err != nil {
		return err
	}
	runtime, err := agent.NewStaticRuntime(context.Background(), config)
	if err != nil {
		return fmt.Errorf("create static runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close static runtime: %w", closeErr)
		}
	}()
	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		return fmt.Errorf("run static reconciliation: %w", err)
	}
	if !staticReconcileSucceeded(result.State) {
		return fmt.Errorf("static reconciliation did not reach Ready: %s", result.State)
	}
	return nil
}

func staticReconcileSucceeded(state reconcile.AgentState) bool {
	return state == reconcile.AgentReady || state == reconcile.AgentDisabled
}
