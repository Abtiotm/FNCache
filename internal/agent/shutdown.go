package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrShutdownTimeout = errors.New("agent shutdown timed out")

type ShutdownWaiter struct{}

func NewShutdownWaiter(timeout time.Duration) (*ShutdownWaiter, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("shutdown timeout must be positive")
	}
	return &ShutdownWaiter{}, nil
}

func (w *ShutdownWaiter) Wait(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return shutdownContextError(ctx)
	}
}

func (w *ShutdownWaiter) WaitError(ctx context.Context, done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return shutdownContextError(ctx)
	}
}

func (w *ShutdownWaiter) Drain(ctx context.Context, results <-chan ScanResult) error {
	for {
		select {
		case _, ok := <-results:
			if !ok {
				return nil
			}
		case <-ctx.Done():
			return shutdownContextError(ctx)
		}
	}
}

func (w *ShutdownWaiter) Close(ctx context.Context, closeFn func() error) error {
	done := make(chan error, 1)
	go func() { done <- closeFn() }()
	return w.WaitError(ctx, done)
}

func shutdownContextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrShutdownTimeout
	}
	return ctx.Err()
}
