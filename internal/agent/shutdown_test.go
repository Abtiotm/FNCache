package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestShutdownWaiterWaitsForCompletion(t *testing.T) {
	waiter, err := NewShutdownWaiter(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	if err := waiter.Wait(context.Background(), done); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownWaiterReportsDeadline(t *testing.T) {
	waiter, err := NewShutdownWaiter(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := waiter.Wait(ctx, make(chan struct{})); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("error = %v, want ErrShutdownTimeout", err)
	}
}

func TestShutdownWaiterClosesAndPropagatesError(t *testing.T) {
	waiter, err := NewShutdownWaiter(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("close failed")
	if err := waiter.Close(context.Background(), func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
