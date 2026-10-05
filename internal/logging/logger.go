package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const defaultRateInterval = 10 * time.Second

type Config struct {
	Level        string
	Component    string
	Node         string
	Writer       io.Writer
	RateInterval time.Duration
	Now          func() time.Time
}

type Logger struct {
	base      *slog.Logger
	component string
	limiter   *RateLimiter
}

func New(config Config) (*Logger, error) {
	level, err := ParseLevel(config.Level)
	if err != nil {
		return nil, err
	}
	if config.Writer == nil {
		config.Writer = os.Stderr
	}
	if config.RateInterval <= 0 {
		config.RateInterval = defaultRateInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	limiter, err := NewRateLimiter(config.RateInterval, config.Now)
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(config.Writer, &slog.HandlerOptions{Level: level})
	base := slog.New(handler).With("component", config.Component, "node", config.Node)
	return &Logger{base: base, component: config.Component, limiter: limiter}, nil
}

func NewFromEnvironment(component string) (*Logger, error) {
	return New(Config{Level: os.Getenv("ONCACHE_LOG_LEVEL"), Component: component, Node: os.Getenv("ONCACHE_NODE_NAME")})
}

func NewDefault(component string) *Logger {
	logger, err := NewFromEnvironment(component)
	if err == nil {
		return logger
	}
	logger, _ = New(Config{Level: "info", Component: component, Node: os.Getenv("ONCACHE_NODE_NAME")})
	return logger
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log level %q", value)
	}
}

func (l *Logger) Error(ctx context.Context, message string, attrs ...any) {
	l.base.ErrorContext(ctx, message, attrs...)
}

func (l *Logger) LogReconcileError(ctx context.Context, key reconcile.ReconcileKey, err error) {
	if l == nil || err == nil {
		return
	}
	class := string(reconcile.ErrorInternal)
	reason := key.Reason
	if reason == "" {
		reason = "RECONCILE_ERROR"
	}
	var classified *reconcile.ClassifiedError
	if errors.As(err, &classified) {
		class = string(classified.Class())
		if classified.ReasonCode() != "" {
			reason = classified.ReasonCode()
		}
	}
	allowed, suppressed := l.limiter.Allow(strings.Join([]string{l.component, class, reason}, ":"))
	if !allowed {
		return
	}
	attrs := []any{"generation", uint64(0), "reconcileKey", key.QueueKey(), "reason", reason, "class", class, "error", err.Error()}
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	level := slog.LevelWarn
	if class == string(reconcile.ErrorInternal) || class == string(reconcile.ErrorSafetyViolation) || class == string(reconcile.ErrorConflict) {
		level = slog.LevelError
	}
	l.base.Log(ctx, level, "reconcile failed", attrs...)
}

type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	entries  map[string]rateEntry
}

type rateEntry struct {
	last       time.Time
	suppressed uint64
}

func NewRateLimiter(interval time.Duration, now func() time.Time) (*RateLimiter, error) {
	if interval <= 0 || now == nil {
		return nil, fmt.Errorf("rate limiter interval and clock are required")
	}
	return &RateLimiter{interval: interval, now: now, entries: make(map[string]rateEntry)}, nil
}

func (r *RateLimiter) Allow(key string) (bool, uint64) {
	if key == "" {
		return true, 0
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[key]
	if !ok || now.Sub(entry.last) >= r.interval {
		suppressed := entry.suppressed
		r.entries[key] = rateEntry{last: now}
		return true, suppressed
	}
	entry.suppressed++
	r.entries[key] = entry
	return false, 0
}
