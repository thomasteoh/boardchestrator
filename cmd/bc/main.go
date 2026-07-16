package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/thomasteoh/boardchestrator/internal/config"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	})))

	slog.Info("starting boardchestrator", "version", "0.1.0")

	switch cmd := os.Args; {
	case len(cmd) == 1 || (len(cmd) > 1 && cmd[1] == "serve"):
		serve(ctx, cfg)
	case len(cmd) > 1 && cmd[1] == "backup":
		backup(ctx, cfg)
	default:
		slog.Error("unknown command, use: serve | backup")
		os.Exit(1)
	}

	<-sig
	cancel()
	slog.Info("shutdown complete")
}
