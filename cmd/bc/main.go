package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/thomasteoh/boardchestrator/internal/config"
)

func main() {
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
		serve(cfg)
	case len(cmd) > 1 && cmd[1] == "backup":
		backup(context.Background(), cfg)
	default:
		slog.Error("unknown command, use: serve | backup")
		os.Exit(1)
	}
}
