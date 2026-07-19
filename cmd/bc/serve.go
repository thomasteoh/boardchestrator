package main

import (
	"context"

	"log/slog"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/server"
)

func serve(cfg *config.Config) {
	ctx := context.Background()
	s := server.New(cfg)

	if err := s.Start(ctx); err != nil {
		slog.Error("serve error", "error", err)
	}
}
