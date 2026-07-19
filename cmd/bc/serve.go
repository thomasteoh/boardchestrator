package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db"
	"github.com/thomasteoh/boardchestrator/internal/server"
)

func serve(cfg *config.Config) {
	if err := runServe(cfg); err != nil {
		slog.Error("serve error", "error", err)
		os.Exit(1)
	}
}

func runServe(cfg *config.Config) error {
	ctx := context.Background()

	d, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()

	if err := db.MigrateUp(d); err != nil {
		return err
	}
	slog.Info("database ready", "path", cfg.DBPath)

	s := server.New(cfg)
	if err := s.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
