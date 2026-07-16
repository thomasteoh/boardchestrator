package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/thomasteoh/boardchestrator/internal/config"
)

func serve(ctx context.Context, cfg *config.Config) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck // trivial hello; failure is not actionable
		w.Write([]byte("Boardchestrator — coming soon"))
	})

	srv := &http.Server{
		Addr:              cfg.Bind,
		Handler:           r,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//nolint:errcheck // shutdown error is best-effort during graceful drain
	srv.Shutdown(shutdownCtx)
}
