package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
)

type Server struct {
	server *http.Server
}

func NewServer(config etc.API, handler http.Handler) (*Server, error) {
	server := &http.Server{
		Addr:         config.Addr,
		Handler:      handler,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	if config.IsTLSEnabled() {
		slog.Info("Starting HTTPS server", slog.String("addr", config.Addr))
		return &Server{server: server}, nil
	}

	slog.Info("Starting HTTP server", slog.String("addr", config.Addr))
	return &Server{server: server}, nil
}

func (s *Server) ListenAndServe() error {
	if s.server.TLSConfig != nil {
		return s.server.ListenAndServeTLS("", "")
	}
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown() {
	slog.Info("Shutting down HTTP server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		slog.Error("Error shutting down HTTP server", slog.String("err", err.Error()))
	}
}
