package httpserver

import (
	"log/slog"
	"net/http"
	"time"
)

// ServerConfig maps validated config values onto every relevant net/http
// timeout and header bound.
type ServerConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// NewServer creates the concrete HTTP server used by the app lifecycle.
func NewServer(cfg ServerConfig, handler http.Handler, logger *slog.Logger) *http.Server {
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
	if logger != nil {
		server.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
	}
	return server
}
