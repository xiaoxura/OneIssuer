package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := loadExampleConfig()
	if err != nil {
		log.Fatal("OIDC example configuration is invalid")
	}
	providerClient := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	discoveryCtx, cancelDiscovery := context.WithTimeout(context.Background(), 10*time.Second)
	metadata, err := discoverProvider(discoveryCtx, providerClient, cfg)
	cancelDiscovery()
	if err != nil {
		log.Fatal("OIDC example could not validate provider Discovery")
	}
	application, err := newExampleApplication(cfg, metadata, providerClient, newMemorySessions(nil))
	if err != nil {
		log.Fatal("OIDC example could not initialize")
	}
	server := &http.Server{
		Addr: cfg.Addr, Handler: application, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		log.Printf("OIDC example %q listening on %s", cfg.Name, cfg.Addr)
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case serveErr := <-errorsChannel:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatal("OIDC example server stopped unexpectedly")
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			log.Fatal("OIDC example graceful shutdown failed")
		}
		if serveErr := <-errorsChannel; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatal("OIDC example server shutdown failed")
		}
	}
}
