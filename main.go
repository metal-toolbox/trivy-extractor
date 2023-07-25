package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/metal-toolbox/trivy-extractor/internal/trivy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handleMetrics(ctx)

	eg, groupCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return trivy.Report(
			&trivy.MetricsServicer{},
			trivy.NewPrometheusMetricsService(),
			groupCtx,
			time.Second*15,
			trivy.NewNamespaceTeam("/data/namespaces.csv"),
		)
	})

	eg.Wait()
}

func handleMetrics(ctx context.Context) {
	server := &http.Server{
		Addr:              ":2112",
		ReadTimeout:       3 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
	}

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		log.Printf("starting HTTP server on address '%s'...", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			return
		}
	}()

	go func() {
		<-ctx.Done()
		log.Println("stopping HTTP server...")
		server.Shutdown(ctx)
	}()

}
