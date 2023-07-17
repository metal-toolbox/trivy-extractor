package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	trivy "github.com/metal-toolbox/trivy-extractor/internal"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cancelChan := make(chan os.Signal, 1)

	handleMetrics(context.Background())

	ch := make(chan struct{})
	ms := &trivy.MetricsServicer{}
	ps := trivy.NewPrometheusMetricsService()
	nsTeam := trivy.NewNamespaceTeam("/data/namespaces.csv")
	trivy.Report(ms, ps, ch, time.Second*15, nsTeam)

	<-cancelChan
	ch <- struct{}{}
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
