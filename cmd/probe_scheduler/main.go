package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	bridgesFile := flag.String("bridges", "data/iran_bridges.json", "Bridges path")
	port := flag.Int("port", 8742, "HTTP listener port")
	flag.Parse()

	_ = bridgesFile

	http.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status": "ok", "probe_scheduler": "active"}`)
	})

	srv := &http.Server{Addr: fmt.Sprintf(":%d", *port)}

	go func() {
		fmt.Printf("probe_scheduler listening on port %d\n", *port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down probe_scheduler...")
}
