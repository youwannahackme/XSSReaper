package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/youwannahackme/XSSReaper/internal/fixtures"
)

func main() {
	port := flag.Int("port", 8888, "Port to run the XSS verification fixture server on")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	slog.Info("Starting XSS verification fixture server", slog.String("addr", addr))

	srv := fixtures.NewHandler()
	if err := http.ListenAndServe(addr, srv); err != nil {
		slog.Error("Fixture server failed", slog.Any("error", err))
		os.Exit(1)
	}
}
