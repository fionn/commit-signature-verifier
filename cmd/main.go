// main as the entrypoint wraps the service runner and exposes it as a binary.
package main

import (
	"log/slog"
	"os"

	"github.com/fionn/commit-signature-verifier/service"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelDebug})))

	err := service.Run()
	if err != nil {
		panic(err)
	}
}
