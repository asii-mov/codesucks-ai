// Command codesucks-ai scans a GitHub repository for vulnerabilities, uses
// Claude to reject false positives and patch real ones, verifies each patch,
// and opens a pull request per confirmed fix.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/asii-mov/codesucks-ai/internal/pipeline"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load() // .env is optional; ignore if absent

	cfg, err := pipeline.ParseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := preflight(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "preflight failed:", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := pipeline.Run(ctx, cfg, pipeline.ProductionDeps(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "run failed:", err)
		os.Exit(1)
	}

	fmt.Printf("Done: %d findings, %d true positives, %d PR(s) opened, %d need review, %d skipped ($%.2f).\n",
		rep.Found, rep.TruePositive, rep.PRd, rep.NeedsReview, rep.Skipped, rep.EstCostUSD)
	fmt.Printf("Report written to %s/report.md\n", cfg.OutDir)
}

// preflight verifies required external tools are present.
func preflight(cfg pipeline.Config) error {
	for _, bin := range []string{"git", pipeline.SemgrepBinary, pipeline.TruffleHogBinary} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%q not found on PATH", bin)
		}
	}
	return nil
}
