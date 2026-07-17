// Command codesucks-ai scans a GitHub repository for vulnerabilities, uses
// Claude to reject false positives and patch real ones, verifies each patch,
// and opens a pull request per confirmed fix.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run is wired to the pipeline in a later milestone.
func run(args []string) error {
	fmt.Println("codesucks-ai: not yet wired")
	return nil
}
