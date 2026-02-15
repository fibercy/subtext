// Command subtext is the CLI client for the Subtext daemon.
package main

import (
	"os"

	"github.com/cy/subtext/cmd/subtext/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
