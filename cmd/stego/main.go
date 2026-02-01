// Command stego is the CLI client for the steganographic chat daemon.
package main

import (
	"os"

	"github.com/cy/stegochat/cmd/stego/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
