// Command agpass is a local secrets broker for AI coding agents.
package main

import (
	"os"

	"agpass/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
