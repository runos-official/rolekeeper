package main

import (
	"fmt"
	"io"
)

// binaryName is the name the binary reports in its version and help text.
const binaryName = "rolekeeper"

// infoArgs answers --version and --help and reports whether it did, so that
// main can stop. Any other argument is ignored, as before: the pod manifest
// passes none.
func infoArgs(args []string, out io.Writer) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-version", "version":
		fmt.Fprintf(out, "%s %s\n", binaryName, version)
		return true
	case "--help", "-help", "-h", "help":
		fmt.Fprintf(out, `%[1]s %[2]s

usage: %[1]s [--version | --help]

It takes no other argument. It reads its configuration from the environment.
The main variables:

  ROID_K8S_TRANSPORT   relay
  ROID_K8S_ACCOUNT     the account that owns this cluster (required)
  ROID_K8S_TRUST_FILE  the pinned trust, a JSON file (required)
  ROID_K8S_STATE_DIR   a writable directory for its state (required)

The full list is at the top of main.go.
`, binaryName, version)
		return true
	}
	return false
}
