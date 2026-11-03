package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInfoArgsAnswerVersionAndHelp(t *testing.T) {
	for _, a := range []string{"--version", "-version", "version"} {
		var out bytes.Buffer
		if !infoArgs([]string{a}, &out) {
			t.Fatalf("%s: not answered", a)
		}
		if got, want := out.String(), binaryName+" "+version+"\n"; got != want {
			t.Fatalf("%s: got %q, want %q", a, got, want)
		}
	}
	for _, a := range []string{"--help", "-help", "-h", "help"} {
		var out bytes.Buffer
		if !infoArgs([]string{a}, &out) {
			t.Fatalf("%s: not answered", a)
		}
		for _, want := range []string{binaryName, "ROID_K8S_TRUST_FILE", "ROID_K8S_STATE_DIR", "ROID_K8S_ACCOUNT"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%s: help does not mention %s:\n%s", a, want, out.String())
			}
		}
	}
}

// Any other argument is ignored, as it was before these flags existed: the pod
// manifest passes none, and a stray argument must not stop the applier.
func TestInfoArgsIgnoreEverythingElse(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--tls-cert-file=x"}, {"serve"}, {"x", "--version"}} {
		var out bytes.Buffer
		if infoArgs(args, &out) {
			t.Fatalf("%v: answered", args)
		}
		if out.Len() != 0 {
			t.Fatalf("%v: wrote %q", args, out.String())
		}
	}
}
