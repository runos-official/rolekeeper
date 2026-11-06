package signer_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// atLeast compares plain vMAJOR.MINOR.PATCH versions (no extra dependency).
func atLeast(v string, maj, min, patch int) bool {
	var a, b, c int
	if _, err := fmt.Sscanf(v, "v%d.%d.%d", &a, &b, &c); err != nil {
		return false
	}
	if a != maj {
		return a > maj
	}
	if b != min {
		return b > min
	}
	return c >= patch
}

// A dependency may pin go-jose v4.1.4, below the GHSA-6mp9-8xrw-74r4 fix. The
// resolved module graph (MVS) must select v4.1.5 or later, whatever a dependency
// asks for.
func TestGoJoseVersionIsAtLeast_4_1_5(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}{{with .Replace}} => {{.Version}}{{end}}", "github.com/go-jose/go-jose/v4").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	v := strings.TrimSpace(string(out))
	if i := strings.LastIndex(v, "=> "); i >= 0 {
		v = v[i+3:]
	}
	if !atLeast(v, 4, 1, 5) {
		t.Fatalf("go-jose resolves to %s, need >= v4.1.5", v)
	}
	t.Logf("go-jose resolves to %s", v)
}
