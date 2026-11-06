package kobj_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/kobj"
)

// Every other RunOS Kubernetes label uses runos.com/. roid's keys follow
// them, and the two old meanings of runos.dev/managed are two keys now: the
// namespace opt-in and the marker on objects roid creates.
func TestKubernetesKeysUseRunosCom(t *testing.T) {
	for got, want := range map[string]string{
		kobj.LabelManaged:       "runos.com/roid-managed",
		kobj.LabelAccess:        "runos.com/roid-access",
		kobj.LabelPolicyVersion: "runos.com/policy-version",
		kobj.LabelAccount:       "runos.com/account",
		kobj.AnnoGrants:         "runos.com/grants",
	} {
		if got != want {
			t.Errorf("key %q, want %q", got, want)
		}
	}
	if kobj.LabelManaged == kobj.LabelAccess {
		t.Fatal("the namespace opt-in and the object marker must be two keys")
	}
	if kobj.NamespaceSelector != "runos.com/roid-access=true" {
		t.Fatalf("default namespace selector %q", kobj.NamespaceSelector)
	}
}

// No file of the module names a roid Kubernetes key under the old prefix.
// Module paths and API group names are not Kubernetes keys of this module.
func TestNoOldKeyPrefixIsLeftInTheModule(t *testing.T) {
	old := regexp.MustCompile(`runos\.dev(/|%2F)(managed|policy-version|account|grants|jti|acct|breakglass|platform|workspace-owner|touched)\b`)
	self := "keys_test.go"
	var hits []string
	_ = filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "out", "state", "certs":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(p) == self || strings.HasSuffix(p, ".log") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 4<<20 {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if old.MatchString(line) {
				hits = append(hits, p+":"+itoa(i+1))
			}
		}
		return nil
	})
	if len(hits) > 0 {
		t.Fatalf("%d lines still use runos.dev/ for a Kubernetes key:\n%s", len(hits), strings.Join(hits, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
