package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/compile"
	"github.com/runos-official/rolekeeper/internal/kobj"
)

// fakeKubectl records its arguments.
func fakeKubectl(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\necho \"$@\" >> " + argsFile + "\ncat >/dev/null\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

// With ServerSide set, a create and a replace are server-side applies with
// the applier's field manager.
func TestServerSideCreateAndReplaceUseApply(t *testing.T) {
	bin, args := fakeKubectl(t)
	k := Kubectl{Bin: bin, ServerSide: true, FieldManager: "roid-k8s-applier"}
	o := kobj.Object{Kind: kobj.KindRoleBinding, Name: "b", Namespace: "apps"}
	if err := k.Create(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := k.Replace(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(args)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("calls: %q", lines)
	}
	for _, l := range lines {
		if !strings.Contains(l, "apply --server-side --field-manager=roid-k8s-applier --force-conflicts -f -") {
			t.Fatalf("not a server-side apply: %q", l)
		}
	}
}

// An empty kubeconfig is not passed, so kubectl uses the in-cluster
// service account.
func TestNoKubeconfigFlagInCluster(t *testing.T) {
	bin, args := fakeKubectl(t)
	k := Kubectl{Bin: bin}
	if _, _, err := k.Get(context.Background(), kobj.KindRoleBinding, "apps", "b"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(args)
	if strings.Contains(string(raw), "--kubeconfig") {
		t.Fatalf("passed --kubeconfig with no file: %q", raw)
	}
}

// Listing managed ConfigMaps reads only the runos namespace, so the applier
// needs no cluster-wide read of ConfigMaps.
func TestManagedConfigMapsAreListedInTheRunosNamespaceOnly(t *testing.T) {
	bin, args := fakeKubectl(t)
	k := Kubectl{Bin: bin}
	_, _ = k.ListManaged(context.Background(), kobj.KindConfigMap)
	raw, _ := os.ReadFile(args)
	if strings.Contains(string(raw), " -A") || !strings.Contains(string(raw), "-n runos") {
		t.Fatalf("configmaps listed beyond the runos namespace: %q", raw)
	}
}

// Kubectl is never asked to delete the deny policy or its binding.
func TestKubectlNeverDeletesTheDenyPolicy(t *testing.T) {
	bin, args := fakeKubectl(t)
	k := Kubectl{Bin: bin}
	for _, kind := range []string{kobj.KindVAP, kobj.KindVAPBinding} {
		if err := k.Delete(context.Background(), kind, "", compile.DenyPolicyName); !errors.Is(err, compile.ErrDenyPolicyKept) {
			t.Errorf("delete %s: %v", kind, err)
		}
	}
	if raw, _ := os.ReadFile(args); len(raw) != 0 {
		t.Fatalf("kubectl ran: %s", raw)
	}
}
