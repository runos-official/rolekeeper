package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// Kubectl implements Kube with the kubectl binary and one kubeconfig. In
// RunOS the cluster agent would run this with its own reduced
// ServiceAccount; the lab uses the kind admin kubeconfig.
type Kubectl struct {
	Bin        string // default "kubectl"
	Kubeconfig string // empty: kubectl's own loading rules (in cluster: the ServiceAccount)
	// ServerSide makes Create and Replace server-side applies owned by
	// FieldManager, the way the in-cluster applier writes.
	ServerSide   bool
	FieldManager string
}

func resource(kind string) string {
	switch kind {
	case kobj.KindClusterRole:
		return "clusterroles.rbac.authorization.k8s.io"
	case kobj.KindClusterRoleBinding:
		return "clusterrolebindings.rbac.authorization.k8s.io"
	case kobj.KindRoleBinding:
		return "rolebindings.rbac.authorization.k8s.io"
	case kobj.KindNamespace:
		return "namespaces"
	case kobj.KindConfigMap:
		return "configmaps"
	case kobj.KindVAP:
		return "validatingadmissionpolicies.admissionregistration.k8s.io"
	case kobj.KindVAPBinding:
		return "validatingadmissionpolicybindings.admissionregistration.k8s.io"
	}
	return kind
}

func (k Kubectl) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	bin := k.Bin
	if bin == "" {
		bin = "kubectl"
	}
	base := []string{"--request-timeout=20s"}
	if k.Kubeconfig != "" {
		base = append([]string{"--kubeconfig", k.Kubeconfig}, base...)
	}
	cmd := exec.CommandContext(ctx, bin, append(base, args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func nsArgs(ns string) []string {
	if ns == "" {
		return nil
	}
	return []string{"-n", ns}
}

func (k Kubectl) Get(ctx context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	out, err := k.run(ctx, nil, append(nsArgs(ns), "get", resource(kind), name, "-o", "json", "--ignore-not-found")...)
	if err != nil {
		return kobj.Object{}, false, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return kobj.Object{}, false, nil
	}
	o, err := kobj.FromJSON(out)
	return o, err == nil, err
}

// Exec runs kubectl with the configured binary and kubeconfig.
func (k Kubectl) Exec(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	return k.run(ctx, stdin, args...)
}

func (k Kubectl) apply(ctx context.Context, o kobj.Object) error {
	fm := k.FieldManager
	if fm == "" {
		fm = "roid"
	}
	_, err := k.run(ctx, o.JSON(), "apply", "--server-side", "--field-manager="+fm, "--force-conflicts", "-f", "-")
	return err
}

func (k Kubectl) Create(ctx context.Context, o kobj.Object) error {
	if k.ServerSide {
		return k.apply(ctx, o)
	}
	_, err := k.run(ctx, o.JSON(), "create", "-f", "-")
	return err
}

func (k Kubectl) Replace(ctx context.Context, o kobj.Object) error {
	if o.Kind == kobj.KindNamespace {
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": o.Labels}})
		_, err := k.run(ctx, nil, "patch", "namespace", o.Name, "--type=merge", "-p", string(patch))
		return err
	}
	if k.ServerSide {
		return k.apply(ctx, o)
	}
	_, err := k.run(ctx, o.JSON(), "replace", "-f", "-")
	return err
}

// Delete removes an object. It refuses the deny policy and its binding
// (compile.ErrDenyPolicyKept) without running kubectl.
func (k Kubectl) Delete(ctx context.Context, kind, ns, name string) error {
	if compile.IsKeptDenyObject(kind, name) {
		return compile.ErrDenyPolicyKept
	}
	_, err := k.run(ctx, nil, append(nsArgs(ns), "delete", resource(kind), name, "--ignore-not-found", "--wait=false")...)
	return err
}

func (k Kubectl) ListManaged(ctx context.Context, kind string) ([]kobj.Object, error) {
	args := []string{"get", resource(kind), "-l", kobj.LabelManaged + "=true", "-o", "json"}
	switch kind {
	case kobj.KindRoleBinding:
		args = append(args, "-A")
	case kobj.KindConfigMap:
		// The only ConfigMap the projection owns is the deny list in the
		// runos namespace, so the applier needs no cluster-wide read of
		// ConfigMaps (which hold other people's configuration).
		args = append(args, "-n", compile.DenyNamespace)
	}
	out, err := k.run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return kobj.ListFromJSON(out)
}

func (k Kubectl) ListRoleBindings(ctx context.Context, ns string) ([]kobj.Object, error) {
	out, err := k.run(ctx, nil, "-n", ns, "get", resource(kobj.KindRoleBinding), "-o", "json")
	if err != nil {
		return nil, err
	}
	return kobj.ListFromJSON(out)
}

// FileSink appends events as JSON lines.
type FileSink struct {
	mu   sync.Mutex
	Path string
}

func (f *FileSink) Add(e Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(e)
	fh, err := os.OpenFile(f.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	_, _ = fh.Write(append(b, '\n'))
}
