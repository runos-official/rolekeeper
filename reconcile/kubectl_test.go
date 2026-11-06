package reconcile_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/reconcile"
)

// The stand-in for kubectl is one shell script, written once for the whole
// test binary: the first run of a new executable file is slow on some systems,
// so a script per test would cost seconds. The script reads the directory of
// the running test from STUB_DIR. It appends its arguments and its standard
// input to the files "args" and "stdin" there, prints the file "err" to
// standard error and the file "out" to standard output, and exits with the
// status in the file "status" (0 when there is none).
const stubBody = `#!/bin/sh
echo "$@" >> "$STUB_DIR/args"
cat >> "$STUB_DIR/stdin"
[ -f "$STUB_DIR/err" ] && cat "$STUB_DIR/err" >&2
[ -f "$STUB_DIR/out" ] && cat "$STUB_DIR/out"
[ -f "$STUB_DIR/status" ] && exit "$(cat "$STUB_DIR/status")"
exit 0
`

var stubBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kubectl-stub")
	if err != nil {
		panic(err)
	}
	stubBin = filepath.Join(dir, "kubectl")
	if err := os.WriteFile(stubBin, []byte(stubBody), 0o755); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// script is the stand-in for one test: its own directory of records.
type script struct {
	dir  string
	bin  string
	args string
	in   string
}

func newScript(t *testing.T) *script {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("STUB_DIR", dir)
	return &script{dir: dir, bin: stubBin, args: filepath.Join(dir, "args"), in: filepath.Join(dir, "stdin")}
}

func (s *script) output(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *script) calls(t *testing.T) []string {
	t.Helper()
	raw, _ := os.ReadFile(s.args)
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (s *script) stdin() string {
	raw, _ := os.ReadFile(s.in)
	return string(raw)
}

const roleBindingJSON = `{"kind":"RoleBinding","metadata":{"name":"runos:view:g:ops","namespace":"apps","resourceVersion":"42","labels":{"runos.com/roid-managed":"true"}},
"subjects":[{"kind":"Group","name":"runos:g:ops:view","apiGroup":"rbac.authorization.k8s.io"}],
"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"runos:view"}}`

func TestGetParsesTheLiveObject(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", roleBindingJSON)
	k := reconcile.Kubectl{Bin: s.bin}
	o, ok, err := k.Get(context.Background(), kobj.KindRoleBinding, "apps", "runos:view:g:ops")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Name != "runos:view:g:ops" || o.ResourceVersion != "42" || o.RoleRef == nil || o.RoleRef.Name != "runos:view" || len(o.Subjects) != 1 {
		t.Fatalf("object %+v", o)
	}
	got := s.calls(t)[0]
	for _, part := range []string{"-n apps", "get rolebindings.rbac.authorization.k8s.io runos:view:g:ops", "-o json", "--ignore-not-found", "--request-timeout=20s"} {
		if !strings.Contains(got, part) {
			t.Errorf("call %q lacks %q", got, part)
		}
	}
}

func TestGetOfAnObjectThatIsNotThereIsNotAnError(t *testing.T) {
	s := newScript(t) // kubectl prints nothing for --ignore-not-found
	k := reconcile.Kubectl{Bin: s.bin}
	_, ok, err := k.Get(context.Background(), kobj.KindClusterRole, "", "runos:view")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Contains(s.calls(t)[0], "-n ") {
		t.Fatalf("a cluster-scoped get passed a namespace: %q", s.calls(t)[0])
	}
}

func TestGetReturnsTheStatusAndTheStderrOfAFailedKubectl(t *testing.T) {
	s := newScript(t)
	s.output(t, "err", "the server is down")
	s.output(t, "status", "1")
	k := reconcile.Kubectl{Bin: s.bin}
	_, ok, err := k.Get(context.Background(), kobj.KindConfigMap, "runos", "x")
	if err == nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !strings.Contains(err.Error(), "the server is down") || !strings.Contains(err.Error(), "kubectl ") {
		t.Fatalf("the error does not carry the command and the reason: %v", err)
	}
}

func TestGetOfOutputThatIsNotJSONIsAnError(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", "not json")
	k := reconcile.Kubectl{Bin: s.bin}
	if _, ok, err := k.Get(context.Background(), kobj.KindRoleBinding, "apps", "x"); err == nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestEveryKindMapsToItsKubernetesResource(t *testing.T) {
	want := map[string]string{
		kobj.KindClusterRole:        "clusterroles.rbac.authorization.k8s.io",
		kobj.KindClusterRoleBinding: "clusterrolebindings.rbac.authorization.k8s.io",
		kobj.KindRoleBinding:        "rolebindings.rbac.authorization.k8s.io",
		kobj.KindNamespace:          "namespaces",
		kobj.KindConfigMap:          "configmaps",
		kobj.KindVAP:                "validatingadmissionpolicies.admissionregistration.k8s.io",
		kobj.KindVAPBinding:         "validatingadmissionpolicybindings.admissionregistration.k8s.io",
		"Other":                     "Other",
	}
	for kind, resource := range want {
		s := newScript(t)
		k := reconcile.Kubectl{Bin: s.bin}
		if _, _, err := k.Get(context.Background(), kind, "", "n"); err != nil {
			t.Fatal(err)
		}
		if got := s.calls(t)[0]; !strings.Contains(got, "get "+resource+" n ") {
			t.Errorf("%s: call %q does not get %s", kind, got, resource)
		}
	}
}

func TestKubeconfigAndTimeoutComeBeforeTheCommand(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin, Kubeconfig: "/etc/kube/config"}
	if _, _, err := k.Get(context.Background(), kobj.KindClusterRole, "", "r"); err != nil {
		t.Fatal(err)
	}
	if got := s.calls(t)[0]; !strings.HasPrefix(got, "--kubeconfig /etc/kube/config --request-timeout=20s get ") {
		t.Fatalf("call %q", got)
	}
}

func TestCreateWithoutServerSideIsAPlainCreateOfTheManifest(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin}
	o := binding("apps", compile.RoleView, compile.GroupSubject("ops", compile.RoleView), pv1)
	if err := k.Create(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if got := s.calls(t)[0]; !strings.HasSuffix(got, "create -f -") {
		t.Fatalf("call %q", got)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s.stdin()), &m); err != nil {
		t.Fatalf("stdin is not a manifest: %v: %q", err, s.stdin())
	}
	if m["kind"] != "RoleBinding" || m["apiVersion"] != "rbac.authorization.k8s.io/v1" {
		t.Fatalf("manifest %v", m)
	}
}

func TestReplaceWithoutServerSideIsAReplace(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin}
	if err := k.Replace(context.Background(), compile.FixedRoles(pv1, account)[0]); err != nil {
		t.Fatal(err)
	}
	if got := s.calls(t)[0]; !strings.HasSuffix(got, "replace -f -") {
		t.Fatalf("call %q", got)
	}
}

func TestServerSideApplyDefaultsTheFieldManager(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin, ServerSide: true}
	if err := k.Create(context.Background(), compile.FixedRoles(pv1, account)[0]); err != nil {
		t.Fatal(err)
	}
	if got := s.calls(t)[0]; !strings.Contains(got, "--field-manager=roid ") {
		t.Fatalf("call %q", got)
	}
}

func TestReplaceOfANamespaceMergesTheLabelsOnly(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin, ServerSide: true}
	if err := k.Replace(context.Background(), desiredNamespace("apps", pv1)); err != nil {
		t.Fatal(err)
	}
	got := s.calls(t)[0]
	if !strings.Contains(got, "patch namespace apps --type=merge -p ") || !strings.Contains(got, kobj.LabelAccess) {
		t.Fatalf("call %q", got)
	}
	if strings.Contains(got, "apply") {
		t.Fatalf("a namespace was applied, not patched: %q", got)
	}
}

func TestDeleteIgnoresAnObjectThatIsAlreadyGoneAndDoesNotWait(t *testing.T) {
	s := newScript(t)
	k := reconcile.Kubectl{Bin: s.bin}
	if err := k.Delete(context.Background(), kobj.KindRoleBinding, "apps", "b"); err != nil {
		t.Fatal(err)
	}
	got := s.calls(t)[0]
	for _, part := range []string{"-n apps", "delete rolebindings.rbac.authorization.k8s.io b", "--ignore-not-found", "--wait=false"} {
		if !strings.Contains(got, part) {
			t.Errorf("call %q lacks %q", got, part)
		}
	}
}

func TestListManagedSelectsByTheManagedLabel(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", `{"items":[`+roleBindingJSON+`]}`)
	k := reconcile.Kubectl{Bin: s.bin}
	objs, err := k.ListManaged(context.Background(), kobj.KindRoleBinding)
	if err != nil || len(objs) != 1 || objs[0].Namespace != "apps" {
		t.Fatalf("objs %+v err %v", objs, err)
	}
	got := s.calls(t)[0]
	if !strings.Contains(got, "-l runos.com/roid-managed=true") || !strings.HasSuffix(got, "-A") {
		t.Fatalf("call %q: role bindings are listed in every namespace", got)
	}
}

func TestListManagedOfClusterRolesIsClusterScoped(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", `{"items":[]}`)
	k := reconcile.Kubectl{Bin: s.bin}
	if objs, err := k.ListManaged(context.Background(), kobj.KindClusterRole); err != nil || len(objs) != 0 {
		t.Fatalf("objs %v err %v", objs, err)
	}
	if got := s.calls(t)[0]; strings.Contains(got, "-A") || strings.Contains(got, "-n ") {
		t.Fatalf("call %q", got)
	}
}

func TestListManagedReturnsTheErrorOfAFailedKubectl(t *testing.T) {
	s := newScript(t)
	s.output(t, "status", "3")
	k := reconcile.Kubectl{Bin: s.bin}
	if _, err := k.ListManaged(context.Background(), kobj.KindClusterRole); err == nil {
		t.Fatal("no error")
	}
}

func TestListRoleBindingsListsOneNamespace(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", `{"items":[`+roleBindingJSON+`,`+roleBindingJSON+`]}`)
	k := reconcile.Kubectl{Bin: s.bin}
	objs, err := k.ListRoleBindings(context.Background(), "apps")
	if err != nil || len(objs) != 2 {
		t.Fatalf("objs %d err %v", len(objs), err)
	}
	if got := s.calls(t)[0]; !strings.Contains(got, "-n apps get rolebindings.rbac.authorization.k8s.io -o json") {
		t.Fatalf("call %q", got)
	}
	s.output(t, "status", "1")
	if _, err := k.ListRoleBindings(context.Background(), "apps"); err == nil {
		t.Fatal("no error")
	}
}

func TestExecRunsKubectlWithTheConfiguredBinaryAndPassesStdin(t *testing.T) {
	s := newScript(t)
	s.output(t, "out", "result")
	k := reconcile.Kubectl{Bin: s.bin}
	out, err := k.Exec(context.Background(), []byte("input"), "version", "--client")
	if err != nil || string(out) != "result" {
		t.Fatalf("out %q err %v", out, err)
	}
	if !strings.HasSuffix(s.calls(t)[0], "version --client") || s.stdin() != "input" {
		t.Fatalf("call %q stdin %q", s.calls(t)[0], s.stdin())
	}
}

func TestKubectlThatIsNotThereIsAnError(t *testing.T) {
	k := reconcile.Kubectl{Bin: filepath.Join(t.TempDir(), "missing")}
	if _, _, err := k.Get(context.Background(), kobj.KindClusterRole, "", "r"); err == nil {
		t.Fatal("no error for a missing binary")
	}
}

func TestACancelledContextStopsKubectl(t *testing.T) {
	s := newScript(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k := reconcile.Kubectl{Bin: s.bin}
	if _, _, err := k.Get(ctx, kobj.KindClusterRole, "", "r"); err == nil {
		t.Fatal("a cancelled context did not stop the call")
	}
}

func TestFileSinkAppendsOneJSONLinePerEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sk := &reconcile.FileSink{Path: path}
	sk.Add(reconcile.Event{Type: reconcile.EvDrift, At: t0, Object: "ClusterRole//runos:view", PolicyVersion: pv1, Action: "repaired", Fields: []string{"rules"}})
	sk.Add(reconcile.Event{Type: reconcile.EvRemoved, At: t0, Object: "RoleBinding/apps/b", PolicyVersion: pv1, Action: "deleted"})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines: %q", len(lines), raw)
	}
	var e reconcile.Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Type != reconcile.EvDrift || e.Fields[0] != "rules" {
		t.Fatalf("line 0: %v %+v", err, e)
	}
	// Fields are left out of the line when there are none.
	if strings.Contains(lines[1], `"fields"`) {
		t.Fatalf("line 1 holds an empty fields list: %s", lines[1])
	}
}

func TestFileSinkThatCannotOpenItsFileDropsTheEventWithoutPanicking(t *testing.T) {
	sk := &reconcile.FileSink{Path: filepath.Join(t.TempDir(), "no", "such", "dir", "events.jsonl")}
	sk.Add(reconcile.Event{Type: reconcile.EvDrift})
}
