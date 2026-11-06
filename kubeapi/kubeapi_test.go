package kubeapi_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/kubeapi"
)

// apiCall is one request the fake API server saw.
type apiCall struct {
	Method, Path, Query, ContentType, Auth, Impersonate, Accept string
	Body                                                        []byte
}

// fakeAPI is a small kube-apiserver: it records every request and answers
// from a map of canned responses keyed by "METHOD path".
type fakeAPI struct {
	mu    sync.Mutex
	calls []apiCall
	resp  map[string]string
	code  map[string]int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, apiCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
		ContentType: r.Header.Get("Content-Type"), Auth: r.Header.Get("Authorization"), Impersonate: r.Header.Get("Impersonate-User"), Accept: r.Header.Get("Accept"), Body: b})
	k := r.Method + " " + r.URL.Path
	body, code := f.resp[k], f.code[k]
	f.mu.Unlock()
	if code == 0 {
		code = 200
	}
	w.Header().Set("Content-Type", "application/json")
	if code/100 == 3 {
		w.Header().Set("Location", "https://elsewhere.example.test/steal")
	}
	w.WriteHeader(code)
	if body == "" {
		body = "{}"
	}
	_, _ = io.WriteString(w, body)
}

func (f *fakeAPI) last() apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeAPI) lastImpersonate() string { return f.last().Impersonate }

func newClient(t *testing.T, f *fakeAPI) (*kubeapi.Client, string) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := kubeapi.New(kubeapi.Config{Server: srv.URL, CAPEM: ca, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	return c, tok
}

// A create or a replace is one server-side apply: a PATCH of the whole
// object with the apply content type, the applier's field manager and
// force, so no Get is needed first and kubectl is not involved.
func TestCreateAndReplaceAreServerSideApplies(t *testing.T) {
	f := &fakeAPI{}
	c, _ := newClient(t, f)
	o := kobj.Object{Kind: kobj.KindRoleBinding, Namespace: "apps", Name: "runos:view:u:a",
		Labels:   map[string]string{kobj.LabelManaged: "true"},
		Subjects: []kobj.Subject{{Kind: "Group", Name: "runos:u:a:view", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:  &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "runos:view"}}
	for _, op := range []func(context.Context, kobj.Object) error{c.Create, c.Replace} {
		if err := op(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		got := f.last()
		if got.Method != http.MethodPatch || got.Path != "/apis/rbac.authorization.k8s.io/v1/namespaces/apps/rolebindings/runos:view:u:a" {
			t.Fatalf("request: %s %s", got.Method, got.Path)
		}
		if got.ContentType != "application/apply-patch+yaml" {
			t.Fatalf("content type %q", got.ContentType)
		}
		if !strings.Contains(got.Query, "fieldManager=roid-k8s-applier") || !strings.Contains(got.Query, "force=true") {
			t.Fatalf("query %q", got.Query)
		}
		var m map[string]any
		if err := json.Unmarshal(got.Body, &m); err != nil || m["kind"] != "RoleBinding" || m["roleRef"] == nil {
			t.Fatalf("body %s (%v)", got.Body, err)
		}
	}
}

// RunOS owns only its labels on a Namespace: the replace is a merge patch
// of the labels, never an apply that could create the namespace.
func TestNamespaceReplacePatchesLabelsOnly(t *testing.T) {
	f := &fakeAPI{}
	c, _ := newClient(t, f)
	if err := c.Replace(context.Background(), kobj.Object{Kind: kobj.KindNamespace, Name: "apps",
		Labels: map[string]string{kobj.LabelAccess: "true"}}); err != nil {
		t.Fatal(err)
	}
	got := f.last()
	if got.Method != http.MethodPatch || got.Path != "/api/v1/namespaces/apps" || got.ContentType != "application/merge-patch+json" {
		t.Fatalf("request: %s %s %s", got.Method, got.Path, got.ContentType)
	}
	if string(got.Body) != `{"metadata":{"labels":{"runos.com/roid-access":"true"}}}` {
		t.Fatalf("body %s", got.Body)
	}
}

// The API server leaves kind out of list items; the client puts it back, so
// a listed object has the same key as the compiled one.
func TestListsCarryTheKindAndTheLabelSelector(t *testing.T) {
	f := &fakeAPI{resp: map[string]string{
		"GET /apis/rbac.authorization.k8s.io/v1/rolebindings":                 `{"kind":"RoleBindingList","items":[{"metadata":{"name":"b","namespace":"apps","labels":{"runos.com/roid-managed":"true"}},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"runos:view"}}]}`,
		"GET /api/v1/namespaces/" + compile.DenyNamespace + "/configmaps":     `{"items":[]}`,
		"GET /apis/rbac.authorization.k8s.io/v1/namespaces/apps/rolebindings": `{"items":[{"metadata":{"name":"hand","namespace":"apps"}}]}`,
	}}
	c, _ := newClient(t, f)
	rbs, err := c.ListManaged(context.Background(), kobj.KindRoleBinding)
	if err != nil {
		t.Fatal(err)
	}
	if len(rbs) != 1 || rbs[0].Key() != "RoleBinding/apps/b" {
		t.Fatalf("listed %+v", rbs)
	}
	if q := f.last().Query; q != "labelSelector=runos.com%2Froid-managed%3Dtrue" {
		t.Fatalf("query %q", q)
	}
	// ConfigMaps are listed in the runos namespace only, never cluster-wide.
	if _, err := c.ListManaged(context.Background(), kobj.KindConfigMap); err != nil {
		t.Fatal(err)
	}
	if p := f.last().Path; p != "/api/v1/namespaces/runos/configmaps" {
		t.Fatalf("configmaps listed at %s", p)
	}
	all, err := c.ListRoleBindings(context.Background(), "apps")
	if err != nil || len(all) != 1 || all[0].Key() != "RoleBinding/apps/hand" {
		t.Fatalf("namespace list %+v %v", all, err)
	}
}

// A missing object is not an error for Get (ok=false) or Delete; any other
// failure is, with the API server's message.
func TestNotFoundAndErrors(t *testing.T) {
	p := "/apis/rbac.authorization.k8s.io/v1/clusterroles/runos:view"
	f := &fakeAPI{code: map[string]int{"GET " + p: 404, "DELETE " + p: 404,
		"PATCH " + p: 403}, resp: map[string]string{"PATCH " + p: `{"kind":"Status","message":"forbidden: escalate"}`}}
	c, _ := newClient(t, f)
	if _, ok, err := c.Get(context.Background(), kobj.KindClusterRole, "", "runos:view"); ok || err != nil {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if err := c.Delete(context.Background(), kobj.KindClusterRole, "", "runos:view"); err != nil {
		t.Fatalf("delete of a missing object: %v", err)
	}
	err := c.Create(context.Background(), kobj.Object{Kind: kobj.KindClusterRole, Name: "runos:view"})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden: escalate") {
		t.Fatalf("create: %v", err)
	}
}

// The service account token is read at every call, so the kubelet's
// rotation needs no restart.
func TestTokenIsReadAtEveryCall(t *testing.T) {
	f := &fakeAPI{resp: map[string]string{"GET /api/v1/namespaces": `{"items":[{"metadata":{"name":"apps"}},{"metadata":{"name":"web"}}]}`}}
	c, tok := newClient(t, f)
	ns, err := c.ListNamespaces(context.Background(), "runos.com/roid-access=true")
	if err != nil || strings.Join(ns, ",") != "apps,web" {
		t.Fatalf("namespaces %v %v", ns, err)
	}
	if a := f.last().Auth; a != "Bearer tok-1" {
		t.Fatalf("auth %q", a)
	}
	if err := os.WriteFile(tok, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListNamespaces(context.Background(), "runos.com/roid-access=true"); err != nil {
		t.Fatal(err)
	}
	if a := f.last().Auth; a != "Bearer tok-2" {
		t.Fatalf("auth after rotation %q", a)
	}
}

// A redirect would carry the token to another place; the client refuses it.
func TestRedirectIsRefused(t *testing.T) {
	f := &fakeAPI{code: map[string]int{"GET /api/v1/namespaces/x": 302}}
	c, _ := newClient(t, f)
	if _, _, err := c.Get(context.Background(), kobj.KindNamespace, "", "x"); err == nil {
		t.Fatal("a redirect was followed or taken as success")
	}
}

// The in-cluster configuration needs the service host and the mounted
// token and CA; out of the cluster it fails closed.
func TestInClusterNeedsTheServiceAccount(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := kubeapi.InCluster(); err == nil {
		t.Fatal("in-cluster config without KUBERNETES_SERVICE_HOST")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "2001:db8::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	c, err := kubeapi.InClusterAt(t.TempDir())
	if err == nil {
		t.Fatalf("no CA file, still configured: %+v", c)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte("t"), 0o600)
	c, err = kubeapi.InClusterAt(dir)
	if err != nil || c.Server != "https://[2001:db8::1]:443" || c.TokenFile != filepath.Join(dir, "token") {
		t.Fatalf("in-cluster: %+v %v", c, err)
	}
}

// A kubeconfig in JSON (kubectl config view --raw --minify -o json) gives
// the server, the CA and a client certificate, for runs outside a pod.
func TestFromKubeconfigJSON(t *testing.T) {
	raw := `{"current-context":"k","contexts":[{"name":"k","context":{"cluster":"c","user":"u"}}],
	  "clusters":[{"name":"c","cluster":{"server":"https://127.0.0.1:6443","certificate-authority-data":"Y2E="}}],
	  "users":[{"name":"u","user":{"client-certificate-data":"Y2VydA==","client-key-data":"a2V5"}}]}`
	c, err := kubeapi.FromKubeconfigJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://127.0.0.1:6443" || string(c.CAPEM) != "ca" || string(c.ClientCertPEM) != "cert" || string(c.ClientKeyPEM) != "key" {
		t.Fatalf("config %+v", c)
	}
}

// A name that could change the request path is refused before any call.
func TestPathChangingNamesAreRefused(t *testing.T) {
	f := &fakeAPI{}
	c, _ := newClient(t, f)
	for _, n := range []string{"..", "a/b", "a?x=1", "a%2Fb", ""} {
		if err := c.Delete(context.Background(), kobj.KindClusterRole, "", n); err == nil {
			t.Errorf("name %q was accepted", n)
		}
		if _, err := c.ListRoleBindings(context.Background(), n); err == nil {
			t.Errorf("namespace %q was accepted", n)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("requests sent: %+v", f.calls)
	}
}
