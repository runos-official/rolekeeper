// Package kubeapi is the applier's Kubernetes client: the REST API over the
// standard library HTTP client, with the pod's service account in the
// cluster. It implements reconcile.Kube.
//
// Why not client-go: the applier touches seven kinds with five verbs.
// client-go and its API machinery would add dozens of modules to a binary
// whose whole job is RBAC, and every one of them is code that runs with the
// right to bind roles. The few REST paths below are stable (rbac/v1,
// admissionregistration/v1, core/v1) and the tests pin them.
//
// Why not kubectl: one process per object made a pass take seconds, and the
// image would need a pinned kubectl inside. Here a pass is a few lists and
// one server-side apply (a PATCH) per changed object over one kept-alive
// connection.
package kubeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// DefaultFieldManager owns every field the applier writes.
const DefaultFieldManager = "roid-k8s-applier"

// ServiceAccountDir is where the kubelet mounts the pod's token and CA.
const ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Config says how to reach one API server.
type Config struct {
	Server string // https://host:port
	CAPEM  []byte
	// TokenFile is read at every call (the kubelet rotates it). Token is a
	// fixed bearer token instead. A client certificate may be used instead
	// of either.
	TokenFile     string
	Token         string
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	FieldManager  string
	Timeout       time.Duration // per request, default 20s
}

// InCluster is the configuration of a pod: the kubernetes service and the
// mounted service account.
func InCluster() (Config, error) { return InClusterAt(ServiceAccountDir) }

// InClusterAt is InCluster with the service account files in dir.
func InClusterAt(dir string) (Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return Config{}, errors.New("kubeapi: not in a cluster (no KUBERNETES_SERVICE_HOST)")
	}
	if port == "" {
		port = "443"
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return Config{}, fmt.Errorf("kubeapi: cluster CA: %w", err)
	}
	tok := filepath.Join(dir, "token")
	if _, err := os.Stat(tok); err != nil {
		return Config{}, fmt.Errorf("kubeapi: service account token: %w", err)
	}
	return Config{Server: "https://" + net.JoinHostPort(host, port), CAPEM: ca, TokenFile: tok}, nil
}

// FromKubeconfigJSON reads the current context of a kubeconfig in JSON form
// (kubectl config view --raw --minify -o json). It is for runs outside a
// pod: the lab and the tests. It takes inline data only.
func FromKubeconfigJSON(raw []byte) (Config, error) {
	var kc struct {
		Current  string `json:"current-context"`
		Contexts []struct {
			Name    string `json:"name"`
			Context struct {
				Cluster string `json:"cluster"`
				User    string `json:"user"`
			} `json:"context"`
		} `json:"contexts"`
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
				CA     string `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
		Users []struct {
			Name string `json:"name"`
			User struct {
				Cert  string `json:"client-certificate-data"`
				Key   string `json:"client-key-data"`
				Token string `json:"token"`
			} `json:"user"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &kc); err != nil {
		return Config{}, fmt.Errorf("kubeapi: kubeconfig: %w", err)
	}
	var c Config
	var clusterName, userName string
	for _, x := range kc.Contexts {
		if x.Name == kc.Current || (kc.Current == "" && len(kc.Contexts) == 1) {
			clusterName, userName = x.Context.Cluster, x.Context.User
		}
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	for _, x := range kc.Clusters {
		if x.Name == clusterName {
			c.Server, c.CAPEM = x.Cluster.Server, dec(x.Cluster.CA)
		}
	}
	for _, x := range kc.Users {
		if x.Name == userName {
			c.ClientCertPEM, c.ClientKeyPEM, c.Token = dec(x.User.Cert), dec(x.User.Key), x.User.Token
		}
	}
	if c.Server == "" {
		return Config{}, errors.New("kubeapi: kubeconfig: no server for the current context")
	}
	return c, nil
}

// Client calls one API server.
type Client struct {
	base *url.URL
	cfg  Config
	hc   *http.Client
}

// New checks the configuration and builds the HTTP client.
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("kubeapi: the API server must be an https URL, got %q", c.Server)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(c.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.CAPEM) {
			return nil, errors.New("kubeapi: no certificate in the cluster CA")
		}
		tc.RootCAs = pool
	}
	if len(c.ClientCertPEM) > 0 {
		cert, err := tls.X509KeyPair(c.ClientCertPEM, c.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("kubeapi: client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	if c.FieldManager == "" {
		c.FieldManager = DefaultFieldManager
	}
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	return &Client{base: u, cfg: c, hc: &http.Client{
		Timeout:   c.Timeout,
		Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second},
		// A redirect would carry the service account token elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// StatusError is an answer outside 2xx.
type StatusError struct {
	Code    int
	Method  string
	Path    string
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("kubeapi: %s %s: %d %s", e.Method, e.Path, e.Code, e.Message)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// maxBody bounds a response (a list of every RoleBinding in a cluster).
const maxBody = 64 << 20

func (c *Client) do(ctx context.Context, method, path string, q url.Values, ctype string, body []byte) ([]byte, error) {
	return c.doAs(ctx, "", method, path, q, ctype, body)
}

// doAs is do as another user (the Impersonate-User header), or as the
// client's own identity when as is empty.
func (c *Client) doAs(ctx context.Context, as, method, path string, q url.Values, ctype string, body []byte) ([]byte, error) {
	return c.doAccept(ctx, as, "application/json", method, path, q, ctype, body)
}

// doAccept is doAs with the Accept header chosen by the caller.
func (c *Client) doAccept(ctx context.Context, as, accept, method, path string, q url.Values, ctype string, body []byte) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if as != "" {
		req.Header.Set("Impersonate-User", as)
	}
	tok := c.cfg.Token
	if c.cfg.TokenFile != "" {
		b, err := os.ReadFile(c.cfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("kubeapi: service account token: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxBody {
		return nil, fmt.Errorf("kubeapi: %s %s: answer above %d bytes", method, path, maxBody)
	}
	if resp.StatusCode/100 != 2 {
		var st struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(out, &st)
		if st.Message == "" {
			st.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &StatusError{Code: resp.StatusCode, Method: method, Path: path, Message: st.Message}
	}
	return out, nil
}

type res struct{ prefix, plural string }

var resources = map[string]res{
	kobj.KindClusterRole:        {"/apis/rbac.authorization.k8s.io/v1", "clusterroles"},
	kobj.KindClusterRoleBinding: {"/apis/rbac.authorization.k8s.io/v1", "clusterrolebindings"},
	kobj.KindRoleBinding:        {"/apis/rbac.authorization.k8s.io/v1", "rolebindings"},
	kobj.KindVAP:                {"/apis/admissionregistration.k8s.io/v1", "validatingadmissionpolicies"},
	kobj.KindVAPBinding:         {"/apis/admissionregistration.k8s.io/v1", "validatingadmissionpolicybindings"},
	kobj.KindNamespace:          {"/api/v1", "namespaces"},
	kobj.KindConfigMap:          {"/api/v1", "configmaps"},
}

// collection is the path of a kind's objects in ns ("" for a cluster-scoped
// kind, or for a namespaced kind across every namespace).
func collection(kind, ns string) (string, error) {
	r, ok := resources[kind]
	if !ok {
		return "", fmt.Errorf("kubeapi: kind %q is not one the applier writes", kind)
	}
	if ns == "" {
		return r.prefix + "/" + r.plural, nil
	}
	if !safeName(ns) {
		return "", fmt.Errorf("kubeapi: %q is not a namespace name", ns)
	}
	return r.prefix + "/namespaces/" + ns + "/" + r.plural, nil
}

// safeName refuses what could change the request path. Kubernetes names
// never hold these characters, but the name comes from a bundle, and a
// signed bundle is still input.
func safeName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/?#%\\ ")
}

func object(kind, ns, name string) (string, error) {
	p, err := collection(kind, ns)
	if err != nil {
		return "", err
	}
	if !safeName(name) || (ns != "" && !safeName(ns)) {
		return "", fmt.Errorf("kubeapi: %q in %q is not an object name", name, ns)
	}
	return p + "/" + name, nil
}

// Get returns a live object, or ok=false when it does not exist.
func (c *Client) Get(ctx context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	p, err := object(kind, ns, name)
	if err != nil {
		return kobj.Object{}, false, err
	}
	out, err := c.do(ctx, http.MethodGet, p, nil, "", nil)
	if IsNotFound(err) {
		return kobj.Object{}, false, nil
	}
	if err != nil {
		return kobj.Object{}, false, err
	}
	o, err := kobj.FromJSON(out)
	if err != nil {
		return kobj.Object{}, false, err
	}
	o.Kind = kind
	return o, true, nil
}

// Meta is the part of an object's metadata the relay watch needs.
type Meta struct {
	ResourceVersion string
}

// partialMetadata asks the API server for the metadata alone
// (PartialObjectMetadata): a few hundred bytes, whatever the object holds.
const partialMetadata = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json"

// Metadata returns the resourceVersion of an object without its content, or
// ok=false when it does not exist. An answer without a resourceVersion is an
// error: a watch loop that never sees a change would never run a pass.
func (c *Client) Metadata(ctx context.Context, kind, ns, name string) (Meta, bool, error) {
	p, err := object(kind, ns, name)
	if err != nil {
		return Meta{}, false, err
	}
	out, err := c.doAccept(ctx, "", partialMetadata, http.MethodGet, p, nil, "", nil)
	if IsNotFound(err) {
		return Meta{}, false, nil
	}
	if err != nil {
		return Meta{}, false, err
	}
	var m struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return Meta{}, false, fmt.Errorf("kubeapi: metadata of %s/%s: %w", ns, name, err)
	}
	if m.Metadata.ResourceVersion == "" {
		return Meta{}, false, fmt.Errorf("kubeapi: metadata of %s/%s has no resourceVersion", ns, name)
	}
	return Meta{ResourceVersion: m.Metadata.ResourceVersion}, true, nil
}

// apply is one server-side apply of the whole object, owned by the field
// manager, taking fields over from any other manager (the applier is the
// owner of every object it writes).
func (c *Client) apply(ctx context.Context, o kobj.Object) error {
	p, err := object(o.Kind, o.Namespace, o.Name)
	if err != nil {
		return err
	}
	q := url.Values{"fieldManager": {c.cfg.FieldManager}, "force": {"true"}}
	_, err = c.do(ctx, http.MethodPatch, p, q, "application/apply-patch+yaml", o.JSON())
	return err
}

// Create writes the object with a server-side apply.
func (c *Client) Create(ctx context.Context, o kobj.Object) error {
	if o.Kind == kobj.KindNamespace {
		return errors.New("kubeapi: the applier never creates a namespace")
	}
	return c.apply(ctx, o)
}

// Replace writes the object with a server-side apply. For a Namespace it
// merges the RunOS labels only. For the deny policy, its binding and the
// deny list a JSON patch then sets the whole spec or data
// (kobj.ExactPatch): the apply alone keeps a list entry that another field
// manager added. Both requests use the patch verb, the one verb the
// applier holds on these objects.
func (c *Client) Replace(ctx context.Context, o kobj.Object) error {
	if o.Kind == kobj.KindNamespace {
		p, err := object(o.Kind, "", o.Name)
		if err != nil {
			return err
		}
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": o.Labels}})
		_, err = c.do(ctx, http.MethodPatch, p, nil, "application/merge-patch+json", patch)
		return err
	}
	if err := c.apply(ctx, o); err != nil {
		return err
	}
	exact, ok := o.ExactPatch()
	if !ok {
		return nil
	}
	p, err := object(o.Kind, o.Namespace, o.Name)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, p, url.Values{"fieldManager": {c.cfg.FieldManager}}, "application/json-patch+json", exact)
	return err
}

// Delete removes an object; a missing one is not an error. It refuses the
// deny policy and its binding (compile.ErrDenyPolicyKept) without a call.
func (c *Client) Delete(ctx context.Context, kind, ns, name string) error {
	if compile.IsKeptDenyObject(kind, name) {
		return compile.ErrDenyPolicyKept
	}
	p, err := object(kind, ns, name)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, p, nil, "", nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) list(ctx context.Context, kind, ns, selector string) ([]kobj.Object, error) {
	p, err := collection(kind, ns)
	if err != nil {
		return nil, err
	}
	var q url.Values
	if selector != "" {
		q = url.Values{"labelSelector": {selector}}
	}
	out, err := c.do(ctx, http.MethodGet, p, q, "", nil)
	if err != nil {
		return nil, err
	}
	objs, err := kobj.ListFromJSON(out)
	if err != nil {
		return nil, err
	}
	// List items carry no kind; put it back so keys match.
	for i := range objs {
		objs[i].Kind = kind
	}
	return objs, nil
}

// ListManaged lists objects of one kind that carry runos.com/roid-managed=true.
// ConfigMaps are listed in the runos namespace only: the deny list is the
// one ConfigMap the projection owns, so the applier needs no cluster-wide
// read of ConfigMaps.
func (c *Client) ListManaged(ctx context.Context, kind string) ([]kobj.Object, error) {
	ns := ""
	if kind == kobj.KindConfigMap {
		ns = compile.DenyNamespace
	}
	return c.list(ctx, kind, ns, kobj.LabelManaged+"=true")
}

// ListRoleBindings lists every RoleBinding in one namespace.
func (c *Client) ListRoleBindings(ctx context.Context, ns string) ([]kobj.Object, error) {
	if ns == "" {
		return nil, errors.New("kubeapi: ListRoleBindings needs a namespace")
	}
	return c.list(ctx, kobj.KindRoleBinding, ns, "")
}

// ListNamespaces returns the names of the namespaces that match a label
// selector.
func (c *Client) ListNamespaces(ctx context.Context, selector string) ([]string, error) {
	objs, err := c.list(ctx, kobj.KindNamespace, "", selector)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(objs))
	for _, o := range objs {
		names = append(names, o.Name)
	}
	return names, nil
}

// ProbeResult is what the API server did with one canary write.
type ProbeResult int

const (
	// ProbeAllowed: the dry run passed admission.
	ProbeAllowed ProbeResult = iota + 1
	// ProbeDenied: the deny policy refused it.
	ProbeDenied
	// ProbeOther: anything else (RBAC, a server error, another policy).
	// The probe proves nothing either way.
	ProbeOther
)

func (p ProbeResult) String() string {
	switch p {
	case ProbeAllowed:
		return "allowed"
	case ProbeDenied:
		return "denied by the deny list"
	case ProbeOther:
		return "refused for another reason"
	}
	return "unknown"
}

// DenyProbe writes a ConfigMap in ns as a deny canary, in a dry run, and
// says whether the deny policy refused it. It impersonates the
// canary user (the applier may impersonate the two canaries and no one
// else). A dry run goes through admission like a real write and is never
// stored. A SubjectAccessReview would not do: it asks the authorizer only,
// and the deny list is enforced by an admission policy.
func (c *Client) DenyProbe(ctx context.Context, user, ns string) (ProbeResult, string, error) {
	key, ok := strings.CutPrefix(user, compile.UserPrefix)
	if !ok || !compile.IsDenyCanary(key) {
		return ProbeOther, "", fmt.Errorf("kubeapi: %q is not a deny canary", user)
	}
	p, err := collection(kobj.KindConfigMap, ns)
	if err != nil {
		return ProbeOther, "", err
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "roid-deny-canary-probe"}, "data": map[string]string{"probe": "dry-run"}})
	_, err = c.doAs(ctx, user, http.MethodPost, p, url.Values{"dryRun": {"All"}}, "application/json", body)
	var se *StatusError
	switch {
	case err == nil:
		return ProbeAllowed, "", nil
	case errors.As(err, &se) && se.Code == http.StatusForbidden &&
		strings.Contains(se.Message, "ValidatingAdmissionPolicy '"+compile.DenyPolicyName+"'"):
		return ProbeDenied, se.Message, nil
	case errors.As(err, &se):
		return ProbeOther, fmt.Sprintf("%d %s", se.Code, se.Message), nil
	}
	return ProbeOther, "", err
}
