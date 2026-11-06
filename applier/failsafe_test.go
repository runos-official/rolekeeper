package applier_test

// Retire bundles and the applier fail-safe.

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// offerFor seals a bundle of another account for the same cluster.
func (r *rig) offerFor(acct string, version uint64, objs ...kobj.Object) {
	r.t.Helper()
	raw, err := bundle.Seal(context.Background(), r.issuer, bundle.Bundle{Account: acct, Cluster: "cl-1", Version: version,
		PolicyVersion: "pv-1", Namespaces: []string{"apps"}, Objects: objs, IssuedAt: r.now}, 15*time.Minute)
	if err != nil {
		r.t.Fatal(err)
	}
	r.roid.next = raw
}

// A cluster moves from acct-a to acct-b. roid versions bundles per
// (account, cluster), so acct-b's first bundle is v1, while the applier's
// floor is per cluster and holds acct-a's v5. Every acct-b bundle is
// refused as stale, so acct-a's bindings stay on the cluster. The fail-safe
// never fires either: each pass fetched an envelope, which resets its clock.
func TestRetireMovedClusterKeepsTheOldAccountsBindings(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	a.RefusedBound = time.Hour
	r.offer(5, append(denyObjs(t, r.now), binding("alice"))...) // acct-a's v5: alice may view apps
	if res, err := a.RunOnce(context.Background()); err != nil || !res.Applied {
		t.Fatalf("setup v5: %+v %v", res, err)
	}
	// The move: acct-b now holds cl-1, and roid serves acct-b's v1, signed
	// after the move, with bob's grant and no alice.
	var last error
	for range 25 {
		r.now = r.now.Add(time.Hour)
		objs, _ := compile.DenyObjects("pv-1", "acct-b", nil, r.now)
		r.offerFor("acct-b", 1, append(objs, binding("bob"))...)
		_, last = a.RunOnce(context.Background())
	}
	if strings.Contains(strings.Join(r.kube.keys(), " "), "runos:view:u:alice") {
		t.Fatalf("acct-a's binding is still on the cluster 25 h after the cluster moved to acct-b (last pass: %v)", last)
	}
}

// The fail-safe counts any 403 k8s.not_allowed. roid also answers that
// code, with no reason, when the applier's service name is not on
// ROID_K8S_SERVICES: a roid configuration slip, not "this cluster is no
// longer yours". Only the reasons that say so (cluster, retired) should
// count.
func TestFailSafeCountsARefusalWithoutAClusterReason(t *testing.T) {
	c, set := r10Roid(t)
	for _, tc := range []struct {
		body    string
		refused bool
	}{
		{`{"error":{"code":"k8s.not_allowed","reason":"cluster"}}`, true}, // control
		{`{"error":{"code":"k8s.not_allowed","reason":"retired"}}`, true}, // control
		{`{"error":{"code":"k8s.not_allowed"}}`, false},                   // service not on ROID_K8S_SERVICES
	} {
		set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403); _, _ = w.Write([]byte(tc.body)) })
		_, err := c.Fetch(context.Background(), []string{"apps"}, false)
		if got := errors.Is(err, applier.ErrRoidRefused); got != tc.refused {
			t.Fatalf("403 %s: counted toward the fail-safe = %v, want %v (%v)", tc.body, got, tc.refused, err)
		}
	}
}

// The HTTP client follows redirects, so a 403 k8s.not_allowed from
// wherever roid's address redirects to counts as roid's own refusal.
func TestFailSafeCountsARefusalBehindARedirect(t *testing.T) {
	c, set := r10Roid(t)
	set(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"code":"k8s.not_allowed","reason":"cluster"}}`))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	if _, err := c.Fetch(context.Background(), []string{"apps"}, false); errors.Is(err, applier.ErrRoidRefused) {
		t.Fatalf("a redirected 403 counted toward the fail-safe: %v", err)
	}
}

// r10Roid is an HTTPRoid against a TLS test server whose handler the test
// sets.
func r10Roid(t *testing.T) (*applier.HTTPRoid, func(http.HandlerFunc)) {
	t.Helper()
	dir := t.TempDir()
	_, certFile, keyFile, clientPool, _ := certs(t, dir, "applier")
	serverCA, _, _, _, serverLeaf := certs(t, t.TempDir(), "localhost")
	var h http.HandlerFunc = func(http.ResponseWriter, *http.Request) {}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(w, r) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverLeaf}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(dir, "roid-ca.pem")
	_ = os.WriteFile(caFile, serverCA, 0o600)
	c := &applier.HTTPRoid{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Account: "acct-a",
		CertFile: certFile, KeyFile: keyFile, CAFile: caFile}
	return c, func(f http.HandlerFunc) { h = f }
}
