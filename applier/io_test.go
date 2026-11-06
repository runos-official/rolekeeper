package applier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
)

// memCM is an in-memory API server for one ConfigMap.
type memCM struct{ cm *kobj.Object }

func (m *memCM) Get(_ context.Context, kind, ns, name string) (kobj.Object, bool, error) {
	if m.cm == nil || kind != kobj.KindConfigMap || m.cm.Namespace != ns || m.cm.Name != name {
		return kobj.Object{}, false, nil
	}
	return m.cm.Clone(), true, nil
}

func (m *memCM) Create(_ context.Context, o kobj.Object) error {
	c := o.Clone()
	m.cm = &c
	return nil
}

func TestConfigMapFloorSurvivesARestart(t *testing.T) {
	ex := &memCM{}
	f := applier.ConfigMapFloor{Kube: ex, Namespace: "roid-applier", Name: "roid-rbac-floor"}
	if _, ok, err := f.Load(context.Background()); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	if err := f.Store(context.Background(), bundle.Floor{Version: 7, Digest: "d7"}); err != nil {
		t.Fatal(err)
	}
	again := applier.ConfigMapFloor{Kube: ex, Namespace: "roid-applier", Name: "roid-rbac-floor"}
	got, ok, err := again.Load(context.Background())
	if err != nil || !ok || got.Version != 7 || got.Digest != "d7" {
		t.Fatalf("after restart: %+v ok=%v err=%v", got, ok, err)
	}
	if ex.cm.Kind != kobj.KindConfigMap || ex.cm.Data["version"] != "7" {
		t.Fatalf("stored object: %+v", ex.cm)
	}
}

// selfSigned writes a CA and a leaf signed by it, and returns the paths.
func certs(t *testing.T, dir, cn string) (caPEM []byte, certFile, keyFile string, pool *x509.CertPool, leaf tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn + "-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"127.0.0.1", cn},
		IPAddresses: nil, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	kder, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool = x509.NewCertPool()
	pool.AddCert(ca)
	leaf, _ = tls.LoadX509KeyPair(certFile, keyFile)
	return
}

// The client presents its service certificate on every call, reads the
// cert files again each call (a renewal needs no restart), sends the
// managed namespaces and the fresh flag, and posts the status.
func TestRoidClientUsesTheServiceCertificate(t *testing.T) {
	dir := t.TempDir()
	clientCA, certFile, keyFile, clientPool, _ := certs(t, dir, "applier")
	_ = clientCA
	serverCA, _, _, _, serverLeaf := certs(t, t.TempDir(), "localhost")
	var gotQuery string
	var gotStatus applier.Status
	var peers []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers = append(peers, r.TLS.PeerCertificates[0].Subject.CommonName)
		switch r.URL.Path {
		case "/v1/k8s/bundle":
			gotQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"bundle":"x","body":"eyJ9"}`))
		case "/v1/k8s/status":
			_ = json.NewDecoder(r.Body).Decode(&gotStatus)
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverLeaf}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(dir, "roid-ca.pem")
	_ = os.WriteFile(caFile, serverCA, 0o600)
	c := &applier.HTTPRoid{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Account: "acct-a",
		CertFile: certFile, KeyFile: keyFile, CAFile: caFile}
	if _, err := c.Fetch(context.Background(), []string{"apps", "web"}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "account=acct-a") || !strings.Contains(gotQuery, "ns=apps%2Cweb") || !strings.Contains(gotQuery, "fresh=1") {
		t.Fatalf("query: %s", gotQuery)
	}
	if err := c.Report(context.Background(), applier.Status{Version: 3, Applied: true}); err != nil {
		t.Fatal(err)
	}
	if gotStatus.Version != 3 || len(peers) != 2 || peers[0] != "applier" {
		t.Fatalf("status %+v peers %v", gotStatus, peers)
	}
}
