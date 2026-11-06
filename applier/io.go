package applier

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
)

// ConfigMaps is the part of the cluster the floor needs (kubeapi.Client
// and reconcile.Kubectl with ServerSide set implement it).
type ConfigMaps interface {
	Get(ctx context.Context, kind, ns, name string) (kobj.Object, bool, error)
	// Create writes the object with a server-side apply.
	Create(ctx context.Context, o kobj.Object) error
}

// ConfigMapFloor keeps the floor in one ConfigMap in the applier's own
// namespace, so it survives pod restarts and reschedules. The applier's
// RBAC lets it write ConfigMaps there and in the runos namespace only.
type ConfigMapFloor struct {
	Kube      ConfigMaps
	Namespace string
	Name      string
}

// Load reads the ConfigMap; a missing one means no floor yet.
func (f ConfigMapFloor) Load(ctx context.Context) (bundle.Floor, bool, error) {
	cm, ok, err := f.Kube.Get(ctx, kobj.KindConfigMap, f.Namespace, f.Name)
	if err != nil || !ok {
		return bundle.Floor{}, false, err
	}
	v, err := strconv.ParseUint(cm.Data["version"], 10, 64)
	if err != nil {
		return bundle.Floor{}, false, fmt.Errorf("floor configmap: version: %w", err)
	}
	return bundle.Floor{Version: v, Digest: cm.Data["digest"], Retired: cm.Data["retired"] == "true"}, true, nil
}

// Store writes the ConfigMap with a server-side apply. The retired mark
// is written only when set; the apply removes it otherwise.
func (f ConfigMapFloor) Store(ctx context.Context, fl bundle.Floor) error {
	data := map[string]string{"version": strconv.FormatUint(fl.Version, 10), "digest": fl.Digest}
	if fl.Retired {
		data["retired"] = "true"
	}
	return f.Kube.Create(ctx, kobj.Object{Kind: kobj.KindConfigMap, Namespace: f.Namespace, Name: f.Name, Data: data})
}

// ConfigMapKeySets keeps the root-signed policy-bundle key set in one
// ConfigMap next to the floor, so a restart keeps a compromise reset.
type ConfigMapKeySets struct {
	Kube      ConfigMaps
	Namespace string
	Name      string
}

// Load reads the stored key set; a missing ConfigMap means none yet.
func (k ConfigMapKeySets) Load(ctx context.Context) (string, bool, error) {
	cm, ok, err := k.Kube.Get(ctx, kobj.KindConfigMap, k.Namespace, k.Name)
	if err != nil || !ok {
		return "", false, err
	}
	return cm.Data["policy-bundle"], true, nil
}

// Store writes the key set.
func (k ConfigMapKeySets) Store(ctx context.Context, signed string) error {
	return k.Kube.Create(ctx, kobj.Object{Kind: kobj.KindConfigMap, Namespace: k.Namespace, Name: k.Name,
		Data: map[string]string{"policy-bundle": signed}})
}

// HTTPRoid talks to roid's service listener with the cluster's
// service certificate. It reads the certificate files on every call, so a
// renewal written by the certificate client needs no restart.
type HTTPRoid struct {
	BaseURL  string
	Account  string
	CertFile string
	KeyFile  string
	// CAFile is the CA bundle that roid's service listener certificate
	// chains to.
	CAFile  string
	Timeout time.Duration
	// ClientCert, when set, hands out the certificate instead of the files:
	// the service certificate client that enrolled with the pod's service
	// account token and renews in memory (the key never touches a disk).
	ClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

func (c *HTTPRoid) client() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if c.ClientCert != nil {
		tc.GetClientCertificate = c.ClientCert
	} else {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("service certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("roid CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("roid CA bundle: no certificate")
	}
	to := c.Timeout
	if to == 0 {
		to = 20 * time.Second
	}
	tc.RootCAs = pool
	// No redirects: only roid's own answer at its own address may count
	// toward the fail-safe. A 3xx is an unreachable roid.
	return &http.Client{Timeout: to, Transport: &http.Transport{TLSClientConfig: tc},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// KeySet returns the newest root-signed key set of purpose that roid
// serves, or "" when the root signed none yet.
func (c *HTTPRoid) KeySet(ctx context.Context, purpose string) (string, error) {
	cl, err := c.client()
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/v1/keysets/"+url.PathEscape(purpose), nil)
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("key set: roid answered %d", resp.StatusCode)
	}
	var body struct {
		Signed string `json:"signed"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	return body.Signed, nil
}

// maxBundle bounds a bundle body.
const maxBundle = 8 << 20

// Fetch gets the bundle envelope.
func (c *HTTPRoid) Fetch(ctx context.Context, namespaces []string, fresh bool) ([]byte, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}
	q := url.Values{"account": {c.Account}, "ns": {strings.Join(namespaces, ",")}}
	if fresh {
		q.Set("fresh", "1")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/v1/k8s/bundle?"+q.Encode(), nil)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundle+1))
	if err != nil {
		return nil, err
	}
	if code, reason := refusal(body); resp.StatusCode == http.StatusForbidden && code == "k8s.not_allowed" && (reason == "cluster" || reason == "retired") {
		// roid, over the pinned TLS, says it does not serve this applier
		// for this cluster. Only this answer counts toward the
		// fail-safe. A refusal with another reason (or none, as for a
		// service name missing from ROID_K8S_SERVICES) is a roid
		// configuration slip and counts as unreachable.
		return nil, fmt.Errorf("%w: roid answered 403: %s", ErrRoidRefused, bytes.TrimSpace(body))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("roid answered %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	if len(body) > maxBundle {
		return nil, errors.New("bundle too large")
	}
	return body, nil
}

// Report posts one pass result.
func (c *HTTPRoid) Report(ctx context.Context, s Status) error {
	cl, err := c.client()
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	q := url.Values{"account": {c.Account}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/v1/k8s/status?"+q.Encode(), bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("roid answered %d to the status report", resp.StatusCode)
	}
	return nil
}

// refusal reads the error code and reason of a roid error body.
func refusal(body []byte) (code, reason string) {
	var e struct {
		Error struct {
			Code   string `json:"code"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "", ""
	}
	return e.Error.Code, e.Error.Reason
}
