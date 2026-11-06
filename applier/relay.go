package applier

// The relay transport. The applier reads its bundle, key set and signed
// refusal from ConfigMaps in its own namespace, through the Kubernetes API,
// and writes its status to a ConfigMap. Conductor carries the bytes between
// roid and those ConfigMaps. Nothing here trusts the carrier: every byte
// the applier acts on is signed by roid and checked against the pinned
// trust.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/kubeapi"
)

// Keys of the relay ConfigMaps.
const (
	keyToken    = "token"
	keyBodyGz   = "body.gz"
	keyFresh    = "fresh"
	keyKeySet   = "keyset.policy-bundle"
	keyRefusal  = "refusal.jwt"
	keyStatus   = "status.json"
	statusLimit = 60 << 10 // conductor rejects a status above 64 KiB
)

// RelayKube is what the relay needs from the cluster: the ConfigMaps by
// name, a metadata-only read, and a server-side apply for the status.
type RelayKube interface {
	Get(ctx context.Context, kind, ns, name string) (kobj.Object, bool, error)
	Create(ctx context.Context, o kobj.Object) error
	Metadata(ctx context.Context, kind, ns, name string) (kubeapi.Meta, bool, error)
}

// Revision is the resourceVersion of the bundle and relay ConfigMaps.
// A change in either starts a pass at once. "" means the ConfigMap is
// not there.
type Revision struct{ Bundle, Relay string }

// RelayInfo is what the relay status carries beyond Status. The
// applier fills it; ConfigMapRoid writes it.
type RelayInfo struct {
	NeedsFresh bool
	FreshNonce string
	Namespaces []string
	Lagging    bool
	// VerifyError is the class of the last verify failure (not_yet_valid,
	// expired, digest_mismatch, ...), empty after a verified envelope.
	VerifyError        string
	SeenEnvelopeSHA256 string
	LastIssuedAt       time.Time
}

// RelayRoid is a Roid that lives in the cluster. The applier runs the relay
// pass when its Roid implements it.
type RelayRoid interface {
	Roid
	KeySetSource
	// Revision reads the metadata of the bundle and relay ConfigMaps.
	Revision(ctx context.Context) (Revision, error)
	// FetchedRevision is the resourceVersion of the bundle ConfigMap as the
	// last Fetch read it.
	FetchedRevision() string
	// FreshToken is the fresh token that came with the last Fetch, or "".
	FreshToken() string
	// Nonce is this process's fresh-start nonce, made on first use.
	Nonce() string
	// Refusal returns the reason of a signed refusal that verifies and has
	// not expired, or "". Anything else in the marker is ignored.
	Refusal(ctx context.Context) (string, error)
	// SetInfo sets the relay fields of the next status write.
	SetInfo(RelayInfo)
}

// RelayStatus is status.json. Everything in it is advice to conductor.
type RelayStatus struct {
	Format             int        `json:"format"`
	Account            string     `json:"account"`
	Cluster            string     `json:"cluster"`
	ApplierVersion     string     `json:"applier_version"`
	TrustSHA256        string     `json:"trust_sha256"`
	StartedAt          time.Time  `json:"started_at"`
	Seq                uint64     `json:"seq"`
	WrittenAt          time.Time  `json:"written_at"`
	NeedsFresh         bool       `json:"needs_fresh"`
	FreshNonce         string     `json:"fresh_nonce,omitempty"`
	Namespaces         []string   `json:"namespaces"`
	Lagging            bool       `json:"lagging"`
	VerifyError        string     `json:"verify_error"`
	SeenEnvelopeSHA256 string     `json:"seen_envelope_sha256"`
	LastIssuedAt       *time.Time `json:"last_issued_at,omitempty"`
	BundleAgeS         int64      `json:"bundle_age_s"`
	Status             Status     `json:"status"`
}

// ErrNoBundle means the bundle ConfigMap is not complete: it is missing, or
// the token or the body is. It is the unreachable class: it counts for
// nothing and resets nothing.
var ErrNoBundle = errors.New("relay: no complete bundle in the ConfigMap yet")

// ConfigMapRoid is the relay Roid.
type ConfigMapRoid struct {
	Kube RelayKube
	// Verifier checks the signed refusal. It is the verifier the applier
	// uses for bundles, so both read the same pinned key set.
	Verifier  *bundle.Verifier
	Namespace string
	// BundleName, RelayName and StatusName default to roid-rbac-bundle,
	// roid-rbac-relay and roid-rbac-status.
	BundleName, RelayName, StatusName string
	// Account, Cluster and TrustSHA256 are what conductor installed; the
	// status echoes them and conductor compares.
	Account, Cluster, TrustSHA256, Version string
	Started                                time.Time
	Now                                    func() time.Time

	seq       uint64
	nonce     string
	info      RelayInfo
	fetchedRV string
	fresh     string
	relayRV   string
	relay     kobj.Object
}

func (c *ConfigMapRoid) name(n *string, def string) string {
	if *n == "" {
		return def
	}
	return *n
}

func (c *ConfigMapRoid) bundleName() string { return c.name(&c.BundleName, "roid-rbac-bundle") }
func (c *ConfigMapRoid) relayName() string  { return c.name(&c.RelayName, "roid-rbac-relay") }
func (c *ConfigMapRoid) statusName() string { return c.name(&c.StatusName, "roid-rbac-status") }

func (c *ConfigMapRoid) meta(ctx context.Context, name string) (string, error) {
	m, ok, err := c.Kube.Metadata(ctx, kobj.KindConfigMap, c.Namespace, name)
	if err != nil || !ok {
		return "", err
	}
	return m.ResourceVersion, nil
}

// Revision reads the metadata of the two ConfigMaps the relay writes.
func (c *ConfigMapRoid) Revision(ctx context.Context) (Revision, error) {
	b, err := c.meta(ctx, c.bundleName())
	if err != nil {
		return Revision{}, err
	}
	r, err := c.meta(ctx, c.relayName())
	if err != nil {
		return Revision{}, err
	}
	return Revision{Bundle: b, Relay: r}, nil
}

// FetchedRevision is the resourceVersion of the bundle read by Fetch.
func (c *ConfigMapRoid) FetchedRevision() string { return c.fetchedRV }

// FreshToken is the fresh token read together with the bundle.
func (c *ConfigMapRoid) FreshToken() string { return c.fresh }

// Nonce returns this process's nonce (16 random bytes, base64url).
func (c *ConfigMapRoid) Nonce() string {
	if c.nonce == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("relay: no randomness: " + err.Error())
		}
		c.nonce = base64.RawURLEncoding.EncodeToString(b[:])
	}
	return c.nonce
}

// SetInfo sets the relay fields of the next write.
func (c *ConfigMapRoid) SetInfo(i RelayInfo) { c.info = i }

// loadRelay returns the relay ConfigMap, read again only when its
// resourceVersion moved.
func (c *ConfigMapRoid) loadRelay(ctx context.Context) (kobj.Object, bool, error) {
	rv, err := c.meta(ctx, c.relayName())
	if err != nil {
		return kobj.Object{}, false, err
	}
	if rv == "" {
		c.relayRV, c.relay = "", kobj.Object{}
		return kobj.Object{}, false, nil
	}
	if rv == c.relayRV {
		return c.relay, true, nil
	}
	o, ok, err := c.Kube.Get(ctx, kobj.KindConfigMap, c.Namespace, c.relayName())
	if err != nil || !ok {
		return kobj.Object{}, false, err
	}
	c.relayRV, c.relay = o.ResourceVersion, o
	return o, true, nil
}

// KeySet returns the root-signed key set the relay ConfigMap holds, or "".
// The verifier accepts it only if the pinned root signed it and it is not
// older than the set the verifier holds.
func (c *ConfigMapRoid) KeySet(ctx context.Context, purpose string) (string, error) {
	if purpose != "policy-bundle" {
		return "", nil
	}
	o, ok, err := c.loadRelay(ctx)
	if err != nil || !ok {
		return "", err
	}
	return o.Data[keyKeySet], nil
}

// Refusal returns the reason of roid's signed refusal in the relay
// ConfigMap when it verifies under the pinned key set (signature, audience,
// account, class) and has not expired. A marker that fails any of it is
// ignored, as if it were not there.
func (c *ConfigMapRoid) Refusal(ctx context.Context) (string, error) {
	o, ok, err := c.loadRelay(ctx)
	if err != nil || !ok || o.Data[keyRefusal] == "" {
		return "", err
	}
	reason, err := c.Verifier.VerifyRefusal(o.Data[keyRefusal])
	if err != nil {
		return "", nil
	}
	return reason, nil
}

// Fetch refuses with ErrRoidRefused while a signed refusal stands. Otherwise
// it reads the bundle ConfigMap and returns the envelope as roid served it.
// The namespaces and the fresh flag are for the pull transport; here the
// applier passes the namespaces to the status through SetInfo.
func (c *ConfigMapRoid) Fetch(ctx context.Context, _ []string, _ bool) ([]byte, error) {
	reason, err := c.Refusal(ctx)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, fmt.Errorf("%w: signed refusal: %s", ErrRoidRefused, reason)
	}
	o, ok, err := c.Kube.Get(ctx, kobj.KindConfigMap, c.Namespace, c.bundleName())
	if err != nil {
		return nil, err
	}
	tok, gz := o.Data[keyToken], o.BinaryData[keyBodyGz]
	if !ok || tok == "" || len(gz) == 0 {
		return nil, ErrNoBundle
	}
	raw, err := bundle.RebuildEnvelope(tok, gz)
	if err != nil {
		return nil, err
	}
	c.fetchedRV, c.fresh = o.ResourceVersion, o.Data[keyFresh]
	return raw, nil
}

// Report writes status.json with a server-side apply. A failed write is
// tried again at the next pass.
func (c *ConfigMapRoid) Report(ctx context.Context, s Status) error {
	now := c.Now()
	c.seq++
	i := c.info
	rs := RelayStatus{Format: 1, Account: c.Account, Cluster: c.Cluster, ApplierVersion: c.Version, TrustSHA256: c.TrustSHA256,
		StartedAt: c.Started.UTC(), Seq: c.seq, WrittenAt: now.UTC(), NeedsFresh: i.NeedsFresh,
		Namespaces: slices.Clone(i.Namespaces), Lagging: i.Lagging, VerifyError: i.VerifyError,
		SeenEnvelopeSHA256: i.SeenEnvelopeSHA256, Status: s}
	if rs.Namespaces == nil {
		rs.Namespaces = []string{}
	}
	if i.NeedsFresh {
		rs.FreshNonce = i.FreshNonce
	}
	if !i.LastIssuedAt.IsZero() {
		t := i.LastIssuedAt.UTC()
		rs.LastIssuedAt = &t
		rs.BundleAgeS = max(int64(now.Sub(i.LastIssuedAt).Seconds()), 0)
	}
	raw, err := json.Marshal(rs)
	if err == nil && len(raw) > statusLimit {
		// Keep the file under the limit conductor reads: the error text and
		// the namespaces are the only things that can grow.
		rs.Namespaces = []string{}
		if len(rs.Status.Error) > 1000 {
			rs.Status.Error = rs.Status.Error[:1000]
		}
		raw, err = json.Marshal(rs)
	}
	if err != nil {
		return err
	}
	return c.Kube.Create(ctx, kobj.Object{Kind: kobj.KindConfigMap, Namespace: c.Namespace, Name: c.statusName(),
		Data: map[string]string{keyStatus: string(raw)}})
}
