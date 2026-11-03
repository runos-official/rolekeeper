// Package bundle is the signed per-cluster RBAC bundle: what roid compiles
// from an account's groups and grants for one cluster, and what the
// in-cluster applier verifies before it applies anything.
//
// The bundle travels as an envelope: the JSON body and a policy-bundle
// token whose id is the SHA-256 of the body. The token's subject, class and
// audience name an RBAC bundle for one cluster, so a gate projection signed
// with the same key never verifies as an RBAC bundle. Versions only go up:
// the applier keeps a durable floor and refuses an older bundle, and a
// bundle at the same version with other content.
package bundle

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/kobj"
	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

// Format is the body format this package reads and writes.
const Format = 1

// Token fields that mark an RBAC bundle.
const (
	Subject = "k8s-rbac-bundle"
	Class   = "k8s-rbac-bundle"
)

// Audience is the token audience of one cluster's bundle.
func Audience(cluster string) string { return "k8s-rbac:" + cluster }

// Bundle is the body: everything the applier needs for one pass.
type Bundle struct {
	Format  int    `json:"format"`
	Account string `json:"account"`
	Cluster string `json:"cluster"`
	// Version is the bundle version of this cluster. It goes up whenever
	// the content changes (policy, deny list or managed namespaces).
	Version uint64 `json:"version"`
	// PolicyVersion is the compiled policy version label (pv-<n>).
	PolicyVersion string `json:"policy_version"`
	// Namespaces are the managed namespaces roid compiled for.
	Namespaces []string      `json:"namespaces"`
	Objects    []kobj.Object `json:"objects"`
	// DenyOnly is true when roid refused the projection: Objects holds only
	// the deny list, and the applier must remove nothing else.
	DenyOnly bool `json:"deny_only,omitempty"`
	// Retire is true when the cluster left the account, or the account
	// closed. Objects holds only the deny list. The applier removes
	// every object it manages, reports, and stops.
	Retire bool `json:"retire,omitempty"`
	// TooLarge says the full bundle would pass roid's size rule
	// and roid published the deny list alone. It always comes with DenyOnly
	// set. An applier that does not know the field treats the bundle as
	// deny-only, which is safe; one that knows it does the same.
	TooLarge bool      `json:"too_large,omitempty"`
	Skipped  []string  `json:"skipped,omitempty"`
	IssuedAt time.Time `json:"issued_at"`
}

// Envelope is the wire form.
type Envelope struct {
	Bundle string `json:"bundle"`
	Body   []byte `json:"body"`
}

// Errors.
var (
	ErrFormat  = errors.New("bundle: bad_format")
	ErrSubject = errors.New("bundle: not_an_rbac_bundle")
	ErrDigest  = errors.New("bundle: digest_mismatch")
	ErrCluster = errors.New("bundle: wrong_cluster")
	ErrAccount = errors.New("bundle: wrong_account")
	ErrStale   = errors.New("bundle: stale")
)

// Seal signs b with the policy-bundle key of issuer. The token lives ttl.
func Seal(ctx context.Context, issuer *token.Issuer, b Bundle, ttl time.Duration) ([]byte, error) {
	if b.Format == 0 {
		b.Format = Format
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	tok, err := issuer.Issue(ctx, signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: Subject, ID: hex.EncodeToString(sum[:]), Audience: jwt.Audience{Audience(b.Cluster)}},
		Class:  Class, Account: b.Account,
	}, ttl)
	if err != nil {
		return nil, fmt.Errorf("bundle: sign: %w", err)
	}
	return json.Marshal(Envelope{Bundle: tok, Body: body})
}

// Trust is what the applier pins: the issuer, its cluster, the offline
// root public key and the root-signed policy-bundle key set.
type Trust struct {
	Issuer        string           `json:"issuer"`
	Cluster       string           `json:"cluster"`
	RootPublicDER []byte           `json:"root_public_der"`
	RootAlg       signer.Algorithm `json:"root_alg"`
	// RootChain is the root chain file (root.chain.json): the
	// handovers from the pinned root. Empty: only the pinned root signs.
	RootChain  json.RawMessage `json:"root_chain,omitempty"`
	BundleKeys keys.Doc        `json:"bundle_keys"`
}

// Verifier checks envelopes for one cluster.
type Verifier struct {
	cluster string
	account string // ExpectAccount; "" checks no account
	tok     *token.Verifier
	view    *keys.View
}

// NewVerifier builds a verifier from trust. The key set must verify under
// the root key, or NewVerifier fails.
//
// statePath keeps the highest root chain this verifier accepted, so a
// restart with an older trust file keeps it. Required.
func NewVerifier(trust Trust, now func() time.Time, statePath string) (*Verifier, error) {
	if trust.Cluster == "" || trust.Issuer == "" {
		return nil, fmt.Errorf("%w: trust needs an issuer and a cluster", ErrFormat)
	}
	pin, err := roottrust.PinDER(trust.RootAlg, trust.RootPublicDER)
	if err != nil {
		return nil, fmt.Errorf("bundle: root key: %w", err)
	}
	roots, err := roottrust.Load(roottrust.Config{Pin: pin, Chain: trust.RootChain, StatePath: statePath, Now: now})
	if err != nil {
		return nil, fmt.Errorf("bundle: root chain: %w", err)
	}
	// The key set is durable too, so a restart keeps the
	// set it holds and the root that signed it (precedence).
	view, err := keys.NewViewRoots(signer.PurposePolicyBundle, roots, trust.BundleKeys, statePath+".bundle-keys")
	if err != nil {
		return nil, fmt.Errorf("bundle: key set: %w", err)
	}
	return &Verifier{cluster: trust.Cluster, view: view, tok: &token.Verifier{Purpose: signer.PurposePolicyBundle, Issuer: trust.Issuer,
		Audience: Audience(trust.Cluster), Classes: []string{Class, relayClassFresh, relayClassRefusal}, Keys: view, Now: now}}, nil
}

// ExpectAccount makes Verify refuse a bundle of any account but acct
// (ErrAccount): the applier's ROID_K8S_ACCOUNT. Call it before the first
// Verify; it is not safe for concurrent use with Verify.
func (v *Verifier) ExpectAccount(acct string) { v.account = acct }

// UpdateKeys applies a root-signed policy-bundle key set newer than the
// one the verifier holds: a publish ceremony adds the next key, a
// compromise reset removes one.
func (v *Verifier) UpdateKeys(signed string) error { return v.view.Update(signed) }

// RootHealth is the root state of the policy-bundle key set:
// EndsSoon means the new root must re-sign it before the old root's
// overlap ends.
func (v *Verifier) RootHealth() roottrust.Health { return v.view.RootHealth() }

// KeySet is the root-signed key set the verifier last accepted, or "" when
// it holds only the install pin.
func (v *Verifier) KeySet() string { return v.view.Signed() }

// Verified is a bundle whose token, digest and cluster checked out.
type Verified struct {
	Bundle   Bundle
	Digest   string
	IssuedAt time.Time
	Expires  time.Time
}

// Verify checks raw: the token under the pinned key set, the subject, the
// body digest, the format and the cluster. It does not check the floor.
func (v *Verifier) Verify(raw []byte) (Verified, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Bundle == "" || len(env.Body) == 0 {
		return Verified{}, fmt.Errorf("%w: envelope", ErrFormat)
	}
	claims, err := v.tok.Verify(env.Bundle)
	if err != nil {
		return Verified{}, fmt.Errorf("bundle: token: %w", err)
	}
	// The verifier also accepts the fresh and refusal classes (same key,
	// same audience). Neither is a bundle.
	if claims.Class != Class || claims.Subject != Subject {
		return Verified{}, ErrSubject
	}
	sum := sha256.Sum256(env.Body)
	dig := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(dig), []byte(claims.ID)) != 1 {
		return Verified{}, ErrDigest
	}
	var b Bundle
	if err := json.Unmarshal(env.Body, &b); err != nil {
		return Verified{}, fmt.Errorf("%w: body", ErrFormat)
	}
	if b.Format != Format || b.Account == "" || b.Account != claims.Account || b.Version == 0 {
		return Verified{}, ErrFormat
	}
	if b.Cluster != v.cluster {
		return Verified{}, ErrCluster
	}
	for _, o := range b.Objects {
		// binaryData belongs to live ConfigMaps. No compiled object has it.
		if len(o.BinaryData) > 0 {
			return Verified{}, fmt.Errorf("%w: %s carries binaryData", ErrFormat, o.Key())
		}
	}
	if v.account != "" && b.Account != v.account {
		return Verified{}, ErrAccount
	}
	out := Verified{Bundle: b, Digest: ContentDigest(b)}
	if claims.IssuedAt != nil {
		out.IssuedAt = claims.IssuedAt.Time()
	}
	if claims.Expiry != nil {
		out.Expires = claims.Expiry.Time()
	}
	return out, nil
}

// ContentDigest is the digest of a bundle's content: the body with the
// issue time cleared, so a re-signed copy of the same content compares
// equal and only a content change needs a new version.
func ContentDigest(b Bundle) string {
	b.IssuedAt = time.Time{}
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Floor is the newest bundle an applier applied.
type Floor struct {
	Version uint64 `json:"version"`
	Digest  string `json:"digest"`
	// Retired says the applier removed everything it manages and
	// stopped: a retire bundle, or the local fail-safe.
	Retired bool `json:"retired,omitempty"`
}

// FloorStore keeps the floor across restarts.
type FloorStore interface {
	// Load returns the floor; ok is false when none was ever stored.
	Load(ctx context.Context) (f Floor, ok bool, err error)
	Store(ctx context.Context, f Floor) error
}

// CheckFloor refuses a version below the stored floor, and the floor's
// version with other content. A store that cannot be read refuses too.
func CheckFloor(ctx context.Context, s FloorStore, version uint64, digest string) error {
	f, ok, err := s.Load(ctx)
	if err != nil {
		return fmt.Errorf("bundle: floor unreadable, nothing applied: %w", err)
	}
	if !ok {
		return nil
	}
	return CheckFloorValue(f, version, digest)
}

// CheckFloorValue refuses a version below f, and f's version with other
// content.
func CheckFloorValue(f Floor, version uint64, digest string) error {
	switch {
	case version < f.Version:
		return fmt.Errorf("%w: v%d is below the floor v%d", ErrStale, version, f.Version)
	case version == f.Version && digest != f.Digest:
		return fmt.Errorf("%w: v%d content differs from the applied v%d", ErrStale, version, f.Version)
	}
	return nil
}

// FileFloor keeps the floor in a file (tests and out-of-cluster runs).
type FileFloor struct{ Path string }

// Load reads the file.
func (f FileFloor) Load(_ context.Context) (Floor, bool, error) {
	raw, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Floor{}, false, nil
	}
	if err != nil {
		return Floor{}, false, err
	}
	var fl Floor
	if err := json.Unmarshal(raw, &fl); err != nil {
		return Floor{}, false, err
	}
	return fl, true, nil
}

// Store writes the file atomically.
func (f FileFloor) Store(_ context.Context, fl Floor) error {
	raw, _ := json.Marshal(fl)
	tmp := filepath.Join(filepath.Dir(f.Path), "."+filepath.Base(f.Path)+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}
