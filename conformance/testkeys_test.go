package conformance_test

// TEST-ONLY keys. Every private key in the vectors comes from a seed that
// anybody can compute: SHA-256 of "rolekeeper-conformance-v1/TEST-ONLY/" and
// a label. They exist to make the vectors byte-for-byte reproducible, and a
// verifier must never trust one outside these tests. docs/conformance.md
// lists the labels, so the signing side can derive the same keys.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/runos-official/rolekeeper/signer"
)

const seedPrefix = "rolekeeper-conformance-v1/TEST-ONLY/"

// Labels of the test keys.
const (
	labelRoot        = "root"         // the offline root that the trust pins
	labelOtherRoot   = "other-root"   // a root that nobody pinned
	labelBundleKey   = "bundle-1"     // the active policy-bundle key
	labelBundleNext  = "bundle-2"     // the standby policy-bundle key
	labelForgedKey   = "forged"       // a key that signs under the id of bundle-1
	labelStrangerKey = "stranger"     // a key that nobody published
	labelStrangerNxt = "stranger-two" // the standby of the stranger
)

func seedFor(label string) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte(seedPrefix + label))
	return ed25519.NewKeyFromSeed(sum[:])
}

// keyID is the id a test key has in custody and in the key set.
func keyID(label string) string { return "conformance-test-only-" + label }

type fixedKey struct {
	id       string
	priv     ed25519.PrivateKey
	info     signer.KeyInfo
	disabled bool
}

// fixedBackend is a custody backend whose keys are the test keys, handed out
// in the order of its list. EdDSA signatures are deterministic, so a token
// signed here is the same bytes on every run.
type fixedBackend struct {
	mu      sync.Mutex
	order   []*fixedKey
	next    int
	byID    map[string]*fixedKey
	created time.Time
}

// keySpec names a test key and the id it has in custody.
type keySpec struct{ id, label string }

func spec(label string) keySpec { return keySpec{id: keyID(label), label: label} }

// newFixedBackend returns a backend that creates the given keys, one per
// CreateKey call, in that order.
func newFixedBackend(created time.Time, specs ...keySpec) *fixedBackend {
	b := &fixedBackend{byID: map[string]*fixedKey{}, created: created}
	for _, sp := range specs {
		b.order = append(b.order, &fixedKey{id: sp.id, priv: seedFor(sp.label)})
	}
	return b
}

func (b *fixedBackend) CreateKey(_ context.Context, purpose signer.Purpose, alg signer.Algorithm) (signer.KeyInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if alg != signer.AlgEdDSA {
		return signer.KeyInfo{}, signer.ErrUnsupportedAlgorithm
	}
	if b.next >= len(b.order) {
		return signer.KeyInfo{}, fmt.Errorf("fixedBackend: no key left for %s", purpose)
	}
	k := b.order[b.next]
	b.next++
	der, err := x509.MarshalPKIXPublicKey(k.priv.Public())
	if err != nil {
		return signer.KeyInfo{}, err
	}
	k.info = signer.KeyInfo{ID: k.id, Purpose: purpose, Algorithm: signer.AlgEdDSA, PublicDER: der, CreatedAt: b.created, Custody: "conformance-test-only"}
	b.byID[k.id] = k
	return k.info, nil
}

func (b *fixedBackend) PublicKey(_ context.Context, id string) (signer.KeyInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.byID[id]
	if !ok {
		return signer.KeyInfo{}, signer.ErrUnknownKey
	}
	return k.info, nil
}

func (b *fixedBackend) Sign(_ context.Context, req signer.SignRequest) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.byID[req.KeyID]
	if !ok {
		return nil, signer.ErrUnknownKey
	}
	if req.Purpose != k.info.Purpose {
		return nil, signer.ErrWrongPurpose
	}
	if k.disabled {
		return nil, signer.ErrKeyDisabled
	}
	if err := signer.CheckDigest(k.info.Algorithm, req.Digest, req.Hash); err != nil {
		return nil, err
	}
	return k.priv.Sign(nil, req.Digest, crypto.Hash(0))
}

func (b *fixedBackend) DisableKey(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.byID[id]
	if !ok {
		return signer.ErrUnknownKey
	}
	k.disabled = true
	return nil
}
