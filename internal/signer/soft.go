package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SoftBackend keeps keys in process memory. It is for tests and for the
// signerd process only. It never returns private material.
type SoftBackend struct {
	mu      sync.Mutex
	keys    map[string]*softKey
	offline bool // true: only the keyset-root purpose
	custody string
	signs   atomic.Int64
	down    atomic.Bool
	now     func() time.Time
}

type softKey struct {
	info     KeyInfo
	priv     crypto.Signer
	disabled bool
}

// NewSoftBackend returns an online backend for the seven online purposes.
func NewSoftBackend() *SoftBackend {
	return &SoftBackend{keys: map[string]*softKey{}, custody: "soft", now: time.Now}
}

// NewOfflineRootBackend simulates the offline, two-person root custody. It
// accepts only PurposeKeySetRoot.
func NewOfflineRootBackend() *SoftBackend {
	return &SoftBackend{keys: map[string]*softKey{}, offline: true, custody: "offline-root-sim", now: time.Now}
}

// SetCustody changes the provenance label (signerd uses "signerd/soft").
func (b *SoftBackend) SetCustody(c string) { b.custody = c }

// SignCount is the number of signatures made, for tests that prove a
// verifier never calls the signer.
func (b *SoftBackend) SignCount() int64 { return b.signs.Load() }

// SetDown simulates a signer outage: every call returns ErrUnavailable.
func (b *SoftBackend) SetDown(down bool) { b.down.Store(down) }

func (b *SoftBackend) purposeAllowed(p Purpose) bool {
	if !p.Valid() {
		return false
	}
	if b.offline {
		return p == PurposeKeySetRoot
	}
	return p != PurposeKeySetRoot
}

func (b *SoftBackend) CreateKey(_ context.Context, purpose Purpose, alg Algorithm) (KeyInfo, error) {
	if b.down.Load() {
		return KeyInfo{}, ErrUnavailable
	}
	if !b.purposeAllowed(purpose) {
		return KeyInfo{}, fmt.Errorf("%w: backend does not hold %q keys", ErrWrongPurpose, purpose)
	}
	var priv crypto.Signer
	switch alg {
	case AlgEdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyInfo{}, err
		}
		priv = k
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return KeyInfo{}, err
		}
		priv = k
	default:
		return KeyInfo{}, ErrUnsupportedAlgorithm
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return KeyInfo{}, err
	}
	var rnd [10]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return KeyInfo{}, err
	}
	info := KeyInfo{
		ID:        string(purpose) + "-" + hex.EncodeToString(rnd[:]),
		Purpose:   purpose,
		Algorithm: alg,
		PublicDER: der,
		CreatedAt: b.now().UTC(),
		Custody:   b.custody,
	}
	b.mu.Lock()
	b.keys[info.ID] = &softKey{info: info, priv: priv}
	b.mu.Unlock()
	return info, nil
}

func (b *SoftBackend) get(id string) (*softKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.keys[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	return k, nil
}

func (b *SoftBackend) PublicKey(_ context.Context, keyID string) (KeyInfo, error) {
	if b.down.Load() {
		return KeyInfo{}, ErrUnavailable
	}
	k, err := b.get(keyID)
	if err != nil {
		return KeyInfo{}, err
	}
	return k.info, nil
}

func (b *SoftBackend) Sign(_ context.Context, req SignRequest) ([]byte, error) {
	if b.down.Load() {
		return nil, ErrUnavailable
	}
	k, err := b.get(req.KeyID)
	if err != nil {
		return nil, err
	}
	if req.Purpose != k.info.Purpose {
		return nil, fmt.Errorf("%w: key %s is %s, request says %s", ErrWrongPurpose, req.KeyID, k.info.Purpose, req.Purpose)
	}
	b.mu.Lock()
	disabled := k.disabled
	b.mu.Unlock()
	if disabled {
		return nil, ErrKeyDisabled
	}
	if err := CheckDigest(k.info.Algorithm, req.Digest, req.Hash); err != nil {
		return nil, err
	}
	b.signs.Add(1)
	return k.priv.Sign(rand.Reader, req.Digest, req.Hash)
}

func (b *SoftBackend) DisableKey(_ context.Context, keyID string) error {
	if b.down.Load() {
		return ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.keys[keyID]
	if !ok {
		return ErrUnknownKey
	}
	if !k.disabled {
		k.disabled = true
		k.info.Disabled, k.info.DisabledAt = true, b.now().UTC()
	}
	return nil
}
