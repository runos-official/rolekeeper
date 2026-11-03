package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"
)

// Errors shared by every backend. A remote backend maps them back from the
// wire so that errors.Is works on both sides of the socket.
var (
	ErrWrongPurpose         = errors.New("signer: wrong_key_purpose")
	ErrUnknownKey           = errors.New("signer: unknown_key")
	ErrKeyDisabled          = errors.New("signer: key_disabled")
	ErrUnsupportedAlgorithm = errors.New("signer: unsupported_algorithm")
	ErrBadDigest            = errors.New("signer: bad_digest")
	ErrUnavailable          = errors.New("signer: unavailable")
	// ErrNoDecision: a strict signer refuses a request with no decision id.
	ErrNoDecision = errors.New("signer: no_decision_id")
	// ErrDecisionReused: a strict signer binds one decision id to one
	// signed request. A second, different request under the same
	// id is refused.
	ErrDecisionReused = errors.New("signer: decision_id_reused")
	// ErrNotAllowed: the operation is not offered on this surface.
	ErrNotAllowed = errors.New("signer: not_allowed")
)

// KeyInfo is the creation record of one key. It never holds private
// material. Custody names the backend that holds the key, for
// provenance.
type KeyInfo struct {
	ID        string    `json:"id"`
	Purpose   Purpose   `json:"purpose"`
	Algorithm Algorithm `json:"alg"`
	PublicDER []byte    `json:"public_der"` // PKIX SubjectPublicKeyInfo
	CreatedAt time.Time `json:"created_at"`
	Custody   string    `json:"custody"`
	// Disabled is custody's own word that the private half no longer signs.
	// DisabledAt is when, when custody knows it; zero otherwise. A key ring
	// never publishes a disabled key as active or standby, and a retired one
	// only inside the overlap counted from DisabledAt.
	Disabled   bool      `json:"disabled,omitempty"`
	DisabledAt time.Time `json:"disabled_at,omitzero"`
}

// PublicKey parses PublicDER.
func (k KeyInfo) PublicKey() (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(k.PublicDER)
	if err != nil {
		return nil, err
	}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if k.Algorithm != AlgEdDSA {
			return nil, ErrUnsupportedAlgorithm
		}
	case *ecdsa.PublicKey:
		if k.Algorithm != AlgES256 || p.Curve != elliptic.P256() {
			return nil, ErrUnsupportedAlgorithm
		}
	case *rsa.PublicKey:
		if k.Algorithm != AlgRS256 || p.N.BitLen() < MinRSABits {
			return nil, ErrUnsupportedAlgorithm
		}
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return pub, nil
}

// SignRequest asks the custody backend for one signature. For EdDSA, Digest
// is the whole message and Hash is 0 (Ed25519 signs the message). For ES256,
// Digest is the SHA-256 of the message and Hash is crypto.SHA256.
type SignRequest struct {
	KeyID   string      `json:"kid"`
	Purpose Purpose     `json:"purpose"`
	Digest  []byte      `json:"digest"`
	Hash    crypto.Hash `json:"hash"`
	// DecisionID names the authorize() decision this signature serves.
	// A strict signer refuses a request without one.
	DecisionID string `json:"decision_id,omitempty"`
}

// Backend is the custody seam. Everything that holds private keys sits
// behind it: the in-process SoftBackend (tests), the remote Unix-socket
// signer, and other custody systems later.
//
// Contract every implementation must keep:
//   - CreateKey makes a non-exportable key bound to one purpose and returns
//     only its public record. There is no export method.
//   - Sign refuses with ErrWrongPurpose when req.Purpose differs from the
//     purpose recorded at creation. The purpose must live in the custody
//     system itself (a key tag or label of the custody system), so a
//     caller that lies about purpose cannot sign.
//   - Sign refuses a digest that does not fit the key algorithm.
//   - DisableKey is permanent for signing; PublicKey keeps working so that
//     verifiers can still read old records.
//   - Any transport or custody failure returns an error wrapping
//     ErrUnavailable. Callers fail closed.
type Backend interface {
	CreateKey(ctx context.Context, purpose Purpose, alg Algorithm) (KeyInfo, error)
	PublicKey(ctx context.Context, keyID string) (KeyInfo, error)
	Sign(ctx context.Context, req SignRequest) ([]byte, error)
	DisableKey(ctx context.Context, keyID string) error
}

// Retirer is a Backend that disables a key only against evidence the
// custody side checks itself. For a purpose with a root-signed
// key set the evidence is a root-signed set (compact JWS) that removes the
// key, or that shows it retiring for at least the overlap window. The
// signer socket client implements it, because the socket refuses a plain
// DisableKey. Callers that hold a Retirer use RetireKey, not
// DisableKey.
type Retirer interface {
	RetireKey(ctx context.Context, keyID, evidence string) error
}

// DecisionBinder keeps the rule "one decision id signs one request" in
// state that every signer pod shares: the custody database
// itself, not one pod's file. BindDecision records that id signed the
// request with sum. It reports false when id is already bound to another
// sum; the same pair again is true.
type DecisionBinder interface {
	BindDecision(ctx context.Context, id string, sum [32]byte) (bool, error)
}

// Retire disables keyID in b: through RetireKey with the evidence when b is
// a Retirer, otherwise through DisableKey.
func Retire(ctx context.Context, b Backend, keyID, evidence string) error {
	if r, ok := b.(Retirer); ok {
		// The evidence is the authority; the decision id names the step.
		if DecisionFromContext(ctx) == "" {
			ctx = ContextWithDecision(ctx, "retire-"+keyID)
		}
		return r.RetireKey(ctx, keyID, evidence)
	}
	return b.DisableKey(ctx, keyID)
}

// CheckDigest enforces the digest shape for an algorithm. Backends call it
// before they sign.
func CheckDigest(alg Algorithm, digest []byte, h crypto.Hash) error {
	switch alg {
	case AlgEdDSA:
		if h != crypto.Hash(0) || len(digest) == 0 {
			return fmt.Errorf("%w: EdDSA signs the message, no prehash", ErrBadDigest)
		}
	case AlgES256, AlgRS256:
		if h != crypto.SHA256 || len(digest) != 32 {
			return fmt.Errorf("%w: %s needs a SHA-256 digest", ErrBadDigest, alg)
		}
	default:
		return ErrUnsupportedAlgorithm
	}
	return nil
}

// Signer adapts one Backend key to crypto.Signer. It is the only handle the
// identity service holds. It carries the key id and purpose, and passes the
// purpose on every sign so that the custody layer can refuse a mismatch.
type Signer struct {
	backend  Backend
	info     KeyInfo
	pub      crypto.PublicKey
	timeout  time.Duration
	decision string
}

var _ crypto.Signer = (*Signer)(nil)

// WithDecision returns a copy of s that sends id as the DecisionID of every
// sign request. A strict signer socket refuses a
// request without one.
func (s *Signer) WithDecision(id string) *Signer {
	c := *s
	c.decision = id
	return &c
}

type decisionKey struct{}

// ContextWithDecision returns a context that carries the authorize()
// decision id for the signatures made under it. Key sources that
// hand out a Signer from a context, such as keys.Manager.ActiveSigner,
// attach it with WithDecision.
func ContextWithDecision(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, decisionKey{}, id)
}

// DecisionFromContext returns the decision id that ContextWithDecision set.
func DecisionFromContext(ctx context.Context) string {
	id, _ := ctx.Value(decisionKey{}).(string)
	return id
}

// New returns a Signer for keyID, refusing when the key's recorded purpose
// is not purpose.
func New(ctx context.Context, b Backend, keyID string, purpose Purpose) (*Signer, error) {
	info, err := b.PublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if info.Purpose != purpose {
		return nil, fmt.Errorf("%w: key %s is %s, asked for %s", ErrWrongPurpose, keyID, info.Purpose, purpose)
	}
	pub, err := info.PublicKey()
	if err != nil {
		return nil, err
	}
	return &Signer{backend: b, info: info, pub: pub, timeout: 5 * time.Second}, nil
}

func (s *Signer) Public() crypto.PublicKey { return s.pub }
func (s *Signer) KeyID() string            { return s.info.ID }
func (s *Signer) Purpose() Purpose         { return s.info.Purpose }
func (s *Signer) Algorithm() Algorithm     { return s.info.Algorithm }
func (s *Signer) Info() KeyInfo            { return s.info }

// Sign implements crypto.Signer. rand is ignored: the custody backend owns
// its randomness.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	h := crypto.Hash(0)
	if opts != nil {
		h = opts.HashFunc()
	}
	if err := CheckDigest(s.info.Algorithm, digest, h); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.backend.Sign(ctx, SignRequest{KeyID: s.info.ID, Purpose: s.info.Purpose, Digest: digest, Hash: h, DecisionID: s.decision})
}
