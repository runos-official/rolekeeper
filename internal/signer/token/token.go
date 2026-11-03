// Package token issues and verifies the RunOS token purposes as JWTs
// (go-jose v4.1.5): kubernetes-issuer, vpn-lease, gate, operation-grant and
// policy-bundle. The agent CA does not sign JWTs.
//
// Verification order: header policy (alg allowlist, no embedded keys, no
// crit), header purpose and typ, key lookup by kid in this purpose's key set
// only, key algorithm equals header algorithm, signature, claims purpose,
// issuer, audience, exp required, nbf, lifetime cap, token class, revocation.
package token

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
)

var (
	ErrWrongKeyPurpose     = signer.ErrWrongPurpose
	ErrAlgorithmNotAllowed = jws.ErrAlgorithmNotAllowed
	ErrForbiddenHeader     = jws.ErrForbiddenHeader
	ErrBadSignature        = jws.ErrBadSignature
	ErrMalformed           = jws.ErrMalformed
	ErrUnknownKey          = keys.ErrUnknownKey
	ErrKeyRemoved          = keys.ErrKeyRemoved
	ErrWrongType           = errors.New("token: wrong_type")
	ErrExpired             = errors.New("token: expired")
	ErrNotYetValid         = errors.New("token: not_yet_valid")
	ErrWrongAudience       = errors.New("token: wrong_audience")
	ErrWrongIssuer         = errors.New("token: wrong_issuer")
	ErrWrongClass          = errors.New("token: wrong_class")
	ErrMissingClaim        = errors.New("token: missing_claim")
	ErrLifetimeTooLong     = errors.New("token: lifetime_too_long")
	ErrRevoked             = errors.New("token: revoked")
)

var codes = []struct {
	err  error
	code string
}{
	{ErrWrongKeyPurpose, "wrong_key_purpose"}, {ErrAlgorithmNotAllowed, "algorithm_not_allowed"},
	{ErrForbiddenHeader, "forbidden_header"}, {ErrBadSignature, "bad_signature"}, {ErrMalformed, "malformed"},
	{ErrUnknownKey, "unknown_key"}, {ErrKeyRemoved, "key_removed"}, {ErrWrongType, "wrong_type"},
	{ErrExpired, "expired"}, {ErrNotYetValid, "not_yet_valid"}, {ErrWrongAudience, "wrong_audience"},
	{ErrWrongIssuer, "wrong_issuer"}, {ErrWrongClass, "wrong_class"}, {ErrMissingClaim, "missing_claim"},
	{ErrLifetimeTooLong, "lifetime_too_long"}, {ErrRevoked, "revoked"}, {signer.ErrUnavailable, "signer_unavailable"},
}

// Code returns the machine reason for err.
func Code(err error) string {
	for _, c := range codes {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "invalid"
}

// HTTPStatus maps an issue or verify error to the API status: 503 when the
// signer is down, otherwise 401 auth.invalid_credential.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}
	if errors.Is(err, signer.ErrUnavailable) {
		return 503
	}
	return 401
}

// DefaultLeeway is the clock skew allowance.
const DefaultLeeway = 30 * time.Second

// Claims are the standard JWT claims plus RunOS fields.
type Claims struct {
	jwt.Claims
	Purpose signer.Purpose `json:"purpose"`
	Class   string         `json:"cls"`
	Account string         `json:"acct,omitempty"`
	Parent  string         `json:"pcid,omitempty"`
	// Attempt is the retry counter of an idempotent operation grant.
	// It is 0 for the first run. The executors key their single-use
	// record on the digest and the attempt.
	Attempt uint32 `json:"att,omitempty"`
	// Privileged marks a token for a privileged group. It is capped at
	// signer.PrivilegedTokenLifetime (5 minutes).
	Privileged bool `json:"priv,omitempty"`
	// Email and Groups describe the person to an app behind the gate's
	// plain sign-in screen. Only gate tokens for an app carry them.
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// maxLifetime is the lifetime cap for c under purpose p.
func maxLifetime(p signer.Purpose, c *Claims) time.Duration {
	m := p.MaxTokenLifetime()
	if c.Privileged && signer.PrivilegedTokenLifetime < m {
		m = signer.PrivilegedTokenLifetime
	}
	return m
}

func tokenPurpose(p signer.Purpose) bool {
	return p.Valid() && p != signer.PurposeAgentCA && p != signer.PurposeKeySetRoot && p != signer.PurposeEmergencyRoster && p != signer.PurposeSvcMTLS
}

// KeySource hands out the active signer for a purpose (keys.Manager).
type KeySource interface {
	ActiveSigner(ctx context.Context, p signer.Purpose) (*signer.Signer, error)
}

type Issuer struct {
	Keys KeySource
	Name string
	Now  func() time.Time
}

// Issue signs c for purpose p with lifetime ttl.
func (i *Issuer) Issue(ctx context.Context, p signer.Purpose, c Claims, ttl time.Duration) (string, error) {
	if !tokenPurpose(p) {
		return "", fmt.Errorf("%w: %s does not sign tokens", ErrWrongKeyPurpose, p)
	}
	if max := maxLifetime(p, &c); ttl <= 0 || ttl > max {
		return "", fmt.Errorf("%w: %s > %s", ErrLifetimeTooLong, ttl, max)
	}
	s, err := i.Keys.ActiveSigner(ctx, p)
	if err != nil {
		return "", err
	}
	if s.Purpose() != p {
		return "", ErrWrongKeyPurpose
	}
	now := i.Now()
	c.Issuer = i.Name
	c.IssuedAt = jwt.NewNumericDate(now)
	if c.NotBefore == nil {
		c.NotBefore = jwt.NewNumericDate(now)
	}
	c.Expiry = jwt.NewNumericDate(now.Add(ttl))
	c.Purpose = p
	if c.ID == "" {
		var b [16]byte
		_, _ = rand.Read(b[:])
		c.ID = hex.EncodeToString(b[:])
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return jws.Sign(s, p.TokenType(), raw)
}

type Verifier struct {
	Purpose  signer.Purpose
	Issuer   string
	Audience string
	Classes  []string
	Keys     *keys.View
	Now      func() time.Time
	Leeway   time.Duration
	// Revoked returns an error when the credential, its subject or its
	// parent is revoked. Nil means no revocation source.
	Revoked func(*Claims) error
}

// Verify checks tok and returns its claims.
func (v *Verifier) Verify(tok string) (*Claims, error) {
	h, err := jws.PeekHeader(tok)
	if err != nil {
		return nil, err
	}
	if h.Purpose != string(v.Purpose) || v.Keys == nil || v.Keys.Purpose() != v.Purpose {
		return nil, fmt.Errorf("%w: token purpose %q, verifier %s", ErrWrongKeyPurpose, h.Purpose, v.Purpose)
	}
	if h.Typ != v.Purpose.TokenType() {
		return nil, fmt.Errorf("%w: %q", ErrWrongType, h.Typ)
	}
	pub, alg, err := v.Keys.Lookup(h.Kid)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(tok, pub, alg)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrMalformed)
	}
	if c.Purpose != v.Purpose {
		return nil, fmt.Errorf("%w: claim purpose %q", ErrWrongKeyPurpose, c.Purpose)
	}
	if c.Expiry == nil || len(c.Audience) == 0 || c.Issuer == "" {
		return nil, fmt.Errorf("%w: exp, aud and iss are required", ErrMissingClaim)
	}
	leeway := v.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	now := v.Now()
	if c.Issuer != v.Issuer {
		return nil, ErrWrongIssuer
	}
	if v.Audience == "" || !c.Audience.Contains(v.Audience) {
		return nil, ErrWrongAudience
	}
	if !now.Before(c.Expiry.Time().Add(leeway)) {
		return nil, ErrExpired
	}
	if c.NotBefore != nil && now.Add(leeway).Before(c.NotBefore.Time()) {
		return nil, ErrNotYetValid
	}
	start := now
	if c.IssuedAt != nil {
		start = c.IssuedAt.Time()
		if now.Add(leeway).Before(start) {
			return nil, ErrNotYetValid
		}
	}
	if c.Expiry.Time().Sub(start) > maxLifetime(v.Purpose, &c)+leeway {
		return nil, ErrLifetimeTooLong
	}
	if !slices.Contains(v.Classes, c.Class) {
		return nil, fmt.Errorf("%w: %q", ErrWrongClass, c.Class)
	}
	if v.Revoked != nil {
		if err := v.Revoked(&c); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRevoked, err)
		}
	}
	return &c, nil
}
