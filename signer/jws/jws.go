// Package jws wraps go-jose v4 for compact JWS with a strict header policy:
// alg must be EdDSA or ES256, the key is found by kid only (never from an
// embedded jwk, jku, x5u or x5c), and "crit" is refused. Every object carries
// "purpose" and "typ" in the protected header.
package jws

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/runos-official/rolekeeper/signer"
)

var (
	ErrMalformed           = errors.New("jws: malformed")
	ErrAlgorithmNotAllowed = errors.New("jws: algorithm_not_allowed")
	ErrForbiddenHeader     = errors.New("jws: forbidden_header")
	ErrBadSignature        = errors.New("jws: bad_signature")
)

// Allowed is the algorithm allowlist passed to go-jose.
var Allowed = []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256}

const HeaderPurpose = "purpose"

type opaque struct {
	s *signer.Signer
	o jose.OpaqueSigner
}

func (o opaque) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: o.s.Public(), KeyID: o.s.KeyID(), Algorithm: string(o.s.Algorithm()), Use: "sig"}
}
func (o opaque) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.SignatureAlgorithm(o.s.Algorithm())}
}
func (o opaque) SignPayload(p []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if string(alg) != string(o.s.Algorithm()) {
		return nil, ErrAlgorithmNotAllowed
	}
	return o.o.SignPayload(p, alg)
}

// Sign makes a compact JWS over payload with s. The purpose header is the
// signer's own purpose, so a caller cannot label an object with another
// purpose than the key's.
func Sign(s *signer.Signer, typ string, payload []byte) (string, error) {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(HeaderPurpose, string(s.Purpose()))
	js, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(s.Algorithm()),
		Key:       opaque{s: s, o: cryptosigner.Opaque(s)},
	}, opts)
	if err != nil {
		return "", err
	}
	obj, err := js.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// Header is the parsed protected header. It is UNVERIFIED: use it only to
// pick a key or to refuse.
type Header struct {
	Alg, Kid, Typ, Purpose string
}

var forbidden = []string{"jwk", "jku", "x5u", "x5c", "crit", "b64", "zip", "enc"}

// PeekHeader decodes and checks the protected header without verifying.
func PeekHeader(compact string) (Header, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Header{}, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return Header{}, fmt.Errorf("%w: header json", ErrMalformed)
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	h := Header{Alg: str("alg"), Kid: str("kid"), Typ: str("typ"), Purpose: str(HeaderPurpose)}
	if !signer.Algorithm(h.Alg).Allowed() {
		return h, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, h.Alg)
	}
	for _, f := range forbidden {
		if _, ok := m[f]; ok {
			return h, fmt.Errorf("%w: %s", ErrForbiddenHeader, f)
		}
	}
	return h, nil
}

// Verify checks the signature with pub. alg is the algorithm registered for
// the key; a header that names another algorithm is refused (algorithm
// confusion).
func Verify(compact string, pub crypto.PublicKey, alg signer.Algorithm) ([]byte, error) {
	h, err := PeekHeader(compact)
	if err != nil {
		return nil, err
	}
	if h.Alg != string(alg) {
		return nil, fmt.Errorf("%w: header %s, key %s", ErrAlgorithmNotAllowed, h.Alg, alg)
	}
	obj, err := jose.ParseSigned(compact, Allowed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(obj.Signatures) != 1 || obj.Signatures[0].Protected.Algorithm != string(alg) {
		return nil, ErrAlgorithmNotAllowed
	}
	out, err := obj.Verify(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return out, nil
}
