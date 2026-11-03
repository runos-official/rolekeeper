package token_test

import (
	"crypto"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/runos-official/rolekeeper/internal/signer"
)

const cryptoSHA256 = crypto.SHA256

// opaque lets a test build tokens with arbitrary go-jose options (for
// example EmbedJWK) using an attacker's key.
type opaque struct{ s *signer.Signer }

func (o opaque) Public() *jose.JSONWebKey { return &jose.JSONWebKey{Key: o.s.Public()} }
func (o opaque) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.SignatureAlgorithm(o.s.Algorithm())}
}
func (o opaque) SignPayload(p []byte, a jose.SignatureAlgorithm) ([]byte, error) {
	return cryptosigner.Opaque(o.s).SignPayload(p, a)
}
