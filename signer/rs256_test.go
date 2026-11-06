package signer_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/runos-official/rolekeeper/signer"
)

// From the review: RS256 exists only so roid can offer an RS256 ID
// token key (OIDC Core). It is not on the RunOS token allowlist, and no
// RunOS purpose ever gets an RS256 key (Kubernetes stays ES256).
func TestRS256IsKnownButNeverARunOSAlgorithm(t *testing.T) {
	if signer.AlgRS256.Allowed() {
		t.Fatalf("RS256 is on the RunOS token allowlist")
	}
	b := signer.NewSoftBackend()
	for _, p := range signer.AllPurposes() {
		if _, err := b.CreateKey(context.Background(), p, signer.AlgRS256); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
			t.Fatalf("%s: RS256 key created (%v)", p, err)
		}
	}
	d := make([]byte, 32)
	if err := signer.CheckDigest(signer.AlgRS256, d, crypto.SHA256); err != nil {
		t.Fatalf("RS256 SHA-256 digest refused: %v", err)
	}
	if err := signer.CheckDigest(signer.AlgRS256, d[:20], crypto.SHA1); err == nil {
		t.Fatalf("RS256 accepted a SHA-1 digest")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgRS256, PublicDER: der}).PublicKey(); err != nil {
		t.Fatalf("RS256 public key refused: %v", err)
	}
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgES256, PublicDER: der}).PublicKey(); err == nil {
		t.Fatalf("an RSA key passed as ES256")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	sder, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := (signer.KeyInfo{Algorithm: signer.AlgRS256, PublicDER: sder}).PublicKey(); err == nil {
		t.Fatalf("a 1024-bit RSA key was accepted")
	}
}
