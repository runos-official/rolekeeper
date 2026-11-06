package bundle_test

// The two tokens roid signs for the relay path. The fresh token proves
// roid saw the applier's nonce and the content digest of the envelope
// served with it. The refusal token is the only refusal that can feed the
// applier's fail-safe. The claims are fixed by the relay transport.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/token"
)

// sealRelayVerifier checks a relay token under the rig's bundle key set,
// with every relay class allowed. The class and subject checks per use are
// the applier's job; here they are read back from the claims.
func sealRelayVerifier(t *testing.T, r *rig, cluster string) *token.Verifier {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(r.trust.RootPublicDER)
	if err != nil {
		t.Fatal(err)
	}
	view, err := keys.NewView(signer.PurposePolicyBundle, pub, signer.AlgEdDSA, r.trust.BundleKeys)
	if err != nil {
		t.Fatal(err)
	}
	return &token.Verifier{Purpose: signer.PurposePolicyBundle, Issuer: issuerName, Audience: bundle.Audience(cluster),
		Classes: []string{"k8s-rbac-bundle", "k8s-rbac-fresh", "k8s-rbac-refusal"}, Keys: view, Now: func() time.Time { return r.now }}
}

func TestSealFreshClaims(t *testing.T) {
	r := newRig(t)
	const nonce = "AAAAAAAAAAAAAAAAAAAAAA" // 22 chars
	const digest = "9f2c"
	tok, err := bundle.SealFresh(context.Background(), r.issuer, "acct-a", "cl-1", nonce, digest)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sealRelayVerifier(t, r, "cl-1").Verify(tok)
	if err != nil {
		t.Fatalf("fresh token does not verify: %v", err)
	}
	sum := sha256.Sum256([]byte("fresh\x00" + nonce + "\x00" + digest))
	if c.Class != "k8s-rbac-fresh" || c.Subject != "k8s-rbac-fresh" || c.Account != "acct-a" || c.ID != hex.EncodeToString(sum[:]) {
		t.Fatalf("claims %+v", c)
	}
	if !c.Audience.Contains("k8s-rbac:cl-1") {
		t.Fatalf("audience %v", c.Audience)
	}
	if life := c.Expiry.Time().Sub(c.IssuedAt.Time()); life != 15*time.Minute {
		t.Fatalf("life %s, want 15m", life)
	}
	// The token for another cluster does not verify here.
	if _, err := sealRelayVerifier(t, r, "cl-2").Verify(tok); !errors.Is(err, token.ErrWrongAudience) {
		t.Fatalf("other cluster: %v", err)
	}
}

// The jti binds nonce and content: any change of either changes it.
func TestSealFreshJTIBindsNonceAndContent(t *testing.T) {
	r := newRig(t)
	jti := func(nonce, digest string) string {
		tok, err := bundle.SealFresh(context.Background(), r.issuer, "acct-a", "cl-1", nonce, digest)
		if err != nil {
			t.Fatal(err)
		}
		c, err := sealRelayVerifier(t, r, "cl-1").Verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	n1, n2 := strings.Repeat("a", 22), strings.Repeat("b", 22)
	if jti(n1, "d1") == jti(n2, "d1") || jti(n1, "d1") == jti(n1, "d2") {
		t.Fatal("the jti ignores the nonce or the content digest")
	}
	// A shifted boundary must not collide: ("ab","c") vs ("a","bc").
	if jti("ab", "c") == jti("a", "bc") {
		t.Fatal("the jti has no separator between nonce and digest")
	}
}

func TestSealFreshRefusesBadInput(t *testing.T) {
	r := newRig(t)
	for name, c := range map[string][4]string{
		"no account": {"", "cl-1", "AAAAAAAAAAAAAAAAAAAAAA", "d"},
		"no cluster": {"acct-a", "", "AAAAAAAAAAAAAAAAAAAAAA", "d"},
		"no nonce":   {"acct-a", "cl-1", "", "d"},
		"no digest":  {"acct-a", "cl-1", "AAAAAAAAAAAAAAAAAAAAAA", ""},
	} {
		if _, err := bundle.SealFresh(context.Background(), r.issuer, c[0], c[1], c[2], c[3]); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestSealRefusalClaims(t *testing.T) {
	r := newRig(t)
	seen := map[string]bool{}
	for _, reason := range []string{"cluster", "retired"} {
		tok, err := bundle.SealRefusal(context.Background(), r.issuer, "acct-a", "cl-1", reason)
		if err != nil {
			t.Fatal(err)
		}
		c, err := sealRelayVerifier(t, r, "cl-1").Verify(tok)
		if err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
		if c.Class != "k8s-rbac-refusal" || c.Subject != "k8s-rbac-refusal:"+reason || c.Account != "acct-a" || !c.Audience.Contains("k8s-rbac:cl-1") {
			t.Fatalf("%s: claims %+v", reason, c)
		}
		if len(c.ID) != 32 || seen[c.ID] {
			t.Fatalf("%s: jti %q is not a fresh 128 bit value", reason, c.ID)
		}
		seen[c.ID] = true
		if c.Expiry.Time().Sub(c.IssuedAt.Time()) != 15*time.Minute {
			t.Fatalf("%s: life", reason)
		}
		// Not an RBAC bundle: the subject differs from Subject.
		if c.Subject == bundle.Subject {
			t.Fatal("a refusal carries the bundle subject")
		}
	}
	// Two tokens for the same input differ (random jti).
	a, _ := bundle.SealRefusal(context.Background(), r.issuer, "acct-a", "cl-1", "cluster")
	b, _ := bundle.SealRefusal(context.Background(), r.issuer, "acct-a", "cl-1", "cluster")
	if a == b {
		t.Fatal("two refusals are byte equal")
	}
}

func TestSealRefusalRefusesBadInput(t *testing.T) {
	r := newRig(t)
	for _, reason := range []string{"", "other", "Cluster", "cluster "} {
		if _, err := bundle.SealRefusal(context.Background(), r.issuer, "acct-a", "cl-1", reason); err == nil {
			t.Errorf("reason %q signed", reason)
		}
	}
	if _, err := bundle.SealRefusal(context.Background(), r.issuer, "", "cl-1", "cluster"); err == nil {
		t.Error("no account signed")
	}
	if _, err := bundle.SealRefusal(context.Background(), r.issuer, "acct-a", "", "cluster"); err == nil {
		t.Error("no cluster signed")
	}
}
