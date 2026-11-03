package bundle_test

// The checks the relay applier adds to the bundle
// package (the relay token claims). This
// file mints the fresh and refusal tokens itself with the test issuer, so it
// does not depend on the sealing side of the same tokens.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/internal/bundle"
	"github.com/runos-official/rolekeeper/internal/kobj"
	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/token"
)

const nonce = "AAAAAAAAAAAAAAAAAAAAAA" // 22 chars of base64url

func (r *rig) mint(t *testing.T, cls, sub, acct, cluster, jti string, ttl time.Duration) string {
	t.Helper()
	tok, err := r.issuer.Issue(context.Background(), signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: sub, ID: jti, Audience: jwt.Audience{bundle.Audience(cluster)}},
		Class:  cls, Account: acct}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func freshJTI(nonce, digest string) string {
	sum := sha256.Sum256([]byte("fresh\x00" + nonce + "\x00" + digest))
	return hex.EncodeToString(sum[:])
}

func (r *rig) fresh(t *testing.T, nonce, digest string) string {
	return r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-1", freshJTI(nonce, digest), 15*time.Minute)
}

func (r *rig) refusal(t *testing.T, reason string) string {
	return r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:"+reason, "acct-a", "cl-1", "", 15*time.Minute)
}

func (r *rig) expecting(t *testing.T) *bundle.Verifier {
	v := r.verifier(t)
	v.ExpectAccount("acct-a")
	return v
}

func TestTooLargeIsASignedFieldAndPartOfTheContent(t *testing.T) {
	r := newRig(t)
	b := body(2)
	b.DenyOnly, b.TooLarge = true, true
	got, err := r.verifier(t).Verify(r.seal(t, b))
	if err != nil || !got.Bundle.TooLarge || !got.Bundle.DenyOnly {
		t.Fatalf("%+v %v", got.Bundle, err)
	}
	plain := body(2)
	plain.DenyOnly = true
	if bundle.ContentDigest(plain) == got.Digest {
		t.Fatal("too_large is not part of the content digest")
	}
	raw, _ := json.Marshal(body(2))
	if strings.Contains(string(raw), "too_large") {
		t.Fatalf("a bundle that is not too large carries the field: %s", raw)
	}
}

// A fresh token or a refusal token carries the same audience and key as a
// bundle. Neither may pass as the bundle itself.
func TestAFreshOrRefusalTokenIsNotABundleToken(t *testing.T) {
	r := newRig(t)
	b := body(3)
	b.IssuedAt = r.now
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	for name, tok := range map[string]string{
		"fresh":   r.mint(t, "k8s-rbac-fresh", "k8s-rbac-bundle", "acct-a", "cl-1", hex.EncodeToString(sum[:]), 15*time.Minute),
		"refusal": r.mint(t, "k8s-rbac-refusal", "k8s-rbac-bundle", "acct-a", "cl-1", hex.EncodeToString(sum[:]), 15*time.Minute),
	} {
		env, _ := json.Marshal(bundle.Envelope{Bundle: tok, Body: raw})
		if _, err := r.expecting(t).Verify(env); err == nil {
			t.Errorf("a %s-class token verified as a bundle", name)
		}
	}
}

func TestVerifyRefusesABundleObjectWithBinaryData(t *testing.T) {
	r := newRig(t)
	b := body(3)
	b.Objects = append(b.Objects, kobj.Object{Kind: kobj.KindConfigMap, Name: "x", Namespace: "runos", BinaryData: map[string][]byte{"k": []byte("v")}})
	if _, err := r.verifier(t).Verify(r.seal(t, b)); !errors.Is(err, bundle.ErrFormat) {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func TestVerifyFresh(t *testing.T) {
	r := newRig(t)
	v := r.expecting(t)
	good := r.fresh(t, nonce, "digest-1")
	if err := v.VerifyFresh(good, nonce, "digest-1"); err != nil {
		t.Fatal(err)
	}
	other := "BBBBBBBBBBBBBBBBBBBBBB"
	cases := map[string]struct {
		tok, nonce, digest string
	}{
		"another nonce":           {good, other, "digest-1"},
		"another content digest":  {good, nonce, "digest-2"},
		"an empty nonce":          {r.fresh(t, "", "digest-1"), "", "digest-1"},
		"not a token":             {"x.y.z", nonce, "digest-1"},
		"a refusal token":         {r.refusal(t, "cluster"), nonce, "digest-1"},
		"another cluster":         {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-2", freshJTI(nonce, "digest-1"), 15*time.Minute), nonce, "digest-1"},
		"another account":         {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-b", "cl-1", freshJTI(nonce, "digest-1"), 15*time.Minute), nonce, "digest-1"},
		"no account":              {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "", "cl-1", freshJTI(nonce, "digest-1"), 15*time.Minute), nonce, "digest-1"},
		"the bundle class":        {r.mint(t, "k8s-rbac-bundle", "k8s-rbac-fresh", "acct-a", "cl-1", freshJTI(nonce, "digest-1"), 15*time.Minute), nonce, "digest-1"},
		"the wrong subject":       {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-bundle", "acct-a", "cl-1", freshJTI(nonce, "digest-1"), 15*time.Minute), nonce, "digest-1"},
		"a plain digest as jti":   {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-1", "digest-1", 15*time.Minute), nonce, "digest-1"},
		"a nonce-less derivation": {r.mint(t, "k8s-rbac-fresh", "k8s-rbac-fresh", "acct-a", "cl-1", func() string { s := sha256.Sum256([]byte("digest-1")); return hex.EncodeToString(s[:]) }(), 15*time.Minute), nonce, "digest-1"},
	}
	for name, c := range cases {
		if err := v.VerifyFresh(c.tok, c.nonce, c.digest); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r.now = r.now.Add(16*time.Minute + 31*time.Second)
	if err := v.VerifyFresh(good, nonce, "digest-1"); err == nil {
		t.Error("an expired fresh token was accepted")
	}
}

func TestVerifyRefusal(t *testing.T) {
	r := newRig(t)
	v := r.expecting(t)
	for _, reason := range []string{"cluster", "retired"} {
		got, err := v.VerifyRefusal(r.refusal(t, reason))
		if err != nil || got != reason {
			t.Fatalf("%s: got %q %v", reason, got, err)
		}
	}
	bad := map[string]string{
		"an unknown reason":       r.refusal(t, "because"),
		"no reason":               r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:", "acct-a", "cl-1", "", 15*time.Minute),
		"another cluster":         r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:cluster", "acct-a", "cl-2", "", 15*time.Minute),
		"another account":         r.mint(t, "k8s-rbac-refusal", "k8s-rbac-refusal:cluster", "acct-b", "cl-1", "", 15*time.Minute),
		"the bundle class":        r.mint(t, "k8s-rbac-bundle", "k8s-rbac-refusal:cluster", "acct-a", "cl-1", "", 15*time.Minute),
		"a fresh token":           r.fresh(t, nonce, "digest-1"),
		"an unsigned compact JWS": "eyJhbGciOiJub25lIn0.e30.",
		"garbage":                 "refused",
	}
	for name, tok := range bad {
		if _, err := v.VerifyRefusal(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := r.refusal(t, "cluster")
	r.now = r.now.Add(16*time.Minute + 31*time.Second)
	if _, err := v.VerifyRefusal(good); err == nil {
		t.Error("an expired refusal was accepted")
	}
}

func gz(t *testing.T, parts ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, p := range parts {
		w, _ := gzip.NewWriterLevel(&buf, 6)
		if _, err := w.Write(p); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
	}
	return buf.Bytes()
}

func TestGunzipBodyReadsExactlyOneMember(t *testing.T) {
	raw := []byte(`{"format":1}`)
	got, err := bundle.GunzipBody(gz(t, raw))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("%q %v", got, err)
	}
	two := gz(t, raw, raw)
	if _, err := bundle.GunzipBody(two); err == nil {
		t.Error("two concatenated members were read")
	}
	if _, err := bundle.GunzipBody(append(gz(t, raw), 0x00, 0x01)); err == nil {
		t.Error("trailing bytes after the member were accepted")
	}
	if _, err := bundle.GunzipBody(append(gz(t, raw), gz(t, raw)[:3]...)); err == nil {
		t.Error("a truncated second member was accepted")
	}
	bad := gz(t, raw)
	bad[len(bad)-6] ^= 0xff // the CRC
	if _, err := bundle.GunzipBody(bad); err == nil {
		t.Error("a corrupt member was accepted")
	}
	if _, err := bundle.GunzipBody(nil); err == nil {
		t.Error("an empty body.gz was accepted")
	}
}

func TestGunzipBodyRefusesMoreThanTheLimits(t *testing.T) {
	big := bytes.Repeat([]byte{'a'}, bundle.MaxBodyBytes+1)
	if _, err := bundle.GunzipBody(gz(t, big)); !errors.Is(err, bundle.ErrTooLarge) {
		t.Fatalf("a body above the cap: %v", err)
	}
	exact := bytes.Repeat([]byte{'a'}, bundle.MaxBodyBytes)
	if _, err := bundle.GunzipBody(gz(t, exact)); err != nil {
		t.Fatalf("a body at the cap: %v", err)
	}
	// Incompressible data above the compressed hard stop.
	noise := make([]byte, bundle.MaxGzBytes+10)
	var x uint32 = 1
	for i := range noise {
		x = x*1664525 + 1013904223
		noise[i] = byte(x >> 24)
	}
	if _, err := bundle.GunzipBody(gz(t, noise)); !errors.Is(err, bundle.ErrTooLarge) {
		t.Fatalf("a body.gz above 900,000 bytes: %v", err)
	}
}

func TestRebuildEnvelopeIsWhatRoidSigned(t *testing.T) {
	r := newRig(t)
	raw := r.seal(t, body(4))
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	gzbody, err := bundle.GzipBody(env.Body)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := bundle.RebuildEnvelope(env.Bundle, gzbody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt, raw) {
		t.Fatal("splitting the envelope is not lossless")
	}
	if _, err := r.expecting(t).Verify(rebuilt); err != nil {
		t.Fatal(err)
	}
	// A tampered body.gz fails the signed digest.
	tampered := bytes.Replace(env.Body, []byte(`"pv-3"`), []byte(`"pv-9"`), 1)
	bad, _ := bundle.GzipBody(tampered)
	rb, _ := bundle.RebuildEnvelope(env.Bundle, bad)
	if _, err := r.expecting(t).Verify(rb); !errors.Is(err, bundle.ErrDigest) {
		t.Fatalf("got %v, want ErrDigest", err)
	}
}

// The audience is the first guard against a bundle for another cluster; the
// cluster inside the signed body is the second. A token with the right
// audience over a body that names another cluster still fails.
func TestAnEnvelopeWhoseBodyNamesAnotherClusterIsRefusedEvenWithTheRightAudience(t *testing.T) {
	r := newRig(t)
	b := body(3)
	b.Cluster = "cl-2"
	b.IssuedAt = r.now
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	tok := r.mint(t, "k8s-rbac-bundle", "k8s-rbac-bundle", "acct-a", "cl-1", hex.EncodeToString(sum[:]), 15*time.Minute)
	env, _ := json.Marshal(bundle.Envelope{Bundle: tok, Body: raw})
	if _, err := r.expecting(t).Verify(env); !errors.Is(err, bundle.ErrCluster) {
		t.Fatalf("got %v, want ErrCluster", err)
	}
}
