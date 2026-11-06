package signer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/signer"
)

// Eleven online purposes, and the offline root apart from them.
func TestPurposes_ElevenDistinctOnlineAndRootSeparate(t *testing.T) {
	ps := signer.AllPurposes()
	if len(ps) != 11 {
		t.Fatalf("want 11 online purposes, got %d", len(ps))
	}
	seen := map[signer.Purpose]bool{}
	for _, p := range ps {
		if !p.Valid() || seen[p] {
			t.Fatalf("purpose %q invalid or duplicated", p)
		}
		seen[p] = true
		if p == signer.PurposeKeySetRoot {
			t.Fatal("the offline root must not be an online purpose")
		}
	}
	if !signer.PurposeKeySetRoot.Valid() {
		t.Fatal("root purpose must be valid for the offline backend")
	}
}

// Overlap is at least twice the longest token lifetime.
func TestOverlapIsAtLeastTwiceLifetime(t *testing.T) {
	for _, p := range signer.AllPurposes() {
		if !p.Rotates() {
			continue
		}
		if p.RotationOverlap() < 2*p.MaxTokenLifetime() {
			t.Fatalf("%s: overlap %s < 2x lifetime %s", p, p.RotationOverlap(), p.MaxTokenLifetime())
		}
	}
	// The agent CA never rotates.
	if signer.PurposeAgentCA.Rotates() {
		t.Fatal("agent-ca must not rotate (standing constraint)")
	}
	// A decision receipt lives at most 60 s, whatever a setting says.
	if signer.PurposeDecisionReceipt.MaxTokenLifetime() != 60*time.Second || !signer.PurposeDecisionReceipt.Rotates() {
		t.Fatal("decision receipts: 60 s hard cap, and the key rotates")
	}
	if typ := signer.PurposeDecisionReceipt.TokenType(); typ == "JWT" || typ == signer.PurposeGate.TokenType() {
		t.Fatalf("decision receipt typ %q must be its own", typ)
	}
	// A job grant lives at most 24 h (a person-started job); the
	if signer.PurposeJobGrant.MaxTokenLifetime() != 24*time.Hour || !signer.PurposeJobGrant.Rotates() ||
		signer.PurposeJobGrant.TokenType() != "runos.job-grant+jwt" {
		t.Fatal("job grants: 24 h hard cap, the key rotates, typ runos.job-grant+jwt")
	}
	if signer.PurposeVPNLease.MaxTokenLifetime().Hours() != 8 {
		t.Fatal("VPN lease cap is 8 hours")
	}
}

func TestSoftBackend_SignsAndVerifiesBothAlgorithms(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	for _, alg := range []signer.Algorithm{signer.AlgEdDSA, signer.AlgES256} {
		info, err := b.CreateKey(ctx, signer.PurposeGate, alg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := signer.New(ctx, b, info.ID, signer.PurposeGate)
		if err != nil {
			t.Fatal(err)
		}
		var _ crypto.Signer = s
		msg := []byte("hello")
		switch alg {
		case signer.AlgEdDSA:
			sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(s.Public().(ed25519.PublicKey), msg, sig) {
				t.Fatal("ed25519 signature does not verify")
			}
		case signer.AlgES256:
			d := sha256.Sum256(msg)
			sig, err := s.Sign(rand.Reader, d[:], crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), d[:], sig) {
				t.Fatal("ecdsa signature does not verify")
			}
		}
	}
}

func TestKeyRefusedForOtherPurpose(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	vpn, err := b.CreateKey(ctx, signer.PurposeVPNLease, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	// Custody layer: the backend refuses a sign request that names another purpose.
	for _, other := range signer.AllPurposes() {
		if other == signer.PurposeVPNLease {
			continue
		}
		_, err := b.Sign(ctx, signer.SignRequest{KeyID: vpn.ID, Purpose: other, Digest: []byte("x")})
		if !errors.Is(err, signer.ErrWrongPurpose) {
			t.Fatalf("backend sign as %s: want ErrWrongPurpose, got %v", other, err)
		}
		if _, err := signer.New(ctx, b, vpn.ID, other); !errors.Is(err, signer.ErrWrongPurpose) {
			t.Fatalf("adapter as %s: want ErrWrongPurpose, got %v", other, err)
		}
	}
	// Each purpose gets its own key id.
	ids := map[string]bool{}
	for _, p := range signer.AllPurposes() {
		k, err := b.CreateKey(ctx, p, signer.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		if ids[k.ID] {
			t.Fatal("key id reused across purposes")
		}
		ids[k.ID] = true
	}
}

func TestBackendRefusesOnlineRootKeyOnOnlineBackend(t *testing.T) {
	b := signer.NewSoftBackend()
	if _, err := b.CreateKey(context.Background(), signer.PurposeKeySetRoot, signer.AlgEdDSA); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("online backend must refuse a root key, got %v", err)
	}
	off := signer.NewOfflineRootBackend()
	if _, err := off.CreateKey(context.Background(), signer.PurposeVPNLease, signer.AlgEdDSA); !errors.Is(err, signer.ErrWrongPurpose) {
		t.Fatalf("offline backend must refuse an online purpose, got %v", err)
	}
	if _, err := off.CreateKey(context.Background(), signer.PurposeKeySetRoot, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
}

func TestSignRejectsDigestThatDoesNotFitAlgorithm(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	ec, _ := b.CreateKey(ctx, signer.PurposeGate, signer.AlgES256)
	d := sha512.Sum384([]byte("x"))
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: ec.ID, Purpose: signer.PurposeGate, Digest: d[:], Hash: crypto.SHA384}); !errors.Is(err, signer.ErrBadDigest) {
		t.Fatalf("ES256 with SHA-384: want ErrBadDigest, got %v", err)
	}
	ed, _ := b.CreateKey(ctx, signer.PurposeGate, signer.AlgEdDSA)
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: ed.ID, Purpose: signer.PurposeGate, Digest: []byte("m"), Hash: crypto.SHA256}); !errors.Is(err, signer.ErrBadDigest) {
		t.Fatalf("EdDSA with prehash: want ErrBadDigest, got %v", err)
	}
	if _, err := b.CreateKey(ctx, signer.PurposeGate, signer.Algorithm("RS256")); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Fatalf("RS256: want ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestDisabledKeyRefusesToSign(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	k, _ := b.CreateKey(ctx, signer.PurposeGate, signer.AlgEdDSA)
	if err := b.DisableKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: k.ID, Purpose: signer.PurposeGate, Digest: []byte("m")}); !errors.Is(err, signer.ErrKeyDisabled) {
		t.Fatalf("want ErrKeyDisabled, got %v", err)
	}
	if _, err := b.Sign(ctx, signer.SignRequest{KeyID: "nope", Purpose: signer.PurposeGate, Digest: []byte("m")}); !errors.Is(err, signer.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

// No backend API returns private key material,
// and each key has a creation record with id, purpose and custody.
func TestNoPrivateMaterialAndProvenance(t *testing.T) {
	ctx := context.Background()
	b := signer.NewSoftBackend()
	k, _ := b.CreateKey(ctx, signer.PurposeOperationGrant, signer.AlgES256)
	if k.ID == "" || k.Purpose != signer.PurposeOperationGrant || k.Custody == "" || k.CreatedAt.IsZero() {
		t.Fatalf("incomplete creation record: %+v", k)
	}
	if _, err := x509.ParsePKCS8PrivateKey(k.PublicDER); err == nil {
		t.Fatal("PublicDER parses as a private key")
	}
	if _, err := k.PublicKey(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(k)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for f := range m {
		switch f {
		case "id", "purpose", "alg", "public_der", "created_at", "custody":
		default:
			t.Fatalf("unexpected KeyInfo field %q", f)
		}
	}
	privTypes := []reflect.Type{
		reflect.TypeOf(ed25519.PrivateKey(nil)),
		reflect.TypeOf(&ecdsa.PrivateKey{}),
		reflect.TypeOf((*crypto.Signer)(nil)).Elem(),
	}
	bt := reflect.TypeOf((*signer.Backend)(nil)).Elem()
	for i := 0; i < bt.NumMethod(); i++ {
		m := bt.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			for _, pt := range privTypes {
				if out == pt {
					t.Fatalf("Backend.%s returns %s", m.Name, out)
				}
			}
		}
	}
}
