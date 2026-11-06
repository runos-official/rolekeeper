package bundle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/keys"
	"github.com/runos-official/rolekeeper/signer/revlog"
	"github.com/runos-official/rolekeeper/signer/token"
)

const issuerName = "https://roid.example.test"

type rig struct {
	issuer *token.Issuer
	trust  bundle.Trust
	now    time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	log, err := revlog.Open(filepath.Join(t.TempDir(), "revocations.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	off := signer.NewOfflineRootBackend()
	rk, err := off.CreateKey(ctx, signer.PurposeKeySetRoot, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	km := keys.NewManager(signer.NewSoftBackend(), log, clock)
	doc, err := km.Bootstrap(ctx, signer.PurposePolicyBundle, signer.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{
		issuer: &token.Issuer{Keys: km, Name: issuerName, Now: clock},
		trust:  bundle.Trust{Issuer: issuerName, Cluster: "cl-1", RootPublicDER: rk.PublicDER, RootAlg: signer.AlgEdDSA, BundleKeys: doc},
		now:    now,
	}
}

func body(version uint64) bundle.Bundle {
	return bundle.Bundle{Format: bundle.Format, Account: "acct-a", Cluster: "cl-1", Version: version, PolicyVersion: "pv-3",
		Namespaces: []string{"apps"},
		Objects: []kobj.Object{{Kind: kobj.KindRoleBinding, Name: "runos:view:u:alice", Namespace: "apps",
			Labels: map[string]string{kobj.LabelManaged: "true"}}}}
}

func (r *rig) seal(t *testing.T, b bundle.Bundle) []byte {
	t.Helper()
	b.IssuedAt = r.now
	raw, err := bundle.Seal(context.Background(), r.issuer, b, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (r *rig) verifier(t *testing.T) *bundle.Verifier {
	t.Helper()
	v, err := bundle.NewVerifier(r.trust, func() time.Time { return r.now }, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealedBundleVerifies(t *testing.T) {
	r := newRig(t)
	got, err := r.verifier(t).Verify(r.seal(t, body(4)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Bundle.Version != 4 || got.Bundle.Account != "acct-a" || len(got.Bundle.Objects) != 1 || got.Digest == "" {
		t.Fatalf("unexpected bundle: %+v", got.Bundle)
	}
}

// A body edited after signing does not match the signed digest.
func TestEditedBodyIsRefused(t *testing.T) {
	r := newRig(t)
	raw := r.seal(t, body(4))
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	b := body(4)
	b.Objects = nil // a revoke hidden by an edit
	env.Body, _ = json.Marshal(b)
	tampered, _ := json.Marshal(env)
	if _, err := r.verifier(t).Verify(tampered); !errors.Is(err, bundle.ErrDigest) {
		t.Fatalf("got %v, want ErrDigest", err)
	}
}

// Another cluster's bundle never applies here.
func TestOtherClustersBundleIsRefused(t *testing.T) {
	r := newRig(t)
	b := body(4)
	b.Cluster = "cl-2"
	if _, err := r.verifier(t).Verify(r.seal(t, b)); err == nil {
		t.Fatal("another cluster's bundle verified")
	}
}

// A gate projection signed with the same policy-bundle key is not an RBAC
// bundle: the subject and audience differ.
func TestGateProjectionIsNotAnRBACBundle(t *testing.T) {
	r := newRig(t)
	b := body(4)
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	tok, err := r.issuer.Issue(context.Background(), signer.PurposePolicyBundle, token.Claims{
		Claims: jwt.Claims{Subject: "gate-projection", ID: hex.EncodeToString(sum[:]), Audience: jwt.Audience{"gate:cl-1"}},
		Class:  "gate-projection", Account: "acct-a"}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(bundle.Envelope{Bundle: tok, Body: raw})
	if _, err := r.verifier(t).Verify(env); err == nil {
		t.Fatal("a gate projection verified as an RBAC bundle")
	}
}

func TestExpiredBundleIsRefused(t *testing.T) {
	r := newRig(t)
	raw := r.seal(t, body(4))
	v, err := bundle.NewVerifier(r.trust, func() time.Time { return r.now.Add(time.Hour) }, filepath.Join(t.TempDir(), "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(raw); err == nil {
		t.Fatal("an expired bundle verified")
	}
}

// The floor refuses an older version and a same version with other
// content, and survives a restart through its store.
func TestFloorRefusesAStaleBundleAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floor.json")
	f := bundle.FileFloor{Path: path}
	if err := bundle.CheckFloor(context.Background(), f, 5, "d5"); err != nil {
		t.Fatal(err)
	}
	if err := f.Store(context.Background(), bundle.Floor{Version: 5, Digest: "d5"}); err != nil {
		t.Fatal(err)
	}
	again := bundle.FileFloor{Path: path} // a restarted applier
	if err := bundle.CheckFloor(context.Background(), again, 4, "d4"); !errors.Is(err, bundle.ErrStale) {
		t.Fatalf("v4 after v5: got %v, want ErrStale", err)
	}
	if err := bundle.CheckFloor(context.Background(), again, 5, "other"); !errors.Is(err, bundle.ErrStale) {
		t.Fatalf("v5 with other content: got %v, want ErrStale", err)
	}
	if err := bundle.CheckFloor(context.Background(), again, 6, "d6"); err != nil {
		t.Fatalf("v6: %v", err)
	}
}

// R10 info: an applier set to one account (ROID_K8S_ACCOUNT) refuses a
// bundle of another account for its cluster. Without the setting, any
// account verifies (the cluster check still holds).
func TestAnotherAccountsBundleIsRefusedWhenTheAccountIsSet(t *testing.T) {
	r := newRig(t)
	b := body(4)
	b.Account = "acct-b"
	raw := r.seal(t, b)
	v := r.verifier(t)
	v.ExpectAccount("acct-a")
	if _, err := v.Verify(raw); !errors.Is(err, bundle.ErrAccount) {
		t.Fatalf("acct-b's bundle on acct-a's applier: got %v, want ErrAccount", err)
	}
	if _, err := v.Verify(r.seal(t, body(5))); err != nil {
		t.Fatalf("control, acct-a's bundle: %v", err)
	}
	if _, err := r.verifier(t).Verify(raw); err != nil {
		t.Fatalf("control, no account set: %v", err)
	}
}
