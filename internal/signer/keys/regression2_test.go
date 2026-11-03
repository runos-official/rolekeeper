package keys_test

// Key-custody regression tests. Each one pins a defect that was found
// and fixed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/keys"
	"github.com/runos-official/rolekeeper/internal/signer/revlog"
)

type r5rig struct {
	b   *signer.SoftBackend
	lg  *revlog.Log
	m   *keys.Manager
	now func() time.Time
}

func newR5Rig(t *testing.T) *r5rig {
	t.Helper()
	lg, err := revlog.Open(filepath.Join(t.TempDir(), "keys.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	b := signer.NewSoftBackend()
	m := keys.NewManager(b, lg, now)
	if _, err := m.Bootstrap(context.Background(), signer.PurposeEmergencyRoster, signer.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	return &r5rig{b: b, lg: lg, m: m, now: now}
}

// In roid the key-set log is the keyset_log table, written by
// the roid role, chained with an unkeyed SHA-256. Anyone who can append a
// row can recompute the chain. Replay applies whatever document an entry
// carries: here an entry that lowers an account's emergency-roster floor,
// which "only goes up". The lowered floor is then the install pin that
// /v1/emergency-roster/keys serves to every new verifier.
func TestReplayRefusesAnEntryThatLowersAFloor(t *testing.T) {
	r := newR5Rig(t)
	p := signer.PurposeEmergencyRoster
	if err := r.m.SetMinVersion(p, "acct-1", 9); err != nil {
		t.Fatal(err)
	}
	forged := r.m.Doc(p)
	forged.Version++
	forged.MinVersions = map[string]uint64{"acct-1": 1}
	if _, err := r.lg.Append(revlog.KindKeySetPublished, string(p), forged); err != nil {
		t.Fatal(err)
	}
	restored := keys.RestoreManager(r.b, r.lg, r.now, keys.Snapshot{})
	if err := restored.Replay(r.lg.Since(0)); err != nil {
		return // refused: fixed
	}
	if got := restored.Doc(p).MinVersion("acct-1"); got < 9 {
		t.Fatalf("Replay accepted an unsigned log entry that lowers the acct-1 floor from 9 to %d", got)
	}
}

// The same unauthenticated entry can swap the public half of the
// active key. Replay never compares a key-set entry with custody, so the
// install pin now names an attacker key under the real kid, while the
// manager keeps signing with the custody key.
func TestReplayRefusesAPublicKeyThatCustodyDoesNotHold(t *testing.T) {
	r := newR5Rig(t)
	p := signer.PurposeEmergencyRoster
	forged := r.m.Doc(p)
	forged.Version++
	forged.Keys = append([]keys.PublishedKey(nil), forged.Keys...)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	kid := ""
	for i := range forged.Keys {
		if forged.Keys[i].State == keys.StateActive {
			forged.Keys[i].PublicDER = der
			kid = forged.Keys[i].Kid
		}
	}
	if _, err := r.lg.Append(revlog.KindKeySetPublished, string(p), forged); err != nil {
		t.Fatal(err)
	}
	restored := keys.RestoreManager(r.b, r.lg, r.now, keys.Snapshot{})
	if err := restored.Replay(r.lg.Since(0)); err != nil {
		return
	}
	held, err := r.b.PublicKey(context.Background(), kid)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.Doc(p).Find(kid); got != nil && !bytes.Equal(got.PublicDER, held.PublicDER) {
		t.Fatalf("Replay installed a pin whose active key %s is not the key custody holds", kid)
	}
}
