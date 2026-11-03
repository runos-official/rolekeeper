package revlog_test

// Replay checks the
// entry hashes and the anchored head, so a truncated or forged replay does
// not unseal a restored state.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer/revlog"
)

// Finding SIG12.
func TestTruncatedReplayRefused(t *testing.T) {
	l, err := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st := revlog.NewState(l)
	snap := st.Snapshot()
	_ = st.RevokePerson("p1")
	_ = st.RevokePerson("p2")
	r := revlog.RestoreState(l, snap)
	if err := r.Replay(l.Since(snap.Watermark)[:1]); !errors.Is(err, revlog.ErrTruncated) {
		t.Fatalf("tail-truncated replay: want ErrTruncated, got %v", err)
	}
	if _, err := r.PersonRevoked("p2"); !errors.Is(err, revlog.ErrReplayRequired) {
		t.Fatalf("state unsealed after a refused replay: %v", err)
	}
	if err := r.Replay(l.Since(snap.Watermark)); err != nil {
		t.Fatalf("full replay: %v", err)
	}
	if ok, _ := r.PersonRevoked("p2"); !ok {
		t.Fatal("p2 not revoked after full replay")
	}
}

// Finding SIG12.
func TestForgedEntryRefused(t *testing.T) {
	l, err := revlog.Open(filepath.Join(t.TempDir(), "rev.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st := revlog.NewState(l)
	snap := st.Snapshot()
	forged := revlog.Entry{Seq: snap.Watermark + 1, Kind: revlog.KindGrantRemoved, Subject: "whatever", Hash: "not-a-hash"}
	r := revlog.RestoreState(l, snap)
	if err := r.Replay([]revlog.Entry{forged}); !errors.Is(err, revlog.ErrChainBroken) {
		t.Fatalf("forged entry: want ErrChainBroken, got %v", err)
	}
}

// A truncated log FILE is caught only by a head anchored outside the log
// (12.11 "The log has an outside anchor").
// Finding SIG12.
func TestExternalHeadCatchesTruncatedLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rev.log")
	l, _ := revlog.Open(path)
	anchor, err := revlog.OpenHeadFile(filepath.Join(dir, "head"))
	if err != nil {
		t.Fatal(err)
	}
	st := revlog.NewState(l)
	snap := st.Snapshot()
	_ = st.RevokePerson("p1")
	_ = st.RevokePerson("p2")
	if err := anchor.Publish(l.Head()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	_ = os.WriteFile(path, []byte(lines[0]), 0o600)
	l2, err := revlog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	r := revlog.RestoreState(l2, snap)
	r.SetAnchor(anchor)
	if err := r.Replay(l2.Since(snap.Watermark)); !errors.Is(err, revlog.ErrTruncated) {
		t.Fatalf("truncated log file with external head: want ErrTruncated, got %v", err)
	}
	// The anchor survives a reopen.
	a2, err := revlog.OpenHeadFile(filepath.Join(dir, "head"))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := a2.Head(); s != 2 {
		t.Fatalf("reopened anchor head %d, want 2", s)
	}
}
