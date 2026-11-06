package revlog_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/signer/revlog"
)

func TestAppendReopenAndSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.log")
	l, err := revlog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range []string{"a", "b", "c"} {
		e, err := l.Append(revlog.KindCredentialRevoked, s, nil)
		if err != nil {
			t.Fatal(err)
		}
		if e.Seq != uint64(i+1) {
			t.Fatalf("seq %d", e.Seq)
		}
	}
	l.Close()
	l2, err := revlog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if seq, _ := l2.Head(); seq != 3 {
		t.Fatalf("head %d", seq)
	}
	got := l2.Since(1)
	if len(got) != 2 || got[0].Subject != "b" || got[1].Subject != "c" {
		t.Fatalf("since(1) = %+v", got)
	}
	e, _ := l2.Append(revlog.KindPersonRevoked, "p", map[string]string{"why": "left"})
	if e.Seq != 4 || e.Prev == "" {
		t.Fatalf("append after reopen: %+v", e)
	}
}

func TestTamperedMiddleEntryIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.log")
	l, _ := revlog.Open(path)
	_, _ = l.Append(revlog.KindCertRevoked, "serial-1", nil)
	_, _ = l.Append(revlog.KindCertRevoked, "serial-2", nil)
	_, _ = l.Append(revlog.KindCertRevoked, "serial-3", nil)
	l.Close()
	raw, _ := os.ReadFile(path)
	bad := strings.Replace(string(raw), "serial-2", "serial-9", 1)
	_ = os.WriteFile(path, []byte(bad), 0o600)
	if _, err := revlog.Open(path); !errors.Is(err, revlog.ErrChainBroken) {
		t.Fatalf("want ErrChainBroken, got %v", err)
	}
}

func TestTruncationDetectedOnlyWithExternalHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.log")
	l, _ := revlog.Open(path)
	_, _ = l.Append(revlog.KindCertRevoked, "s1", nil)
	_, _ = l.Append(revlog.KindCertRevoked, "s2", nil)
	seq, head := l.Head()
	l.Close()
	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	_ = os.WriteFile(path, []byte(lines[0]), 0o600)
	l2, err := revlog.Open(path)
	if err != nil {
		t.Fatalf("a truncated chain is still a valid chain: %v", err)
	}
	if err := l2.CheckHead(seq, head); !errors.Is(err, revlog.ErrTruncated) {
		t.Fatalf("with the externally anchored head: want ErrTruncated, got %v", err)
	}
}

func TestStateReplayAndFailClosedBeforeReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.log")
	l, _ := revlog.Open(path)
	defer l.Close()
	st := revlog.NewState(l)
	snap := st.Snapshot()
	if err := st.RevokePerson("person-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveGrant("grant-7"); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeCredential("cred-3"); err != nil {
		t.Fatal(err)
	}
	r := revlog.RestoreState(l, snap)
	if _, err := r.PersonRevoked("person-1"); !errors.Is(err, revlog.ErrReplayRequired) {
		t.Fatalf("restored state must refuse before replay, got %v", err)
	}
	if err := r.Replay(l.Since(r.Watermark())); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		f    func(string) (bool, error)
		subj string
	}{{r.PersonRevoked, "person-1"}, {r.GrantRemoved, "grant-7"}, {r.CredentialRevoked, "cred-3"}} {
		ok, err := c.f(c.subj)
		if err != nil || !ok {
			t.Fatalf("%s after replay: %v %v", c.subj, ok, err)
		}
	}
}
