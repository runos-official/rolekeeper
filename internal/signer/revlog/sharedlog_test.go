package revlog

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Two writers share one store. Each appends at the tail it last read; a
// writer whose tail is stale gets ErrConflict instead of a silent append
// behind the other writer's entry, so it can re-read and decide again.
func TestSharedLogAppendReportsAConflictToTheCaller(t *testing.T) {
	st := &MemShared{}
	now := func() time.Time { return time.Unix(1700000000, 0) }
	a, b := NewSharedLog(st, now), NewSharedLog(st, now)
	ctx := context.Background()
	if _, err := a.SinceContext(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SinceContext(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(KindCertRenewed, "serial:01", nil); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := b.Append(KindCertRenewed, "serial:01", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("a stale writer must get ErrConflict, got %v", err)
	}
	es, err := b.SinceContext(ctx, 0)
	if err != nil || len(es) != 1 || es[0].Subject != "serial:01" {
		t.Fatalf("after the conflict the writer reads the other entry: %v %+v", err, es)
	}
	e, err := b.Append(KindCertRevoked, "scope:x", map[string]int{"version": 1})
	if err != nil || e.Seq != 2 {
		t.Fatalf("after reading, the append follows the tail: %+v %v", e, err)
	}
	all, _ := st.Entries(ctx)
	if err := CheckChain(all); err != nil || len(all) != 2 {
		t.Fatalf("shared chain: %v, %d entries", err, len(all))
	}
}

// SinceContext returns only entries after seq and refuses a store whose
// chain is broken.
func TestSharedLogSinceReturnsNewerEntriesAndRefusesABrokenChain(t *testing.T) {
	st := &MemShared{}
	l := NewSharedLog(st, time.Now)
	for _, s := range []string{"a", "b", "c"} {
		if _, err := l.Append(KindCertRevoked, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	es, err := l.SinceContext(context.Background(), 1)
	if err != nil || len(es) != 2 || es[0].Subject != "b" {
		t.Fatalf("since 1: %v %+v", err, es)
	}
	st.mu.Lock()
	st.entries[1].Subject = "B"
	st.mu.Unlock()
	if _, err := l.SinceContext(context.Background(), 0); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a changed entry must be refused, got %v", err)
	}
}
