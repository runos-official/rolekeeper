package revlog

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// sharedLogTimeout bounds one call to the shared store.
const sharedLogTimeout = 5 * time.Second

// SharedLog is an Appender over a SharedStore for writers that must decide
// on the latest state: Append writes at the tail the log last read and
// returns ErrConflict when another writer appended first. It never retries
// on its own, because the caller's check may no longer hold; the caller
// reads again (SinceContext) and decides again.
type SharedLog struct {
	st  SharedStore
	Now func() time.Time

	mu       sync.Mutex
	tailSeq  uint64
	tailHash string
}

// NewSharedLog returns a log over st. It reads nothing until the first
// SinceContext or Append.
func NewSharedLog(st SharedStore, now func() time.Time) *SharedLog {
	if now == nil {
		now = time.Now
	}
	return &SharedLog{st: st, Now: now}
}

// SinceContext returns the entries after seq, with the whole chain checked,
// and moves the log's tail to the store's tail.
func (l *SharedLog) SinceContext(ctx context.Context, seq uint64) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, sharedLogTimeout)
	defer cancel()
	es, err := l.st.Entries(ctx)
	if err != nil {
		return nil, err
	}
	if err := CheckChain(es); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if n := len(es); n > 0 {
		l.tailSeq, l.tailHash = es[n-1].Seq, es[n-1].Hash
	} else {
		l.tailSeq, l.tailHash = 0, ""
	}
	l.mu.Unlock()
	if seq >= uint64(len(es)) {
		return nil, nil
	}
	return es[seq:], nil
}

// Since is SinceContext without a context. It returns nil when the store
// cannot be read; callers that must tell an error from an empty log use
// SinceContext.
func (l *SharedLog) Since(seq uint64) []Entry {
	es, _ := l.SinceContext(context.Background(), seq)
	return es
}

// Append writes one entry at the tail this log last read. ErrConflict
// means another writer appended first: read again, then decide again.
func (l *SharedLog) Append(kind Kind, subject string, payload any) (Entry, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Entry{}, err
		}
		raw = b
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Seq: l.tailSeq + 1, At: l.Now().UTC(), Kind: kind, Subject: subject, Payload: raw, Prev: l.tailHash}
	e.Hash = e.ComputeHash()
	ctx, cancel := context.WithTimeout(context.Background(), sharedLogTimeout)
	defer cancel()
	if err := l.st.AppendAt(ctx, e); err != nil {
		return Entry{}, fmt.Errorf("revlog: shared append: %w", err)
	}
	l.tailSeq, l.tailHash = e.Seq, e.Hash
	return e, nil
}
