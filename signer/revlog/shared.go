package revlog

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrConflict means a shared append named a tail that is no longer the
// tail: another writer appended first. The caller reads again.
var ErrConflict = errors.New("revlog: the log moved on (append conflict)")

// SharedStore is a log that several processes share, held by the signer:
// the key-set log lives in the signer's own database, never in the
// identity database. Entries returns the whole log with its chain checked.
// AppendAt stores e only when e.Seq is the next sequence number and e.Prev
// the tail's hash, atomically, and refuses with ErrConflict otherwise.
type SharedStore interface {
	Entries(ctx context.Context) ([]Entry, error)
	AppendAt(ctx context.Context, e Entry) error
}

// CheckChain checks that entries start at 1 and link without a gap.
func CheckChain(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		if e.Seq != uint64(i+1) || e.Prev != prev || e.Hash != e.ComputeHash() {
			return fmt.Errorf("%w at seq %d", ErrChainBroken, e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// MemShared is an in-memory SharedStore for tests and one process.
type MemShared struct {
	mu      sync.Mutex
	entries []Entry
}

func (m *MemShared) Entries(context.Context) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Entry(nil), m.entries...), nil
}

func (m *MemShared) AppendAt(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := ""
	if n := len(m.entries); n > 0 {
		prev = m.entries[n-1].Hash
	}
	if e.Seq != uint64(len(m.entries)+1) || e.Prev != prev {
		return ErrConflict
	}
	if e.Hash != e.ComputeHash() {
		return ErrChainBroken
	}
	m.entries = append(m.entries, e)
	return nil
}
