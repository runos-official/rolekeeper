package roottrust

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrRootRank: a document signed by an earlier root of the chain than the
// document a view holds. A view never goes back to an older root.
var ErrRootRank = errors.New("roottrust: signed by an earlier root than the document held")

// ChainVerifier is a Verifier that knows the chain: a Trust. Views use it to
// rank roots and to check a held document again at use.
type ChainVerifier interface {
	Verifier
	Rank(compact string) (int, bool)
	ValidUntil(compact string) (time.Time, error)
	Gen() uint64
	Now() time.Time
}

var _ ChainVerifier = (*Trust)(nil)

// Held is the root state of the one root-signed document a view holds. It
// is the high-water mark of root precedence (Rank) and the use-time check
// (Check): a view calls Check before it uses what the document says, so a
// document stops counting at the instant its root's overlap ends, or when
// the chain moves past its root, not at the next restart.
type Held struct {
	mu      sync.Mutex
	compact string
	rank    int
	until   time.Time
	gen     uint64
	err     error
	set     bool
}

// Set records compact (empty: the view holds an unsigned install pin).
func (h *Held) Set(v Verifier, compact string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.compact, h.rank, h.until, h.gen, h.err, h.set = compact, -1, time.Time{}, 0, nil, true
	c, ok := v.(ChainVerifier)
	if !ok || compact == "" {
		return
	}
	if r, ok := c.Rank(compact); ok {
		h.rank = r
	}
	h.until, h.err = c.ValidUntil(compact)
	h.gen = c.Gen()
}

// Rank is the chain rank of the held document's root (-1: none). A view
// refuses a document whose root ranks lower.
func (h *Held) Rank() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.set {
		return -1
	}
	return h.rank
}

// Check says whether the held document still counts now.
func (h *Held) Check(v Verifier, what string) error {
	c, ok := v.(ChainVerifier)
	if !ok {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.compact == "" {
		return nil
	}
	if h.err == nil && h.gen == c.Gen() && (h.until.IsZero() || c.Now().Before(h.until)) {
		return nil
	}
	h.until, h.err = c.ValidUntil(h.compact)
	h.gen = c.Gen()
	if h.err != nil {
		return fmt.Errorf("the held %s: %w", what, h.err)
	}
	return nil
}

// RankOf is the chain rank of compact's root under v (-1: none or unknown).
func RankOf(v Verifier, compact string) int {
	if c, ok := v.(ChainVerifier); ok && compact != "" {
		if r, ok := c.Rank(compact); ok {
			return r
		}
	}
	return -1
}
