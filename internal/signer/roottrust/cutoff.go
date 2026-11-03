package roottrust

// The overlap cutoff: the current root alone ends its
// predecessor's overlap early, for the case where the old root may be
// compromised. A cutoff is a link of the root chain with the next sequence
// number. It only ever moves the end earlier, and every verifier honours it
// at the next use of a document the old root signed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/runos-official/rolekeeper/internal/signer"
	"github.com/runos-official/rolekeeper/internal/signer/internal/jws"
)

// CutoffType is the typ header of a cutoff signature.
const CutoffType = "roid-root-cutoff/1"

// Link kinds of the root chain.
const (
	KindHandover = "handover"
	KindCutoff   = "overlap-cutoff"
)

// ClockMargin: each verifier judges the overlap on its own clock, so the
// old root's documents stop counting this long before the stated end.
const ClockMargin = 5 * time.Minute

// Cutoff is what the current root signs to end its predecessor's overlap
// at Until.
type Cutoff struct {
	V        int       `json:"v"`
	Kind     string    `json:"kind"`
	Seq      uint64    `json:"seq"`
	Root     Root      `json:"root"`
	Retire   Root      `json:"retire"`
	IssuedAt time.Time `json:"issued_at"`
	Until    time.Time `json:"until"`
}

// NewCutoff builds link seq: root ends retire's overlap at until.
func NewCutoff(root, retire Root, seq uint64, issued, until time.Time) (Cutoff, error) {
	c := Cutoff{V: 1, Kind: KindCutoff, Seq: seq, Root: root, Retire: retire,
		IssuedAt: issued.UTC().Truncate(time.Second), Until: until.UTC().Truncate(time.Second)}
	return c, c.Check()
}

// Check refuses a cutoff that cannot be right.
func (c Cutoff) Check() error {
	switch {
	case c.V != 1 || c.Kind != KindCutoff:
		return fmt.Errorf("%w: cutoff version %d kind %q", ErrBadStatement, c.V, c.Kind)
	case c.Seq == 0:
		return fmt.Errorf("%w: the sequence number starts at 1", ErrBadStatement)
	case c.Root.same(c.Retire):
		return fmt.Errorf("%w: a root cannot cut its own overlap", ErrBadStatement)
	case c.Until.Before(c.IssuedAt):
		return fmt.Errorf("%w: the cutoff ends before it was issued", ErrBadStatement)
	}
	for _, r := range []Root{c.Root, c.Retire} {
		if r.Alg != signer.AlgEdDSA || r.KeyID == "" || r.check() != nil {
			return fmt.Errorf("%w: root %s", ErrBadStatement, r.Fingerprint())
		}
	}
	return nil
}

// Payload is the exact bytes the current root signs.
func (c Cutoff) Payload() ([]byte, error) { return json.Marshal(c) }

// SignCutoff makes the current root's signature over a cutoff. s must be a
// keyset-root signer.
func SignCutoff(s *signer.Signer, payload []byte) (string, error) {
	if s.Purpose() != signer.PurposeKeySetRoot {
		return "", signer.ErrWrongPurpose
	}
	return jws.Sign(s, CutoffType, payload)
}

// linkKind reads the kind of a link's statement without trusting it.
func linkKind(statement []byte) string {
	var k struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(statement, &k) == nil && k.Kind == KindCutoff {
		return KindCutoff
	}
	return KindHandover
}

// VerifyCutoff checks a cutoff bundle strictly: its own encoding, and the
// signature of the root it names (only that root signs it).
func VerifyCutoff(bundleJSON []byte) (Cutoff, error) {
	var b Bundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return Cutoff{}, fmt.Errorf("%w: %v", ErrBadStatement, err)
	}
	var c Cutoff
	dec := json.NewDecoder(bytes.NewReader(b.Statement))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrBadStatement, err)
	}
	if again, err := c.Payload(); err != nil || !bytes.Equal(again, b.Statement) {
		return c, fmt.Errorf("%w: the cutoff bytes are not its own encoding", ErrBadStatement)
	}
	if err := c.Check(); err != nil {
		return c, err
	}
	if b.Old != "" || b.New == "" {
		return c, fmt.Errorf("%w: only the current root signs a cutoff", ErrBadHandover)
	}
	h, err := jws.PeekHeader(b.New)
	if err != nil || h.Typ != CutoffType || h.Purpose != string(signer.PurposeKeySetRoot) {
		return c, fmt.Errorf("%w: wrong type or purpose in the cutoff signature", ErrBadHandover)
	}
	pk, err := c.Root.key()
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrBadHandover, err)
	}
	got, err := jws.Verify(b.New, pk, c.Root.Alg)
	if err != nil || !bytes.Equal(got, b.Statement) {
		return c, fmt.Errorf("%w: the cutoff is not signed by root %s", ErrBadHandover, c.Root.Fingerprint())
	}
	return c, nil
}

// Link is one decoded link of the root chain.
type Link struct {
	Raw       []byte
	Seq       uint64
	Kind      string
	Statement []byte // the signed statement bytes
	Handover  Statement
	Cutoff    Cutoff
	IssuedAt  time.Time
}

// decodeLink verifies one link's form and signatures, of either kind.
func decodeLink(raw []byte) (Link, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Link{}, fmt.Errorf("%w: %v", ErrBadStatement, err)
	}
	l := Link{Raw: append([]byte(nil), raw...), Statement: b.Statement, Kind: linkKind(b.Statement)}
	if l.Kind == KindCutoff {
		c, err := VerifyCutoff(raw)
		if err != nil {
			return l, err
		}
		l.Seq, l.Cutoff, l.IssuedAt = c.Seq, c, c.IssuedAt
		return l, nil
	}
	st, err := VerifyBundle(raw)
	if err != nil {
		return l, err
	}
	l.Seq, l.Handover, l.IssuedAt = st.Seq, st, st.IssuedAt
	return l, nil
}

// CurrentRoot is the newest root a chain hands over to (false: no handover).
func CurrentRoot(links []Link) (Root, bool) {
	for i := len(links) - 1; i >= 0; i-- {
		if links[i].Kind == KindHandover {
			return links[i].Handover.To, true
		}
	}
	return Root{}, false
}

// applyCutoff moves the predecessor's overlap end earlier. The caller
// holds the lock and checked the sequence number.
func (t *Trust) applyCutoff(l Link, persist bool) error {
	c := l.Cutoff
	head := len(t.roots) - 1
	if head < 1 || !t.roots[head].same(c.Root) || !t.roots[head-1].same(c.Retire) {
		return fmt.Errorf("%w: a cutoff comes from the current root and ends its predecessor's overlap", ErrNotCurrent)
	}
	if !c.Until.Before(t.roots[head-1].until) {
		return fmt.Errorf("%w: a cutoff only ends the overlap earlier (now %s)", ErrBadStatement, t.roots[head-1].until.UTC().Format(time.RFC3339))
	}
	if c.IssuedAt.After(t.now().Add(time.Hour)) {
		return fmt.Errorf("%w: the cutoff is dated in the future", ErrBadStatement)
	}
	if persist && t.path != "" {
		if err := writeState(t.path, t.snapshot(l.Raw)); err != nil {
			return fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	t.roots[head-1].until = c.Until
	t.gen++
	t.bundles = append(t.bundles, l.Raw)
	return nil
}
