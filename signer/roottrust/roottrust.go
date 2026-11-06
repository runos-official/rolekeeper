// Package roottrust lets a verifier follow the offline root from one key to
// another without a rebuild (for example a move to a root held in another
// way).
//
// A handover statement says: "the root with public key A hands over to the
// root with public key B, and A stays valid until a stated time". Both roots
// sign the same statement bytes. The old root's signature is the authority.
// The new root's signature proves that somebody holds B: a handover to a key
// that nobody holds would lock every verifier out.
//
// A verifier pins one root, as before. It then applies the handover bundle
// (Trust.Apply). From then on it accepts a root-signed document from either
// root until the overlap ends, and from the new root only after that.
// Nothing under the root changes: key sets, anchor bundles, certificates and
// CA keys stay as they are, because they chain to "the root", not to one of
// its keys. The new root signs the next key set as usual.
package roottrust

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/runos-official/rolekeeper/signer"
	"github.com/runos-official/rolekeeper/signer/jws"
)

// HandoverType is the typ header of a handover signature.
const HandoverType = "roid-root-handover/1"

// MaxOverlap is the longest time the old root may stay valid after a
// handover. A long overlap keeps a retired key useful to a thief.
const MaxOverlap = 180 * 24 * time.Hour

var (
	ErrBadStatement = errors.New("roottrust: the handover statement is not acceptable")
	ErrNotCurrent   = errors.New("roottrust: the handover does not start from the root this verifier trusts now")
	ErrBadHandover  = errors.New("roottrust: the handover signatures do not check")
	ErrRootExpired  = errors.New("roottrust: signed by a root whose overlap has ended")
	// ErrRootRetired: the old root signed this document after the handover
	// (or gave no signing time). Once a handover is accepted only the new
	// root signs new documents.
	ErrRootRetired = errors.New("roottrust: the old root signed this after the handover; only the new root signs new documents")
	ErrState       = errors.New("roottrust: the trust state is unreadable or does not match the pinned root")
)

// Root is the public record of one root key.
type Root struct {
	KeyID     string           `json:"key_id"`
	Alg       signer.Algorithm `json:"alg"`
	PublicDER []byte           `json:"public_der"`
}

func (r Root) same(o Root) bool {
	return r.Alg == o.Alg && subtle.ConstantTimeCompare(r.PublicDER, o.PublicDER) == 1
}

func (r Root) key() (crypto.PublicKey, error) {
	return signer.KeyInfo{Algorithm: r.Alg, PublicDER: r.PublicDER}.PublicKey()
}

// Fingerprint is the first 16 hex digits of the SHA-256 of the public key.
func (r Root) Fingerprint() string {
	h := sha256.Sum256(r.PublicDER)
	return hex.EncodeToString(h[:8])
}

// StatementVersion is the statement format. Version 2 carries the
// sequence number of the handover in the root chain.
const StatementVersion = 2

// Statement is what both roots sign. Seq is the handover's place in the
// root chain: the first handover from the pinned root is 1, the next 2.
type Statement struct {
	V            int       `json:"v"`
	Seq          uint64    `json:"seq"`
	From         Root      `json:"from"`
	To           Root      `json:"to"`
	IssuedAt     time.Time `json:"issued_at"`
	OverlapUntil time.Time `json:"overlap_until"`
}

// NewStatement builds the statement for handover seq of the root chain,
// which starts at issued.
func NewStatement(from, to Root, seq uint64, issued time.Time, overlap time.Duration) (Statement, error) {
	s := Statement{V: StatementVersion, Seq: seq, From: from, To: to, IssuedAt: issued.UTC().Truncate(time.Second), OverlapUntil: issued.UTC().Truncate(time.Second).Add(overlap)}
	return s, s.Check()
}

// Check refuses a statement that cannot be right.
func (s Statement) Check() error {
	switch {
	case s.V != StatementVersion:
		return fmt.Errorf("%w: version %d", ErrBadStatement, s.V)
	case s.Seq == 0:
		return fmt.Errorf("%w: the sequence number starts at 1", ErrBadStatement)
	case s.From.Alg != signer.AlgEdDSA || s.To.Alg != signer.AlgEdDSA:
		return fmt.Errorf("%w: both roots must be %s", ErrBadStatement, signer.AlgEdDSA)
	case s.From.same(s.To):
		return fmt.Errorf("%w: the new root is the old root", ErrBadStatement)
	case !s.OverlapUntil.After(s.IssuedAt):
		return fmt.Errorf("%w: the overlap does not end after the handover starts", ErrBadStatement)
	case s.OverlapUntil.Sub(s.IssuedAt) > MaxOverlap:
		return fmt.Errorf("%w: the overlap is longer than %s", ErrBadStatement, MaxOverlap)
	}
	for _, r := range []Root{s.From, s.To} {
		if _, err := r.key(); err != nil {
			return fmt.Errorf("%w: public key %s does not parse as %s", ErrBadStatement, r.Fingerprint(), r.Alg)
		}
		if r.KeyID == "" {
			return fmt.Errorf("%w: a root has no key id", ErrBadStatement)
		}
	}
	return nil
}

// Payload is the exact bytes both roots sign.
func (s Statement) Payload() ([]byte, error) { return json.Marshal(s) }

// DigestOf is the hex SHA-256 of the statement bytes. The custodians confirm
// the first 16 characters.
func DigestOf(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// Bundle is the file that goes to verifiers: the statement bytes and the two
// signatures (compact JWS over those bytes).
type Bundle struct {
	Statement []byte `json:"statement"`
	Old       string `json:"old_signature,omitempty"`
	New       string `json:"new_signature,omitempty"`
}

// SignSide makes one root's signature over the statement bytes. s must be a
// keyset-root signer.
func SignSide(s *signer.Signer, payload []byte) (string, error) {
	if s.Purpose() != signer.PurposeKeySetRoot {
		return "", signer.ErrWrongPurpose
	}
	return jws.Sign(s, HandoverType, payload)
}

// Decode reads a bundle and its statement strictly.
func Decode(bundleJSON []byte) (Bundle, Statement, error) {
	var b Bundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return b, Statement{}, fmt.Errorf("%w: %v", ErrBadStatement, err)
	}
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(b.Statement))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return b, st, fmt.Errorf("%w: %v", ErrBadStatement, err)
	}
	if again, err := st.Payload(); err != nil || !bytes.Equal(again, b.Statement) {
		return b, st, fmt.Errorf("%w: the statement bytes are not its own encoding", ErrBadStatement)
	}
	return b, st, st.Check()
}

func verifyHandoverSig(compact string, r Root, payload []byte) error {
	h, err := jws.PeekHeader(compact)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadHandover, err)
	}
	if h.Typ != HandoverType || h.Purpose != string(signer.PurposeKeySetRoot) {
		return fmt.Errorf("%w: wrong type or purpose in the signature header", ErrBadHandover)
	}
	pk, err := r.key()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadHandover, err)
	}
	got, err := jws.Verify(compact, pk, r.Alg)
	if err != nil {
		return fmt.Errorf("%w: root %s: %v", ErrBadHandover, r.Fingerprint(), err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("%w: root %s signed other bytes", ErrBadHandover, r.Fingerprint())
	}
	return nil
}

// VerifyNewSignature checks only the new root's signature of a bundle. The old
// root signs after it: a handover to a key that nobody holds is never started.
func VerifyNewSignature(bundleJSON []byte) error {
	b, st, err := Decode(bundleJSON)
	if err != nil {
		return err
	}
	if b.New == "" {
		return fmt.Errorf("%w: the new root has not signed", ErrBadHandover)
	}
	return verifyHandoverSig(b.New, st.To, b.Statement)
}

// VerifyBundle checks both signatures of a bundle against the roots that its
// own statement names. It does not say whether a verifier trusts the old
// root: Trust.Apply does.
func VerifyBundle(bundleJSON []byte) (Statement, error) {
	b, st, err := Decode(bundleJSON)
	if err != nil {
		return st, err
	}
	if b.Old == "" || b.New == "" {
		return st, fmt.Errorf("%w: both the old root and the new root must sign", ErrBadHandover)
	}
	if err := verifyHandoverSig(b.Old, st.From, b.Statement); err != nil {
		return st, err
	}
	if err := verifyHandoverSig(b.New, st.To, b.Statement); err != nil {
		return st, err
	}
	return st, nil
}

// Verifier is what a key-set view or an anchor view asks to check a
// root-signed document. Trust implements it.
type Verifier interface {
	// Verify checks a compact JWS signed by a root this verifier accepts now
	// and returns its payload.
	Verify(compact string) ([]byte, error)
}

type entry struct {
	Root
	pub   crypto.PublicKey
	until time.Time // zero: no end
	since time.Time // the handover that made this root current (zero: the pin)
}

// Trust is a verifier's list of accepted roots: the pinned one, and the
// ones that applied handovers added.
type Trust struct {
	mu      sync.Mutex
	now     func() time.Time
	roots   []entry
	bundles [][]byte
	path    string
	gen     uint64 // moves with every applied handover
}

var _ Verifier = (*Trust)(nil)

// New pins one root. A nil now means time.Now.
func New(pin Root, now func() time.Time) (*Trust, error) {
	if now == nil {
		now = time.Now
	}
	pk, err := pin.key()
	if err != nil {
		return nil, fmt.Errorf("roottrust: the pinned root: %w", err)
	}
	return &Trust{now: now, roots: []entry{{Root: pin, pub: pk}}}, nil
}

type stateFile struct {
	Pin     Root              `json:"pin"`
	Bundles []json.RawMessage `json:"bundles"`
}

// Open is New plus a state file that keeps the handovers applied. The file
// is checked again at every start, and one that does not match the pin or
// does not verify fails closed.
func Open(pin Root, statePath string, now func() time.Time) (*Trust, error) {
	t, err := New(pin, now)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(statePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	default:
		var sf stateFile
		if err := json.Unmarshal(b, &sf); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrState, err)
		}
		if !sf.Pin.same(pin) {
			return nil, fmt.Errorf("%w: it was written for another pinned root", ErrState)
		}
		for _, raw := range sf.Bundles {
			if _, err := t.apply(raw, false); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrState, err)
			}
		}
	}
	t.path = statePath
	return t, nil
}

// Apply installs one handover bundle. It must be the next link of the
// chain: the next sequence number, from the root this verifier trusts now
// (no end time), with both signatures and an overlap of at most
// MaxOverlap. A link that is already applied is a no-op.
func (t *Trust) Apply(bundleJSON []byte) (Statement, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.apply(bundleJSON, true)
}

func (t *Trust) apply(bundleJSON []byte, persist bool) (Statement, error) {
	l, err := decodeLink(bundleJSON)
	if err != nil {
		return l.Handover, err
	}
	st := l.Handover
	held := uint64(len(t.bundles))
	switch {
	case l.Seq <= held:
		// A sequence the verifier holds: the same link again changes
		// nothing, any other link there is a fork or a rollback.
		if bytes.Equal(statementOf(t.bundles[l.Seq-1]), l.Statement) {
			return st, nil
		}
		return st, fmt.Errorf("%w: link %d is not the one this verifier holds", ErrFork, l.Seq)
	case l.Seq > held+1:
		return st, fmt.Errorf("%w: link %d follows %d", ErrMissingLink, l.Seq, held)
	}
	if held > 0 {
		if prev, err := decodeLink(t.bundles[held-1]); err == nil && l.IssuedAt.Before(prev.IssuedAt) {
			return st, fmt.Errorf("%w: link %d is dated before link %d", ErrBadStatement, l.Seq, prev.Seq)
		}
	}
	if l.Kind == KindCutoff {
		return Statement{Seq: l.Seq}, t.applyCutoff(l, persist)
	}
	for _, e := range t.roots {
		if e.same(st.To) {
			return st, fmt.Errorf("%w: the new root is one this verifier already holds", ErrNotCurrent)
		}
	}
	head := t.roots[len(t.roots)-1]
	if !head.until.IsZero() || !head.same(st.From) {
		return st, fmt.Errorf("%w: it starts from root %s", ErrNotCurrent, st.From.Fingerprint())
	}
	if st.IssuedAt.After(t.now().Add(time.Hour)) {
		return st, fmt.Errorf("%w: the handover is dated in the future", ErrBadStatement)
	}
	pk, err := st.To.key()
	if err != nil {
		return st, err
	}
	if persist && t.path != "" {
		sf := t.snapshot(bundleJSON)
		if err := writeState(t.path, sf); err != nil {
			return st, fmt.Errorf("%w: %v", ErrState, err)
		}
	}
	t.roots[len(t.roots)-1].until = st.OverlapUntil
	t.roots = append(t.roots, entry{Root: st.To, pub: pk, since: st.IssuedAt})
	t.gen++
	t.bundles = append(t.bundles, append([]byte(nil), bundleJSON...))
	return st, nil
}

// statementOf is the signed statement bytes of a stored link.
func statementOf(raw []byte) []byte {
	var b Bundle
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return b.Statement
}

func (t *Trust) snapshot(extra []byte) stateFile {
	sf := stateFile{Pin: t.roots[0].Root}
	for _, b := range t.bundles {
		sf.Bundles = append(sf.Bundles, b)
	}
	if extra != nil {
		sf.Bundles = append(sf.Bundles, extra)
	}
	return sf
}

func writeState(path string, sf stateFile) error {
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Accepted lists the roots a document may be signed by right now.
func (t *Trust) Accepted() []Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.acceptedLocked(t.now())
}

func (t *Trust) acceptedLocked(now time.Time) []Root {
	var out []Root
	for _, e := range t.roots {
		if e.until.IsZero() || now.Before(e.until) {
			out = append(out, e.Root)
		}
	}
	return out
}

// Current is the newest root.
func (t *Trust) Current() Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.roots[len(t.roots)-1].Root
}

// Verify checks a compact JWS against every root accepted now. A signature
// that checks under a root whose overlap has ended gets ErrRootExpired, which
// also satisfies errors.Is for the bad-signature error of the jws package.
func (t *Trust) Verify(compact string) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	payload, _, _, err := t.checkLocked(compact)
	return payload, err
}

// checkLocked is the one root rule, evaluated now. A document
// counts when the current root signed it, or when the direct predecessor
// signed it before the handover that retired it (its signing time, the
// payload's issued_at or iat, is before that handover) and the
// predecessor's overlap has not ended. It returns the payload, the rank of
// the signing root (0: the pin) and the instant the document stops counting
// (zero: no end).
func (t *Trust) checkLocked(compact string) ([]byte, int, time.Time, error) {
	for i, e := range t.roots {
		payload, err := jws.Verify(compact, e.pub, e.Alg)
		if err != nil {
			continue
		}
		at, ok := signingTime(payload)
		until, err := t.ruleLocked(i, at, ok)
		if err != nil {
			return nil, i, until, err
		}
		return payload, i, until, nil
	}
	return nil, -1, time.Time{}, jws.ErrBadSignature
}

// ruleLocked is the one root rule for a document root i signed at at
// (hasTime false: the document gives no signing time). It returns the
// instant the document stops counting (zero: no end).
func (t *Trust) ruleLocked(i int, at time.Time, hasTime bool) (time.Time, error) {
	head := len(t.roots) - 1
	if i == head {
		return time.Time{}, nil
	}
	e := t.roots[i]
	end := e.until.Add(-ClockMargin) // verifiers' clocks differ
	if i != head-1 || !t.now().Before(end) {
		return end, fmt.Errorf("%w: %w: root %s, overlap ended %s; the new root must re-sign every key set before the overlap ends (%s)",
			ErrRootExpired, jws.ErrBadSignature, e.Fingerprint(), t.endOfLocked(e.Fingerprint()), RunbookStep)
	}
	if !hasTime || !at.Before(t.roots[head].since) {
		return end, fmt.Errorf("%w: %w: root %s, handover %s", ErrRootRetired, jws.ErrBadSignature,
			e.Fingerprint(), t.roots[head].since.UTC().Format(time.RFC3339))
	}
	return end, nil
}

// VerifyRaw checks a raw signature (not a JWS) by a root of the chain over
// msg, made at signedAt (zero: unknown), under the one root rule. Ed25519
// signs msg itself; P-256 signs its SHA-256 (ASN.1).
func (t *Trust) VerifyRaw(msg, sig []byte, signedAt time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, e := range t.roots {
		if !rawVerify(e.pub, msg, sig) {
			continue
		}
		_, err := t.ruleLocked(i, signedAt, !signedAt.IsZero())
		return err
	}
	return jws.ErrBadSignature
}

// signingTime reads a document's own signing time: issued_at (RFC 3339) or
// iat (Unix seconds), as every root-signed document carries one.
func signingTime(payload []byte) (time.Time, bool) {
	var d struct {
		IssuedAt *time.Time `json:"issued_at"`
		Iat      *int64     `json:"iat"`
	}
	if json.Unmarshal(payload, &d) != nil {
		return time.Time{}, false
	}
	switch {
	case d.IssuedAt != nil && !d.IssuedAt.IsZero():
		return *d.IssuedAt, true
	case d.Iat != nil:
		return time.Unix(*d.Iat, 0), true
	}
	return time.Time{}, false
}

// Rank is the position in the chain of the root that signed compact (0:
// the pin), whether or not the document still counts. A view refuses a
// document whose rank is below the one it holds.
func (t *Trust) Rank(compact string) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, e := range t.roots {
		if _, err := jws.Verify(compact, e.pub, e.Alg); err == nil {
			return i, true
		}
	}
	return -1, false
}

// ValidUntil checks compact now and returns the instant it stops counting
// (zero: no end while the chain stays as it is). A view checks again at
// that instant and whenever Gen moves.
func (t *Trust) ValidUntil(compact string) (time.Time, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _, until, err := t.checkLocked(compact)
	return until, err
}

// Pin is the pinned original root.
func (t *Trust) Pin() Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.roots[0].Root
}

// CurrentRank is the rank of the current root.
func (t *Trust) CurrentRank() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.roots) - 1
}

// Now is the trust's clock.
func (t *Trust) Now() time.Time { return t.now() }

// Gen moves with every handover the trust applies.
func (t *Trust) Gen() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

func (t *Trust) endOfLocked(fp string) string {
	for _, e := range t.roots {
		if e.Fingerprint() == fp {
			return e.until.UTC().Format(time.RFC3339)
		}
	}
	return ""
}
