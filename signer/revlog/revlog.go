// Package revlog is the append-only revocation log. It lives
// outside the identity database and outside the key store. Every
// revocation, grant removal, key compromise and key-set change is written
// here first, then applied. After a restore, each component replays the log
// from its snapshot watermark before it signs or decides.
//
// Format: JSON lines, each entry hash-chained to the one before. The chain
// detects edits; truncation is detected only against an externally anchored
// head (CheckHead).
//
// Every Replay first calls VerifyReplay. It
// checks each entry hash, the chain between entries, gaps, and that the
// entries reach every anchored head: the log's own head, and an external
// head (HeadFile, the stand-in for an external audit sink). A replay
// that fails the check applies nothing and leaves the state sealed.
package revlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindKeyCompromised Kind = "key.compromised"
	// KindKeyDisabled: custody disabled a key. The signer replays
	// these before it serves, so a restore of its database never brings the
	// private half back.
	KindKeyDisabled       Kind = "key.disabled"
	KindKeySetPublished   Kind = "keyset.published"
	KindCertRevoked       Kind = "cert.revoked"
	KindCredentialRevoked Kind = "credential.revoked"
	KindPersonRevoked     Kind = "person.revoked"
	KindGrantRemoved      Kind = "grant.removed"
	// KindLegacyImported records a legacy certificate record imported into
	// the signed agent list.
	KindLegacyImported Kind = "legacy.imported"
	// KindCertRenewed records that a certificate has a successor, so the
	// one-successor rule survives a restart.
	KindCertRenewed Kind = "cert.renewed"
)

var (
	ErrChainBroken    = errors.New("revlog: chain broken")
	ErrTruncated      = errors.New("revlog: log is shorter than the anchored head")
	ErrReplayRequired = errors.New("revlog: restored state must replay the revocation log first")
)

type Entry struct {
	Seq     uint64          `json:"seq"`
	At      time.Time       `json:"at"`
	Kind    Kind            `json:"kind"`
	Subject string          `json:"subject"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Prev    string          `json:"prev"`
	Hash    string          `json:"hash"`
}

// ComputeHash is the chain hash of e: the SHA-256 of its JSON form with
// Hash empty. A log kept somewhere other than a file (a database table)
// uses it to build and check the same chain.
func (e Entry) ComputeHash() string { return e.computeHash() }

func (e Entry) computeHash() string {
	c := e
	c.Hash = ""
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Appender is what components write to.
type Appender interface {
	Append(kind Kind, subject string, payload any) (Entry, error)
}

type Log struct {
	mu      sync.Mutex
	f       *os.File
	entries []Entry
	Now     func() time.Time
}

// Open reads and verifies an existing log (or creates one) and opens it for
// append only.
func Open(path string) (*Log, error) {
	l := &Log{Now: time.Now}
	if rf, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(rf)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		prev := ""
		for sc.Scan() {
			var e Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				rf.Close()
				return nil, fmt.Errorf("%w: %v", ErrChainBroken, err)
			}
			if e.Prev != prev || e.Hash != e.computeHash() || e.Seq != uint64(len(l.entries)+1) {
				rf.Close()
				return nil, fmt.Errorf("%w at seq %d", ErrChainBroken, e.Seq)
			}
			prev = e.Hash
			l.entries = append(l.entries, e)
		}
		rf.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Close() error { return l.f.Close() }

// Append writes and fsyncs one entry before it returns.
func (l *Log) Append(kind Kind, subject string, payload any) (Entry, error) {
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
	prev := ""
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Hash
	}
	e := Entry{Seq: uint64(len(l.entries) + 1), At: l.Now().UTC(), Kind: kind, Subject: subject, Payload: raw, Prev: prev}
	e.Hash = e.computeHash()
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, err
	}
	l.entries = append(l.entries, e)
	return e, nil
}

// Anchor is a log head (sequence number and hash) that a replay must reach.
// *Log is an Anchor for its own head. HeadFile is an Anchor held outside the
// log, so a truncated log file shows.
type Anchor interface {
	Head() (uint64, string)
}

// AnchorOf returns the anchors for a component that writes to app: app
// itself when it exposes a head, plus every non-nil extra anchor.
func AnchorOf(app Appender, extra ...Anchor) []Anchor {
	var out []Anchor
	if a, ok := app.(Anchor); ok && a != nil {
		out = append(out, a)
	}
	for _, a := range extra {
		if a != nil {
			out = append(out, a)
		}
	}
	return out
}

// VerifyReplay checks the entries after watermark before a restored
// component applies them: no gap, a correct hash on every entry, each Prev
// equal to the hash before it, and every anchored head above the watermark
// present with the same hash. A short entry list gives ErrTruncated; any
// other mismatch gives ErrChainBroken.
func VerifyReplay(entries []Entry, watermark uint64, anchors ...Anchor) error {
	next := watermark + 1
	prev := ""
	byseq := map[uint64]string{}
	for _, e := range entries {
		if e.Seq <= watermark {
			if e.Seq == watermark {
				prev = e.Hash
			}
			continue
		}
		if e.Seq != next {
			return fmt.Errorf("%w: gap before seq %d", ErrChainBroken, e.Seq)
		}
		if e.Hash != e.computeHash() {
			return fmt.Errorf("%w: bad hash at seq %d", ErrChainBroken, e.Seq)
		}
		if prev != "" && e.Prev != prev {
			return fmt.Errorf("%w: prev mismatch at seq %d", ErrChainBroken, e.Seq)
		}
		prev = e.Hash
		byseq[e.Seq] = e.Hash
		next++
	}
	for _, a := range anchors {
		hs, hh := a.Head()
		if hs <= watermark {
			continue
		}
		got, ok := byseq[hs]
		if !ok {
			return fmt.Errorf("%w: replay ends at seq %d, anchored head is %d", ErrTruncated, next-1, hs)
		}
		if got != hh {
			return fmt.Errorf("%w: anchored head hash differs at seq %d", ErrChainBroken, hs)
		}
	}
	return nil
}

// HeadFile is a log head stored outside the log: the stand-in for the
// audit sink that receives the head hash at a fixed interval. Publish
// never moves the head back.
type HeadFile struct {
	mu   sync.Mutex
	path string
	seq  uint64
	hash string
}

// OpenHeadFile loads the head stored at path, or starts with no head.
func OpenHeadFile(path string) (*HeadFile, error) {
	h := &HeadFile{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return nil, fmt.Errorf("%w: head file", ErrChainBroken)
	}
	seq, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: head file: %v", ErrChainBroken, err)
	}
	h.seq, h.hash = seq, f[1]
	return h, nil
}

// Publish stores a new head. A lower sequence number is refused.
func (h *HeadFile) Publish(seq uint64, hash string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if seq < h.seq {
		return fmt.Errorf("%w: head %d is below the anchored %d", ErrChainBroken, seq, h.seq)
	}
	tmp := h.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d %s\n", seq, hash); err != nil {
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
	if err := os.Rename(tmp, h.path); err != nil {
		return err
	}
	h.seq, h.hash = seq, hash
	return nil
}

// Head returns the anchored head.
func (h *HeadFile) Head() (uint64, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seq, h.hash
}

// Head returns the last sequence number and hash. RunOS would anchor this
// outside the log (for example in each root-signed key-set reset or with an
// external witness) so that truncation shows.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return 0, ""
	}
	e := l.entries[len(l.entries)-1]
	return e.Seq, e.Hash
}

// CheckHead refuses a log that does not contain the anchored head.
func (l *Log) CheckHead(seq uint64, hash string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq == 0 {
		return nil
	}
	if uint64(len(l.entries)) < seq {
		return ErrTruncated
	}
	if l.entries[seq-1].Hash != hash {
		return ErrChainBroken
	}
	return nil
}

// Since returns the entries after seq.
func (l *Log) Since(seq uint64) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq >= uint64(len(l.entries)) {
		return nil
	}
	out := make([]Entry, len(l.entries)-int(seq))
	copy(out, l.entries[seq:])
	return out
}

// State holds the person, grant and credential revocations that the
// decision path and token verifiers consult. It is the "identity database"
// part that a backup restores.
type State struct {
	mu          sync.Mutex
	log         Appender
	persons     map[string]bool
	grants      map[string]bool
	creds       map[string]bool
	watermark   uint64
	needsReplay bool
	anchor      Anchor
}

type StateSnapshot struct {
	Watermark   uint64   `json:"watermark"`
	Persons     []string `json:"persons"`
	Grants      []string `json:"grants"`
	Credentials []string `json:"credentials"`
}

func NewState(log Appender) *State {
	return &State{log: log, persons: map[string]bool{}, grants: map[string]bool{}, creds: map[string]bool{}}
}

// RestoreState loads a backup. The result refuses every query until Replay.
func RestoreState(log Appender, s StateSnapshot) *State {
	st := NewState(log)
	for _, p := range s.Persons {
		st.persons[p] = true
	}
	for _, g := range s.Grants {
		st.grants[g] = true
	}
	for _, c := range s.Credentials {
		st.creds[c] = true
	}
	st.watermark = s.Watermark
	st.needsReplay = true
	return st
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *State) Snapshot() StateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StateSnapshot{Watermark: s.watermark, Persons: keys(s.persons), Grants: keys(s.grants), Credentials: keys(s.creds)}
}

func (s *State) Watermark() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watermark
}

func (s *State) record(kind Kind, subject string) error {
	e, err := s.log.Append(kind, subject, nil) // log first, then apply
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apply(e)
	return nil
}

func (s *State) apply(e Entry) {
	switch e.Kind {
	case KindPersonRevoked:
		s.persons[e.Subject] = true
	case KindGrantRemoved:
		s.grants[e.Subject] = true
	case KindCredentialRevoked:
		s.creds[e.Subject] = true
	}
	if e.Seq > s.watermark {
		s.watermark = e.Seq
	}
}

func (s *State) RevokePerson(id string) error     { return s.record(KindPersonRevoked, id) }
func (s *State) RemoveGrant(id string) error      { return s.record(KindGrantRemoved, id) }
func (s *State) RevokeCredential(id string) error { return s.record(KindCredentialRevoked, id) }

// SetAnchor adds an external head that Replay must reach.
func (s *State) SetAnchor(a Anchor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.anchor = a
}

// Replay applies log entries after the watermark and unseals the state. It
// first checks the entries with VerifyReplay; on failure it applies
// nothing and the state stays sealed.
func (s *State) Replay(entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := VerifyReplay(entries, s.watermark, AnchorOf(s.log, s.anchor)...); err != nil {
		return err
	}
	for _, e := range entries {
		if e.Seq <= s.watermark {
			continue
		}
		s.apply(e)
	}
	s.needsReplay = false
	return nil
}

func (s *State) query(m map[string]bool, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.needsReplay {
		return false, ErrReplayRequired
	}
	return m[id], nil
}

func (s *State) PersonRevoked(id string) (bool, error)     { return s.query(s.persons, id) }
func (s *State) GrantRemoved(id string) (bool, error)      { return s.query(s.grants, id) }
func (s *State) CredentialRevoked(id string) (bool, error) { return s.query(s.creds, id) }
