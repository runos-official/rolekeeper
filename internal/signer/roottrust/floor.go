package roottrust

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// ErrBelowFloor: the chain is shorter than the minimum this build knows
// of. A verifier refuses to start rather than trust an older chain.
var ErrBelowFloor = errors.New("roottrust: the root chain is below the floor this build carries")

// Floors is the minimum chain sequence per pinned root (its fingerprint),
// baked into every build from floors.json. It lives in the build, where
// neither a database writer nor a ConfigMap writer reaches: the root
// ceremony adds or raises an entry in the release that publishes a new
// link (the root ceremony prints the entry).
var Floors = map[string]uint64{}

//go:embed floors.json
var floorsJSON []byte

// ErrBadFloors: floors.json does not parse or holds a bad entry.
var ErrBadFloors = errors.New("roottrust: floors.json is not acceptable")

// ErrNoFloor: the pinned root has no entry in floors.json.
var ErrNoFloor = errors.New("roottrust: the pinned root has no floor entry in this build (signer/roottrust/floors.json)")

// FloorEntry is one pinned root of a deployment.
type FloorEntry struct {
	Env  string `json:"env"`
	Pin  string `json:"pin"`
	Seq  uint64 `json:"seq"`
	Note string `json:"note"`
}

type floorsFile struct {
	V      int          `json:"v"`
	Floors []FloorEntry `json:"floors"`
}

var floorEntries []FloorEntry

var pinHex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ParseFloors reads a floors file strictly.
func ParseFloors(b []byte) ([]FloorEntry, error) {
	var f floorsFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadFloors, err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrBadFloors, f.V)
	}
	seen := map[string]bool{}
	for _, e := range f.Floors {
		if !pinHex.MatchString(e.Pin) || e.Env == "" || seen[e.Pin] {
			return nil, fmt.Errorf("%w: entry %q for %q", ErrBadFloors, e.Pin, e.Env)
		}
		seen[e.Pin] = true
	}
	return f.Floors, nil
}

func init() {
	es, err := ParseFloors(floorsJSON)
	if err != nil {
		panic(err) // a broken floors.json never ships: the tests read it
	}
	floorEntries = es
	for _, e := range es {
		Floors[e.Pin] = e.Seq
	}
}

// FloorEntries are the entries of the build's floors.json.
func FloorEntries() []FloorEntry { return append([]FloorEntry(nil), floorEntries...) }

// HasFloor says whether the build lists a pinned root.
func HasFloor(pinFingerprint string) bool {
	floorMu.Lock()
	defer floorMu.Unlock()
	_, ok := Floors[pinFingerprint]
	return ok
}

// FloorOfFingerprint is the build's floor of a pin by fingerprint.
func FloorOfFingerprint(pinFingerprint string) uint64 {
	floorMu.Lock()
	defer floorMu.Unlock()
	return Floors[pinFingerprint]
}

// RequireFloor refuses a pinned root the build does not list (outside dev:
// a deployment's root is always in floors.json).
func RequireFloor(pin Root) error {
	if !HasFloor(pin.Fingerprint()) {
		return fmt.Errorf("%w: root %s", ErrNoFloor, pin.Fingerprint())
	}
	return nil
}

var floorMu sync.Mutex

// FloorOf is the baked floor of a pinned root.
func FloorOf(pin Root) uint64 {
	floorMu.Lock()
	defer floorMu.Unlock()
	return Floors[pin.Fingerprint()]
}

// SetFloorForTest sets one pin's floor and returns the restore function.
func SetFloorForTest(pinFingerprint string, seq uint64) func() {
	floorMu.Lock()
	defer floorMu.Unlock()
	old, had := Floors[pinFingerprint]
	Floors[pinFingerprint] = seq
	return func() {
		floorMu.Lock()
		defer floorMu.Unlock()
		if had {
			Floors[pinFingerprint] = old
		} else {
			delete(Floors, pinFingerprint)
		}
	}
}

// CheckFloor refuses a chain below the baked floor of its pin.
func (t *Trust) CheckFloor() error {
	pin := t.Pin()
	if f, held := FloorOf(pin), t.Seq(); held < f {
		return fmt.Errorf("%w: the chain holds %d links, this build requires %d for root %s", ErrBelowFloor, held, f, pin.Fingerprint())
	}
	return nil
}
