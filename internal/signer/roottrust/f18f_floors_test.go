package roottrust_test

import (
	"errors"
	"testing"

	"github.com/runos-official/rolekeeper/internal/signer/roottrust"
)

// The floor is real. floors.json (embedded) lists every pinned
// root of a deployment with its minimum chain sequence; HasFloor and
// FloorEntries read it.
func TestF18fTheFloorsFileIsCheckedInAndWellFormed(t *testing.T) {
	es := roottrust.FloorEntries()
	if len(es) == 0 {
		t.Fatal("floors.json lists no pinned root")
	}
	seen := map[string]bool{}
	for _, e := range es {
		if len(e.Pin) != 16 || e.Env == "" || e.Note == "" {
			t.Errorf("entry %+v: a 16-hex pin fingerprint, an environment and a note", e)
		}
		if seen[e.Pin] {
			t.Errorf("pin %s is listed twice", e.Pin)
		}
		seen[e.Pin] = true
		if !roottrust.HasFloor(e.Pin) || roottrust.FloorOfFingerprint(e.Pin) != e.Seq {
			t.Errorf("entry %+v is not the build's floor", e)
		}
	}
	if !envListed(es, "dev") {
		t.Error("the dev root has no floor entry")
	}
	if _, err := roottrust.ParseFloors([]byte(`{"v":1,"floors":[{"env":"x","pin":"zz","seq":0,"note":"n"}]}`)); !errors.Is(err, roottrust.ErrBadFloors) {
		t.Fatalf("a bad pin: %v", err)
	}
	if _, err := roottrust.ParseFloors([]byte(`{"v":1,"floors":[],"extra":1}`)); !errors.Is(err, roottrust.ErrBadFloors) {
		t.Fatalf("an unknown field: %v", err)
	}
}

func envListed(es []roottrust.FloorEntry, env string) bool {
	for _, e := range es {
		if e.Env == env {
			return true
		}
	}
	return false
}
