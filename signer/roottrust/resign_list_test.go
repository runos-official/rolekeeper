package roottrust_test

import (
	"strings"
	"testing"

	"github.com/runos-official/rolekeeper/signer/roottrust"
)

// The re-sign list is generated from the registry: every artifact
// the new root re-signs gives at least one line, the key sets and anchor
// bundles one per purpose, and the BMC enrolment certificates their own.
func TestTheReSignListComesFromTheRegistry(t *testing.T) {
	items := roottrust.ReSignItems()
	all := strings.Join(items, "\n")
	for _, a := range roottrust.Artifacts {
		if !a.ReSign {
			continue
		}
		if !strings.Contains(all, a.Name) {
			t.Errorf("%s re-signs but is not on the list:\n%s", a.Name, all)
		}
		for _, p := range a.Purposes {
			if !strings.Contains(all, "re-sign "+string(p)) && !strings.Contains(all, "re-sign anchors "+string(p)) {
				t.Errorf("%s purpose %s is not on the list", a.Name, p)
			}
		}
	}
	for _, want := range []string{"re-sign gate", "re-sign decision-receipt", "re-sign anchors agent-ca", roottrust.ArtBMCEnrolment} {
		if !strings.Contains(all, want) {
			t.Errorf("the list lacks %q:\n%s", want, all)
		}
	}
}
