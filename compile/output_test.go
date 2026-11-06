package compile_test

import (
	"slices"
	"testing"

	"github.com/runos-official/rolekeeper/compile"
)

func sampleOutput() compile.Output {
	return compile.Output{Entries: []compile.Entry{
		{Subject: compile.PersonRoleSubject("alice", compile.RoleEdit), Kind: "Group", Role: compile.RoleEdit, Person: "alice"},
		{Subject: compile.GroupSubject("ops", compile.RoleView), Kind: "Group", Role: compile.RoleView, Via: "ops"},
		{Subject: compile.GroupSubject("ops", compile.RoleExec), Kind: "Group", Role: compile.RoleExec, Via: "ops"},
		{Subject: compile.GroupSubject("dev", compile.RoleView), Kind: "Group", Role: compile.RoleView, Via: "dev"},
		{Subject: compile.PersonRoleSubject("bob", compile.RoleView), Kind: "Group", Role: compile.RoleView, Person: "bob"},
	}}
}

func subjects(es []compile.Entry) []string {
	var s []string
	for _, e := range es {
		s = append(s, e.Subject)
	}
	return s
}

func TestHeldReturnsDirectGrantsAndGrantsOfTheGroupsAPersonIsIn(t *testing.T) {
	out := sampleOutput()
	got := subjects(out.Held("alice", []string{"ops"}))
	want := []string{"runos:u:alice:edit", "runos:g:ops:view", "runos:g:ops:exec"}
	if !slices.Equal(got, want) {
		t.Fatalf("alice in ops holds %v, want %v", got, want)
	}
}

func TestHeldIgnoresOtherPeopleAndOtherGroups(t *testing.T) {
	out := sampleOutput()
	if got := out.Held("carol", []string{"qa"}); len(got) != 0 {
		t.Fatalf("a stranger in an unrelated group holds %v", got)
	}
	got := subjects(out.Held("bob", nil))
	if !slices.Equal(got, []string{"runos:u:bob:view"}) {
		t.Fatalf("bob with no groups holds %v", got)
	}
}

func TestHeldNeverMatchesAnEmptyPersonOrGroup(t *testing.T) {
	// An entry has Person or Via, never both. A blank id must not match the
	// blank field of the other kind.
	out := sampleOutput()
	if got := out.Held("", []string{""}); len(got) != 0 {
		t.Fatalf("blank person and group matched %v", got)
	}
}

func TestHeldOfAnEmptyOutputIsEmpty(t *testing.T) {
	if got := (compile.Output{}).Held("alice", []string{"ops"}); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestClaimGroupsAreSortedAndHoldEachSubjectOnce(t *testing.T) {
	es := []compile.Entry{
		{Subject: "runos:g:ops:view", Kind: "Group"},
		{Subject: "runos:cw:view", Kind: "Group"},
		{Subject: "runos:g:ops:view", Kind: "Group"},
		{Subject: "runos:u:alice:edit", Kind: "Group"},
	}
	got := compile.ClaimGroups(es)
	want := []string{"runos:cw:view", "runos:g:ops:view", "runos:u:alice:edit"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestClaimGroupsSkipEntriesThatAreNotGroups(t *testing.T) {
	es := []compile.Entry{{Subject: "runos:u:alice", Kind: "User"}, {Subject: "runos:g:ops:view", Kind: "Group"}}
	if got := compile.ClaimGroups(es); !slices.Equal(got, []string{"runos:g:ops:view"}) {
		t.Fatalf("got %v", got)
	}
	if got := compile.ClaimGroups(nil); len(got) != 0 {
		t.Fatalf("no entries gave %v", got)
	}
}

func TestClaimGroupsOfHeldEntriesAreWhatATokenCarries(t *testing.T) {
	out := sampleOutput()
	got := compile.ClaimGroups(out.Held("alice", []string{"ops", "dev"}))
	want := []string{"runos:g:dev:view", "runos:g:ops:exec", "runos:g:ops:view", "runos:u:alice:edit"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
