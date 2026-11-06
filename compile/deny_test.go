package compile_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

func kinds(objs []kobj.Object) []string {
	var k []string
	for _, o := range objs {
		k = append(k, o.Kind)
	}
	return k
}

func TestDenyObjectsAreThePolicyTheListAndTheBindingInApplyOrder(t *testing.T) {
	objs, err := compile.DenyObjects("pv-3", "acct-a", nil, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{kobj.KindVAP, kobj.KindConfigMap, kobj.KindVAPBinding}
	if !slices.Equal(kinds(objs), want) {
		t.Fatalf("kinds %v, want %v", kinds(objs), want)
	}
	for _, o := range objs {
		if o.Name != compile.DenyPolicyName || o.Labels[kobj.LabelPolicyVersion] != "pv-3" || o.Labels[kobj.LabelAccount] != "acct-a" {
			t.Errorf("%s: %+v", o.Kind, o)
		}
	}
	if objs[1].Namespace != compile.DenyNamespace || len(objs[1].Data) != 0 {
		t.Fatalf("the list: %+v", objs[1])
	}
}

func TestDenyListHoldsAPersonUntilTheirExpiry(t *testing.T) {
	until := fixedNow.Add(15 * time.Minute)
	objs, err := compile.DenyObjects("pv-1", "acct-a", []compile.Deny{{Person: "alice", Until: until}}, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := objs[1].Data["alice"]; got != until.Format(time.RFC3339) {
		t.Fatalf("alice expires %q", got)
	}
}

func TestDenyListDropsAnEntryOnceItsExpiryHasPassed(t *testing.T) {
	deny := []compile.Deny{
		{Person: "alice", Until: fixedNow.Add(-time.Second)},
		{Person: "bob", Until: fixedNow},
		{Person: "carol", Until: fixedNow.Add(time.Second)},
	}
	objs, err := compile.DenyObjects("pv-1", "acct-a", deny, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := objs[1].Data["alice"]; ok {
		t.Error("alice is past her expiry and still on the list")
	}
	if _, ok := objs[1].Data["bob"]; ok {
		t.Error("an expiry equal to now is over")
	}
	if _, ok := objs[1].Data["carol"]; !ok {
		t.Error("carol is still cut")
	}
}

func TestDenyListKeepsTheLaterExpiryOfTwoEntriesForOnePerson(t *testing.T) {
	early, late := fixedNow.Add(time.Minute), fixedNow.Add(time.Hour)
	for _, deny := range [][]compile.Deny{
		{{Person: "alice", Until: early}, {Person: "alice", Until: late}},
		{{Person: "alice", Until: late}, {Person: "alice", Until: early}},
	} {
		objs, err := compile.DenyObjects("pv-1", "acct-a", deny, fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		if got := objs[1].Data["alice"]; got != late.Format(time.RFC3339) {
			t.Fatalf("alice expires %q, want %q", got, late.Format(time.RFC3339))
		}
	}
}

func TestDenyListWritesTheExpiryInUTC(t *testing.T) {
	zone := time.FixedZone("plus-two", 2*3600)
	until := fixedNow.Add(time.Hour).In(zone)
	objs, err := compile.DenyObjects("pv-1", "acct-a", []compile.Deny{{Person: "alice", Until: until}}, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := objs[1].Data["alice"]; got != "2030-01-02T04:04:05Z" {
		t.Fatalf("got %q", got)
	}
}

func TestDenyListRefusesAReservedCanaryAndAnIdThatIsNoSubject(t *testing.T) {
	future := fixedNow.Add(time.Hour)
	for _, person := range []string{compile.DenyCanaries[0], compile.DenyCanaries[1], "Alice", "a:b", ""} {
		_, err := compile.DenyObjects("pv-1", "acct-a", []compile.Deny{{Person: person, Until: future}}, fixedNow)
		var ce *compile.Error
		if !errors.As(err, &ce) || ce.Code != "policy.invalid" {
			t.Errorf("person %q: err %v, want policy.invalid", person, err)
		}
	}
}

func TestDenyListChecksAnExpiredEntryToo(t *testing.T) {
	// An invalid id is refused even when its expiry has passed: the input is
	// wrong, whether or not the entry would land.
	_, err := compile.DenyObjects("pv-1", "acct-a", []compile.Deny{{Person: "Bad Id", Until: fixedNow.Add(-time.Hour)}}, fixedNow)
	if err == nil {
		t.Fatal("an invalid id was accepted")
	}
}

func TestDenyCanaries(t *testing.T) {
	if compile.DenyCanaries[0] == compile.DenyCanaries[1] {
		t.Fatal("the two canaries are one name")
	}
	for _, c := range compile.DenyCanaries {
		if !compile.IsDenyCanary(c) {
			t.Errorf("%s is not a canary", c)
		}
		if !compile.ValidSubjectID(c) {
			t.Errorf("%s cannot ride on the list", c)
		}
		if got := compile.CanaryUser(c); got != compile.UserPrefix+c {
			t.Errorf("canary user %q", got)
		}
	}
	if compile.IsDenyCanary("alice") || compile.IsDenyCanary("") {
		t.Fatal("a person is a canary")
	}
	if _, err := time.Parse(time.RFC3339, compile.CanaryUntil); err != nil {
		t.Fatalf("the canary expiry is not RFC 3339: %v", err)
	}
}

func TestOnlyTheDenyPolicyAndItsBindingAreKept(t *testing.T) {
	if !compile.IsKeptDenyObject(kobj.KindVAP, compile.DenyPolicyName) || !compile.IsKeptDenyObject(kobj.KindVAPBinding, compile.DenyPolicyName) {
		t.Fatal("the deny policy or its binding can be deleted")
	}
	for _, c := range [][2]string{
		{kobj.KindConfigMap, compile.DenyPolicyName},
		{kobj.KindVAP, "other"},
		{kobj.KindClusterRole, compile.DenyPolicyName},
	} {
		if compile.IsKeptDenyObject(c[0], c[1]) {
			t.Errorf("%s %s is kept", c[0], c[1])
		}
	}
}

func TestDenyPolicyTargetsPersonsOnlyAndFailsClosed(t *testing.T) {
	spec := compile.DenyPolicySpec()
	if spec["failurePolicy"] != "Fail" {
		t.Fatalf("failurePolicy %v", spec["failurePolicy"])
	}
	conds, _ := spec["matchConditions"].([]any)
	if len(conds) != 1 {
		t.Fatalf("match conditions %v", conds)
	}
	expr, _ := conds[0].(map[string]any)["expression"].(string)
	if expr != "request.userInfo.username.startsWith('"+compile.UserPrefix+"')" {
		t.Fatalf("the policy matches %q", expr)
	}
	rules := spec["matchConstraints"].(map[string]any)["resourceRules"].([]any)[0].(map[string]any)
	ops, _ := rules["operations"].([]any)
	for _, op := range []string{"CREATE", "UPDATE", "DELETE", "CONNECT"} {
		if !slices.Contains(ops, any(op)) {
			t.Errorf("operation %s is not refused", op)
		}
	}
}

func TestDenyBindingAllowsWhenTheListIsMissing(t *testing.T) {
	// Deny with a missing list would refuse every write by every user and
	// stop the cluster, so a missing list must allow.
	spec := compile.DenyBindingSpec()
	ref := spec["paramRef"].(map[string]any)
	if ref["parameterNotFoundAction"] != "Allow" || ref["name"] != compile.DenyPolicyName || ref["namespace"] != compile.DenyNamespace {
		t.Fatalf("paramRef %v", ref)
	}
	if actions, _ := spec["validationActions"].([]any); len(actions) != 1 || actions[0] != "Deny" {
		t.Fatalf("validationActions %v", spec["validationActions"])
	}
}

func TestDenyInstallListPutsTheListBeforeThePolicyAndTheBinding(t *testing.T) {
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(compile.DenyInstallList("acct-a"), &list); err != nil {
		t.Fatal(err)
	}
	if list.Kind != "List" || len(list.Items) != 3 {
		t.Fatalf("list %+v", list)
	}
	got := []string{list.Items[0].Kind, list.Items[1].Kind, list.Items[2].Kind}
	want := []string{kobj.KindConfigMap, kobj.KindVAP, kobj.KindVAPBinding}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if v := list.Items[0].Metadata.Labels[kobj.LabelPolicyVersion]; v != compile.InstallPolicyVersion {
		t.Fatalf("install label %q", v)
	}
}
