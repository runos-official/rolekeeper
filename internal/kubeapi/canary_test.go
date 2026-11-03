package kubeapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/runos-official/rolekeeper/internal/compile"
	"github.com/runos-official/rolekeeper/internal/kobj"
	"github.com/runos-official/rolekeeper/internal/kubeapi"
)

// The client never sends a delete of the deny policy or its binding.
func TestTheDenyPolicyIsNeverDeleted(t *testing.T) {
	f := &fakeAPI{}
	c, _ := newClient(t, f)
	for _, kind := range []string{kobj.KindVAP, kobj.KindVAPBinding} {
		err := c.Delete(context.Background(), kind, "", compile.DenyPolicyName)
		if !errors.Is(err, compile.ErrDenyPolicyKept) {
			t.Errorf("delete %s: %v, want ErrDenyPolicyKept", kind, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a delete reached the API server: %+v", f.calls)
	}
}

// The canary probe is a dry-run create of a ConfigMap as the canary user
// (impersonation). A dry run goes through admission; a SubjectAccessReview
// asks only the authorizer, so it would never see the deny policy.
func TestDenyProbeIsADryRunWriteAsTheCanary(t *testing.T) {
	p := "/api/v1/namespaces/roid-k8s-applier/configmaps"
	user := compile.CanaryUser(compile.DenyCanaries[0])
	for _, c := range []struct {
		name string
		code int
		body string
		want kubeapi.ProbeResult
	}{
		{"allowed", 201, `{"kind":"ConfigMap"}`, kubeapi.ProbeAllowed},
		{"refused by the deny policy", 403, `{"kind":"Status","message":"configmaps \"x\" is forbidden: ValidatingAdmissionPolicy 'runos-deny-writes' with binding 'runos-deny-writes' denied request: runos: this person's writes are cut (deny list)"}`, kubeapi.ProbeDenied},
		{"refused by RBAC", 403, `{"kind":"Status","message":"configmaps is forbidden: User \"runos:u:runos-deny-canary-a\" cannot create resource \"configmaps\""}`, kubeapi.ProbeOther},
		{"server error", 500, `{"kind":"Status","message":"etcd"}`, kubeapi.ProbeOther},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAPI{code: map[string]int{"POST " + p: c.code}, resp: map[string]string{"POST " + p: c.body}}
			cl, _ := newClient(t, f)
			got, msg, err := cl.DenyProbe(context.Background(), user, "roid-k8s-applier")
			if got != c.want || err != nil {
				t.Fatalf("got %v %q %v, want %v", got, msg, err, c.want)
			}
			if c.want != kubeapi.ProbeAllowed && msg == "" {
				t.Fatal("a refusal came back without the API server's message")
			}
			last := f.last()
			if last.Method != "POST" || last.Path != p || last.Query != "dryRun=All" {
				t.Fatalf("request %s %s?%s, want a dry-run POST to %s", last.Method, last.Path, last.Query, p)
			}
			if f.lastImpersonate() != user {
				t.Fatalf("impersonated %q, want %q", f.lastImpersonate(), user)
			}
			var cm struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(last.Body, &cm); err != nil || cm.Kind != "ConfigMap" || cm.Metadata.Name == "" {
				t.Fatalf("body %s", last.Body)
			}
		})
	}
	// A user that is not a canary is never impersonated.
	f := &fakeAPI{}
	cl, _ := newClient(t, f)
	if _, _, err := cl.DenyProbe(context.Background(), "runos:u:operator-g", "roid-k8s-applier"); err == nil || len(f.calls) != 0 {
		t.Fatalf("probe as a person: %v, %d calls", err, len(f.calls))
	}
}
