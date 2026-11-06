package applier_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/compile"
	"github.com/runos-official/rolekeeper/kobj"
)

// A grant in the bundle ConfigMap becomes a binding, a revoke removes it, and
// the status ConfigMap carries the relay status schema.
func TestRelayAGrantBecomesABindingAndTheStatusIsWritten(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	raw := r.publish(t, 1, "alice")
	res := mustPass(t, a)
	if !res.Applied || !r.bound("alice") {
		t.Fatalf("v1 not applied: %+v", res)
	}
	st := r.status(t)
	if st.Format != 1 || st.Account != "acct-a" || st.Cluster != "cl-1" || st.ApplierVersion != "1.3.0-test" || st.TrustSHA256 != r.trustSum {
		t.Fatalf("identity fields: %+v", st)
	}
	if !st.Status.Applied || st.Status.Version != 1 || st.NeedsFresh || st.FreshNonce != "" || st.Lagging || st.VerifyError != "" {
		t.Fatalf("state fields: %+v", st)
	}
	if !bytes.Equal([]byte(st.SeenEnvelopeSHA256), []byte(sha(raw))) {
		t.Fatalf("seen envelope %s, want the digest of the envelope bytes %s: splitting the envelope must be lossless", st.SeenEnvelopeSHA256, sha(raw))
	}
	if len(st.Namespaces) != 1 || st.Namespaces[0] != "apps" || st.LastIssuedAt == nil || !st.LastIssuedAt.Equal(r.now) || st.StartedAt.IsZero() || st.WrittenAt.IsZero() {
		t.Fatalf("fields: %+v", st)
	}
	r.now = r.now.Add(time.Minute)
	r.publish(t, 2) // alice revoked
	mustPass(t, a)
	if r.bound("alice") {
		t.Fatal("the revoked binding stayed")
	}
	if got := r.status(t); got.Status.Version != 2 || got.BundleAgeS != 0 {
		t.Fatalf("status after the revoke: %+v", got)
	}
}

// 3.3: seq moves on every write, started_at stays for the process and moves
// for a new one. Conductor forwards on a change of the pair.
func TestRelayStatusSeqCountsEveryWriteAndStartedAtIsPerProcess(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 1, "alice")
	mustPass(t, a)
	s1 := r.status(t)
	mustPass(t, a) // nothing changed, inside the heartbeat: no write
	if s2 := r.status(t); s2.Seq != s1.Seq {
		t.Fatalf("a pass that changed nothing wrote the status (seq %d -> %d)", s1.Seq, s2.Seq)
	}
	r.now = r.now.Add(61 * time.Second) // the 60 s heartbeat
	mustPass(t, a)
	s3 := r.status(t)
	if s3.Seq <= s1.Seq || !s3.StartedAt.Equal(s1.StartedAt) || !s3.WrittenAt.After(s1.WrittenAt) {
		t.Fatalf("heartbeat: %+v then %+v", s1, s3)
	}
	if s3.BundleAgeS != 61 {
		t.Fatalf("bundle_age_s %d, want 61", s3.BundleAgeS)
	}
	r.now = r.now.Add(time.Second)
	b := r.mk(t) // a restart
	mustPass(t, b)
	s4 := r.status(t)
	if !s4.StartedAt.After(s1.StartedAt) {
		t.Fatalf("a new process kept started_at: %v vs %v", s4.StartedAt, s1.StartedAt)
	}
}

// 5.1: nothing there yet, or half a pair, is the unreachable class: an
// error, no status of failure, no work, and nothing for the fail-safe.
func TestRelayMissingOrHalfWrittenBundleIsUnreachableNotRefused(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	ctx := context.Background()
	if _, err := a.RunOnce(ctx); err == nil {
		t.Fatal("no bundle yet: want an error")
	}
	raw := r.envelope(t, bundle.Bundle{Version: 1, Namespaces: []string{"apps"}, Objects: denyObjs(t, r.now)})
	var env bundle.Envelope
	_ = json.Unmarshal(raw, &env)
	for name, put := range map[string]func(){
		"token without body.gz": func() { r.rk.put("roid-rbac-bundle", map[string]string{"token": env.Bundle}, nil) },
		"body.gz without token": func() { r.rk.put("roid-rbac-bundle", nil, map[string][]byte{"body.gz": gzipOf(t, env.Body)}) },
		"an empty body.gz": func() {
			r.rk.put("roid-rbac-bundle", map[string]string{"token": env.Bundle}, map[string][]byte{"body.gz": {}})
		},
	} {
		put()
		res, err := a.RunOnce(ctx)
		if err == nil || res.Applied || errors.Is(err, applier.ErrRoidRefused) {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		if r.floorVersion() != 0 {
			t.Fatalf("%s: the floor moved", name)
		}
	}
}

// 2.1 and 5.2: a body.gz that is not one clean member, or is tampered, or is
// above the limit, never applies. The status says why.
func TestRelayBadBodyGzIsRefusedAndTheStatusSaysWhy(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	raw := r.publish(t, 1, "alice")
	mustPass(t, a)
	var env bundle.Envelope
	_ = json.Unmarshal(raw, &env)
	good := gzipOf(t, env.Body)

	tampered := bytes.Replace(env.Body, []byte(`"alice"`), []byte(`"malic"`), -1)
	noise := make([]byte, 1_000_000)
	var x uint32 = 7
	for i := range noise {
		x = x*1664525 + 1013904223
		noise[i] = byte(x >> 24)
	}
	for name, c := range map[string]struct {
		gz   []byte
		want string
	}{
		"a tampered body":     {gzipOf(t, bytes.Replace(env.Body, []byte(`"pv-1"`), []byte(`"pv-9"`), 1)), "digest_mismatch"},
		"trailing bytes":      {append(append([]byte(nil), good...), 1, 2, 3), "bad_format"},
		"two members":         {append(append([]byte(nil), good...), good...), "bad_format"},
		"above 900,000 bytes": {gzipOf(t, noise), "too_large"},
		"not gzip":            {[]byte("hello"), "bad_format"},
	} {
		_ = tampered
		r.now = r.now.Add(time.Second)
		r.rk.put("roid-rbac-bundle", map[string]string{"token": env.Bundle}, map[string][]byte{"body.gz": c.gz})
		res, err := a.RunOnce(context.Background())
		if err == nil || res.Applied {
			t.Fatalf("%s: applied (%+v %v)", name, res, err)
		}
		if st := r.status(t); st.VerifyError != c.want || st.Status.Error == "" {
			t.Fatalf("%s: verify_error %q (want %q), status %+v", name, st.VerifyError, c.want, st.Status)
		}
		if !r.bound("alice") {
			t.Fatalf("%s: a refused bundle removed alice's binding", name)
		}
	}
}

// B1: an empty or other namespace list in the signed bundle, against a
// cluster that labels its own, applies the deny list and removes nothing.
func TestRelayABundleWithOtherNamespacesIsLaggingAndOnlyTheDenyListLands(t *testing.T) {
	for name, nss := range map[string][]string{"an empty list": nil, "another list": {"apps", "extra"}, "a smaller list": {"other"}} {
		t.Run(name, func(t *testing.T) {
			r := newRelayRig(t)
			a := r.mk(t)
			r.publish(t, 1, "alice")
			mustPass(t, a)
			r.now = r.now.Add(time.Minute)
			list, _ := compile.DenyObjects("pv-2", "acct-a", []compile.Deny{{Person: "mallory", Until: denyUntil}}, r.now)
			r.write(t, r.envelope(t, bundle.Bundle{Version: 2, PolicyVersion: "pv-2", Namespaces: nss, Objects: list}), "")
			res, err := a.RunOnce(context.Background())
			if err != nil || res.Applied || !res.Lagging {
				t.Fatalf("lagging pass: %+v %v", res, err)
			}
			if !r.bound("alice") {
				t.Fatal("a lagging bundle removed a binding")
			}
			cm, _, _ := r.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
			if cm.Data["mallory"] == "" {
				t.Fatal("the deny list did not land (the deny list is always applied)")
			}
			if r.floorVersion() != 1 {
				t.Fatalf("a lagging bundle stored the floor: v%d", r.floorVersion())
			}
			st := r.status(t)
			if !st.Lagging || len(st.Namespaces) != 1 || st.Namespaces[0] != "apps" {
				t.Fatalf("status: %+v (the next status must carry what the cluster labels)", st)
			}
			// The bundle that matches applies and clears the flag.
			r.now = r.now.Add(time.Minute)
			r.publish(t, 3, "alice", "bob")
			if res := mustPass(t, a); !res.Applied || res.Lagging || !r.bound("bob") {
				t.Fatalf("matching bundle: %+v", res)
			}
			if st := r.status(t); st.Lagging {
				t.Fatalf("still lagging: %+v", st)
			}
		})
	}
}

// 5.4 does not touch the retire bundle or a deny-only bundle: both are
// exempt from the equality rule.
func TestRelayRetireAndDenyOnlyBundlesAreExemptFromTheEqualityRule(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 1, "alice")
	mustPass(t, a)
	r.now = r.now.Add(time.Minute)
	r.write(t, r.envelope(t, bundle.Bundle{Version: 2, Namespaces: nil, Objects: denyObjs(t, r.now), DenyOnly: true}), "")
	res := mustPass(t, a)
	if res.Lagging || !res.Applied || r.floorVersion() != 2 || !r.bound("alice") {
		t.Fatalf("deny-only: %+v floor v%d", res, r.floorVersion())
	}
	r.now = r.now.Add(time.Minute)
	r.write(t, r.envelope(t, bundle.Bundle{Version: 3, Namespaces: nil, Objects: denyObjs(t, r.now), Retire: true}), "")
	res = mustPass(t, a)
	if !res.Retired || r.bound("alice") {
		t.Fatalf("retire: %+v", res)
	}
}

// 2.2: a bundle with TooLarge is deny-only whether or not DenyOnly is also
// set in the body: nothing is removed, the deny list lands.
func TestRelayATooLargeBundleIsTreatedAsDenyOnly(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 1, "alice")
	mustPass(t, a)
	r.now = r.now.Add(time.Minute)
	list, _ := compile.DenyObjects("pv-2", "acct-a", []compile.Deny{{Person: "mallory", Until: denyUntil}}, r.now)
	r.write(t, r.envelope(t, bundle.Bundle{Version: 2, PolicyVersion: "pv-2", Namespaces: []string{"apps"}, Objects: list, TooLarge: true}), "")
	res, err := a.RunOnce(context.Background())
	if err != nil || !res.Applied {
		t.Fatalf("too large: %+v %v", res, err)
	}
	if !r.bound("alice") {
		t.Fatal("a TooLarge bundle removed a binding")
	}
	if st := r.status(t); !st.Status.DenyOnly {
		t.Fatalf("status: %+v", st.Status)
	}
}

// M2 / 5.5: a lint finding in the bundle still lands a clean deny list. A
// deny list that fails its own lint lands nothing.
func TestRelayALintFindingStillAppliesTheDenyListAndNothingElse(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 1, "alice")
	mustPass(t, a)
	r.now = r.now.Add(time.Minute)
	list, _ := compile.DenyObjects("pv-2", "acct-a", []compile.Deny{{Person: "mallory", Until: denyUntil}}, r.now)
	evil := binding("eve")
	evil.RoleRef = &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}
	r.write(t, r.envelope(t, bundle.Bundle{Version: 2, PolicyVersion: "pv-2", Namespaces: []string{"apps"}, Objects: append(list, evil, binding("alice"))}), "")
	_, err := a.RunOnce(context.Background())
	if err == nil {
		t.Fatal("a cluster-admin binding applied")
	}
	cm, _, _ := r.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	if cm.Data["mallory"] == "" {
		t.Fatal("the lint finding stopped the deny list")
	}
	if r.bound("eve") || !r.bound("alice") || r.floorVersion() != 1 {
		t.Fatalf("something else landed or went: eve=%v alice=%v floor=v%d", r.bound("eve"), r.bound("alice"), r.floorVersion())
	}
	// A deny list that is not clean on its own lands nothing.
	r.now = r.now.Add(time.Minute)
	bad, _ := compile.DenyObjects("pv-3", "acct-a", []compile.Deny{{Person: "zed", Until: denyUntil}}, r.now)
	for i := range bad {
		if bad[i].Kind == kobj.KindConfigMap {
			bad[i].Data["zed"] = "not-a-time"
		}
	}
	r.write(t, r.envelope(t, bundle.Bundle{Version: 3, PolicyVersion: "pv-3", Namespaces: []string{"apps"}, Objects: append(bad, evil)}), "")
	_, _ = a.RunOnce(context.Background())
	cm, _, _ = r.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	if cm.Data["zed"] != "" {
		t.Fatal("a deny list that fails lint landed")
	}
}

// The same rule holds for the pull transport.
func TestPullALintFindingStillAppliesTheDenyList(t *testing.T) {
	r := newRig(t)
	a := r.applier(r.now.Add(-time.Minute))
	r.offer(1, append(denyObjs(t, r.now), binding("alice"))...)
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(time.Minute)
	list, _ := compile.DenyObjects("pv-2", "acct-a", []compile.Deny{{Person: "mallory", Until: denyUntil}}, r.now)
	evil := binding("eve")
	evil.RoleRef = &kobj.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}
	r.offer(2, append(list, evil)...)
	if _, err := a.RunOnce(context.Background()); err == nil {
		t.Fatal("applied")
	}
	cm, _, _ := r.kube.Get(context.Background(), kobj.KindConfigMap, compile.DenyNamespace, compile.DenyPolicyName)
	if cm.Data["mallory"] == "" {
		t.Fatal("pull: the lint finding stopped the deny list")
	}
}

// 7.2: a bundle for another cluster or another account never applies, also
// when the whole envelope is copied in from there.
func TestRelayABundleForAnotherClusterOrAccountIsRefused(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	other := map[string]bundle.Bundle{
		"another cluster": {Cluster: "cl-2", Version: 1, Namespaces: []string{"apps"}, Objects: []kobj.Object{binding("mallory")}},
		"another account": {Account: "acct-b", Version: 1, Namespaces: []string{"apps"}, Objects: []kobj.Object{binding("mallory")}},
	}
	for name, b := range other {
		r.rk.put("roid-rbac-bundle", nil, nil)
		r.write(t, r.envelope(t, b), "")
		res, err := a.RunOnce(context.Background())
		if err == nil || res.Applied || r.bound("mallory") {
			t.Fatalf("%s: applied (%+v %v)", name, res, err)
		}
		if st := r.status(t); st.Status.Error == "" || st.VerifyError == "" {
			t.Fatalf("%s: the refusal is not in the status: %+v", name, st)
		}
		if r.floorVersion() != 0 {
			t.Fatalf("%s: the floor moved", name)
		}
	}
	// The error classes, straight from the verifier.
	v, _ := bundle.NewVerifier(r.trust, r.clock, t.TempDir()+"/c.json")
	v.ExpectAccount("acct-a")
	if _, err := v.Verify(r.envelope(t, other["another cluster"])); err == nil {
		t.Error("another cluster verified")
	}
	if _, err := v.Verify(r.envelope(t, other["another account"])); !errors.Is(err, bundle.ErrAccount) {
		t.Errorf("another account: %v", err)
	}
}

// 12.2 replay: a lower version, and the same version with other content.
func TestRelayReplayOfALowerOrChangedVersionIsRefused(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 5, "alice")
	mustPass(t, a)
	r.now = r.now.Add(time.Minute)
	r.publish(t, 4, "alice", "mallory")
	if _, err := a.RunOnce(context.Background()); !errors.Is(err, bundle.ErrStale) || r.bound("mallory") {
		t.Fatalf("lower version: %v", err)
	}
	r.publish(t, 5, "alice", "mallory")
	if _, err := a.RunOnce(context.Background()); !errors.Is(err, bundle.ErrStale) || r.bound("mallory") {
		t.Fatalf("same version, other content: %v", err)
	}
	// After a restart too (the floor is durable).
	b := r.mk(t)
	if _, err := b.RunOnce(context.Background()); !errors.Is(err, bundle.ErrStale) || r.bound("mallory") {
		t.Fatalf("after a restart: %v", err)
	}
}

// 3.2: the watch reads metadata only. The bundle is read in full only when
// its resourceVersion changed, and a change starts a pass at once.
func TestRelayWatchReadsMetadataAndTheBundleOnlyOnChange(t *testing.T) {
	r := newRelayRig(t)
	a := r.mk(t)
	r.publish(t, 1, "alice")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.RunRelay(ctx, 5*time.Millisecond, time.Hour, nil)
		close(done)
	}()
	waitFor(t, func() bool { return r.bound("alice") })
	gets := r.rk.getCount("roid-rbac-bundle")
	time.Sleep(100 * time.Millisecond)
	if n := r.rk.getCount("roid-rbac-bundle"); n != gets {
		t.Fatalf("the bundle was read in full %d more times while nothing changed", n-gets)
	}
	r.rk.mu.Lock()
	metas := r.rk.metas
	r.rk.mu.Unlock()
	if metas < 5 {
		t.Fatalf("only %d metadata reads in 100 ms", metas)
	}
	r.publish(t, 2, "alice", "bob") // r.now is read by the loop: do not move it
	waitFor(t, func() bool { return r.bound("bob") })
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out")
}

// In relay mode the applier needs an account: a verifier built without one
// checks nothing (m1), so the command refuses to start.
func TestRelayConfigRefusesNoAccountAndAnUnknownTransport(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		fail string
	}{
		{map[string]string{"ROID_K8S_TRANSPORT": "relay", "ROID_K8S_TRUST_FILE": "/x", "ROID_K8S_STATE_DIR": "/y"}, "ROID_K8S_ACCOUNT"},
		{map[string]string{"ROID_K8S_TRANSPORT": "carrier-pigeon", "ROID_K8S_ACCOUNT": "a"}, "ROID_K8S_TRANSPORT"},
	} {
		_, err := applier.ParseRelayEnv(func(k string) string { return tc.env[k] })
		if err == nil || !strings.Contains(err.Error(), tc.fail) {
			t.Errorf("%v: got %v, want a refusal naming %s", tc.env, err, tc.fail)
		}
	}
	cfg, err := applier.ParseRelayEnv(func(k string) string {
		return map[string]string{"ROID_K8S_TRANSPORT": "relay", "ROID_K8S_ACCOUNT": "acct-a", "ROID_K8S_TRUST_FILE": "/t", "ROID_K8S_STATE_DIR": "/s"}[k]
	})
	if err != nil || cfg.WatchEvery != 500*time.Millisecond || cfg.Interval != 2*time.Second || cfg.ReportEvery != 60*time.Second ||
		cfg.BundleName != "roid-rbac-bundle" || cfg.RelayName != "roid-rbac-relay" || cfg.StatusName != "roid-rbac-status" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	if _, err := applier.ParseRelayEnv(func(k string) string {
		return map[string]string{"ROID_K8S_TRANSPORT": "relay", "ROID_K8S_ACCOUNT": "a", "ROID_K8S_TRUST_FILE": "/t", "ROID_K8S_STATE_DIR": "/s", "ROID_K8S_WATCH_EVERY": "10ms"}[k]
	}); err == nil {
		t.Error("a watch interval under 100ms was accepted")
	}
	// Pull keeps its old requirements and ignores the relay names.
	cfg, err = applier.ParseRelayEnv(func(k string) string { return map[string]string{"ROID_K8S_ACCOUNT": "a"}[k] })
	if err != nil || cfg.Relay {
		t.Fatalf("pull: %+v %v", cfg, err)
	}
}
