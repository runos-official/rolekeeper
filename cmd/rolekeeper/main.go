// Command rolekeeper runs inside a RunOS cluster and applies the
// cluster's signed RBAC bundle (package applier). Two transports:
//
//	pull   (default) it pulls the bundle from roid with the cluster's
//	       service certificate.
//	relay  ROID_K8S_TRANSPORT=relay: it reads the bundle, the key set and
//	       roid's signed refusal from ConfigMaps in its own namespace, which
//	       conductor writes, and writes its status to a ConfigMap. It never
//	       talks to roid: no enrolment, no roid token, no roid address.
//
// Configuration (environment):
//
//	ROID_K8S_TRANSPORT      pull (default) or relay
//	ROID_K8S_URL            pull only: roid's service listener, https://...
//	ROID_K8S_ACCOUNT        the account that owns this cluster (both transports; a
//	                        verifier without it would check no account)
//	ROID_K8S_TRUST_FILE     bundle.Trust JSON: issuer, cluster, root key, bundle key set
//	ROID_K8S_STATE_DIR      a directory for the applier's state (the root chain floor)
//	ROID_K8S_SA_TOKEN_FILE  pull only: the projected service account token (audience roid). When set,
//	                        the applier enrols and renews its certificate itself and
//	                        keeps the key in memory; the two files below are not used.
//	ROID_K8S_SERVICE        its registered service name (default k8s-applier)
//	ROID_K8S_DNS            the DNS name in its certificate
//	POD_NAME, POD_NAMESPACE from the downward API
//	ROID_K8S_CERT_FILE      otherwise: the service certificate (renewed in place by another client)
//	ROID_K8S_KEY_FILE       its private key
//	ROID_K8S_CA_FILE        the CA bundle of roid's service listener
//	ROID_K8S_FLOOR_NS       namespace of the floor ConfigMap (default: the pod's namespace)
//	ROID_K8S_FLOOR_NAME     its name (default roid-rbac-floor)
//	ROID_K8S_KEYS_NAME      the ConfigMap, next to the floor, that keeps the root-signed
//	                        policy-bundle key set the applier follows from roid
//	                        (default roid-rbac-keys)
//	ROID_K8S_NS_SELECTOR    label selector of managed namespaces (default runos.com/roid-access=true)
//	ROID_K8S_INTERVAL       pass interval, a Go duration (default 2s)
//	ROID_K8S_REPORT_EVERY   status heartbeat when nothing changes (default 5m; 60s in relay)
//	ROID_K8S_BUNDLE_NAME    relay only: the bundle ConfigMap (default roid-rbac-bundle)
//	ROID_K8S_RELAY_NAME     relay only: key set and refusal (default roid-rbac-relay)
//	ROID_K8S_STATUS_NAME    relay only: the status ConfigMap (default roid-rbac-status)
//	ROID_K8S_WATCH_EVERY    relay only: how often the ConfigMap metadata is read
//	                        (default 500ms, at least 100ms)
//	ROID_K8S_CANARY_NS      namespace of the deny canary's dry-run write (default: the pod's namespace)
//	ROID_K8S_CANARY_EVERY   how often the canary on the deny list turns over (default 30s)
//	KUBECONFIG              optional, outside a pod only: a kubeconfig in JSON
//	                        (kubectl config view --raw --minify -o json). In the
//	                        cluster the pod's service account is used.
//
// The applier talks to the API server over its REST API (package kubeapi):
// there is no kubectl in the image.
//
// This build runs the relay transport. Enrolment with a service account
// token (ROID_K8S_SA_TOKEN_FILE) is not part of it.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/runos-official/rolekeeper/applier"
	"github.com/runos-official/rolekeeper/bundle"
	"github.com/runos-official/rolekeeper/kobj"
	"github.com/runos-official/rolekeeper/kubeapi"
	"github.com/runos-official/rolekeeper/reconcile"
)

// version is set at build time (-X main.version).
var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("rolekeeper: %s is required", k)
	}
	return v
}

func main() {
	if infoArgs(os.Args[1:], os.Stdout) {
		return
	}
	var trust bundle.Trust
	raw, err := os.ReadFile(must("ROID_K8S_TRUST_FILE"))
	if err != nil {
		log.Fatalf("rolekeeper: trust file: %v", err)
	}
	if err := json.Unmarshal(raw, &trust); err != nil {
		log.Fatalf("rolekeeper: trust file: %v", err)
	}
	sum := sha256.Sum256(raw)
	trustSum := hex.EncodeToString(sum[:])
	// The highest root chain is kept beside the applier's state, so
	// a restart with an older trust file keeps it.
	stateDir := must("ROID_K8S_STATE_DIR")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatalf("rolekeeper: ROID_K8S_STATE_DIR: %v", err)
	}
	v, err := bundle.NewVerifier(trust, time.Now, filepath.Join(stateDir, "root-chain.json"))
	if err != nil {
		log.Fatalf("rolekeeper: %v", err)
	}
	cfg, err := applier.ParseRelayEnv(os.Getenv)
	if err != nil {
		log.Fatalf("rolekeeper: %v", err)
	}
	every, heartbeat := cfg.Interval, cfg.ReportEvery
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// A bundle of another account never applies here, whoever signed it.
	v.ExpectAccount(cfg.Account)
	kc, err := kubeClient()
	if err != nil {
		log.Fatalf("rolekeeper: %v", err)
	}
	canaryEvery, err := time.ParseDuration(env("ROID_K8S_CANARY_EVERY", "30s"))
	if err != nil || canaryEvery < time.Second {
		log.Fatal("rolekeeper: ROID_K8S_CANARY_EVERY must be a duration of at least 1s")
	}
	// The local fail-safe. Only roid's own refusal counts toward it,
	// never an outage, so the bound is long and at least an hour.
	refusedBound, err := time.ParseDuration(env("ROID_K8S_REFUSED_BOUND", "24h"))
	if err != nil || refusedBound < time.Hour {
		log.Fatal("rolekeeper: ROID_K8S_REFUSED_BOUND must be a duration of at least 1h")
	}
	retiredEvery, err := time.ParseDuration(env("ROID_K8S_RETIRED_EVERY", "10m"))
	if err != nil || retiredEvery < time.Minute {
		log.Fatal("rolekeeper: ROID_K8S_RETIRED_EVERY must be a duration of at least 1m")
	}
	selector := env("ROID_K8S_NS_SELECTOR", kobj.NamespaceSelector)
	floorNS := env("ROID_K8S_FLOOR_NS", env("POD_NAMESPACE", "runos"))
	var transport applier.Roid
	if cfg.Relay {
		transport = &applier.ConfigMapRoid{Kube: kc, Verifier: v, Namespace: env("POD_NAMESPACE", "roid-k8s-applier"),
			BundleName: cfg.BundleName, RelayName: cfg.RelayName, StatusName: cfg.StatusName,
			Account: cfg.Account, Cluster: trust.Cluster, TrustSHA256: trustSum, Version: version, Started: time.Now(), Now: time.Now}
	} else {
		roid := &applier.HTTPRoid{BaseURL: must("ROID_K8S_URL"), Account: cfg.Account, CAFile: must("ROID_K8S_CA_FILE")}
		if tf := os.Getenv("ROID_K8S_SA_TOKEN_FILE"); tf != "" {
			roid.ClientCert = enrol(ctx, roid.BaseURL, roid.CAFile, tf, trust.Cluster)
		} else {
			roid.CertFile, roid.KeyFile = must("ROID_K8S_CERT_FILE"), must("ROID_K8S_KEY_FILE")
		}
		transport = roid
	}
	a := &applier.Applier{
		Verifier: v,
		Floor:    applier.ConfigMapFloor{Kube: kc, Namespace: floorNS, Name: env("ROID_K8S_FLOOR_NAME", "roid-rbac-floor")},
		// Follow the root-signed policy-bundle key
		// set roid serves, so a compromise reset reaches this cluster.
		KeySets:     applier.ConfigMapKeySets{Kube: kc, Namespace: floorNS, Name: env("ROID_K8S_KEYS_NAME", "roid-rbac-keys")},
		Roid:        transport,
		Kube:        kc,
		Namespaces:  func(ctx context.Context) ([]string, error) { return kc.ListNamespaces(ctx, selector) },
		Now:         time.Now,
		Started:     time.Now(),
		ReportEvery: heartbeat,
		// The deny canary: after every pass, a dry-run write as each
		// of the two canaries tells whether the deny list really cuts.
		Probe:           kc,
		CanaryNamespace: env("ROID_K8S_CANARY_NS", env("POD_NAMESPACE", "roid-k8s-applier")),
		CanaryEvery:     canaryEvery,
		RefusedBound:    refusedBound,
		RetiredEvery:    retiredEvery,
	}
	log.Printf("rolekeeper %s started: %s transport, cluster %s, every %s, floor in %s", version, map[bool]string{true: "relay", false: "pull"}[cfg.Relay], trust.Cluster, every, floorNS)
	canary := ""
	retired := false
	onPass := func(res applier.Result, err error) {
		if res.Retired != retired {
			switch {
			case res.FailSafe:
				log.Printf("rolekeeper: FAIL-SAFE: roid refused this applier past %s; removed every roid-managed binding and stopped", refusedBound)
			case res.Retired:
				log.Printf("rolekeeper: retired by roid (v%d): removed every roid-managed binding and stopped", res.Version)
			default:
				log.Printf("rolekeeper: resumed with v%d", res.Version)
			}
			retired = res.Retired
		}
		if res.Canary != canary {
			if res.Canary == applier.CanaryFailing {
				log.Printf("rolekeeper: DENY CANARY FAILING: %s", res.CanaryReason)
			} else {
				log.Printf("rolekeeper: deny canary %s", res.Canary)
			}
			canary = res.Canary
		}
		if n := res.Report.Count(reconcile.EvDenyListMissing); n > 0 {
			log.Printf("rolekeeper: DENY LIST WAS MISSING and was written back (every write was allowed while it was gone)")
		}
		if n := res.Report.Count(reconcile.EvDenyPolicyMissing); n > 0 {
			log.Printf("rolekeeper: DENY POLICY OR BINDING MISSING: not re-created (the installer owns it); see the Kubernetes access runbook")
		}
		if err != nil {
			log.Printf("rolekeeper: pass refused or failed (bundle v%d): %v", res.Version, err)
			return
		}
		if n := len(res.Report.Events); n > 0 {
			log.Printf("rolekeeper: applied v%d, %d changes", res.Version, n)
		}
	}
	if cfg.Relay {
		a.RunRelay(ctx, cfg.WatchEvery, every, onPass)
	} else {
		a.Run(ctx, every, onPass)
	}
}

// kubeClient is the pod's service account, or a JSON kubeconfig outside a
// pod.
func kubeClient() (*kubeapi.Client, error) {
	if p := os.Getenv("KUBECONFIG"); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		c, err := kubeapi.FromKubeconfigJSON(raw)
		if err != nil {
			return nil, err
		}
		return kubeapi.New(c)
	}
	c, err := kubeapi.InCluster()
	if err != nil {
		return nil, err
	}
	return kubeapi.New(c)
}
