package applier

import (
	"fmt"
	"time"
)

// EnvConfig is the transport part of the applier's environment.
type EnvConfig struct {
	// Relay is ROID_K8S_TRANSPORT=relay. The default is pull.
	Relay   bool
	Account string
	// Relay only.
	BundleName, RelayName, StatusName string
	WatchEvery                        time.Duration
	// Interval is the pass interval, ReportEvery the status heartbeat.
	Interval, ReportEvery time.Duration
}

// ParseRelayEnv reads ROID_K8S_TRANSPORT and the settings that depend on
// it. In relay mode ROID_K8S_URL, ROID_K8S_CA_FILE, ROID_K8S_SA_TOKEN_FILE,
// ROID_K8S_SERVICE_ACCOUNT, ROID_K8S_DNS, ROID_K8S_CERT_FILE,
// ROID_K8S_KEY_FILE and POD_NAME are not read at all. The account is
// required in both modes: a verifier built without one checks no account
// (ExpectAccount("") is a no-op), so the command refuses to start.
func ParseRelayEnv(get func(string) string) (EnvConfig, error) {
	val := func(k, def string) string {
		if v := get(k); v != "" {
			return v
		}
		return def
	}
	var c EnvConfig
	switch get("ROID_K8S_TRANSPORT") {
	case "", "pull":
	case "relay":
		c.Relay = true
	default:
		return c, fmt.Errorf("ROID_K8S_TRANSPORT must be pull or relay, got %q", get("ROID_K8S_TRANSPORT"))
	}
	if c.Account = get("ROID_K8S_ACCOUNT"); c.Account == "" {
		return c, fmt.Errorf("ROID_K8S_ACCOUNT is required: a verifier without an account checks no account")
	}
	dur := func(k, def string, min time.Duration) (time.Duration, error) {
		d, err := time.ParseDuration(val(k, def))
		if err != nil || d < min {
			return 0, fmt.Errorf("%s must be a duration of at least %s", k, min)
		}
		return d, nil
	}
	var err error
	if c.Relay {
		for _, k := range []string{"ROID_K8S_TRUST_FILE", "ROID_K8S_STATE_DIR"} {
			if get(k) == "" {
				return c, fmt.Errorf("%s is required", k)
			}
		}
		c.BundleName = val("ROID_K8S_BUNDLE_NAME", "roid-rbac-bundle")
		c.RelayName = val("ROID_K8S_RELAY_NAME", "roid-rbac-relay")
		c.StatusName = val("ROID_K8S_STATUS_NAME", "roid-rbac-status")
		if c.WatchEvery, err = dur("ROID_K8S_WATCH_EVERY", "500ms", 100*time.Millisecond); err != nil {
			return c, err
		}
		if c.ReportEvery, err = dur("ROID_K8S_REPORT_EVERY", "60s", time.Second); err != nil {
			return c, err
		}
	} else if c.ReportEvery, err = dur("ROID_K8S_REPORT_EVERY", "5m", time.Second); err != nil {
		return c, err
	}
	if c.Interval, err = dur("ROID_K8S_INTERVAL", "2s", time.Second); err != nil {
		return c, err
	}
	return c, nil
}
