//go:build windows

// Windows egress lockdown (AW-T2B-v0.1 Phase B1, iteration 0): a Windows Firewall
// outbound BLOCK rule scoped to the agent's binary. Windows Firewall does not
// filter loopback, so the broker proxy on 127.0.0.1 stays reachable while every
// other outbound connection from the agent is dropped by the OS — a raw socket
// cannot bypass the proxy.
//
// Requires admin (firewall config). The rule is named, scoped to one executable,
// and removed on cleanup (and any stale rule is removed first), so the blast radius
// is the confined agent only.
//
// Iteration 1 will replace this with FWPM filters keyed on a per-confinement token
// SID (robust against a dropped helper exe). netsh is the simplest thing that
// proves the raw-socket bypass is closed, end to end, today.
//
// Licensed under the Apache License 2.0.
package enforce

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

const awEgressRuleName = "AgentWarden-egress-lockdown"

type netshFilter struct{}

// newNetFilter returns the Windows egress-lockdown backend.
func newNetFilter() NetFilter { return &netshFilter{} }

func (netshFilter) Lock(exePath string) (func(), error) {
	abs, err := filepath.Abs(exePath)
	if err != nil {
		abs = exePath
	}
	// Remove any stale rule from a previous (crashed) run before adding ours.
	_, _ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+awEgressRuleName)

	// Block all outbound for this program EXCEPT loopback (127.0.0.0/8), so the
	// broker proxy on 127.0.0.1 is reached cleanly while every external destination
	// (incl. 1.1.1.1) is dropped. Scoping the block to the non-loopback IPv4 range
	// avoids a program-wide block also catching the loopback proxy connection (which
	// Windows Firewall's loopback exemption does not reliably cover for program rules).
	// IPv6 non-loopback lockdown is an iteration-1 item (the proxy + demo are IPv4).
	const nonLoopbackV4 = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255"
	out, err := runNetsh("advfirewall", "firewall", "add", "rule",
		"name="+awEgressRuleName, "dir=out", "action=block",
		"program="+abs, "enable=yes", "profile=any", "remoteip="+nonLoopbackV4)
	if err != nil {
		return func() {}, fmt.Errorf("netsh add rule failed (run as Administrator?): %v: %s", err, out)
	}

	cleanup := func() {
		_, _ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+awEgressRuleName)
	}
	return cleanup, nil
}

func runNetsh(args ...string) (string, error) {
	b, err := exec.Command("netsh", args...).CombinedOutput()
	return string(b), err
}
