// NetFilter is the Tier-2-b egress-lockdown component (AW-T2B-v0.1 §3 Phase B1):
// it makes a confined process physically unable to reach the network except
// through the broker proxy — enforced by the OS, so a raw socket cannot bypass it.
//
// This is the answer to threat-model RR-7 for the network surface, and it needs
// NO kernel driver: it uses the OS firewall / Windows Filtering Platform (the same
// mechanism the Windows Firewall is built on), configured from user mode.
//
// Iteration 0 (this file's Windows impl) keys the lockdown on the agent's binary
// path via the OS firewall. A later iteration will key on a per-confinement token
// SID via the FWPM API for robustness against a dropped helper executable.
//
// Licensed under the Apache License 2.0.
package enforce

// NetFilter installs and removes an OS-enforced egress lockdown for a confined
// process. Loopback (the broker proxy) stays reachable; all other outbound is
// blocked.
type NetFilter interface {
	// Lock locks down egress for the process image at exePath. It returns a cleanup
	// that removes the lockdown; cleanup is always safe to call (a no-op if nothing
	// was installed). A non-nil error means the lockdown was NOT applied (e.g. no
	// admin) — the caller should fall back to Job-Object containment and say so.
	Lock(exePath string) (cleanup func(), err error)
}
