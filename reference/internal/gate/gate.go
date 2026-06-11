// Package gate implements the irreversible-frontier decision procedure
// (AW-Spec v0.2 §3.3, §7.2). It emits exactly one of four verdicts —
// allow / deny / escalate / sandbox — and never lets an agent self-authorize.
//
// Licensed under the Apache License 2.0.
package gate

import (
	"github.com/aiegis/agentwarden/internal/capability"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Gate evaluates policy for irreversible actions.
type Gate struct {
	pol          *policy.Policy
	trustRootKey []byte
	// realHandlers is the set of substrates with a real effect handler in this
	// build. A substrate not present here cannot yield a real `allow` — only
	// `sandbox` or `deny` (the AW-G-1 external-side-effect gap, AW-Spec §4.4).
	realHandlers map[awspec.Substrate]bool
}

// New builds a gate. realHandlers lists substrates this build can really act on.
func New(pol *policy.Policy, trustRootKey []byte, realHandlers map[awspec.Substrate]bool) *Gate {
	return &Gate{pol: pol, trustRootKey: trustRootKey, realHandlers: realHandlers}
}

// Decision is the gate's output for one irreversible action.
type Decision struct {
	Verdict awspec.Verdict
	Reason  string
}

// Decide runs the AW-Spec §7.2 procedure for an irreversible action with category
// cat. Callers MUST only route irreversible actions here (the broker classifies).
func (g *Gate) Decide(a awspec.Action, cat awspec.IrrevCategory) Decision {
	// Step 2: categorically-non-overridable deny dominates everything.
	if g.pol.HardDenied(a) {
		return Decision{Verdict: awspec.Deny, Reason: "categorically non-overridable (hard_deny)"}
	}

	// Step 3: most-specific rule, else fail-closed default. Never default-allow.
	verdict, matched := g.pol.Resolve(a)
	if !matched {
		verdict = g.pol.Defaults.Irreversible // validated to never be Allow
	}

	// Step 4: capability verification (if one is carried). A failed check denies.
	if a.Carried != nil {
		if vr := capability.Verify(a.Carried, a, g.trustRootKey); !vr.OK {
			return Decision{Verdict: awspec.Deny, Reason: "capability check failed: " + vr.Reason}
		}
	}

	// Self-authorization guard (AW-Spec §7.4): an `allow`/`sandbox` here is only
	// reachable from user-authored policy + verified capability above. The agent's
	// own assertions never reach this code path — Action carries no "I am allowed"
	// field. (Invariant enforced by construction / type system.)

	// Constraint: a real `allow` requires a real handler AND, if a capability is
	// carried, that it be STABLE (AW-G-2 hook, §6.3). Otherwise downgrade.
	if verdict == awspec.Allow {
		if !g.realHandlers[a.Substrate] {
			// No real handler (e.g. I-VALUE / I-PHYS in P1): cannot really do it.
			if cat.NonContainableExternal() {
				// Safe to rehearse rather than deny outright.
				return Decision{Verdict: awspec.Sandbox,
					Reason: "no real handler for non-containable external effect; rehearsed (AW-G-1)"}
			}
			return Decision{Verdict: awspec.Deny, Reason: "policy allowed but no real handler (fail-closed)"}
		}
		if !capability.GrantsRealIrreversibleReach(a.Carried) {
			return Decision{Verdict: awspec.Sandbox,
				Reason: "capability not STABLE; real reach withheld, rehearsed (AW-G-2 §6.3)"}
		}
	}

	reason := "matched policy rule"
	if !matched {
		reason = "fail-closed default"
	}
	return Decision{Verdict: verdict, Reason: reason}
}
