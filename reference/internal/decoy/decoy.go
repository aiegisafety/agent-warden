// Package decoy serves the `sandbox` verdict (AW-Spec v0.2 §3.6, AW-G-1). It
// returns plausible, substrate-shaped results to the agent while guaranteeing no
// real substrate is touched. This package deliberately imports NO real I/O handler
// (no net, no payment client): isolation is enforced by construction.
//
// Licensed under the Apache License 2.0.
package decoy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Router routes a sandboxed action to a substrate-shaped decoy.
type Router struct{}

func New() *Router { return &Router{} }

// Simulate returns a plausible result for a sandboxed action. It MUST NOT touch
// the real substrate. The returned Result always has Simulated=true.
func (r *Router) Simulate(a awspec.Action) awspec.Result {
	switch a.Substrate {
	case awspec.SubNet:
		// Synthetic HTTP-shaped response; nothing leaves the host.
		return awspec.Result{
			Verdict:   awspec.Sandbox,
			Simulated: true,
			Payload:   `{"status":200,"body":"","note":"simulated egress — no data left the host"}`,
			Reason:    "decoy net.egress (AW-G-1)",
		}
	case awspec.SubValue:
		// Synthetic transaction receipt; no rail is touched.
		ref := fakeRef(a)
		return awspec.Result{
			Verdict:   awspec.Sandbox,
			Simulated: true,
			Payload:   fmt.Sprintf(`{"status":"confirmed","tx_ref":"SANDBOX-%s","note":"simulated transfer — no funds moved"}`, ref),
			Reason:    "decoy value.transfer (AW-G-1)",
		}
	case awspec.SubPhys:
		return awspec.Result{
			Verdict:   awspec.Sandbox,
			Simulated: true,
			Payload:   `{"status":"ack","note":"simulated actuation — no physical effect"}`,
			Reason:    "decoy phys (AW-G-1; real governance = PEA-R)",
		}
	default:
		return awspec.Result{
			Verdict:   awspec.Sandbox,
			Simulated: true,
			Payload:   `{"status":"ok","note":"simulated effect — nothing real touched"}`,
			Reason:    "decoy generic (AW-G-1)",
		}
	}
}

func fakeRef(a awspec.Action) string {
	h := sha256.Sum256([]byte(a.AgentID + "|" + a.Class + "|" + a.Params["dest"] + "|" + a.Params["amount"]))
	return hex.EncodeToString(h[:])[:12]
}
