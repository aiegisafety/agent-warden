// Package awspec defines the wire-level types shared between the AW broker,
// its components, and agent adapters. These types implement AW-Spec v0.2.
//
// Licensed under the Apache License 2.0.
package awspec

// Substrate is a class of real-world resource the broker mediates (AW-Spec §2, §4).
type Substrate string

const (
	SubFS    Substrate = "fs"    // filesystem
	SubProc  Substrate = "proc"  // workspace / process
	SubNet   Substrate = "net"   // external network egress
	SubCred  Substrate = "cred"  // credentials / secrets
	SubValue Substrate = "value" // value transfer rails
	SubPhys  Substrate = "phys"  // physical actuators (bridge to PEA-R)
	SubDB    Substrate = "db"    // database (P2, via DB Warden)
)

// IrrevCategory is the irreversibility classification of an action (AW-Spec §4.1).
// The empty value "" / Reversible means the action is fully contained-reversible.
type IrrevCategory string

const (
	Reversible IrrevCategory = "reversible"
	IEgress    IrrevCategory = "I-EGRESS"  // external egress
	IValue     IrrevCategory = "I-VALUE"   // value transfer
	IPhys      IrrevCategory = "I-PHYS"    // physical execution
	IDestroy   IrrevCategory = "I-DESTROY" // no-snapshot destruction
)

// Irreversible reports whether c is one of the four irreversible base categories.
func (c IrrevCategory) Irreversible() bool {
	switch c {
	case IEgress, IValue, IPhys, IDestroy:
		return true
	default:
		return false
	}
}

// NonContainableExternal reports whether c is an irreversible category that acts on
// a party outside the user's boundary and therefore cannot be snapshot/rolled back.
// These are the categories for which the `sandbox` verdict is the explore path
// (AW-Spec §4.4, AW-G-1). I-DESTROY is irreversible but local, so it is NOT here.
func (c IrrevCategory) NonContainableExternal() bool {
	switch c {
	case IEgress, IValue, IPhys:
		return true
	default:
		return false
	}
}

// Verdict is the gate's decision on an irreversible action (AW-Spec §2, §3.3).
// The four verdicts are the load-bearing AW-G-1 addition in v0.2.
type Verdict string

const (
	Allow    Verdict = "allow"    // release the real effect
	Deny     Verdict = "deny"     // block it
	Escalate Verdict = "escalate" // route to a human
	Sandbox  Verdict = "sandbox"  // release a simulated effect against a decoy (AW-G-1)
)

// LifecycleState is the trust stage of a capability (AW-Spec §6.3, AW-G-2, P3).
type LifecycleState string

const (
	Experimental LifecycleState = "EXPERIMENTAL"
	Candidate    LifecycleState = "CANDIDATE"
	Approved     LifecycleState = "APPROVED"
	Stable       LifecycleState = "STABLE"
	Deprecated   LifecycleState = "DEPRECATED"
)

// Capability is unforgeable carried authority attached to a request (AW-Spec §6.1).
type Capability struct {
	CapType        string            `json:"cap_type"`
	ParamBounds    map[string]string `json:"param_bounds"`
	Scope          []Substrate       `json:"scope"`
	Validity       string            `json:"validity"`
	Lineage        string            `json:"lineage"`         // ref to user-authored policy grant
	LifecycleState LifecycleState    `json:"lifecycle_state"` // §6.3 (P3); defaults STABLE for user grants
	IntegrityTag   string            `json:"integrity_tag"`   // hex HMAC under trust-root key
}

// Action is a concrete operation an agent proposes through the broker (AW-Spec §2).
type Action struct {
	AgentID   string            `json:"agent_id"`
	Substrate Substrate         `json:"substrate"`
	Class     string            `json:"action_class"` // e.g. "fs.write", "net.egress", "value.transfer"
	Params    map[string]string `json:"params"`       // path, dest, amount, bytes-digest, ...
	Carried   *Capability       `json:"carried,omitempty"`
	Taint     string            `json:"taint,omitempty"` // provenance summary (AW-Spec §5.5)

	// Integration provenance (AW-INT-v0.1 §1.4). All omitempty so Tier-0 callers
	// (e.g. the qwen sim) that leave them zero serialize identically to before —
	// existing ledgers and tests stay byte-stable.
	Source string            `json:"source,omitempty"` // adapter id, e.g. "openclaw"
	Tier   int               `json:"tier,omitempty"`   // 1=cooperative hook, 2=OS interception
	Tool   string            `json:"tool,omitempty"`   // raw agent tool name (audit)
	Ctx    map[string]string `json:"ctx,omitempty"`    // correlation: agent_id/session_id/run_id/tool_call_id
}

// Result is what the broker returns to the agent after mediating an action.
type Result struct {
	Verdict   Verdict `json:"verdict"`
	Simulated bool    `json:"simulated"` // true iff routed to a decoy (AW-G-1)
	Payload   string  `json:"payload"`   // substrate-shaped result (real or decoy)
	Reason    string  `json:"reason"`
}
