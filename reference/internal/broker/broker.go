// Package broker is the mediation layer: the single path by which a governed agent
// reaches any substrate (AW-Spec v0.2 §3.1). It classifies each action by
// substrate + irreversibility, routes reversible effects to the containment engine
// and irreversible effects to the gate, then honors the verdict — including routing
// `sandbox` to the decoy router. It grants no ambient authority.
//
// Licensed under the Apache License 2.0.
package broker

import (
	"fmt"
	"net/url"

	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/vault"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// RealHandler performs a real (non-simulated) irreversible effect for a substrate
// the build actually supports. Returns a substrate-shaped payload.
type RealHandler func(a awspec.Action) (string, error)

// VaultResolver turns a vaulted alias into its plaintext secret + binding. Only the
// broker holds one, and only at the egress boundary (AW-HLD-P2-CRED §3). *vault.Vault
// satisfies it.
type VaultResolver interface {
	Resolve(alias string) (string, vault.Binding, error)
}

// Broker wires the components together.
type Broker struct {
	journal      *contain.Journal
	gate         *gate.Gate
	led          *ledger.Ledger
	decoy        *decoy.Router
	realHandlers map[awspec.Substrate]RealHandler
	vault        VaultResolver // optional (P2 credential vault); nil = no vault refs allowed
}

// New builds a broker.
func New(j *contain.Journal, g *gate.Gate, l *ledger.Ledger, d *decoy.Router,
	realHandlers map[awspec.Substrate]RealHandler) *Broker {
	return &Broker{journal: j, gate: g, led: l, decoy: d, realHandlers: realHandlers}
}

// WithVault attaches a credential vault (P2). Without it, any action carrying a
// `${vault:...}` reference is denied. Returns the broker for chaining.
func (b *Broker) WithVault(v VaultResolver) *Broker {
	b.vault = v
	return b
}

// Classify determines the irreversibility category of an action (AW-Spec §4).
// Reversible returns awspec.Reversible. Conservative: unknown → irreversible.
func (b *Broker) Classify(a awspec.Action) awspec.IrrevCategory {
	switch a.Substrate {
	case awspec.SubFS:
		switch a.Class {
		case "fs.read":
			return awspec.Reversible
		case "fs.write", "fs.delete":
			if b.journal != nil && b.journal.InScope(a.Params["path"]) {
				return awspec.Reversible // contained: snapshot + rollback
			}
			return awspec.IDestroy // outside snapshot scope: no recoverable pre-state
		}
		return awspec.IDestroy // unknown fs op: conservative
	case awspec.SubProc:
		return awspec.Reversible // restartable/sandboxed workspace
	case awspec.SubNet:
		return awspec.IEgress
	case awspec.SubCred:
		return awspec.IEgress // using/exporting a secret = it leaves the boundary
	case awspec.SubValue:
		return awspec.IValue
	case awspec.SubPhys:
		return awspec.IPhys
	default:
		return awspec.IEgress // unknown substrate: strictest external posture (conservative)
	}
}

// Mediate is the ONLY path to a substrate. It returns the result of the action.
func (b *Broker) Mediate(a awspec.Action) (awspec.Result, error) {
	cat := b.Classify(a)

	// Reversible effects run free through the containment engine — no gate.
	if !cat.Irreversible() {
		return b.runReversible(a)
	}

	// Credential vault (P2): resolve + destination-bind-check any ${vault:...}
	// references BEFORE gating. A reference with no vault, an unknown alias, or a
	// destination outside the secret's binding is a recorded deny — the secret is
	// never resolved into anything the agent or ledger can see.
	resolved, vdeny := b.prepareVault(a)
	if vdeny != "" {
		if _, err := b.led.Append(ledger.Body{
			RecordType: ledger.GateDecision, AgentID: a.AgentID, Substrate: a.Substrate,
			ActionClass: a.Class, IrrevCategory: cat, Verdict: awspec.Deny,
			Taint: a.Taint, EffectDigest: vdeny, Source: a.Source, Tier: a.Tier, Tool: a.Tool,
		}); err != nil {
			return awspec.Result{}, err
		}
		return awspec.Result{Verdict: awspec.Deny, Reason: vdeny}, nil
	}

	// Irreversible: consult the gate.
	dec := b.gate.Decide(a, cat)

	capRef := ""
	var lifecycle awspec.LifecycleState
	if a.Carried != nil {
		capRef = a.Carried.Lineage
		lifecycle = a.Carried.LifecycleState
	}

	// Record the gate verdict BEFORE any effect is released (AW-Spec §3.3).
	if _, err := b.led.Append(ledger.Body{
		RecordType:     ledger.GateDecision,
		AgentID:        a.AgentID,
		Substrate:      a.Substrate,
		ActionClass:    a.Class,
		IrrevCategory:  cat,
		Verdict:        dec.Verdict,
		CapabilityRef:  capRef,
		LifecycleState: lifecycle,
		Taint:          a.Taint,
		EffectDigest:   dec.Reason,
		Source:         a.Source,
		Tier:           a.Tier,
		Tool:           a.Tool,
	}); err != nil {
		return awspec.Result{}, err
	}

	switch dec.Verdict {
	case awspec.Deny:
		return awspec.Result{Verdict: awspec.Deny, Reason: dec.Reason}, nil

	case awspec.Escalate:
		// P1: surface to the caller (a human channel decides). No effect released.
		return awspec.Result{Verdict: awspec.Escalate, Reason: dec.Reason}, nil

	case awspec.Sandbox:
		res := b.decoy.Simulate(a)
		if _, err := b.led.Append(ledger.Body{
			RecordType:    ledger.IrreversibleEffect,
			AgentID:       a.AgentID,
			Substrate:     a.Substrate,
			ActionClass:   a.Class,
			IrrevCategory: cat,
			Verdict:       awspec.Sandbox,
			Simulated:     true, // AW-G-1: user can always tell rehearsed from real
			CapabilityRef: capRef,
			Taint:         a.Taint,
			EffectDigest:  "decoy:" + res.Payload,
			Source:        a.Source,
			Tier:          a.Tier,
			Tool:          a.Tool,
		}); err != nil {
			return awspec.Result{}, err
		}
		return res, nil

	case awspec.Allow:
		h, ok := b.realHandlers[a.Substrate]
		if !ok {
			// Should not happen: gate downgrades Allow without a real handler.
			return awspec.Result{Verdict: awspec.Deny, Reason: "no real handler (defensive)"}, nil
		}
		// Vault injection happens HERE and only here: the real secret enters the
		// outbound request inside the egress boundary, never the agent's view.
		ainj := a
		if len(resolved) > 0 {
			ainj.Params = injectParams(a.Params, resolved)
		}
		payload, err := h(ainj)
		if err != nil {
			// Even an error string could echo an injected secret — redact it.
			return awspec.Result{}, fmt.Errorf("%s", awspec.Redact(err.Error(), resolved))
		}
		// Redact any resolved secret before the agent or the ledger can see it.
		safe := awspec.Redact(payload, resolved)
		if _, err := b.led.Append(ledger.Body{
			RecordType:    ledger.IrreversibleEffect,
			AgentID:       a.AgentID,
			Substrate:     a.Substrate,
			ActionClass:   a.Class,
			IrrevCategory: cat,
			Verdict:       awspec.Allow,
			Simulated:     false,
			CapabilityRef: capRef,
			Taint:         a.Taint,
			EffectDigest:  digest(safe),
			Source:        a.Source,
			Tier:          a.Tier,
			Tool:          a.Tool,
		}); err != nil {
			return awspec.Result{}, err
		}
		return awspec.Result{Verdict: awspec.Allow, Payload: safe, Reason: "real effect released"}, nil

	default:
		return awspec.Result{}, fmt.Errorf("unknown verdict %q", dec.Verdict)
	}
}

// runReversible handles contained filesystem/workspace effects through the journal.
func (b *Broker) runReversible(a awspec.Action) (awspec.Result, error) {
	switch {
	case a.Substrate == awspec.SubFS && a.Class == "fs.write":
		if err := b.journal.Write(a.Params["path"], []byte(a.Params["content"])); err != nil {
			return awspec.Result{}, err
		}
	case a.Substrate == awspec.SubFS && a.Class == "fs.delete":
		if err := b.journal.Delete(a.Params["path"]); err != nil {
			return awspec.Result{}, err
		}
	case a.Substrate == awspec.SubFS && a.Class == "fs.read":
		// no effect
	case a.Substrate == awspec.SubProc:
		// no contained effect modeled in P1
	}
	return awspec.Result{Verdict: awspec.Allow, Reason: "reversible — ran free (contained)"}, nil
}

// prepareVault resolves and destination-bind-checks every ${vault:alias} in the
// action's params. Returns the resolved alias→value map (for injection at egress)
// or a non-empty deny reason. The returned map must NEVER be logged or returned to
// the agent; it is consumed only by injectParams inside the egress boundary.
func (b *Broker) prepareVault(a awspec.Action) (map[string]string, string) {
	aliases := awspec.ParamVaultRefs(a.Params)
	if len(aliases) == 0 {
		return nil, "" // no vault involvement — zero behavior change
	}
	if b.vault == nil {
		return nil, "vault reference present but no vault is configured (fail-closed)"
	}
	dest := destOf(a)
	resolved := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		val, binding, err := b.vault.Resolve(alias)
		if err != nil {
			return nil, "unknown vault alias: " + alias
		}
		if !binding.Allows(a.Substrate, dest) {
			return nil, fmt.Sprintf("secret %q is not bound to destination %q (substrate %s)", alias, dest, a.Substrate)
		}
		resolved[alias] = val
	}
	return resolved, ""
}

// destOf extracts the destination an action targets, for vault binding checks.
func destOf(a awspec.Action) string {
	if d := a.Params["dest"]; d != "" {
		return d
	}
	if h := a.Params["host"]; h != "" {
		return h
	}
	if t := a.Params["to"]; t != "" {
		return t
	}
	if u := a.Params["url"]; u != "" {
		if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
			return pu.Hostname()
		}
	}
	return ""
}

// injectParams returns a copy of params with every ${vault:alias} replaced by its
// resolved secret. Used only on the outbound request inside the egress boundary.
func injectParams(params, resolved map[string]string) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		if nv, err := awspec.InjectRefs(v, resolved); err == nil {
			out[k] = nv
		} else {
			out[k] = v // prepareVault already resolved all refs; defensive
		}
	}
	return out
}

func digest(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
