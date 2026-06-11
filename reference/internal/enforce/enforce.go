// Package enforce is the Tier-2 OS-interception layer (AW-INT-v0.1 Part 2): the
// non-bypassable backstop for an agent that ignores the cooperative Tier-1 hook
// and drops to raw syscalls (threat-model RR-7). It confines the agent process so
// every irreversible external effect is forced through the AW broker, and grants
// the process no ambient authority to reach a substrate any other way.
//
// This file is the substrate-independent contract. Concrete backends:
//   - jobobject_windows.go  (//go:build windows)  — T2-a user-mode confinement
//   - stub_other.go         (//go:build !windows) — compiles everywhere; unsupported
//   - proxy/                — local egress proxy raising net effects to the broker
//
// Honesty boundary (carried into code): the user-mode T2-a backend closes the
// casual-bypass case; a determined native bypass of WFP/minifilter is still
// possible until the kernel-mode T2-b driver lands. We do NOT claim
// non-bypassability from T2-a alone (AW-INT-v0.1 §2.2).
//
// Licensed under the Apache License 2.0.
package enforce

import (
	"context"
	"errors"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// ErrUnsupported is returned by backends not available on the current OS.
var ErrUnsupported = errors.New("enforce: OS-level interception not supported on this platform")

// AgentSpec describes the agent process to confine (AW-INT-v0.1 §2.3).
type AgentSpec struct {
	Exe         string   // agent executable
	Args        []string // its arguments
	WorkDir     string   // brokered, journaled working directory
	EgressProxy string   // host:port of the AW egress proxy; all egress is pinned here

	// NoChildProcesses, when true, launches the agent with the Windows
	// CHILD_PROCESS_RESTRICTED mitigation so it cannot spawn ANY child process
	// (AW-T2B-v0.1 Phase B1 step 1). This closes the "drop a helper exe to evade the
	// per-binary egress rule" bypass: with no child allowed, the agent binary is the
	// only thing that can run, so the egress lockdown keyed on it is complete.
	// Windows-only; ignored elsewhere.
	NoChildProcesses bool

	// LowIntegrity, when true, runs the agent at Windows **Low** integrity level and
	// labels WorkDir Low (AW-T2B-v0.1 Phase B2). Windows Mandatory Integrity Control
	// then lets the agent write its (Low-labeled) workspace but DENIES writes to
	// normal medium/high-integrity locations (the user's files, system dirs, startup
	// folders) — OS-enforced filesystem containment with no kernel driver.
	// Windows-only; ignored elsewhere.
	LowIntegrity bool
}

// Verdict is re-exported so backends and the broker speak one verdict vocabulary.
type Verdict = awspec.Verdict

// EffectFunc mediates one intercepted effect. A backend MUST block the
// originating thread until this returns, and MUST treat any non-Allow as
// "do not release the real effect". If it cannot call the mediator at all, it
// MUST deny (fail-closed, §2.3 rule 1).
type EffectFunc func(awspec.Action) Verdict

// Interceptor confines an agent and routes its irreversible effects to a Mediator.
type Interceptor interface {
	// Launch starts the agent under confinement and blocks until it exits.
	Launch(ctx context.Context, spec AgentSpec) error
	// OnEffect registers the mediation callback (AW-INT-v0.1 §2.3).
	OnEffect(EffectFunc)
}

// Validate checks an AgentSpec for the minimum a backend needs.
func (s AgentSpec) Validate() error {
	if s.Exe == "" {
		return errors.New("enforce: AgentSpec.Exe is required")
	}
	if s.WorkDir == "" {
		return errors.New("enforce: AgentSpec.WorkDir is required (must be brokered/journaled)")
	}
	return nil
}
