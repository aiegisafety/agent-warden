// Package exec is the subprocess adapter: it launches an agent as a child process
// and wires the agent's stdout/stdin to the broker's protocol server (AW-Spec
// v0.2 §3.1). The agent reaches the world ONLY by writing awproto Requests to its
// stdout; the broker mediates each and returns a Response on the agent's stdin.
//
// Honesty note (threat-model RR-5, charter §14): this gives complete mediation by
// construction only over the agent's *protocol* tool surface. A child process can
// still attempt raw syscalls; constraining that requires OS-level sandboxing
// (seccomp / job objects / containers) and is the explicit P1 hardening step. The
// reference adapter does not yet claim syscall-level confinement.
//
// Licensed under the Apache License 2.0.
package exec

import (
	"io"
	"os/exec"

	"github.com/aiegis/agentwarden/internal/server"
)

// Run launches cmd (a prepared *exec.Cmd for the agent) and serves the broker
// protocol over its stdio until the agent exits. Returns the first error from
// pipe setup, the serve loop, or the agent's exit.
func Run(m server.Mediator, cmd *exec.Cmd) error {
	agentOut, err := cmd.StdoutPipe() // agent writes Requests here
	if err != nil {
		return err
	}
	agentIn, err := cmd.StdinPipe() // broker writes Responses here
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	serveErr := server.Serve(m, agentOut, agentIn)

	// Signal end-of-input to the agent and wait for it to exit.
	_ = agentIn.Close()
	waitErr := cmd.Wait()

	if serveErr != nil && serveErr != io.EOF {
		return serveErr
	}
	return waitErr
}
