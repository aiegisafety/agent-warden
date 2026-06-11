// Bridge protocol + loop for the Tier-1 OpenClaw adapter (AW-INT-v0.1 §1.2, §1.5).
//
// Wire: the OpenClaw TS shim and this Go bridge exchange newline-delimited JSON
// over stdio (the shim spawns `aw-openclaw-bridge` as a child) or a loopback
// socket. The shim sends a ToolCall; the bridge replies with a ToolVerdict the
// shim turns into an OpenClaw `before_tool_call` return:
//
//	allow    -> shim returns undefined            (tool runs)
//	deny     -> shim returns {block, blockReason}
//	escalate -> shim returns {requireApproval{…}}  (timeout=deny, fail-closed)
//	sandbox  -> shim returns {params: decoyParams} (tool runs against a decoy)
//
// This file is transport-agnostic: Serve takes any io.Reader/io.Writer.
//
// Licensed under the Apache License 2.0.
package openclaw

import (
	"encoding/json"
	"io"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// ToolCall is what the OpenClaw shim forwards from `before_tool_call`.
// It is intentionally dumb: the raw tool name + params + correlation context.
type ToolCall struct {
	ID     int               `json:"id"`
	Agent  string            `json:"agent,omitempty"`
	Tool   string            `json:"tool"`
	Params map[string]string `json:"params"`
	Ctx    map[string]string `json:"ctx,omitempty"` // agent_id/session_id/run_id/tool_call_id
}

// ApprovalSpec mirrors OpenClaw's requireApproval shape (verified docs/plugins/hooks).
type ApprovalSpec struct {
	Title           string `json:"title"`
	Description     string `json:"description"`
	Severity        string `json:"severity"`         // info|warning|critical
	TimeoutMs       int    `json:"timeoutMs"`        // 0 => shim default
	TimeoutBehavior string `json:"timeoutBehavior"`  // MUST be "deny" (fail-closed)
}

// ToolVerdict is the bridge's answer. Exactly one of the decision-specific
// fields is meaningful per Decision (§1.5).
type ToolVerdict struct {
	ID          int               `json:"id"`
	Decision    string            `json:"decision"` // allow|deny|escalate|sandbox
	BlockReason string            `json:"blockReason,omitempty"`
	DecoyParams map[string]string `json:"decoyParams,omitempty"`
	Approval    *ApprovalSpec     `json:"approval,omitempty"`
	Simulated   bool              `json:"simulated,omitempty"`
	LedgerNote  string            `json:"ledgerNote,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// Mediator is the broker entry point the bridge drives.
type Mediator interface {
	Mediate(a awspec.Action) (awspec.Result, error)
}

// Translate maps a ToolCall through the mediator into a ToolVerdict.
// On any mediation error it returns a fail-closed deny (§1.5: absence of an
// allow is never an allow).
func Translate(m Mediator, tc ToolCall) ToolVerdict {
	a := MapToolCall(tc)
	res, err := m.Mediate(a)
	if err != nil {
		return ToolVerdict{ID: tc.ID, Decision: string(awspec.Deny),
			BlockReason: "aw-broker error (fail-closed): " + err.Error(), Error: err.Error()}
	}
	v := ToolVerdict{ID: tc.ID, Decision: string(res.Verdict), Simulated: res.Simulated, LedgerNote: res.Reason}
	switch res.Verdict {
	case awspec.Deny:
		v.BlockReason = res.Reason
	case awspec.Escalate:
		v.Approval = &ApprovalSpec{
			Title:           "Agent Warden: approve " + tc.Tool + "?",
			Description:     res.Reason,
			Severity:        "warning",
			TimeoutBehavior: "deny", // fail-closed (§1.5)
		}
	case awspec.Sandbox:
		// Redirect the tool to a harmless decoy. P1: a marker the shim honors by
		// pointing the call at a no-op endpoint; perfect indistinguishability is
		// NOT required, user-visible `simulated` IS (AW-Spec §3.6/§7.5).
		v.DecoyParams = decoyFor(tc)
	case awspec.Allow:
		// shim returns undefined; nothing extra needed.
	}
	return v
}

// decoyFor produces decoy params for a sandboxed tool call. It never carries the
// real destination/amount; it points the tool at an inert local sink.
func decoyFor(tc ToolCall) map[string]string {
	d := map[string]string{"aw_decoy": "1", "aw_original_tool": tc.Tool}
	switch {
	case tc.Params["url"] != "":
		d["url"] = "http://127.0.0.1:9/aw-decoy" // discard port, never reached
	case tc.Params["to"] != "" || tc.Params["dest"] != "":
		d["to"] = "aw-decoy@localhost.invalid"
	}
	return d
}

// Serve runs the bridge loop until in reaches EOF. One ToolCall per line in,
// one ToolVerdict per line out. Malformed input lines yield a fail-closed deny.
func Serve(m Mediator, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var tc ToolCall
		if err := dec.Decode(&tc); err != nil {
			if err == io.EOF {
				return nil
			}
			// Malformed line: fail closed, keep serving.
			if encErr := enc.Encode(ToolVerdict{Decision: string(awspec.Deny),
				BlockReason: "malformed tool call (fail-closed)", Error: err.Error()}); encErr != nil {
				return encErr
			}
			continue
		}
		if err := enc.Encode(Translate(m, tc)); err != nil {
			return err
		}
	}
}
