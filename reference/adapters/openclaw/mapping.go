// Package openclaw is the Tier-1 cooperative adapter that bridges OpenClaw's
// in-process `before_tool_call` plugin hook to the Agent Warden broker
// (AW-INT-v0.1, Part 1). A thin TypeScript shim inside OpenClaw forwards each
// tool call here as a ToolCall; this package maps it to a canonical
// awspec.Action, lets the broker mediate it, and returns a ToolVerdict the shim
// translates back into an OpenClaw hook return.
//
// Design rule (AW-INT-v0.1 §1.2): all policy lives in Go. The TS shim makes no
// security decision; it can only fail closed. Tool→Action *mapping* lives here
// (not in TS) so classification fidelity is one auditable place — the answer to
// the arXiv-2603.27517 finding that lexical, per-layer allowlists get bypassed.
//
// Licensed under the Apache License 2.0.
package openclaw

import (
	"strings"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// MapToolCall translates an OpenClaw tool call into a canonical awspec.Action
// (AW-INT-v0.1 §1.3). The mapping fixes the substrate + action class; the
// broker's Classify still decides irreversibility, and the gate still decides
// the verdict — mapping never pre-judges policy.
//
// Unknown tools map to a fail-closed action (substrate "" / class "unknown")
// that the broker treats with its strictest external posture, so an unmapped
// tool can never pass through ungoverned (§1.3 normative).
func MapToolCall(tc ToolCall) awspec.Action {
	sub, class := classify(tc.Tool)
	a := awspec.Action{
		AgentID:   firstNonEmpty(tc.Agent, ctxVal(tc.Ctx, "agent_id"), "openclaw-agent"),
		Substrate: sub,
		Class:     class,
		Params:    tc.Params,
		// Integration provenance (§1.4).
		Source: "openclaw",
		Tier:   1,
		Tool:   tc.Tool,
		Ctx:    tc.Ctx,
	}
	return a
}

// classify maps an OpenClaw tool name to (substrate, action class).
// Verified against docs.openclaw.ai tool inventory (AW-INT-v0.1 §1.3) and a live
// OpenClaw run (2026.6.5), which calls tools with UNDERSCORE names (e.g.
// `web_fetch`). We normalize `_`→`-` and lowercase so both naming conventions
// map identically; an unrecognized tool still falls through to a fail-closed
// `unknown` (which the gate denies unless policy allows it).
func classify(tool string) (awspec.Substrate, string) {
	tool = strings.ToLower(strings.ReplaceAll(tool, "_", "-"))
	switch tool {
	// Shell execution. NOTE: we deliberately do NOT lexically trust the command
	// string. We hand it to the proc substrate; the broker/contain engine owns
	// reversibility, not a parse of the command (arXiv-2603.27517 §exec-allowlist).
	case "exec", "process", "shell", "bash", "code-execution":
		return awspec.SubProc, "process.exec"

	// Filesystem writes — reversible via the journal when in scope.
	case "write", "write-file", "apply_patch", "apply-patch", "edit", "diffs":
		return awspec.SubFS, "fs.write"
	case "delete", "rm", "remove-file":
		return awspec.SubFS, "fs.delete"
	case "read", "read-file", "pdf", "view":
		return awspec.SubFS, "fs.read"

	// Network egress — data may leave the boundary (I-EGRESS).
	case "web-fetch", "web", "web-search", "browser", "fetch",
		"brave-search", "duckduckgo-search", "exa-search", "perplexity-search",
		"firecrawl", "tavily", "image-generation", "video-generation", "tts":
		return awspec.SubNet, "net.egress"

	// Value transfer / outbound message to a third party — external irreversible.
	case "email", "send-email", "message", "send-message", "sms", "voice-call",
		"payment", "pay", "transfer", "checkout":
		return awspec.SubValue, "value.message"

	// Credential use/export.
	case "secret", "credential", "api-key", "token":
		return awspec.SubCred, "cred.use"

	default:
		// Fail-closed: empty substrate falls through broker.Classify's default
		// branch → strictest external posture (deny unless policy allows).
		return awspec.Substrate(""), "unknown"
	}
}

func ctxVal(m map[string]string, k string) string {
	if m == nil {
		return ""
	}
	return m[k]
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
