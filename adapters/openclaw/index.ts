// Agent Warden — OpenClaw Tier-1 adapter (the "dumb shim", AW-INT-v0.1 §1.2).
//
// This plugin makes NO security decision. It forwards each tool call to the Go
// broker (`aw-openclaw-bridge`) and translates the broker's verdict back into an
// OpenClaw `before_tool_call` return. Every failure path returns `block` — the
// shim can only fail closed. All policy, classification, reversibility, and the
// tamper-evident ledger live in Go.
//
// Verified against docs.openclaw.ai/plugins/hooks (before_tool_call /
// after_tool_call / before_install) and the BeforeToolCallResult shape.
//
// Licensed under the Apache License 2.0.

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { AwClient } from "./awclient.js";

// One bridge process per Gateway. Path is configurable; defaults to PATH lookup.
const BRIDGE_BIN = process.env.AW_BRIDGE_BIN || "aw-openclaw-bridge";
const BRIDGE_ARGS = (process.env.AW_BRIDGE_ARGS || "").split(" ").filter(Boolean);

export default definePluginEntry({
  id: "agent-warden",
  name: "Agent Warden",
  register(api) {
    const aw = new AwClient(BRIDGE_BIN, BRIDGE_ARGS);

    // Loud, greppable proof-of-load. If you do NOT see this line in the Gateway
    // log, the plugin did not register and tool calls are UNGOVERNED — re-run the
    // setup script (scripts/aw-openclaw-setup.sh) and confirm `plugins inspect`.
    try {
      process.stderr.write(
        `[agent-warden] registered before_tool_call/after_tool_call/before_install ` +
          `(bridge=${BRIDGE_BIN}). Tool calls are now governed.\n`,
      );
    } catch {
      /* never throw from the banner */
    }

    // THE GATE. Runs at high priority so AW sees the call before other hooks.
    api.on(
      "before_tool_call",
      async (event: any, ctx: any) => {
        // The SDK exposes correlation either as a second `ctx` arg or as event.ctx;
        // read whichever is present. These are audit-only — decisions fail closed
        // regardless of whether they resolve.
        const c = ctx ?? event.ctx ?? {};
        const flatParams = flatten(event.params);
        let v;
        try {
          v = await aw.mediate({
            tool: event.toolName,
            params: flatParams,
            ctx: {
              agent_id: c.agentId ?? "",
              session_id: c.sessionId ?? c.sessionKey ?? "",
              run_id: c.runId ?? event.runId ?? "",
              tool_call_id: event.toolCallId ?? "",
            },
          });
        } catch (err) {
          // Bridge unreachable / malformed → fail closed.
          return { block: true, blockReason: `Agent Warden unavailable (fail-closed): ${String(err)}` };
        }

        switch (v.decision) {
          case "allow":
            return; // undefined = no decision, tool runs
          case "deny":
            return { block: true, blockReason: v.blockReason || "Agent Warden: denied" };
          case "escalate":
            return {
              requireApproval: {
                title: v.approval?.title || "Agent Warden: approve this action?",
                description: v.approval?.description || "",
                severity: (v.approval?.severity as "info" | "warning" | "critical") || "warning",
                timeoutMs: v.approval?.timeoutMs || 60_000,
                timeoutBehavior: "deny", // fail-closed
              },
            };
          case "sandbox":
            // Redirect the tool to the decoy params the broker chose. The agent
            // proceeds; the ledger marks it simulated.
            return { params: { ...event.params, ...(v.decoyParams || {}) } };
          default:
            return { block: true, blockReason: "Agent Warden: unknown verdict" };
        }
      },
      { priority: 100 },
    );

    // Observe real results → AW ledger (best-effort; never blocks).
    api.on("after_tool_call", async (event: any) => {
      aw.observe(event.toolName, event.error ? "error" : "ok");
    });

    // Capability surface: gate skill/plugin installs (Bucket B / AW-G-2).
    api.on("before_install", async (event: any) => {
      try {
        const v = await aw.mediate({
          tool: "install",
          params: { kind: String(event.kind ?? "skill"), source: String(event.source ?? "") },
          ctx: {},
        });
        if (v.decision === "deny") return { block: true, blockReason: v.blockReason || "Agent Warden: install denied" };
      } catch {
        return { block: true, blockReason: "Agent Warden unavailable (fail-closed)" };
      }
      return;
    });

    api.on("gateway_stop", () => aw.close());
  },
});

// OpenClaw params are arbitrary JSON; the bridge speaks string→string. Flatten
// scalars to strings and JSON-encode nested values so nothing is lost.
function flatten(params: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(params ?? {})) {
    out[k] = typeof val === "string" ? val : typeof val === "object" ? JSON.stringify(val) : String(val);
  }
  return out;
}
