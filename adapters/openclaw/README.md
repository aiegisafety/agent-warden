# Agent Warden — OpenClaw adapter (Tier-1)

Routes every OpenClaw tool call through the Agent Warden broker before it runs.
Reversible actions run free; the irreversible frontier is gated with
**allow / deny / escalate / sandbox** and recorded in a user-owned, tamper-evident
hash-chain ledger.

## How it fits together

```
OpenClaw runtime
  └─ before_tool_call hook  →  index.ts (dumb shim)  →  awclient.ts
                                                          │  newline-JSON over stdio
                                                          ▼
                                              aw-openclaw-bridge  (Go, this repo)
                                                          │
                                                          ▼
                                       broker → gate → {contain|decoy} → ledger
```

The TypeScript shim makes **no security decision**. It forwards the call and
translates the verdict; every error path returns `block` (fail-closed). All
policy, classification, reversibility and the ledger are in Go.

## Honest scope (read this)

This is **Tier-1 cooperative governance**: it governs OpenClaw's *plugin tool-call
surface* via the documented `before_tool_call` hook. A compromised agent that
drops to a **raw syscall** or spawns a child process outside the hook is **not**
stopped at Tier-1 — that requires **Tier-2 OS enforcement**
(`reference/internal/enforce`, Windows Job Object + egress proxy this round;
kernel WFP/minifilter to follow). We do not claim Tier-1 is bypass-proof.

## Files (native OpenClaw plugin layout, verified vs docs.openclaw.ai)

| File | Role |
|---|---|
| `openclaw.plugin.json` | manifest — discovery + config validation (required: `id`, `configSchema`) |
| `package.json` | declares the entrypoint via `"openclaw": { "extensions": ["./index.ts"] }` |
| `index.ts` | the dumb shim: registers `before_tool_call` / `after_tool_call` / `before_install` via `api.on(...)` |
| `awclient.ts` | newline-JSON transport to the Go bridge |

OpenClaw loads the `.ts` entry directly — **no separate build step** for the shim.

## Set up (one command, deterministic)

OpenClaw runs as a daemon, so a hand-typed install/enable/restart can silently
leave the plugin un-hooked — and then tool calls run **ungoverned** with no error.
The setup script removes that failure mode: it builds the bridge, **self-tests it**,
installs it on PATH behind a fixed-data-dir wrapper, links + enables the plugin,
restarts the Gateway, and then **asserts** that the `before_tool_call` hook is
actually registered. It exits `0` only if Agent Warden is governing.

```sh
# Linux (e.g. the throwaway OpenClaw VPS); needs go, node/npm, openclaw + onboarded.
chmod +x scripts/*.sh
AW_DATA_DIR=/root/aw-data scripts/aw-openclaw-setup.sh
```

Re-check health any time (read-only — checks PATH, self-test, hook registration,
ledger freshness, and reminds you of the two classic traps):

```sh
scripts/aw-openclaw-doctor.sh
```

### Verify the binary in isolation (no OpenClaw)

```sh
reference/bin/aw-openclaw-bridge -selftest   # drives all four verdicts, prints PASS/FAIL
reference/bin/aw-openclaw-bridge -version
```

### Drive a real, governed tool call

1. Start the **gateway-backed** terminal UI:
   ```sh
   openclaw tui
   ```
   Confirm the status bar shows `gateway connected`.
2. Ask the agent to write a file (runs free), fetch a non-allowlisted URL
   (→ escalate / approval), or "send an email / make a payment" (→ sandbox: the
   agent believes it acted; the ledger says `simulated`).
3. Verify the tamper-evident chain the bridge wrote:
   ```sh
   cd reference
   go run ./cmd/aw-verify -ledger /root/aw-data/.aw-openclaw/ledger.log
   ```

### Windows (manual)

```
cd reference
go build -o bin\aw-openclaw-bridge.exe .\cmd\aw-openclaw-bridge
bin\aw-openclaw-bridge.exe -selftest
set AW_BRIDGE_BIN=%CD%\bin\aw-openclaw-bridge.exe
openclaw plugins install --link ..\adapters\openclaw
openclaw plugins enable agent-warden
openclaw gateway restart
openclaw plugins inspect agent-warden --runtime --json   :: look for before_tool_call
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Tool calls run with no approval/deny ever | Plugin not hooked in the running Gateway | `scripts/aw-openclaw-doctor.sh`; if hook missing, re-run `aw-openclaw-setup.sh` |
| Agent says it's "sandboxed" but the ledger is empty | You're in **embedded** mode (`chat` / `terminal` / `tui --local`) — the plugin is bypassed | Use `openclaw tui` (gateway-backed); confirm `gateway connected` |
| Every tool call is blocked | Bridge binary missing/not executable → shim fails **closed** (by design) | Check `command -v aw-openclaw-bridge`; re-run setup; or set `AW_BRIDGE_BIN` to an absolute path |
| Plugin not in `plugins list` after restart | Link/enable didn't take | Re-run `aw-openclaw-setup.sh` (idempotent: re-links + enables + restarts + asserts) |
| Want proof in logs that the plugin loaded | — | Grep the Gateway log for `[agent-warden]` (e.g. `/tmp/openclaw-*/openclaw-*.log`); the shim prints a registration banner on load |

> **Trust the ledger, not the agent.** The agent will confabulate about its
> environment ("blocked by an embedded sandbox"). The tamper-evident ledger +
> `aw-verify` is the ground truth of what was actually governed.

## Reliability model (how it fails)

The shim makes **no** security decision and **only fails closed**. The transport
to the Go bridge is hardened: a missing/crashed bridge is caught (the child
`error`/`exit` events are handled, so it can never take down the Gateway plugin
host), every in-flight and new call resolves a fail-closed `deny`, and a dead
bridge is respawned on the next call with **bounded backoff** so a permanently
broken binary fails cheaply instead of spin-looping. A slow bridge times out to
`deny`. In every degraded state, the safe outcome (block) is the default.

## Env

| Var | Meaning |
|---|---|
| `AW_BRIDGE_BIN` | path to `aw-openclaw-bridge` (default: PATH lookup) |
| `AW_BRIDGE_ARGS` | extra bridge args, e.g. `-policy C:\path\policy.json` |
