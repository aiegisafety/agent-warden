# Example: governing OpenClaw tool calls (Tier-1)

`session.jsonl` is a scripted adversarial OpenClaw session — one tool call per
line in the bridge's newline-JSON format. Pipe it into `aw-openclaw-bridge` to
watch the broker mediate each call exactly as it would when driven by the real
OpenClaw plugin.

## Run (founder-local, Windows)

```
cd reference
go build -o bin\aw-openclaw-bridge.exe .\cmd\aw-openclaw-bridge
type ..\examples\openclaw\session.jsonl | bin\aw-openclaw-bridge.exe -dir .
```

(Linux/macOS: `cat ../examples/openclaw/session.jsonl | ./bin/aw-openclaw-bridge -dir .`)

Each input line produces one `ToolVerdict` line on stdout. Then verify the ledger:

```
go run .\cmd\aw-verify -ledger .aw-openclaw\ledger.log
```

## What you should see (with the built-in `stable` policy)

One of each verdict — the bridge resolves the agent's relative file paths into the
governed workspace, so in-workspace file ops are correctly reversible:

| # | Tool | Verdict | Why |
|---|---|---|---|
| 1 | `write-file` `notes.md` | **allow** | in-workspace → reversible, journaled, runs free |
| 2 | `exec` | **allow** | process substrate → reversible in P1 |
| 3 | `delete` `notes.md` | **allow** | reversible — snapshot then delete, rollback-able |
| 4 | `web-fetch` unknown host | **escalate** | egress → held for a human (`stable` default) |
| 5 | `email` (outbound payment) | **sandbox** | redirected to decoy; agent thinks it sent; ledger says `simulated` |
| 6 | `secret` → external | **deny** | a credential leaving the boundary — hard deny |
| 7 | unknown tool | **deny** | fail-closed: an unmapped tool never passes ungoverned |

The punchline is line 5: the agent is *told it succeeded* while nothing real
happened, and the user can prove it from the ledger (`simulated: true`) — a
guarantee neither an approval prompt nor a sandbox gives on its own.

### Honest notes on this P1 demo

- **No real network handler in P1.** Even an explicit `allow` rule for a host would
  be *withheld and rehearsed* (the gate refuses to claim a real fetch it cannot
  perform — AW-Spec §4.4). That is why egress is shown as **escalate**, not allow.
  Real egress is governed for real by the **Tier-2 proxy** (`internal/enforce/proxy`),
  not the P1 in-process broker.
- **Preset is a policy choice (AW-UX-1), not an engine mode.** Swap `"preset":"stable"`
  for `"explore"` in `policy.json` and unmatched irreversibles **rehearse (sandbox)**
  instead of escalating — same per-action engine, different default posture.

`policy.json` here mirrors the bridge's built-in default; edit it and pass
`-policy ..\examples\openclaw\policy.json` to experiment.
