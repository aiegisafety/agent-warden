# Agent Warden

**A user-owned control plane for autonomous agents.** Let an agent run the whole
job at full speed — and keep control of the irreversible frontier, with a
tamper-evident record of everything it did.

> Everyone is racing to build an agent that can do anything. Agent Warden is the
> layer that makes you *willing* to let it.

## The idea in one line

**Separate an agent's *initiative* from its *authority*.** Reversible operations
run with zero friction. A gate engages **only** at the irreversible frontier —
sending data outside your boundary, moving money, acting physically, or destroying
something with no backup. Every gated decision lands in an append-only,
hash-chained ledger you can verify yourself.

Agent Warden is **not** a safer agent. It doesn't compete with OpenClaw, Claude
Code, or AutoGPT — it's the horizontal layer that governs *any* agent you run.

## What it does

- **Bounded downside.** Let the agent finish the job; the worst case can't sink you.
- **Reversible by default.** Snapshots before destructive-but-reversible operations; one-command rollback.
- **Gates only what's irreversible** — external egress, value transfer, physical action, no-backup destruction.
- **A ledger you can audit yourself** — what the agent did, and whether anything irreversible slipped through.

## Two ways to govern any agent

- **Cooperative adapter (Tier-1).** Insert the broker at an agent's tool-call
  boundary. An **experimental OpenClaw adapter** (`adapters/openclaw/`) loads into
  a real OpenClaw via its `before_tool_call` plugin hook and maps each tool call to
  a verdict — *allow / deny / escalate / sandbox*.
- **OS-level confinement (Tier-2).** Run any process — cooperative or not — inside
  an OS jail with its network egress pinned to the broker. A **Windows user-mode
  backend** (`reference/internal/enforce/`) confines a process in a Job Object and
  mediates its egress, with no cooperation from the agent.

## Honest scope

This is an early, working reference implementation — developer-grade, not yet a
consumer installer. What's real today: the governance engine end to end (including
a real LLM agent driven through it); a Tier-1 OpenClaw adapter that loads into a
real OpenClaw and has governed a real tool call into the ledger (**experimental** —
the gateway plugin lifecycle is still being hardened for reliability); and a Tier-2
Windows confinement that jails a process in a Job Object and makes its **network
egress non-bypassable** — the agent can only reach the network through the broker,
a raw socket is dropped by the OS firewall, and it cannot even spawn a helper
process to get around the rule (child-process creation is blocked); and its
**filesystem writes are contained to its sandbox** — it runs at Low integrity, so
the OS denies any write to your files or system dirs. All of that is enforced by the
OS with **no kernel driver**.

What's **not** done: Tier-2 *contains* filesystem damage but does not yet *mediate*
every write — transparent per-write snapshot/gating on arbitrary paths (for
rollback) needs a kernel **minifilter**, designed but not built; it's the only piece
that requires an in-kernel driver. There is no packaged installer yet. We say what
we secure and what we don't.

## Try it in 60 seconds

You need [Go](https://go.dev/dl/) installed. No other dependencies.

```sh
cd reference
go build -o bin/awarden      ./cmd/awarden
go build -o bin/aw-agent-sim ./cmd/aw-agent-sim
./bin/awarden run -dir .
```

(On Windows, use `bin\awarden.exe` etc.) You'll watch a separate-process agent run
free on reversible work, hit the gate at the irreversible frontier — a data
exfiltration **escalated**, a payment **sandboxed** (fake receipt, no money moved),
a credential export **denied** — then the run is **rolled back** and the ledger
**verified**. Walkthrough: [`examples/freerun-rollback/`](examples/freerun-rollback/).

Run the tests with `go test ./...`.

### More demos

- **Govern any process (Tier-2, Windows).** Confine a stand-in rogue agent in a
  Job Object and watch its network egress get denied / sandboxed / escalated by
  the broker — no cooperation, no OpenClaw: [`examples/tier2-confined-run/`](examples/tier2-confined-run/).
- **Govern OpenClaw (Tier-1, experimental).** Mediate a scripted OpenClaw tool-call
  session through the broker: [`examples/openclaw/`](examples/openclaw/).

## Repository layout

```
reference/                    Go reference implementation
reference/internal/enforce/   Tier-2 OS-level confinement (Windows Job Object + egress proxy)
adapters/openclaw/            Tier-1 OpenClaw plugin adapter (experimental)
examples/                     Reproducible demos
```

## License

Source code is licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE).
