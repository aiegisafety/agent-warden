# Example: Tier-2 confined-run (govern any process, no OpenClaw)

This demo confines a harmless stand-in rogue agent (`aw-rogue-sim`) inside a
**Windows Job Object**, pins its network egress to the Agent Warden proxy, and
mediates every outbound call through the broker into the tamper-evident ledger —
**without the agent's cooperation and without OpenClaw**. It is the
"install once, govern any process" property, and the answer to threat-model RR-7
(a Tier-1 plugin only governs cooperative tool calls; Tier-2 governs at the OS).

## Run (Windows, founder-local)

```
cd reference
go build -o bin\aw-rogue-sim.exe    .\cmd\aw-rogue-sim
go build -o bin\aw-confined-run.exe .\cmd\aw-confined-run
go build -o bin\aw-verify.exe       .\cmd\aw-verify
bin\aw-confined-run.exe -dir . -rogue bin\aw-rogue-sim.exe
```

**Run the prompt as Administrator** to see the Tier-2-b egress lockdown. Without
admin it still runs (Tier-2-a containment), and the rogue's raw-socket test will
show egress is *not* locked down — which is itself the point.

(On Linux/macOS the OS jail is not built this round, so it prints an
"unsupported — run on Windows" notice; the broker/proxy/ledger are cross-platform.)

## What you should see

The rogue narrates (stderr) what it *thinks* happened; the ledger shows the truth:

| Rogue attempt | Destination | Verdict | Rogue sees | Ledger says |
|---|---|---|---|---|
| exfiltrate secrets | `*.evil.test` | **deny** (hard) | HTTP 403 blocked | `net deny` |
| charge a card $4999 | `pay.test` | **sandbox** | HTTP 200 "success!" | `net sandbox [SIMULATED]` |
| beacon to C2 | anything else | **escalate** | HTTP 451 held | `net escalate` |

Then the rogue tries two escapes:

- **A raw socket that ignores the proxy.** As admin → `raw socket -> BLOCKED by the
  OS` (the egress lockdown drops it). Without admin → `raw socket -> CONNECTED` (the
  proxy was only a suggestion — exactly the bypass Tier-2-b closes).
- **Spawning a helper process** whose exe isn't covered by the per-binary egress
  rule. With child-process blocking (default) → `spawn helper -> BLOCKED` — the OS
  refuses to let the agent start *any* child, so it can't drop an unmonitored process
  to evade the rule. (Pass `-allow-children` to fall back to the exec launch and see
  it run.)
- **Planting a file outside its sandbox** (in your home dir). With Low-integrity
  containment (default) → `write outside sandbox -> BLOCKED` — the OS denies the
  Low-integrity agent any write to your normal files; it can write only its
  Low-labeled workspace. (Pass `-no-low-integrity` to disable and see it succeed.)

Plus the launch itself was gated through the broker, and the whole process tree
runs in a Job Object that is killed when Agent Warden exits (kill-on-close). The
agent is created **suspended** and jailed before it runs a single instruction.

The punchline mirrors Tier-1: the rogue believes the payment went through; your
own ledger proves it was simulated and nothing real happened.

## Honest scope

- **Egress (Tier-2-b, B1):** with admin, the OS firewall blocks the agent's
  non-loopback outbound, so a raw socket *cannot* bypass the broker — no kernel
  driver needed. The per-binary-path rule's one weakness — a *dropped helper exe*
  that the rule doesn't cover — is closed by **child-process blocking** (default):
  the OS won't let the confined agent start any child process at all, so the agent
  binary is the only thing that can run and the rule is complete.
- **Filesystem (Tier-2-b, B2):** the agent runs at **Low integrity**, so the OS
  denies it any write outside its Low-labeled workspace — your files, system dirs,
  and startup folders are off-limits, no kernel driver. What's *not* yet done is
  transparent per-write **mediation** (snapshot/gate every write for rollback on
  arbitrary paths) — that needs a kernel **minifilter** (designed, not built; the
  only piece that requires an in-kernel driver). So today: writes are OS-*contained*
  to the sandbox; per-write *mediation* is the remaining kernel work.

We say what we secure and what we don't: egress and filesystem writes are OS-enforced
today; transparent per-write filesystem mediation is the remaining kernel-driver work.
