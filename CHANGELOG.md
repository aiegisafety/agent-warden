# Changelog

## [Unreleased]

### Added — Unified Evidence Format (AW-EVF v0.1, CC-BY-4.0)
- **One verifier, two ledgers, zero migration.** `spec/AW-EVF-v0.1.md` defines a
  single evidence-record envelope and **SOX/ITGC control-point mapping** spanning
  both the AgentWarden Go hash-chain ledger and the PEA-family `audit.py` audit log,
  which use byte-incompatible chain recipes. Rather than re-hash either (which would
  destroy historical tamper-evidence), the hash recipe becomes a declared, pluggable
  **hash profile** (`aw.onestep.v0.2`, `pea.twostep.v1`) — generalizing AW-Spec §8.3
  hash agility. Closes AW-Spec §11.1 deferred item (4).
- **Proven cross-ledger.** `spec/evf/verify.py` (pure stdlib) independently
  re-derives each native chain (verify-over-trust — imports no product code),
  validates a **real Go-produced** AgentWarden ledger and a **real audit.py-produced**
  PEA chain, lifts every record into the unified envelope with SOX/ITGC fields, and
  localizes tampering on both by flipping one byte. All green
  (`spec/evf/out/PROOF.txt`). The independent re-derivation is byte-exact against
  both products' real output.

### Added — Unified Policy IR (AW-IR L0 v0.1, CC-BY-4.0)
- **One policy contract, four compile targets.** `spec/AW-IR-v0.1.md` specifies a
  Level-0 semantic intermediate representation for authority-governance policy.
  An action-gate policy (AgentWarden) and a capability-budget policy (PEA-family
  least-privilege intent governance) are now two *encodings* of the **same**
  decision, with DB Warden and BizWarden reserved as further targets — instead of
  each product carrying a private policy dialect. Companion to AW-Spec §7; closes
  AW-Spec §11.1 deferred item (2) at Level 0.
- **SoD profile (first profile).** A reusable, categorically-non-overridable
  Segregation-of-Duties rule pack (`distinct_principals` initiator ≠ approver,
  plus quorum) authored once and reusable across every target.
- **Round-trip compile proof.** `spec/ir/prove.py` (pure stdlib) lifts two existing
  shipped policy files into the IR and lowers them back, asserting structural
  round-trip, **decision equivalence** over a coverage vector, and IR idempotence —
  all green (`spec/ir/out/PROOF.txt`). This is the executable form of AW-IR §9.

### Added — P2 credential vault (secrets the agent never sees)
- **`cred` substrate, made real.** The agent references a vaulted secret as
  `${vault:alias}` and never holds its value. Agent Warden resolves and **injects**
  the real secret at the egress boundary, then **redacts** it from everything the
  agent and the ledger can observe (`internal/vault`, `pkg/awspec` cred helpers).
- **User-owned vault at rest** — AES-256-GCM under a passphrase-derived key
  (PBKDF2, stdlib only; zero dependencies). Tamper/​wrong-passphrase fail to unseal.
- **Destination binding** — a secret is bound to a substrate + destination(s); using
  it for any other destination is **denied** before the value is ever resolved.
- **`cred.export` hard floor** — reading a secret's plaintext is non-overridable
  deny; the supported path is *use via injection*, which never needs export.
- **Demo + invariant** — `cmd/aw-vault-demo` (and `-selftest`): an agent uses a
  vaulted token for an allowed API, is denied for a disallowed destination, and is
  denied an export — with a **canary-grep** asserting the secret appears in neither
  the agent's view nor the ledger. `make vault-demo`.

### Added — Tier-1 reliability + Windows packaging
- **Deterministic OpenClaw setup** — `scripts/aw-openclaw-setup.sh` builds the
  bridge, self-tests it, installs it on PATH behind a fixed-data-dir wrapper, links
  + enables the plugin, restarts the Gateway, and **asserts** the `before_tool_call`
  hook is actually registered. It exits non-zero unless Agent Warden is governing —
  removing the silent "plugin didn't hook, tool calls ran ungoverned" failure mode.
- **Health doctor** — `scripts/aw-openclaw-doctor.sh` (read-only) checks bridge
  PATH + self-test, plugin enable, hook registration, and ledger freshness, and
  reminds you of the two traps (`tui` vs `chat`; don't trust the agent's self-report).
- **Bridge self-test + version** — `aw-openclaw-bridge -selftest` drives all four
  verdicts through a throwaway broker (no OpenClaw needed) and prints PASS/FAIL;
  `-version` stamps the adapter version.
- **Hardened TS shim** — the transport now handles the child `error`/`exit` events
  (a missing/crashed bridge can no longer take down the Gateway plugin host),
  guards `stdin` writes, respawns a dead bridge with **bounded backoff**, and emits
  greppable `[agent-warden]` diagnostics. Every degraded state fails **closed**.
- **Windows packaging** — `packaging/` builds a portable zip (`install.ps1`,
  per-user, no admin) and an Inno Setup installer (`AgentWarden-Setup-v<ver>.exe`),
  both adding the binaries to PATH. One command: `packaging/build_release.ps1`.

### Added — two ways to govern any agent
- **Tier-1 OpenClaw adapter (experimental)** — `adapters/openclaw/` loads into a
  real OpenClaw via its `before_tool_call` plugin hook (verified against OpenClaw
  2026.6.5) and maps each tool call to a broker verdict (allow / deny / escalate /
  sandbox). A Go bridge (`cmd/aw-openclaw-bridge`) keeps all policy in Go; the
  TypeScript shim makes no decision and fails closed. Demo: `examples/openclaw/`.
  Gateway setup is now scripted + asserted (`scripts/aw-openclaw-setup.sh`) and the
  transport is crash-hardened; broad multi-version lifecycle hardening continues.
- **Tier-2 OS-level confinement (Windows, user-mode)** — `internal/enforce/`
  confines a process in a **Job Object** (kill-on-close, process cap) and pins its
  network egress to a broker-backed proxy, governing it with no cooperation.
  `cmd/aw-confined-run` + `cmd/aw-rogue-sim` demonstrate a rogue stand-in whose
  exfiltration is denied, payment sandboxed (simulated), and beacon escalated — all
  recorded in the ledger. Demo: `examples/tier2-confined-run/`. A `stub` backend
  keeps non-Windows builds green; raw-socket bypass and filesystem mediation await
  the kernel driver (designed in the private Tier-2 notes).
  - **Hardened launch:** the agent is created **suspended**, assigned to the Job
    Object while frozen, then resumed — it executes no instruction before it is
    jailed (closes the Start→Assign race). `NO_PROXY` is cleared so egress can't
    leak around the proxy; the job dies on unhandled exceptions and forbids
    breakaway.
  - **Non-bypassable egress (T2-b, B1):** with admin, an OS firewall rule blocks the
    agent's non-loopback outbound, so a **raw socket cannot bypass the broker** — no
    kernel driver required (loopback to the proxy stays open). The rogue now attempts
    a raw socket to prove it.
  - **Child-process blocking (T2-b, B1 step 1):** with `AgentSpec.NoChildProcesses`
    (default in `confined-run`), the agent is launched via `CreateProcessW` with the
    **CHILD_PROCESS_RESTRICTED** mitigation, so it cannot spawn *any* child — closing
    the "drop a helper exe to evade the per-binary egress rule" bypass. The rogue now
    attempts to spawn a helper to prove it is blocked.
  - **Filesystem containment (T2-b, B2):** with `AgentSpec.LowIntegrity` (default in
    `confined-run`), the suspended agent's token is dropped to **Low integrity** and
    its workspace is labeled Low, so Windows MIC denies it any write outside the
    sandbox — the user's files and system dirs are off-limits, no kernel driver. The
    rogue now tries to plant a file in the home dir to prove it is blocked. Transparent
    per-write FS *mediation* (snapshot/gate on arbitrary paths) remains the kernel
    minifilter work.

### Added — real LLM agent, mediated end to end
- A separate-process agent reaches the world only through the broker protocol
  (`pkg/awproto`, `internal/server`, `adapters/exec`).
- `awarden run` — the freerun-rollback demo: an agent runs free on reversible work,
  hits the gate at the irreversible frontier, is contained, and the run is rolled
  back and verified. See `examples/freerun-rollback/`.
- `awarden run-llm` — a real LLM coding agent whose every action is mediated by the
  broker.

### Core engine
- Mediation broker (no ambient authority), filesystem reversibility with snapshot +
  rollback, an irreversible-frontier gate (allow / deny / escalate / sandbox),
  user-authored policy, carried-capability checks, and an append-only SHA-256
  hash-chained ledger with a standalone verifier (`aw-verify`).
- Zero external dependencies.
