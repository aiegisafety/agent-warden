# reference/ — Go reference implementation

A local, single-user control plane for autonomous agents. Licensed **Apache-2.0**
(see `../LICENSE`). **Zero external dependencies** — no `go get`, no network needed
to build or test.

**Status:** working reference implementation — broker pipeline + four-verdict gate
+ filesystem reversibility/rollback + SHA-256 hash-chain ledger + decoy router for
the `sandbox` verdict + a real LLM agent driven through it.

## Build & test (local)

```sh
cd reference
go test ./...                 # unit tests (ledger / gate / broker / policy)
go build ./...                # compile everything
go build -o bin/awarden   ./cmd/awarden
go build -o bin/aw-verify ./cmd/aw-verify
# or just:
make all
```

## Try the demo

```sh
make demo      # runs the freerun-rollback demo in ./_demo
make verify    # verifies the ledger the demo produced
```

The demo drives a scripted agent: reversible filesystem edits run free (journaled),
a non-whitelisted egress **escalates**, a payment (`I-VALUE`) is **sandboxed**
(fake receipt, nothing real, logged `simulated:true`), a `cred.export` is
**hard-denied**, then the run is **rolled back** and the ledger **verified**.

## Run a REAL LLM agent through the broker (M2)

`aw-agent-qwen` is a real coding agent driven by Tongyi Qianwen (DashScope's
OpenAI-compatible API). Every action it takes is mediated by the broker; its calls
to the LLM are its *cognition* and are deliberately not mediated (we govern what an
agent does, not what it thinks).

```sh
# Test the plumbing with NO key and NO network:
make run-llm-dry

# Run the real agent (set your key first; it is read from the environment only,
# never written to disk or logged):
#   Windows:  set DASHSCOPE_API_KEY=sk-...
#   macOS/Linux:  export DASHSCOPE_API_KEY=sk-...
make run-llm
```

**Key handling:** the agent reads `DASHSCOPE_API_KEY` from the environment only. Do
not paste it into any file. `.env` is git-ignored; never commit a key.

## Package layout

```
pkg/awspec/         shared wire types: Action, Verdict (4), Capability, Result
internal/broker/    mediation: classify + dispatch (no ambient authority)
internal/contain/   filesystem reversibility: userspace journal + rollback
internal/gate/      4-verdict decision procedure, fail-closed, hard-deny, lifecycle hook
internal/decoy/     decoy router serving the `sandbox` verdict (AW-G-1; touches nothing real)
internal/policy/    user-authored policy (JSON) + preset expansion (AW-UX-1)
internal/capability/ carried-capability verify (HMAC), lineage, lifecycle (AW-G-2)
internal/ledger/    append-only SHA-256 hash-chain + Verify (verify-over-trust)
cmd/awarden/        demo driver + verify subcommand
cmd/aw-verify/      standalone ledger verifier
```

> Note: the reference uses **JSON** policy files for zero dependencies. A YAML
> front-end is a later addition.
