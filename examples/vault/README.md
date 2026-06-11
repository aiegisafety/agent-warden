# Example — credential vault (P2, `cred` substrate)

**Secrets the agent never sees.** The agent references a vaulted secret as
`${vault:github_token}`; Agent Warden injects the real value at the egress boundary
and redacts it from everything the agent and the ledger can observe.

## Run

```sh
cd reference
make vault-demo            # or: go run ./cmd/aw-vault-demo -dir ./_vault
go run ./cmd/aw-vault-demo -selftest   # headless PASS/FAIL, exit 0/1
```

## What it shows

| Case | Action | Verdict | Why |
|---|---|---|---|
| Use | `net.egress` to `api.github.com` with `Authorization: Bearer ${vault:github_token}` | **allow** | destination is in the secret's binding; token injected at egress, agent sees `⟨vault:github_token⟩` |
| Use (wrong dest) | same token to `evil.test` | **deny** | destination not bound — the secret is never even resolved |
| Export | read the token's plaintext | **deny** | `cred.export` is a non-overridable hard floor |

Then a **canary check** asserts the secret value appears in **neither** the agent's
output **nor** the ledger. Verify the tamper-evident chain afterward:

```sh
go run ./cmd/aw-verify -ledger ./_vault/.aw-vault/ledger.log
```

## Honest scope

This is a *reference* vault — correct and demonstrable, AES-256-GCM at rest with a
passphrase-derived key, zero dependencies. Hardware-backed keys (KMS/HSM), rotation,
and multi-tenant isolation are the closed PEA production engine, not this open
reference. And the vault stops a secret from **leaking** or being used **off its
binding**; it does not claim to stop misuse of a legitimately-scoped secret — that
is contained by scope, not prevented (charter §5).
