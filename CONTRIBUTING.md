# Contributing to Agent Warden

Thanks for your interest. This repository contains the open reference
implementation (Apache-2.0).

## Sign-off (DCO)

All contributions are accepted under the
[Developer Certificate of Origin](DCO.txt). Sign off every commit:

```
git commit -s -m "your message"
```

This appends a `Signed-off-by:` line certifying you wrote the contribution or have
the right to submit it. We use DCO, not a CLA, to keep the barrier low.

## Changing code

1. Discuss non-trivial work in an issue first.
2. Branch, implement, add tests. Changes that affect a safety behavior (a gate
   verdict, reversibility, the ledger) should include a test demonstrating it.
3. `git commit -s` (DCO), open a PR, link the issue.

## Honesty rule

Agent Warden makes a specific, bounded safety claim and is explicit about what it
does *not* prevent. Contributions — code, docs, or copy — must not overclaim the
guarantee. Overclaiming is treated as a defect.
