# examples/ — reproducible demos

The proof you can run yourself: let an agent loose in a repo, watch it run freely on
everything reversible, hit the gate at the irreversible frontier, and roll back
cleanly — then verify the whole episode from the hash-chained ledger.

- [`freerun-rollback/`](freerun-rollback/) — a separate-process agent edits files
  freely (all reversible), an egress is escalated, a payment is sandboxed, a
  credential export is denied; then the run is rolled back and the ledger verified.
  Run it with `awarden run` (stand-in agent) or `awarden run-llm` (real LLM agent)
  from `../reference`.
