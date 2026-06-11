# Agent Warden reference implementation — local build/test.
# Zero external dependencies (ADR-0002); no `go get` / network needed.

.PHONY: all build test vet fmt demo run verify clean openclaw-example confined-run vault-demo

all: fmt vet test build

build:
	go build ./...
	go build -o bin/awarden            ./cmd/awarden
	go build -o bin/aw-verify          ./cmd/aw-verify
	go build -o bin/aw-agent-sim       ./cmd/aw-agent-sim
	go build -o bin/aw-agent-qwen      ./cmd/aw-agent-qwen
	go build -o bin/aw-openclaw-bridge ./cmd/aw-openclaw-bridge
	go build -o bin/aw-rogue-sim       ./cmd/aw-rogue-sim
	go build -o bin/aw-confined-run    ./cmd/aw-confined-run
	go build -o bin/aw-vault-demo      ./cmd/aw-vault-demo

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# In-process scripted demo.
demo: build
	./bin/awarden demo -dir ./_demo

# M1: separate-process stand-in agent mediated by the broker.
run: build
	./bin/awarden run -dir ./_run

# M2: REAL LLM agent (Qwen) mediated by the broker. Needs DASHSCOPE_API_KEY in env.
# Use `make run-llm-dry` to test the plumbing with no API key / no network.
run-llm: build
	./bin/awarden run-llm -dir ./_llm

run-llm-dry: build
	./bin/awarden run-llm -dir ./_llm -dry-run

# Verify a ledger produced by `make run`.
verify:
	./bin/aw-verify -ledger ./_run/.aw-run/ledger.log

# Tier-1 OpenClaw adapter: pipe a scripted adversarial session through the bridge.
openclaw-example: build
	cat ../examples/openclaw/session.jsonl | ./bin/aw-openclaw-bridge -dir ./_openclaw
	./bin/aw-verify -ledger ./_openclaw/.aw-openclaw/ledger.log

# Tier-2 (T2-a): confine the rogue stand-in in a Job Object, mediate its egress.
# Windows-only for the real jail; on other OSes it prints an unsupported notice.
confined-run: build
	./bin/aw-confined-run -dir ./_confined -rogue ./bin/aw-rogue-sim

# P2 credential vault: an agent uses a vaulted secret it never sees; injected at
# the egress boundary, redacted from agent + ledger; off-binding use & export denied.
vault-demo: build
	./bin/aw-vault-demo -dir ./_vault

clean:
	rm -rf bin _demo _run _llm _openclaw _confined _vault
