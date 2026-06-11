// Command aw-openclaw-bridge is the Go side of the Tier-1 OpenClaw adapter
// (AW-INT-v0.1 Part 1). The OpenClaw TypeScript plugin spawns this binary and
// talks newline-JSON over stdio: it writes one ToolCall per line, this process
// mediates each through the AW broker and writes back one ToolVerdict per line.
//
// All policy lives here (Go); the TS plugin is a dumb shim that only fails closed.
//
//	aw-openclaw-bridge [-dir DIR] [-policy FILE]
//
// -dir     scratch root for the journal + ledger (default ".")
// -policy  policy JSON (default: a built-in policy demonstrating all four verdicts)
//
// Licensed under the Apache License 2.0.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aiegis/agentwarden/adapters/openclaw"
	"github.com/aiegis/agentwarden/internal/broker"
	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// version is stamped into -version output and the self-test banner. Bump on
// adapter protocol or behavior changes so the setup script can assert a minimum.
const version = "0.2.0"

// defaultPolicy governs OpenClaw tool mappings (adapters/openclaw/mapping.go).
// `stable` preset = unmatched irreversibles escalate to a human (conservative),
// giving a crisp one-of-each demo:
//   - fs.* / exec (in workspace) → reversible: ALLOW (journaled, run free)
//   - net.egress                 → ESCALATE (un-allowlisted egress → human)
//   - value.message              → SANDBOX (4th verdict: outbound msg/payment → decoy)
//   - cred.use                   → DENY (hard_deny: a secret leaving the boundary)
//   - unknown (unmapped tool)    → DENY (hard_deny: never pass ungoverned)
//
// Note (honest, P1): there is no real network handler in P1, so even an explicit
// net `allow` rule would be withheld and rehearsed (gate downgrade, AW-Spec §4.4).
// We therefore escalate egress rather than imply a real fetch.
const defaultPolicy = `{
  "version": "0.2",
  "preset": "stable",
  "defaults": { "irreversible": "" },
  "rules": [
    { "match": { "substrate": "net", "class": "net.egress" }, "verdict": "escalate" },
    { "match": { "substrate": "value", "class": "value.message" }, "verdict": "sandbox" }
  ],
  "hard_deny": [
    { "match": { "class": "cred.use" } },
    { "match": { "class": "unknown" } }
  ]
}`

func main() {
	fs := flag.NewFlagSet("aw-openclaw-bridge", flag.ExitOnError)
	dir := fs.String("dir", ".", "scratch root for journal + ledger")
	policyPath := fs.String("policy", "", "policy JSON file (default: built-in)")
	selftest := fs.Bool("selftest", false, "run a built-in self-test (no OpenClaw needed) and exit 0/1")
	showVer := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVer {
		fmt.Println("aw-openclaw-bridge", version)
		return
	}
	if *selftest {
		os.Exit(runSelftest(*policyPath))
	}

	if err := run(*dir, *policyPath); err != nil {
		fmt.Fprintln(os.Stderr, "aw-openclaw-bridge:", err)
		os.Exit(1)
	}
}

// runSelftest drives canned tool calls through a throwaway broker and checks the
// four-verdict mapping end to end, WITHOUT OpenClaw. It lets the setup script (or
// a human) confirm the binary is healthy in isolation before wiring the Gateway.
// Returns a process exit code (0 = PASS, 1 = FAIL).
func runSelftest(policyPath string) int {
	tmp, err := os.MkdirTemp("", "aw-bridge-selftest-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "selftest: cannot create temp dir:", err)
		return 1
	}
	defer os.RemoveAll(tmp)

	m, err := buildMediator(tmp, policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "selftest: build mediator:", err)
		return 1
	}

	// tool name -> expected verdict, exercising each branch of the default policy.
	cases := []struct {
		tool   string
		params map[string]string
		want   string
	}{
		{"write_file", map[string]string{"path": "notes.txt", "content": "hi"}, "allow"},
		{"web_fetch", map[string]string{"url": "https://example.com"}, "escalate"},
		{"send_email", map[string]string{"to": "x@y.com", "body": "hi"}, "sandbox"},
		{"secret", map[string]string{"key": "API_KEY"}, "deny"},          // cred.use → hard_deny
		{"totally_unknown_tool", map[string]string{}, "deny"},            // unknown → hard_deny
	}

	ok := true
	for i, c := range cases {
		v := openclaw.Translate(m, openclaw.ToolCall{ID: i + 1, Tool: c.tool, Params: c.params})
		mark := "PASS"
		if v.Decision != c.want {
			mark, ok = "FAIL", false
		}
		fmt.Printf("  [%s] %-22s want=%-8s got=%-8s\n", mark, c.tool, c.want, v.Decision)
	}

	if ok {
		fmt.Printf("aw-openclaw-bridge %s self-test: PASS (%d cases)\n", version, len(cases))
		return 0
	}
	fmt.Fprintf(os.Stderr, "aw-openclaw-bridge %s self-test: FAIL\n", version)
	return 1
}

func run(dir, policyPath string) error {
	m, err := buildMediator(dir, policyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "aw-openclaw-bridge %s ready (dir=%s, workspace=%s). Reading tool calls on stdin.\n",
		version, filepath.Join(dir, ".aw-openclaw"), m.worktree)
	return openclaw.Serve(m, os.Stdin, os.Stdout)
}

// buildMediator wires policy → gate → broker → workspaceResolver under `dir`.
// Shared by run() (live stdio loop) and runSelftest() (canned checks).
func buildMediator(dir, policyPath string) (*workspaceResolver, error) {
	root := filepath.Join(dir, ".aw-openclaw")
	worktree := filepath.Join(root, "workspace")
	store := filepath.Join(root, "snapshots")
	ledgerPath := filepath.Join(root, "ledger.log")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		return nil, err
	}

	var pol *policy.Policy
	var err error
	if policyPath == "" {
		p := filepath.Join(root, "policy.json")
		if err := os.WriteFile(p, []byte(defaultPolicy), 0o600); err != nil {
			return nil, err
		}
		policyPath = p
	}
	if pol, err = policy.Load(policyPath); err != nil {
		return nil, err
	}

	led, err := ledger.Open(ledgerPath)
	if err != nil {
		return nil, err
	}
	j, err := contain.NewJournal(worktree, store)
	if err != nil {
		return nil, err
	}
	g := gate.New(pol, []byte("DEMO-TRUST-ROOT-KEY"), map[awspec.Substrate]bool{
		awspec.SubFS: true, awspec.SubProc: true, // net/value/cred not "real" in P1
	})
	b := broker.New(j, g, led, decoy.New(), map[awspec.Substrate]broker.RealHandler{})

	// In real OpenClaw the agent's file paths are relative to its workspace. Resolve
	// relative fs paths into the journaled worktree so in-workspace file ops are
	// correctly seen as reversible (and absolute out-of-tree paths stay gated).
	wsWorktree, _ := filepath.Abs(worktree)
	return &workspaceResolver{inner: b, worktree: wsWorktree}, nil
}

// workspaceResolver rewrites relative filesystem paths to live under the governed
// workspace before mediation, mirroring how OpenClaw resolves agent file paths.
type workspaceResolver struct {
	inner    *broker.Broker
	worktree string
}

func (w *workspaceResolver) Mediate(a awspec.Action) (awspec.Result, error) {
	if a.Substrate == awspec.SubFS {
		if p := a.Params["path"]; p != "" && !filepath.IsAbs(p) {
			// copy the map so we don't mutate the caller's
			np := make(map[string]string, len(a.Params))
			for k, v := range a.Params {
				np[k] = v
			}
			np["path"] = filepath.Join(w.worktree, p)
			a.Params = np
		}
	}
	return w.inner.Mediate(a)
}
