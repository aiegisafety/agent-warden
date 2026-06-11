// Command awarden is the P1 reference control plane. In this skeleton it runs the
// `freerun-rollback` demo (P1-HLD §9): a scripted agent runs free on reversible
// filesystem effects, hits the gate at the irreversible frontier (egress denied,
// out-of-tree destruction gated, a payment SANDBOXed), then the run is rolled back
// and the ledger verified.
//
// Subcommands:
//
//	awarden demo   [-dir DIR]                 run the in-process scripted demo
//	awarden run    [-dir DIR]                 run the SEPARATE-PROCESS agent demo (M1)
//	awarden verify -ledger FILE               verify a ledger's hash chain
//
// Licensed under the Apache License 2.0.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	awexec "github.com/aiegis/agentwarden/adapters/exec"
	"github.com/aiegis/agentwarden/internal/broker"
	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "demo":
		dir := "."
		if len(os.Args) >= 4 && os.Args[2] == "-dir" {
			dir = os.Args[3]
		}
		if err := runDemo(dir); err != nil {
			fmt.Fprintln(os.Stderr, "demo error:", err)
			os.Exit(1)
		}
	case "run":
		dir := "."
		if len(os.Args) >= 4 && os.Args[2] == "-dir" {
			dir = os.Args[3]
		}
		if err := runSession(dir); err != nil {
			fmt.Fprintln(os.Stderr, "run error:", err)
			os.Exit(1)
		}
	case "run-llm":
		fs := flag.NewFlagSet("run-llm", flag.ExitOnError)
		dir := fs.String("dir", ".", "scratch directory")
		task := fs.String("task", "", "task for the agent (optional; agent has a default)")
		dry := fs.Bool("dry-run", false, "run the agent without the LLM (canned actions)")
		_ = fs.Parse(os.Args[2:])
		if err := runLLMSession(*dir, *task, *dry); err != nil {
			fmt.Fprintln(os.Stderr, "run-llm error:", err)
			os.Exit(1)
		}
	case "verify":
		if len(os.Args) != 4 || os.Args[2] != "-ledger" {
			fmt.Fprintln(os.Stderr, "usage: awarden verify -ledger FILE")
			os.Exit(2)
		}
		res, err := ledger.Verify(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if res.OK {
			fmt.Printf("OK: chain intact (%d records)\n", res.Count)
			return
		}
		fmt.Printf("TAMPER at seq %d: %s\n", res.BadSeq, res.Detail)
		os.Exit(1)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: awarden <demo|run|run-llm|verify> ...")
	os.Exit(2)
}

// demoPolicy is the `explore` preset policy used by the demo.
const demoPolicy = `{
  "version": "0.2",
  "preset": "explore",
  "defaults": { "irreversible": "" },
  "rules": [
    { "match": { "substrate": "net", "class": "net.egress", "dest": "api.github.com" }, "verdict": "allow" },
    { "match": { "substrate": "net", "class": "net.egress" }, "verdict": "escalate" },
    { "match": { "substrate": "value", "class": "value.transfer" }, "verdict": "sandbox" }
  ],
  "hard_deny": [
    { "match": { "substrate": "net", "class": "net.egress", "dest_in": ["*.known-exfil"] } },
    { "match": { "class": "cred.export" } }
  ]
}`

func runDemo(dir string) error {
	root := filepath.Join(dir, ".aw-demo")
	worktree := filepath.Join(root, "repo")
	store := filepath.Join(root, "snapshots")
	ledgerPath := filepath.Join(root, "ledger.log")
	policyPath := filepath.Join(root, "policy.json")

	_ = os.RemoveAll(root)
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(demoPolicy), 0o600); err != nil {
		return err
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		return err
	}
	j, err := contain.NewJournal(worktree, store)
	if err != nil {
		return err
	}
	// Real handlers: fs is handled by the journal (reversible path); no real
	// handler for net/value/phys in P1 (gate sandboxes/denies them).
	realHandlers := map[awspec.Substrate]broker.RealHandler{}
	g := gate.New(pol, []byte("DEMO-TRUST-ROOT-KEY"), map[awspec.Substrate]bool{
		awspec.SubFS: true, awspec.SubProc: true, // net intentionally NOT real here
	})
	b := broker.New(j, g, led, decoy.New(), realHandlers)

	fmt.Println("== Agent Warden P1 demo (freerun-rollback) ==")
	script := []awspec.Action{
		{AgentID: "demo", Substrate: awspec.SubFS, Class: "fs.write",
			Params: map[string]string{"path": filepath.Join(worktree, "main.go"), "content": "package main\n"}},
		{AgentID: "demo", Substrate: awspec.SubFS, Class: "fs.delete",
			Params: map[string]string{"path": filepath.Join(worktree, "main.go")}},
		{AgentID: "demo", Substrate: awspec.SubNet, Class: "net.egress",
			Params: map[string]string{"dest": "evil.example.com"}}, // → escalate
		{AgentID: "demo", Substrate: awspec.SubValue, Class: "value.transfer",
			Params: map[string]string{"dest": "acct-999", "amount": "5000"}}, // → sandbox
		{AgentID: "demo", Substrate: awspec.SubCred, Class: "cred.export",
			Params: map[string]string{"dest": "evil.example.com"}}, // → hard deny
	}
	for i, a := range script {
		res, err := b.Mediate(a)
		if err != nil {
			return err
		}
		sim := ""
		if res.Simulated {
			sim = " [SIMULATED]"
		}
		fmt.Printf("  [%d] %-14s %-16s -> %s%s  (%s)\n", i+1, a.Substrate, a.Class, res.Verdict, sim, res.Reason)
	}

	fmt.Printf("\nJournaled reversible ops: %d\n", j.Count())
	if err := j.Rollback(); err != nil {
		return err
	}
	fmt.Println("Rolled back: worktree restored to pre-run state.")

	res, err := ledger.Verify(ledgerPath)
	if err != nil {
		return err
	}
	fmt.Printf("Ledger verify: OK=%v records=%d\n", res.OK, res.Count)
	fmt.Printf("\nLedger: %s\nPolicy: %s\n", ledgerPath, policyPath)
	return nil
}

// runSession is the M1 demo: the agent runs as a SEPARATE PROCESS and can only
// reach the world through the broker protocol (adapters/exec). Contrast the
// agent's own narration (stderr) with the ledger truth below.
func runSession(dir string) error {
	root := filepath.Join(dir, ".aw-run")
	worktree := filepath.Join(root, "repo")
	store := filepath.Join(root, "snapshots")
	ledgerPath := filepath.Join(root, "ledger.log")
	policyPath := filepath.Join(root, "policy.json")

	_ = os.RemoveAll(root)
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(demoPolicy), 0o600); err != nil {
		return err
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		return err
	}
	j, err := contain.NewJournal(worktree, store)
	if err != nil {
		return err
	}
	g := gate.New(pol, []byte("DEMO-TRUST-ROOT-KEY"), map[awspec.Substrate]bool{
		awspec.SubFS: true, awspec.SubProc: true,
	})
	b := broker.New(j, g, led, decoy.New(), map[awspec.Substrate]broker.RealHandler{})

	sim, err := simPath()
	if err != nil {
		return err
	}
	fmt.Println("== Agent Warden M1 demo (separate-process agent, mediated by broker) ==")
	fmt.Printf("agent binary: %s\n\n", sim)

	cmd := exec.Command(sim, "-worktree", worktree)
	cmd.Stderr = os.Stderr // surface the agent's own (mis)perception
	if err := awexec.Run(b, cmd); err != nil {
		return err
	}

	// The ledger is the authoritative record — note where it disagrees with the
	// agent's view above (e.g., the "successful" payment is marked simulated).
	fmt.Println("\n-- ledger: what the broker actually did --")
	recs, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Body.RecordType != ledger.GateDecision {
			continue
		}
		note := ""
		if r.Body.Verdict == awspec.Sandbox {
			note = "  <- SIMULATED (agent was fooled; nothing real happened)"
		}
		fmt.Printf("  %-7s %-14s %-16s -> %s%s\n", r.Body.IrrevCategory, r.Body.Substrate, r.Body.ActionClass, r.Body.Verdict, note)
	}

	fmt.Printf("\nJournaled reversible ops: %d\n", j.Count())
	if err := j.Rollback(); err != nil {
		return err
	}
	fmt.Println("Rolled back: worktree restored to pre-run state.")

	vr, err := ledger.Verify(ledgerPath)
	if err != nil {
		return err
	}
	fmt.Printf("Ledger verify: OK=%v records=%d\n", vr.OK, vr.Count)
	fmt.Printf("\nLedger: %s\n", ledgerPath)
	return nil
}

// simPath locates the aw-agent-sim binary built alongside awarden.
func simPath() (string, error) { return agentBinPath("aw-agent-sim") }

// agentBinPath locates an agent binary built alongside awarden.
func agentBinPath(name string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(filepath.Dir(self), name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s not found next to awarden (%s); build it first: go build -o %q ./cmd/%s", name, p, p, trimExe(name))
	}
	return p, nil
}

func trimExe(n string) string {
	if runtime.GOOS == "windows" && len(n) > 4 && n[len(n)-4:] == ".exe" {
		return n[:len(n)-4]
	}
	return n
}

// runLLMSession is the M2 demo: a REAL LLM agent (aw-agent-qwen) runs as a separate
// process and reaches the world only through the broker. The agent inherits the
// environment (so DASHSCOPE_API_KEY is available to it); the broker never sees it.
func runLLMSession(dir, task string, dry bool) error {
	root := filepath.Join(dir, ".aw-llm")
	worktree := filepath.Join(root, "repo")
	store := filepath.Join(root, "snapshots")
	ledgerPath := filepath.Join(root, "ledger.log")
	policyPath := filepath.Join(root, "policy.json")

	_ = os.RemoveAll(root)
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(demoPolicy), 0o600); err != nil {
		return err
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		return err
	}
	j, err := contain.NewJournal(worktree, store)
	if err != nil {
		return err
	}
	g := gate.New(pol, []byte("DEMO-TRUST-ROOT-KEY"), map[awspec.Substrate]bool{awspec.SubFS: true, awspec.SubProc: true})
	b := broker.New(j, g, led, decoy.New(), map[awspec.Substrate]broker.RealHandler{})

	agent, err := agentBinPath("aw-agent-qwen")
	if err != nil {
		return err
	}
	fmt.Println("== Agent Warden M2 demo (REAL LLM agent via broker) ==")
	if dry {
		fmt.Println("(dry-run: no LLM call; canned action sequence)")
	}

	args := []string{"-worktree", worktree}
	if task != "" {
		args = append(args, "-task", task)
	}
	if dry {
		args = append(args, "-dry-run")
	}
	cmd := exec.Command(agent, args...)
	cmd.Env = os.Environ() // pass DASHSCOPE_API_KEY through to the agent; broker never sees it
	cmd.Stderr = os.Stderr
	if err := awexec.Run(b, cmd); err != nil {
		return err
	}

	fmt.Println("\n-- ledger: what the broker actually did --")
	recs, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Body.RecordType != ledger.GateDecision {
			continue
		}
		note := ""
		if r.Body.Verdict == awspec.Sandbox {
			note = "  <- SIMULATED (nothing real happened)"
		}
		fmt.Printf("  %-7s %-14s %-16s -> %s%s\n", r.Body.IrrevCategory, r.Body.Substrate, r.Body.ActionClass, r.Body.Verdict, note)
	}
	fmt.Printf("\nJournaled reversible ops: %d\n", j.Count())
	if err := j.Rollback(); err != nil {
		return err
	}
	fmt.Println("Rolled back: worktree restored to pre-run state.")
	vr, err := ledger.Verify(ledgerPath)
	if err != nil {
		return err
	}
	fmt.Printf("Ledger verify: OK=%v records=%d\n", vr.OK, vr.Count)
	fmt.Printf("\nLedger: %s\n", ledgerPath)
	return nil
}
