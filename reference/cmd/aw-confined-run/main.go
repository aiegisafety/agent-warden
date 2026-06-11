// Command aw-confined-run is the Tier-2 user-mode (T2-a) demo (AW-INT-v0.1 §2.2):
// it confines a stand-in rogue agent inside a Windows Job Object, pins its network
// egress to the Agent Warden proxy, mediates every outbound call through the
// broker, and records the verdicts in the tamper-evident ledger — all WITHOUT the
// agent's cooperation and WITHOUT OpenClaw. This is the "install once, govern any
// process" property.
//
//	aw-confined-run [-dir DIR] [-rogue PATH]
//
// Honest scope (T2-a): containment (Job Object kill-on-close + process cap),
// launch gating, and network mediation for proxy-respecting processes. A process
// that ignores HTTP_PROXY and opens a raw socket is NOT stopped at T2-a — that is
// the kernel WFP/minifilter job (T2-b kernel driver, designed separately).
//
// Windows-only for the real run (Job Object). On other OSes the interceptor stub
// returns ErrUnsupported so the module still builds and tests pass.
//
// Licensed under the Apache License 2.0.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aiegis/agentwarden/internal/broker"
	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/enforce"
	"github.com/aiegis/agentwarden/internal/enforce/proxy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// confinedPolicy governs the rogue's egress (all seen as net.egress by the proxy):
//   - *.evil.test     → hard deny (exfiltration)            → HTTP 403
//   - pay.test        → sandbox (decoy: rogue thinks it paid)→ HTTP 200 simulated
//   - anything else   → escalate (held for a human)         → HTTP 451
const confinedPolicy = `{
  "version": "0.2",
  "preset": "stable",
  "defaults": { "irreversible": "" },
  "rules": [
    { "match": { "substrate": "net", "class": "net.egress", "dest": "pay.test" }, "verdict": "sandbox" },
    { "match": { "substrate": "net", "class": "net.egress" }, "verdict": "escalate" }
  ],
  "hard_deny": [
    { "match": { "substrate": "net", "class": "net.egress", "dest_in": ["*.evil.test"] } }
  ]
}`

func main() {
	fs := flag.NewFlagSet("aw-confined-run", flag.ExitOnError)
	dir := fs.String("dir", ".", "scratch root for journal + ledger")
	rogue := fs.String("rogue", "", "path to aw-rogue-sim binary (default: ./bin/aw-rogue-sim[.exe])")
	allowChildren := fs.Bool("allow-children", false, "do NOT block child processes (falls back to the exec launch)")
	noLowIntegrity := fs.Bool("no-low-integrity", false, "do NOT run the agent at Low integrity (skip B2 filesystem containment)")
	_ = fs.Parse(os.Args[1:])

	if err := run(*dir, *rogue, !*allowChildren, !*noLowIntegrity); err != nil {
		fmt.Fprintln(os.Stderr, "aw-confined-run:", err)
		os.Exit(1)
	}
}

func run(dir, rogue string, noChildren, lowIntegrity bool) error {
	root := filepath.Join(dir, ".aw-confined")
	worktree := filepath.Join(root, "workspace")
	store := filepath.Join(root, "snapshots")
	ledgerPath := filepath.Join(root, "ledger.log")
	policyPath := filepath.Join(root, "policy.json")
	// Demo behavior: start each run with a fresh ledger so the output shows just this
	// run's verdicts. (A real deployment keeps the append-only ledger across the
	// agent's whole life — that persistence is the point of a tamper-evident audit.)
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(policyPath, []byte(confinedPolicy), 0o600); err != nil {
		return err
	}

	if rogue == "" {
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		rogue = filepath.Join("bin", "aw-rogue-sim"+ext)
	}
	if _, err := os.Stat(rogue); err != nil {
		return fmt.Errorf("rogue binary not found at %q (build it: go build -o %s ./cmd/aw-rogue-sim): %w", rogue, rogue, err)
	}

	// Broker: FS + Proc are "real" (reversible/launch); net has no real handler so
	// the gate decides allow/deny/escalate/sandbox per policy.
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

	// Egress proxy on a loopback port, backed by the broker.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	px := proxy.New(b, "confined-rogue", nil)
	go func() { _ = http.Serve(ln, px) }()
	proxyURL := "http://" + ln.Addr().String()

	// Confine + launch the rogue. The interceptor gates the launch through the
	// broker and pins the child's egress to proxyURL.
	ic := enforce.NewInterceptor()
	ic.OnEffect(func(a awspec.Action) enforce.Verdict {
		res, mErr := b.Mediate(a)
		if mErr != nil {
			return awspec.Deny // fail closed
		}
		return res.Verdict
	})
	spec := enforce.AgentSpec{
		Exe: mustAbs(rogue), WorkDir: mustAbs(worktree), EgressProxy: proxyURL,
		NoChildProcesses: noChildren,
		LowIntegrity:     lowIntegrity,
	}

	fmt.Println("== Agent Warden — Tier-2 confined-run (T2-a) ==")
	fmt.Printf("confining %s in a Job Object; egress pinned to %s\n\n", rogue, proxyURL)

	launchErr := ic.Launch(context.Background(), spec)
	if errors.Is(launchErr, enforce.ErrUnsupported) {
		fmt.Println("\n[!] OS-level confinement is Windows-only this round (Job Object).")
		fmt.Println("    Run this on your Windows machine to see the real jail. The egress")
		fmt.Println("    proxy + broker + ledger above are cross-platform and already wired.")
		return nil
	}
	if launchErr != nil {
		return launchErr
	}

	// The rogue has exited and the job is closed. Show the ground truth.
	fmt.Println("\n-- Ledger (the truth the rogue can't see) --")
	recs, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		return err
	}
	for _, r := range recs {
		sim := ""
		if r.Body.Simulated {
			sim = " [SIMULATED]"
		}
		fmt.Printf("  seq %d  %-11s %-12s -> %s%s  (%s)\n",
			r.Body.Seq, r.Body.Substrate, r.Body.ActionClass, r.Body.Verdict, sim, r.Body.EffectDigest)
	}
	vr, err := ledger.Verify(ledgerPath)
	if err != nil {
		return err
	}
	fmt.Printf("\nLedger verify: OK=%v records=%d (%s)\n", vr.OK, vr.Count, vr.Detail)
	return nil
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
