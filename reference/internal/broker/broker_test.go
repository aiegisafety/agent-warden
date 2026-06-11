package broker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

func setup(t *testing.T) (*Broker, string, string) {
	t.Helper()
	root := t.TempDir()
	worktree := filepath.Join(root, "repo")
	store := filepath.Join(root, "snap")
	ledgerPath := filepath.Join(root, "ledger.log")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{
		Version:  "0.2",
		Defaults: policy.Defaults{Irreversible: awspec.Deny},
		Rules: []policy.Rule{
			{Match: policy.Match{Substrate: awspec.SubNet, Class: "net.egress"}, Verdict: awspec.Escalate},
			{Match: policy.Match{Substrate: awspec.SubValue, Class: "value.transfer"}, Verdict: awspec.Sandbox},
		},
		HardDeny: []policy.Rule{{Match: policy.Match{Class: "cred.export"}}},
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	j, err := contain.NewJournal(worktree, store)
	if err != nil {
		t.Fatal(err)
	}
	g := gate.New(pol, []byte("k"), map[awspec.Substrate]bool{awspec.SubFS: true})
	b := New(j, g, led, decoy.New(), map[awspec.Substrate]RealHandler{})
	return b, worktree, ledgerPath
}

func TestReversibleWriteThenRollback(t *testing.T) {
	b, worktree, _ := setup(t)
	existing := filepath.Join(worktree, "keep.txt")
	if err := os.WriteFile(existing, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(worktree, "new.txt")

	// Agent overwrites an existing file and creates a new one — both reversible.
	if res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubFS, Class: "fs.write",
		Params: map[string]string{"path": existing, "content": "CHANGED"}}); err != nil || res.Verdict != awspec.Allow {
		t.Fatalf("write: %v %+v", err, res)
	}
	if _, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubFS, Class: "fs.write",
		Params: map[string]string{"path": created, "content": "NEW"}}); err != nil {
		t.Fatal(err)
	}
	// Confirm effects applied.
	if got, _ := os.ReadFile(existing); string(got) != "CHANGED" {
		t.Fatalf("expected CHANGED, got %q", got)
	}

	if err := b.journal.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Existing file restored; created file removed.
	if got, _ := os.ReadFile(existing); string(got) != "ORIGINAL" {
		t.Fatalf("rollback failed to restore; got %q", got)
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatal("rollback failed to remove created file")
	}
}

func TestOutOfTreeDeleteIsGated(t *testing.T) {
	b, _, _ := setup(t)
	// A delete outside the worktree is I-DESTROY → gate → fail-closed default deny.
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubFS, Class: "fs.delete",
		Params: map[string]string{"path": "/etc/passwd"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Deny {
		t.Fatalf("expected out-of-tree delete to be denied, got %s", res.Verdict)
	}
}

func TestEgressEscalates(t *testing.T) {
	b, _, _ := setup(t)
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"dest": "evil.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Escalate {
		t.Fatalf("expected escalate, got %s", res.Verdict)
	}
}

func TestValueSandboxedAndSimulatedLogged(t *testing.T) {
	b, _, ledgerPath := setup(t)
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubValue, Class: "value.transfer",
		Params: map[string]string{"dest": "acct", "amount": "100"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Sandbox || !res.Simulated {
		t.Fatalf("expected sandbox+simulated, got %s simulated=%v", res.Verdict, res.Simulated)
	}
	// Ledger must contain an irreversible_effect record marked simulated=true.
	recs, err := ledger.ReadAll(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	foundSim := false
	for _, r := range recs {
		if r.Body.RecordType == ledger.IrreversibleEffect && r.Body.Simulated && r.Body.Verdict == awspec.Sandbox {
			foundSim = true
		}
	}
	if !foundSim {
		t.Fatal("expected a simulated irreversible_effect record in the ledger")
	}
}

func TestCredExportHardDenied(t *testing.T) {
	b, _, _ := setup(t)
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubCred, Class: "cred.export",
		Params: map[string]string{"dest": "evil.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Deny {
		t.Fatalf("expected hard deny for cred.export, got %s", res.Verdict)
	}
}

func TestLedgerVerifiesAfterRun(t *testing.T) {
	b, _, ledgerPath := setup(t)
	acts := []awspec.Action{
		{AgentID: "a", Substrate: awspec.SubNet, Class: "net.egress", Params: map[string]string{"dest": "x"}},
		{AgentID: "a", Substrate: awspec.SubValue, Class: "value.transfer", Params: map[string]string{"dest": "y", "amount": "1"}},
		{AgentID: "a", Substrate: awspec.SubCred, Class: "cred.export", Params: map[string]string{"dest": "z"}},
	}
	for _, a := range acts {
		if _, err := b.Mediate(a); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ledger.Verify(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("ledger should verify after run: %+v", res)
	}
}
