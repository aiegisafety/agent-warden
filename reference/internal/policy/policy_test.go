package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExplorePresetDefaultsToSandbox(t *testing.T) {
	p, err := Load(writePolicy(t, `{"version":"0.2","preset":"explore","defaults":{"irreversible":""},"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Irreversible != awspec.Sandbox {
		t.Fatalf("explore preset should default irreversible→sandbox, got %s", p.Defaults.Irreversible)
	}
}

func TestStablePresetDefaultsToEscalate(t *testing.T) {
	p, err := Load(writePolicy(t, `{"version":"0.2","preset":"stable","defaults":{"irreversible":""},"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Irreversible != awspec.Escalate {
		t.Fatalf("stable preset should default irreversible→escalate, got %s", p.Defaults.Irreversible)
	}
}

func TestRejectDefaultAllow(t *testing.T) {
	_, err := Load(writePolicy(t, `{"version":"0.2","defaults":{"irreversible":"allow"},"rules":[]}`))
	if err == nil {
		t.Fatal("policy with default irreversible=allow must be rejected (fail-closed)")
	}
}

func TestEmptyDefaultBecomesDeny(t *testing.T) {
	p, err := Load(writePolicy(t, `{"version":"0.2","defaults":{"irreversible":""},"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Irreversible != awspec.Deny {
		t.Fatalf("empty default should fail closed to deny, got %s", p.Defaults.Irreversible)
	}
}

func TestMostSpecificResolution(t *testing.T) {
	p, err := Load(writePolicy(t, `{
      "version":"0.2","defaults":{"irreversible":"deny"},
      "rules":[
        {"match":{"substrate":"net","class":"net.egress"},"verdict":"escalate"},
        {"match":{"substrate":"net","class":"net.egress","dest":"api.github.com"},"verdict":"allow"}
      ]}`))
	if err != nil {
		t.Fatal(err)
	}
	a := awspec.Action{Substrate: awspec.SubNet, Class: "net.egress", Params: map[string]string{"dest": "api.github.com"}}
	if v, ok := p.Resolve(a); !ok || v != awspec.Allow {
		t.Fatalf("expected most-specific dest rule to win (allow), got %s ok=%v", v, ok)
	}
	b := awspec.Action{Substrate: awspec.SubNet, Class: "net.egress", Params: map[string]string{"dest": "other"}}
	if v, _ := p.Resolve(b); v != awspec.Escalate {
		t.Fatalf("expected generic egress escalate, got %s", v)
	}
}

func TestHardDenyGlob(t *testing.T) {
	p, err := Load(writePolicy(t, `{
      "version":"0.2","defaults":{"irreversible":"deny"},"rules":[],
      "hard_deny":[{"match":{"substrate":"net","class":"net.egress","dest_in":["*.known-exfil"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	a := awspec.Action{Substrate: awspec.SubNet, Class: "net.egress", Params: map[string]string{"dest": "data.known-exfil"}}
	if !p.HardDenied(a) {
		t.Fatal("expected glob hard_deny to match data.known-exfil")
	}
}
