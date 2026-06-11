package awspec

import "testing"

func TestVaultRefs(t *testing.T) {
	got := VaultRefs("Bearer ${vault:gh_token} and ${vault:gh_token} and ${vault:openai.key}")
	if len(got) != 2 || got[0] != "gh_token" || got[1] != "openai.key" {
		t.Fatalf("VaultRefs = %v, want [gh_token openai.key] (distinct, in order)", got)
	}
	if VaultRefs("no refs here") != nil {
		t.Errorf("expected nil for no refs")
	}
}

func TestParamVaultRefsAndHas(t *testing.T) {
	p := map[string]string{"authorization": "Bearer ${vault:tok}", "url": "https://x/${vault:tok}/${vault:id}"}
	if !HasVaultRef(p) {
		t.Fatal("HasVaultRef should be true")
	}
	refs := ParamVaultRefs(p)
	if len(refs) != 2 {
		t.Fatalf("ParamVaultRefs = %v, want 2 distinct", refs)
	}
	if HasVaultRef(map[string]string{"a": "plain"}) {
		t.Error("HasVaultRef should be false for plain params")
	}
}

func TestInjectRefs(t *testing.T) {
	out, err := InjectRefs("Bearer ${vault:tok}", map[string]string{"tok": "SECRET"})
	if err != nil || out != "Bearer SECRET" {
		t.Fatalf("InjectRefs = %q, %v; want 'Bearer SECRET', nil", out, err)
	}
	if _, err := InjectRefs("Bearer ${vault:missing}", map[string]string{"tok": "SECRET"}); err == nil {
		t.Fatal("expected error for unresolved reference (fail closed)")
	}
}

func TestRedact(t *testing.T) {
	resolved := map[string]string{"tok": "SECRETCANARY", "empty": ""}
	in := "response: SECRETCANARY appeared SECRETCANARY twice"
	out := Redact(in, resolved)
	if out != "response: ⟨vault:tok⟩ appeared ⟨vault:tok⟩ twice" {
		t.Fatalf("Redact = %q", out)
	}
	// Empty values must not blank the whole string.
	if Redact("abc", resolved) != "abc" {
		t.Errorf("empty value should be skipped")
	}
}
