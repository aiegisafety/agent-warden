package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v, err := Open(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open new: %v", err)
	}
	v.Put("github_token", "ghp_SECRETCANARY123", Binding{Substrate: awspec.SubNet, Dests: []string{".github.com"}})
	if err := v.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	v2, err := Open(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	val, b, err := v2.Resolve("github_token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "ghp_SECRETCANARY123" {
		t.Errorf("value = %q, want the canary", val)
	}
	if !b.Allows(awspec.SubNet, "api.github.com") {
		t.Errorf("binding should allow api.github.com")
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	v, _ := Open(path, "right-pass")
	v.Put("a", "secret", Binding{})
	if err := v.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "WRONG-pass"); err == nil {
		t.Fatal("expected unseal failure with wrong passphrase")
	}
}

func TestTamperFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	v, _ := Open(path, "p")
	v.Put("a", "secret", Binding{})
	if err := v.Seal(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 0xFF // flip a ciphertext byte
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "p"); err == nil {
		t.Fatal("expected unseal failure on tampered file (GCM auth)")
	}
}

func TestBindingAllows(t *testing.T) {
	b := Binding{Substrate: awspec.SubNet, Dests: []string{"api.exact.com", ".github.com"}}
	cases := []struct {
		sub  awspec.Substrate
		dest string
		want bool
	}{
		{awspec.SubNet, "api.exact.com", true},   // exact
		{awspec.SubNet, "api.github.com", true},  // suffix
		{awspec.SubNet, "github.com", false},     // ".github.com" does not match bare "github.com"
		{awspec.SubNet, "evil.test", false},      // unlisted
		{awspec.SubValue, "api.github.com", false}, // wrong substrate
	}
	for _, c := range cases {
		if got := b.Allows(c.sub, c.dest); got != c.want {
			t.Errorf("Allows(%s,%q) = %v, want %v", c.sub, c.dest, got, c.want)
		}
	}
}

func TestResolveUnknown(t *testing.T) {
	v, _ := Open(filepath.Join(t.TempDir(), "v.enc"), "p")
	if _, _, err := v.Resolve("nope"); err == nil {
		t.Fatal("expected ErrNotFound for unknown alias")
	}
}
