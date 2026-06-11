// Credential-substrate helpers (AW-HLD-P2-CRED). The agent references a vaulted
// secret as `${vault:alias}`; it never holds the value. These helpers parse those
// references and redact resolved values so a secret can never echo back to the
// agent, the result payload, or the ledger.
//
// Licensed under the Apache License 2.0.
package awspec

import (
	"fmt"
	"regexp"
	"strings"
)

// Credential action classes (AW-HLD-P2-CRED §2).
const (
	ClassCredUse    = "cred.use"    // reference a vaulted secret for an authorized destination
	ClassCredExport = "cred.export" // read the plaintext back — always denied (hard floor)
)

// RedactMarker is what a resolved secret is replaced with everywhere the agent or
// the ledger could see it.
func RedactMarker(alias string) string { return "⟨vault:" + alias + "⟩" }

// vaultRefRe matches `${vault:alias}` with alias in [A-Za-z0-9_.-].
var vaultRefRe = regexp.MustCompile(`\$\{vault:([A-Za-z0-9_.\-]+)\}`)

// VaultRefs returns the distinct aliases referenced anywhere in s (order of first
// appearance).
func VaultRefs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range vaultRefRe.FindAllStringSubmatch(s, -1) {
		a := m[1]
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// ParamVaultRefs returns the distinct aliases referenced across all params.
func ParamVaultRefs(params map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range params {
		for _, a := range VaultRefs(v) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// HasVaultRef reports whether any param carries a `${vault:...}` reference.
func HasVaultRef(params map[string]string) bool {
	for _, v := range params {
		if vaultRefRe.MatchString(v) {
			return true
		}
	}
	return false
}

// InjectRefs replaces every `${vault:alias}` in s with the resolved secret value
// from resolved[alias]. Used ONLY at the egress boundary, on the outbound copy of
// a request — never on anything returned to the agent. An unresolved alias is an
// error (fail closed: we must not send a literal `${vault:...}` upstream).
func InjectRefs(s string, resolved map[string]string) (string, error) {
	var bad string
	out := vaultRefRe.ReplaceAllStringFunc(s, func(m string) string {
		alias := vaultRefRe.FindStringSubmatch(m)[1]
		val, ok := resolved[alias]
		if !ok {
			bad = alias
			return m
		}
		return val
	})
	if bad != "" {
		return "", fmt.Errorf("unresolved vault reference %q", bad)
	}
	return out, nil
}

// Redact replaces every resolved secret VALUE in s with its alias marker. This is
// the choke point that keeps secrets out of agent-visible output and the ledger
// (AW-HLD-P2-CRED §5). Empty values are skipped.
func Redact(s string, resolved map[string]string) string {
	for alias, val := range resolved {
		if val == "" {
			continue
		}
		s = strings.ReplaceAll(s, val, RedactMarker(alias))
	}
	return s
}
