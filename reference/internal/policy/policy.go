// Package policy loads the user-authored policy file from the trust root and
// resolves the most-specific matching rule for an action (AW-Spec v0.2 §3.5, §7).
//
// The reference implementation uses JSON (zero external dependencies, per
// ADR-0002). The YAML shown in the spec/HLD is illustrative; a YAML front-end is a
// later addition. Presets (AW-UX-1) expand into per-action rules at load time —
// there is NO global runtime mode (AW-Spec §7.6, §10.6).
//
// Licensed under the Apache License 2.0.
package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Match is a predicate over an action. Empty fields are wildcards. The optional
// flags express the small set of predicates P1 needs.
type Match struct {
	Substrate          awspec.Substrate `json:"substrate,omitempty"`
	Class              string           `json:"class,omitempty"`
	Dest               string           `json:"dest,omitempty"`
	DestIn             []string         `json:"dest_in,omitempty"`
	PathOutsideWorktree *bool           `json:"path_outside_worktree,omitempty"`
}

// Rule maps a Match to a verdict (AW-Spec §7.1).
type Rule struct {
	Match   Match          `json:"match"`
	Verdict awspec.Verdict `json:"verdict"`
}

// Defaults holds the fail-closed default for unmatched irreversible actions.
type Defaults struct {
	Irreversible awspec.Verdict `json:"irreversible"`
}

// Policy is the parsed, preset-expanded policy.
type Policy struct {
	Version  string   `json:"version"`
	Preset   string   `json:"preset,omitempty"` // explore | stable | "" (custom)
	Defaults Defaults `json:"defaults"`
	Rules    []Rule   `json:"rules"`
	HardDeny []Rule   `json:"hard_deny"` // categorically non-overridable (AW-Spec §7.2)
}

// Load reads, parses, validates and preset-expands a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	p.applyPreset()
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// applyPreset expands a coarse preset into per-action rules/defaults. This is the
// AW-UX-1 mechanism: a preset is configuration over the per-action engine, never a
// runtime mode. Explicit rules already present are preserved (preset only fills
// the default posture).
func (p *Policy) applyPreset() {
	switch p.Preset {
	case "explore":
		// Prefer rehearsal: unmatched irreversibles are sandboxed, not denied.
		if p.Defaults.Irreversible == "" {
			p.Defaults.Irreversible = awspec.Sandbox
		}
	case "stable":
		// Conservative: unmatched irreversibles escalate to a human.
		if p.Defaults.Irreversible == "" {
			p.Defaults.Irreversible = awspec.Escalate
		}
	}
}

func (p *Policy) validate() error {
	// Fail-closed: the default for irreversible actions must never be allow
	// (AW-Spec §7.2). Empty is treated as deny.
	if p.Defaults.Irreversible == "" {
		p.Defaults.Irreversible = awspec.Deny
	}
	if p.Defaults.Irreversible == awspec.Allow {
		return fmt.Errorf("invalid policy: default for irreversible actions may not be 'allow' (fail-closed, AW-Spec §7.2)")
	}
	return nil
}

// matches reports whether a rule's Match selects action a, and a specificity score
// (higher = more specific) used to pick the most-specific rule.
func (m Match) matches(a awspec.Action) (bool, int) {
	score := 0
	if m.Substrate != "" {
		if m.Substrate != a.Substrate {
			return false, 0
		}
		score++
	}
	if m.Class != "" {
		if m.Class != a.Class {
			return false, 0
		}
		score += 2
	}
	if m.Dest != "" {
		if m.Dest != a.Params["dest"] {
			return false, 0
		}
		score += 4
	}
	if len(m.DestIn) > 0 {
		if !globAny(m.DestIn, a.Params["dest"]) {
			return false, 0
		}
		score += 3
	}
	if m.PathOutsideWorktree != nil {
		outside := a.Params["path_outside_worktree"] == "true"
		if *m.PathOutsideWorktree != outside {
			return false, 0
		}
		score += 2
	}
	return true, score
}

// HardDenied reports whether action a matches any categorically-non-overridable
// rule (AW-Spec §7.2 step 2). These can never be flipped by anything.
func (p *Policy) HardDenied(a awspec.Action) bool {
	for _, r := range p.HardDeny {
		if ok, _ := r.Match.matches(a); ok {
			return true
		}
	}
	return false
}

// Resolve returns the most-specific matching rule verdict and true, or ("", false)
// if no rule matches (caller then applies the fail-closed default).
func (p *Policy) Resolve(a awspec.Action) (awspec.Verdict, bool) {
	best := -1
	var verdict awspec.Verdict
	found := false
	for _, r := range p.Rules {
		if ok, s := r.Match.matches(a); ok && s > best {
			best = s
			verdict = r.Verdict
			found = true
		}
	}
	return verdict, found
}

// globAny reports whether s matches any of the patterns, where a leading "*."
// matches any suffix. Minimal glob for P1.
func globAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if len(p) > 2 && p[0] == '*' && p[1] == '.' {
			suffix := p[1:] // ".known-exfil"
			if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
				return true
			}
		} else if p == s {
			return true
		}
	}
	return false
}
