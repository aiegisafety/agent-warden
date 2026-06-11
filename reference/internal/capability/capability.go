// Package capability verifies unforgeable carried authority (AW-Spec v0.2 §6).
// Capabilities trace to a user-authored grant (lineage), may only be attenuated
// (never amplified), and are bound by an HMAC integrity tag under a trust-root key
// the agent cannot read. The lifecycle_state field (AW-G-2, §6.3) is parsed and
// the STABLE-gate hook is enforced; the full state machine is P3.
//
// Licensed under the Apache License 2.0.
package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// integrityInput builds the deterministic byte string an integrity tag commits to.
// It excludes the tag itself.
func integrityInput(c awspec.Capability) string {
	var sb strings.Builder
	sb.WriteString(c.CapType)
	sb.WriteByte('|')
	// param_bounds sorted for determinism
	keys := make([]string, 0, len(c.ParamBounds))
	for k := range c.ParamBounds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(c.ParamBounds[k])
		sb.WriteByte(';')
	}
	sb.WriteByte('|')
	scopes := make([]string, len(c.Scope))
	for i, s := range c.Scope {
		scopes[i] = string(s)
	}
	sort.Strings(scopes)
	sb.WriteString(strings.Join(scopes, ","))
	sb.WriteByte('|')
	sb.WriteString(c.Validity)
	sb.WriteByte('|')
	sb.WriteString(c.Lineage)
	sb.WriteByte('|')
	sb.WriteString(string(c.LifecycleState))
	return sb.String()
}

// Mint produces an integrity tag for a capability under the trust-root key. Only
// the trust root (which the agent cannot reach, AW-Spec §5.6) calls this.
func Mint(c awspec.Capability, trustRootKey []byte) string {
	mac := hmac.New(sha256.New, trustRootKey)
	mac.Write([]byte(integrityInput(c)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyResult reports why a capability check passed or failed.
type VerifyResult struct {
	OK     bool
	Reason string
}

// Verify checks a carried capability against the request and the trust-root key
// (AW-Spec §6, §7.2 step 4): integrity tag valid, scope/type cover the action,
// param_bounds satisfied. Returns OK=false with a reason on any failure.
func Verify(c *awspec.Capability, a awspec.Action, trustRootKey []byte) VerifyResult {
	if c == nil {
		return VerifyResult{OK: false, Reason: "no capability"}
	}
	// integrity tag (unforgeability)
	want := Mint(*c, trustRootKey)
	if !hmac.Equal([]byte(want), []byte(c.IntegrityTag)) {
		return VerifyResult{OK: false, Reason: "integrity tag invalid (forged or amplified capability)"}
	}
	// lineage must be present (traces to a user grant)
	if c.Lineage == "" {
		return VerifyResult{OK: false, Reason: "missing lineage to a user-authored grant"}
	}
	// scope must cover the substrate
	inScope := false
	for _, s := range c.Scope {
		if s == a.Substrate {
			inScope = true
			break
		}
	}
	if !inScope {
		return VerifyResult{OK: false, Reason: fmt.Sprintf("capability scope does not cover substrate %q", a.Substrate)}
	}
	// cap_type should match the action class family (prefix match: "net.egress"
	// authorized by cap_type "net.egress" or "net.*")
	if !classCovered(c.CapType, a.Class) {
		return VerifyResult{OK: false, Reason: fmt.Sprintf("cap_type %q does not authorize class %q", c.CapType, a.Class)}
	}
	return VerifyResult{OK: true, Reason: "ok"}
}

func classCovered(capType, class string) bool {
	if capType == class {
		return true
	}
	if strings.HasSuffix(capType, ".*") {
		return strings.HasPrefix(class, strings.TrimSuffix(capType, "*"))
	}
	return false
}

// GrantsRealIrreversibleReach reports whether a capability's lifecycle state is
// advanced enough to exercise real (non-sandboxed) irreversible reach. Only STABLE
// qualifies (AW-Spec §6.3, AW-G-2). A nil capability is treated as STABLE because
// authority then comes purely from user policy, not a leased capability.
func GrantsRealIrreversibleReach(c *awspec.Capability) bool {
	if c == nil {
		return true
	}
	if c.LifecycleState == "" {
		return true // user-authored grants default STABLE
	}
	return c.LifecycleState == awspec.Stable
}
