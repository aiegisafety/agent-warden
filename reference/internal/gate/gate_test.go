package gate

import (
	"testing"

	"github.com/aiegis/agentwarden/internal/capability"
	"github.com/aiegis/agentwarden/internal/policy"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

func boolp(b bool) *bool { return &b }

func testPolicy() *policy.Policy {
	return &policy.Policy{
		Version:  "0.2",
		Defaults: policy.Defaults{Irreversible: awspec.Deny},
		Rules: []policy.Rule{
			{Match: policy.Match{Substrate: awspec.SubNet, Class: "net.egress", Dest: "api.github.com"}, Verdict: awspec.Allow},
			{Match: policy.Match{Substrate: awspec.SubNet, Class: "net.egress"}, Verdict: awspec.Escalate},
			{Match: policy.Match{Substrate: awspec.SubValue, Class: "value.transfer"}, Verdict: awspec.Sandbox},
		},
		HardDeny: []policy.Rule{
			{Match: policy.Match{Class: "cred.export"}},
		},
	}
}

func newGate(p *policy.Policy) *Gate {
	// net has NO real handler here, to exercise the AW-G-1 downgrade path.
	return New(p, []byte("k"), map[awspec.Substrate]bool{awspec.SubFS: true, awspec.SubNet: true})
}

func TestHardDenyDominates(t *testing.T) {
	g := newGate(testPolicy())
	a := awspec.Action{Substrate: awspec.SubCred, Class: "cred.export",
		Params: map[string]string{"dest": "api.github.com"}}
	if d := g.Decide(a, awspec.IEgress); d.Verdict != awspec.Deny {
		t.Fatalf("hard_deny must yield deny, got %s", d.Verdict)
	}
}

func TestMostSpecificAllow(t *testing.T) {
	g := newGate(testPolicy())
	a := awspec.Action{Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"dest": "api.github.com"}}
	if d := g.Decide(a, awspec.IEgress); d.Verdict != awspec.Allow {
		t.Fatalf("expected allow for whitelisted dest, got %s (%s)", d.Verdict, d.Reason)
	}
}

func TestGenericEgressEscalates(t *testing.T) {
	g := newGate(testPolicy())
	a := awspec.Action{Substrate: awspec.SubNet, Class: "net.egress",
		Params: map[string]string{"dest": "evil.example.com"}}
	if d := g.Decide(a, awspec.IEgress); d.Verdict != awspec.Escalate {
		t.Fatalf("expected escalate for non-whitelisted egress, got %s", d.Verdict)
	}
}

func TestValueSandboxed(t *testing.T) {
	g := newGate(testPolicy())
	a := awspec.Action{Substrate: awspec.SubValue, Class: "value.transfer",
		Params: map[string]string{"dest": "x", "amount": "1"}}
	if d := g.Decide(a, awspec.IValue); d.Verdict != awspec.Sandbox {
		t.Fatalf("expected sandbox for value transfer, got %s", d.Verdict)
	}
}

func TestFailClosedDefaultDeny(t *testing.T) {
	g := newGate(testPolicy())
	// physical action: no rule, default is deny.
	a := awspec.Action{Substrate: awspec.SubPhys, Class: "phys.move"}
	if d := g.Decide(a, awspec.IPhys); d.Verdict != awspec.Deny {
		t.Fatalf("expected fail-closed deny, got %s", d.Verdict)
	}
}

func TestAllowDowngradesToSandboxWhenNoRealHandler(t *testing.T) {
	p := testPolicy()
	// Policy explicitly allows a value transfer, but there is no real handler for
	// value, and it is a non-containable external effect → AW-G-1 downgrade.
	p.Rules = append([]policy.Rule{
		{Match: policy.Match{Substrate: awspec.SubValue, Class: "value.transfer", Dest: "vendor"}, Verdict: awspec.Allow},
	}, p.Rules...)
	g := newGate(p)
	a := awspec.Action{Substrate: awspec.SubValue, Class: "value.transfer",
		Params: map[string]string{"dest": "vendor"}}
	if d := g.Decide(a, awspec.IValue); d.Verdict != awspec.Sandbox {
		t.Fatalf("expected allow→sandbox downgrade (no real handler), got %s (%s)", d.Verdict, d.Reason)
	}
}

func TestNonStableCapabilityDowngrades(t *testing.T) {
	p := testPolicy()
	p.Rules = append([]policy.Rule{
		{Match: policy.Match{Substrate: awspec.SubFS, Class: "fs.archive"}, Verdict: awspec.Allow},
	}, p.Rules...)
	g := newGate(p)
	// fs HAS a real handler, but the carried capability is EXPERIMENTAL → §6.3 hook
	// withholds real reach and rehearses instead.
	cap := awspec.Capability{
		CapType: "fs.archive", Scope: []awspec.Substrate{awspec.SubFS},
		Lineage: "grant-1", LifecycleState: awspec.Experimental,
	}
	cap.IntegrityTag = capability.Mint(cap, []byte("k"))
	a := awspec.Action{Substrate: awspec.SubFS, Class: "fs.archive",
		Params: map[string]string{}, Carried: &cap}
	if d := g.Decide(a, awspec.IDestroy); d.Verdict != awspec.Sandbox {
		t.Fatalf("expected EXPERIMENTAL capability to downgrade allow→sandbox, got %s (%s)", d.Verdict, d.Reason)
	}
}

func TestForgedCapabilityDenied(t *testing.T) {
	g := newGate(testPolicy())
	cap := awspec.Capability{CapType: "fs.archive", Scope: []awspec.Substrate{awspec.SubFS},
		Lineage: "grant-1", LifecycleState: awspec.Stable, IntegrityTag: "deadbeef"}
	a := awspec.Action{Substrate: awspec.SubFS, Class: "fs.archive", Carried: &cap}
	if d := g.Decide(a, awspec.IDestroy); d.Verdict != awspec.Deny {
		t.Fatalf("expected forged capability to be denied, got %s", d.Verdict)
	}
}
