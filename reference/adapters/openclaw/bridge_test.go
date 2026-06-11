package openclaw

import (
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// fakeMediator returns a fixed verdict keyed by substrate, so we test the
// mapping + verdict translation without the full broker.
type fakeMediator struct {
	byClass map[string]awspec.Result
	err     error
}

func (f fakeMediator) Mediate(a awspec.Action) (awspec.Result, error) {
	if f.err != nil {
		return awspec.Result{}, f.err
	}
	if r, ok := f.byClass[a.Class]; ok {
		return r, nil
	}
	return awspec.Result{Verdict: awspec.Allow}, nil
}

func TestMapToolCall_Provenance(t *testing.T) {
	a := MapToolCall(ToolCall{Tool: "exec", Params: map[string]string{"command": "ls"},
		Ctx: map[string]string{"agent_id": "default", "run_id": "r1"}})
	if a.Source != "openclaw" || a.Tier != 1 || a.Tool != "exec" {
		t.Fatalf("provenance not set: %+v", a)
	}
	if a.Substrate != awspec.SubProc || a.Class != "process.exec" {
		t.Fatalf("exec mapping wrong: %s/%s", a.Substrate, a.Class)
	}
	if a.AgentID != "default" {
		t.Fatalf("agent id from ctx expected, got %q", a.AgentID)
	}
}

func TestClassify_Table(t *testing.T) {
	cases := []struct {
		tool     string
		wantSub  awspec.Substrate
		wantCls  string
	}{
		{"exec", awspec.SubProc, "process.exec"},
		{"apply_patch", awspec.SubFS, "fs.write"},
		{"delete", awspec.SubFS, "fs.delete"},
		{"web-fetch", awspec.SubNet, "net.egress"},
		// Real OpenClaw (2026.6.5) calls tools with UNDERSCORE names; the
		// normalizer must map these the same as their hyphen forms.
		{"web_fetch", awspec.SubNet, "net.egress"},
		{"web_search", awspec.SubNet, "net.egress"},
		{"read_file", awspec.SubFS, "fs.read"},
		{"email", awspec.SubValue, "value.message"},
		{"secret", awspec.SubCred, "cred.use"},
		{"totally-unknown-tool", awspec.Substrate(""), "unknown"},
	}
	for _, c := range cases {
		s, cl := classify(c.tool)
		if s != c.wantSub || cl != c.wantCls {
			t.Errorf("classify(%q) = %s/%s, want %s/%s", c.tool, s, cl, c.wantSub, c.wantCls)
		}
	}
}

func TestTranslate_AllFourVerdicts(t *testing.T) {
	m := fakeMediator{byClass: map[string]awspec.Result{
		"process.exec":  {Verdict: awspec.Allow, Reason: "reversible"},
		"fs.delete":     {Verdict: awspec.Deny, Reason: "hard-deny destroy"},
		"value.message": {Verdict: awspec.Escalate, Reason: "value transfer needs human"},
		"net.egress":    {Verdict: awspec.Sandbox, Simulated: true, Reason: "decoy"},
	}}

	allow := Translate(m, ToolCall{ID: 1, Tool: "exec"})
	if allow.Decision != "allow" || allow.BlockReason != "" || allow.Approval != nil {
		t.Errorf("allow translation wrong: %+v", allow)
	}

	deny := Translate(m, ToolCall{ID: 2, Tool: "delete", Params: map[string]string{"path": "/x"}})
	if deny.Decision != "deny" || deny.BlockReason == "" {
		t.Errorf("deny translation wrong: %+v", deny)
	}

	esc := Translate(m, ToolCall{ID: 3, Tool: "email", Params: map[string]string{"to": "a@b.com"}})
	if esc.Decision != "escalate" || esc.Approval == nil || esc.Approval.TimeoutBehavior != "deny" {
		t.Errorf("escalate must produce fail-closed approval: %+v", esc)
	}

	sb := Translate(m, ToolCall{ID: 4, Tool: "web-fetch", Params: map[string]string{"url": "http://evil"}})
	if sb.Decision != "sandbox" || !sb.Simulated || sb.DecoyParams["url"] == "http://evil" {
		t.Errorf("sandbox must redirect to decoy and mark simulated: %+v", sb)
	}
}

func TestTranslate_FailClosedOnError(t *testing.T) {
	m := fakeMediator{err: errBoom{}}
	v := Translate(m, ToolCall{ID: 9, Tool: "exec"})
	if v.Decision != "deny" {
		t.Fatalf("broker error must fail closed to deny, got %q", v.Decision)
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
