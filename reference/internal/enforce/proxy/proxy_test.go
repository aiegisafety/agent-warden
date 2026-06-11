package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

type fakeMediator struct {
	res awspec.Result
	err error
	got awspec.Action
}

func (f *fakeMediator) Mediate(a awspec.Action) (awspec.Result, error) {
	f.got = a
	return f.res, f.err
}

func do(s *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://evil.example.com/x", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestProxy_DenyBlocksEgress(t *testing.T) {
	m := &fakeMediator{res: awspec.Result{Verdict: awspec.Deny, Reason: "blocked"}}
	rec := do(New(m, "a", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny must be 403, got %d", rec.Code)
	}
	if m.got.Substrate != awspec.SubNet || m.got.Tier != 2 || m.got.Params["dest"] != "evil.example.com" {
		t.Fatalf("egress action not formed correctly: %+v", m.got)
	}
}

func TestProxy_SandboxReturnsDecoy(t *testing.T) {
	m := &fakeMediator{res: awspec.Result{Verdict: awspec.Sandbox, Simulated: true}}
	rec := do(New(m, "a", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("X-AW-Simulated") != "1" {
		t.Fatalf("sandbox must be a simulated 200, got %d hdr=%q", rec.Code, rec.Header().Get("X-AW-Simulated"))
	}
}

func TestProxy_EscalateHolds(t *testing.T) {
	m := &fakeMediator{res: awspec.Result{Verdict: awspec.Escalate}}
	rec := do(New(m, "a", nil))
	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("escalate must hold (451), got %d", rec.Code)
	}
}

func TestProxy_FailClosedOnError(t *testing.T) {
	m := &fakeMediator{err: errBoom{}}
	rec := do(New(m, "a", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("broker error must fail closed (502), got %d", rec.Code)
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
