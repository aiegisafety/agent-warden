package enforce

import (
	"context"
	"runtime"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

func TestAgentSpecValidate(t *testing.T) {
	if err := (AgentSpec{}).Validate(); err == nil {
		t.Fatal("empty spec must be invalid")
	}
	if err := (AgentSpec{Exe: "x"}).Validate(); err == nil {
		t.Fatal("missing WorkDir must be invalid")
	}
	if err := (AgentSpec{Exe: "x", WorkDir: "/w"}).Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
}

func TestInterceptorContract(t *testing.T) {
	ic := NewInterceptor()
	if Platform() == "" {
		t.Fatal("Platform() must be non-empty")
	}
	var seen awspec.Action
	ic.OnEffect(func(a awspec.Action) Verdict { seen = a; return awspec.Allow })

	// Invalid spec is rejected before any OS work, on every platform.
	if err := ic.Launch(context.Background(), AgentSpec{}); err == nil {
		t.Fatal("Launch must reject invalid spec")
	}

	// On non-Windows the backend is the stub: a valid spec yields ErrUnsupported
	// (and never touches the mediator). On Windows it would attempt a real launch,
	// which we don't exercise in unit tests.
	if runtime.GOOS != "windows" {
		err := ic.Launch(context.Background(), AgentSpec{Exe: "true", WorkDir: t.TempDir()})
		if err != ErrUnsupported {
			t.Fatalf("non-windows Launch must return ErrUnsupported, got %v", err)
		}
		if seen.Class != "" {
			t.Fatalf("stub must not call mediator, but saw %q", seen.Class)
		}
	}
}

func TestEffectFuncHonorsVerdict(t *testing.T) {
	var f EffectFunc = func(a awspec.Action) Verdict {
		if a.Class == "process.launch" {
			return awspec.Deny
		}
		return awspec.Allow
	}
	if f(awspec.Action{Class: "process.launch"}) != awspec.Deny {
		t.Fatal("EffectFunc verdict not honored")
	}
}
