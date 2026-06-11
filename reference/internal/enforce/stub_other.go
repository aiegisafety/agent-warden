//go:build !windows

// Non-Windows builds get a stub interceptor so the whole module compiles and
// `go test ./...` stays green in the cloud sandbox and on Linux, while the real
// OS confinement is Windows-only this round (AW-INT-v0.1 §2.5). A future Linux
// seccomp/namespaces backend would replace this file's NewInterceptor.
//
// Licensed under the Apache License 2.0.
package enforce

import "context"

// stubInterceptor honors the contract but cannot actually confine: every method
// reports unsupported. It exists for cross-platform compilation only.
type stubInterceptor struct{ onEffect EffectFunc }

// NewInterceptor returns the platform interceptor. On non-Windows it is a stub.
func NewInterceptor() Interceptor { return &stubInterceptor{} }

func (s *stubInterceptor) OnEffect(f EffectFunc) { s.onEffect = f }

func (s *stubInterceptor) Launch(ctx context.Context, spec AgentSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	return ErrUnsupported
}

// Platform reports the backend name (for diagnostics/tests).
func Platform() string { return "stub(non-windows)" }
