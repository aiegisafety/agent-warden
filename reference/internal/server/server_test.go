package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awproto"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// fakeMediator returns a fixed verdict per substrate so we can test the loop
// without the full broker.
type fakeMediator struct{ calls int }

func (f *fakeMediator) Mediate(a awspec.Action) (awspec.Result, error) {
	f.calls++
	switch a.Substrate {
	case awspec.SubValue:
		return awspec.Result{Verdict: awspec.Sandbox, Simulated: true, Payload: "decoy"}, nil
	case awspec.SubCred:
		return awspec.Result{Verdict: awspec.Deny, Reason: "hard deny"}, nil
	default:
		return awspec.Result{Verdict: awspec.Allow}, nil
	}
}

func TestServeMediatesEachRequest(t *testing.T) {
	// Two requests, newline-delimited, fed as the agent's stdout.
	in := &bytes.Buffer{}
	enc := awproto.NewEncoder(in)
	if err := enc.WriteRequest(awproto.Request{ID: 1, Action: awspec.Action{Substrate: awspec.SubFS, Class: "fs.write"}}); err != nil {
		t.Fatal(err)
	}
	if err := enc.WriteRequest(awproto.Request{ID: 2, Action: awspec.Action{Substrate: awspec.SubValue, Class: "value.transfer"}}); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	m := &fakeMediator{}
	if err := Serve(m, in, out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if m.calls != 2 {
		t.Fatalf("expected 2 mediated calls, got %d", m.calls)
	}

	dec := awproto.NewDecoder(out)
	r1, _ := dec.ReadResponse()
	r2, _ := dec.ReadResponse()
	if r1.ID != 1 || r1.Result.Verdict != awspec.Allow {
		t.Fatalf("resp1 unexpected: %+v", r1)
	}
	if r2.ID != 2 || r2.Result.Verdict != awspec.Sandbox || !r2.Result.Simulated {
		t.Fatalf("resp2 should be sandbox+simulated: %+v", r2)
	}
}

func TestServeStopsAtEOF(t *testing.T) {
	out := &bytes.Buffer{}
	if err := Serve(&fakeMediator{}, strings.NewReader(""), out); err != nil {
		t.Fatalf("empty stream should return nil, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("no input should produce no output, got %q", out.String())
	}
}
