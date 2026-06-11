// Package server runs the broker's agent-facing protocol loop (AW-Spec v0.2 §3.1).
// It reads awproto Requests from a stream, mediates each through the broker, and
// writes back Responses. It is transport-agnostic: the same loop serves a
// subprocess over stdio (adapters/exec), a socket, or an in-memory pipe (tests).
//
// Licensed under the Apache License 2.0.
package server

import (
	"io"

	"github.com/aiegis/agentwarden/pkg/awproto"
	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Mediator is the single mediated entry point the server drives (the AW broker).
type Mediator interface {
	Mediate(a awspec.Action) (awspec.Result, error)
}

// Serve reads Requests from in and writes Responses to out until in reaches EOF.
// Every action is mediated; the agent obtains no result except through here.
func Serve(m Mediator, in io.Reader, out io.Writer) error {
	dec := awproto.NewDecoder(in)
	enc := awproto.NewEncoder(out)
	for {
		req, err := dec.ReadRequest()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		resp := awproto.Response{ID: req.ID}
		res, mErr := m.Mediate(req.Action)
		if mErr != nil {
			resp.Error = mErr.Error()
		} else {
			resp.Result = res
		}
		if err := enc.WriteResponse(resp); err != nil {
			return err
		}
	}
}
