// Package awproto defines the newline-delimited JSON protocol an agent uses to
// reach the world through the AW broker (AW-Spec v0.2 §3.1). The agent process
// has no other tool surface: every effect is a Request it writes, and the only
// thing it gets back is a mediated Response. This protocol IS the broker's
// install footprint — "no governance without mediation."
//
// Wire format: one JSON object per line (UTF-8, '\n'-terminated), in both
// directions. Requests carry a monotonic id; the matching Response echoes it.
//
// Honesty note: routing the agent's *tool calls* through this protocol gives
// complete mediation by construction only insofar as the agent has no other way
// to act. OS-level sandboxing of the agent process (so it cannot bypass the
// protocol via raw syscalls) is a hardening step tracked as a residual risk
// (threat-model RR-5, charter §14); it is NOT claimed by this protocol alone.
//
// Licensed under the Apache License 2.0.
package awproto

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Request is one mediated action the agent asks the broker to perform.
type Request struct {
	ID     int            `json:"id"`
	Action awspec.Action  `json:"action"`
}

// Response is the broker's mediated answer to a Request.
type Response struct {
	ID     int           `json:"id"`
	Result awspec.Result `json:"result"`
	Error  string        `json:"error,omitempty"`
}

// Encoder writes protocol messages as newline-delimited JSON.
type Encoder struct{ w *bufio.Writer }

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: bufio.NewWriter(w)} }

func (e *Encoder) WriteRequest(r Request) error  { return e.writeJSON(r) }
func (e *Encoder) WriteResponse(r Response) error { return e.writeJSON(r) }

func (e *Encoder) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	if err := e.w.WriteByte('\n'); err != nil {
		return err
	}
	return e.w.Flush()
}

// Decoder reads newline-delimited JSON protocol messages.
type Decoder struct{ s *bufio.Scanner }

func NewDecoder(r io.Reader) *Decoder {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return &Decoder{s: s}
}

// ReadRequest reads the next Request. Returns io.EOF when the stream ends.
func (d *Decoder) ReadRequest() (Request, error) {
	if !d.s.Scan() {
		if err := d.s.Err(); err != nil {
			return Request{}, err
		}
		return Request{}, io.EOF
	}
	var r Request
	err := json.Unmarshal(d.s.Bytes(), &r)
	return r, err
}

// ReadResponse reads the next Response. Returns io.EOF when the stream ends.
func (d *Decoder) ReadResponse() (Response, error) {
	if !d.s.Scan() {
		if err := d.s.Err(); err != nil {
			return Response{}, err
		}
		return Response{}, io.EOF
	}
	var r Response
	err := json.Unmarshal(d.s.Bytes(), &r)
	return r, err
}
