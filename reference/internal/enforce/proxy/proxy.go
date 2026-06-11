// Package proxy is the Tier-2 user-mode network mediation point (AW-INT-v0.1
// §2.2 T2-a): a local HTTP proxy the confined agent is pinned to. Every outbound
// request is raised to the AW broker as a net.egress action BEFORE any bytes
// leave the host, and the broker's verdict decides what happens:
//
//	allow    → forward the request for real
//	deny     → 403, nothing leaves
//	escalate → 451, held for a human (nothing leaves)
//	sandbox  → 200 with a decoy body; the agent believes it reached the world
//
// This gives real egress governance in user mode today; kernel-enforced WFP
// (so a process that ignores the proxy still cannot send) is the T2-b driver.
//
// Stdlib only (ADR-0002).
//
// Licensed under the Apache License 2.0.
package proxy

import (
	"fmt"
	"io"
	"net/http"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// Mediator is the broker entry point the proxy consults.
type Mediator interface {
	Mediate(a awspec.Action) (awspec.Result, error)
}

// Server is an http.Handler that mediates outbound requests.
type Server struct {
	M         Mediator
	AgentID   string
	transport http.RoundTripper
}

// New builds a proxy server. rt may be nil (defaults to http.DefaultTransport).
func New(m Mediator, agentID string, rt http.RoundTripper) *Server {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Server{M: m, AgentID: agentID, transport: rt}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	act := awspec.Action{
		AgentID:   nonEmpty(s.AgentID, "confined-agent"),
		Substrate: awspec.SubNet,
		Class:     "net.egress",
		Params:    map[string]string{"dest": host, "method": r.Method, "url": r.URL.String()},
		Source:    "enforce.proxy",
		Tier:      2,
		Tool:      "http",
	}
	res, err := s.M.Mediate(act)
	if err != nil {
		// Fail-closed: a broker error never lets bytes out.
		http.Error(w, "aw-proxy: mediation error (fail-closed)", http.StatusBadGateway)
		return
	}
	switch res.Verdict {
	case awspec.Deny:
		http.Error(w, "aw-proxy: egress denied — "+res.Reason, http.StatusForbidden)
	case awspec.Escalate:
		http.Error(w, "aw-proxy: egress held for approval — "+res.Reason, http.StatusUnavailableForLegalReasons)
	case awspec.Sandbox:
		// Decoy: the agent gets a plausible success; nothing real was sent.
		w.Header().Set("X-AW-Simulated", "1")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"aw_simulated\":true,\"dest\":%q}\n", host)
	case awspec.Allow:
		s.forward(w, r)
	default:
		http.Error(w, "aw-proxy: unknown verdict", http.StatusBadGateway)
	}
}

// forward performs the real outbound request after an allow verdict.
func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // required for client requests
	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "aw-proxy: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
