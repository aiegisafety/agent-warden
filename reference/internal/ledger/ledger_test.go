package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

func appendN(t *testing.T, l *Ledger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append(Body{
			RecordType:    GateDecision,
			AgentID:       "a",
			Substrate:     awspec.SubNet,
			ActionClass:   "net.egress",
			IrrevCategory: awspec.IEgress,
			Verdict:       awspec.Sandbox,
			Simulated:     true,
			EffectDigest:  "x",
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
}

func TestAppendAndVerifyIntact(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ledger.log")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 5)

	res, err := Verify(p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 5 || res.BadSeq != -1 {
		t.Fatalf("expected intact chain of 5, got %+v", res)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ledger.log")
	l, _ := Open(p)
	appendN(t, l, 2)

	l2, err := Open(p) // reopen: must recover head + seq
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 2)

	res, _ := Verify(p)
	if !res.OK || res.Count != 4 {
		t.Fatalf("reopened chain broken: %+v", res)
	}
}

func TestTamperDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ledger.log")
	l, _ := Open(p)
	appendN(t, l, 4)

	// Tamper with the body of record seq 2, keeping its stored chain_hash.
	recs := mustReadLines(t, p)
	var r Record
	if err := json.Unmarshal(recs[2], &r); err != nil {
		t.Fatal(err)
	}
	r.Body.EffectDigest = "TAMPERED" // body changes; chain_hash now won't recompute
	tampered, _ := json.Marshal(r)
	recs[2] = tampered
	writeLines(t, p, recs)

	res, err := Verify(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected tamper to be detected")
	}
	if res.BadSeq != 2 {
		t.Fatalf("expected BadSeq 2, got %d (%s)", res.BadSeq, res.Detail)
	}
}

func TestChainHashDeterministic(t *testing.T) {
	b := Body{Seq: 0, TS: "fixed", HashAlg: "sha256", RecordType: GateDecision,
		AgentID: "a", Substrate: awspec.SubValue, ActionClass: "value.transfer",
		IrrevCategory: awspec.IValue, Verdict: awspec.Sandbox, Simulated: true}
	h1, err := computeChainHash(genesisHash(), b)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := computeChainHash(genesisHash(), b)
	if h1 != h2 {
		t.Fatal("chain hash not deterministic")
	}
	// A changed body must change the hash.
	b.Simulated = false
	h3, _ := computeChainHash(genesisHash(), b)
	if h3 == h1 {
		t.Fatal("hash did not change when body changed")
	}
}

func mustReadLines(t *testing.T, p string) [][]byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		out = append(out, append([]byte(nil), line...))
	}
	return out
}

func writeLines(t *testing.T, p string, lines [][]byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
